use std::{io, io::Write};
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io::Bytes;
use std::iter::Map;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_std::fs::File;
use async_std::io::BufReader;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Timelike, TimeZone, Utc};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use futures::Stream;
use futures::stream::TryStreamExt;
use log::{debug, error, info, warn};
use mongodb::bson::{bson, doc, Document};
use mongodb::Cursor;
use mongodb::options::{AggregateOptions, FindOptions, Hint};
use multibase::Base;
use multihash::Code;
use openssl::pkey::{PKey, Private};
use reqwest::{Body, Response};
use reqwest::multipart::Part;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tempfile::{TempDir, tempdir};
use tokio::fs::File as File_tokio;
use tokio::io::AsyncRead as AsyncRead_Tokio;
use tokio_stream::{Iter as Iter_tokio, StreamExt};
use tokio_util::codec::{BytesCodec, FramedRead};
use uuid::Uuid;
use xz2::stream;

use crate::certificats::{CollectionCertificatsPem, EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ValidateurX509};
use crate::chiffrage::{Chiffreur, CipherMgs2, CommandeSauvegarderCle, Dechiffreur, DecipherMgs2, FingerprintCleChiffree, FormatChiffrage, Mgs2CipherData, Mgs2CipherKeys};
use crate::configuration::{ConfigMessages, IsConfigNoeud};
use crate::constantes::*;
use crate::constantes::Securite::L3Protege;
use crate::fichiers::{CompresseurBytes, DecompresseurBytes, FichierWriter, parse_tar, TraiterFichier};
use crate::formatteur_messages::{DateEpochSeconds, Entete, FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::hachages::{hacher_serializable, Hacheur};
use crate::middleware::{IsConfigurationPki, MiddlewareDb, MiddlewareMessage};
use crate::mongo_dao::MongoDao;
use crate::rabbitmq_dao::TypeMessageOut;
use crate::recepteur_messages::TypeMessage;
use crate::transactions::{regenerer, sauvegarder_batch, TraiterTransaction};
use crate::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage};

/// Lance un backup complet de la collection en parametre.
pub async fn backup<'a, M, S>(middleware: &M, nom_domaine: S, nom_collection_transactions: S, chiffrer: bool) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: MongoDao + ValidateurX509 + Chiffreur + FormatteurMessage + GenerateurMessages + ConfigMessages,
    S: Into<&'a str>,
{
    // Creer repertoire temporaire de travail pour le backup
    let workdir = tempfile::tempdir()?;
    debug!("Backup vers tmp : {:?}", workdir);

    let nom_coll_str = nom_collection_transactions.into();

    let nom_domaine_str = nom_domaine.into();

    let info_backup = BackupInformation::new(
        nom_domaine_str,
        nom_coll_str,
        chiffrer,
        Some(workdir.path().to_owned())
    )?;

    let (reponse, flag_erreur) = match backup_horaire(middleware, workdir, nom_coll_str, &info_backup).await {
        Ok(()) => {
            // Emettre trigger pour declencher backup du jour precedent
            let reponse = middleware.formatter_reponse(json!({"ok": true}), None)?;
            (reponse, false)
        },
        Err(e) => {
            error!("Erreur traitement backup : {:?}", e);
            let reponse = middleware.formatter_reponse(json!({"ok": false, "err": format!("{:?}", e)}), None)?;

            (reponse, true)
        },
    };

    // Utiliser flag pour emettre evenement erreur (note : faire hors du match a cause Err not Send)
    if flag_erreur {
        let timestamp_backup = Utc::now();
        if let Err(e) = emettre_evenement_backup(middleware, &info_backup, "backupHoraireErreur", &timestamp_backup).await {
            error!("Erreur emission evenement erreur de backup : {:?}", e);
        }
        Err("Erreur backup horaire, voir logs")?
    } else {
        backup_quotidien(middleware, &info_backup).await?;
    }

    Ok(Some(reponse))
}

/// Effectue un backup horaire
async fn backup_horaire<M>(middleware: &M, workdir: TempDir, nom_coll_str: &str, info_backup: &BackupInformation) -> Result<(), Box<dyn Error>>
where M: MongoDao + ValidateurX509 + Chiffreur + FormatteurMessage + GenerateurMessages + ConfigMessages,
{
    let timestamp_backup = Utc::now();
    if let Err(e) = emettre_evenement_backup(middleware, &info_backup, "backupHoraireDebut", &timestamp_backup).await {
        error!("Erreur emission evenement debut backup : {:?}", e);
    }

    // Generer liste builders domaine/heures
    let builders = grouper_backups(middleware, &info_backup).await?;

    debug!("Backup horaire collection {} : {:?}", nom_coll_str, builders);

    // Tenter de charger entete du dernier backup de ce domaine/partition
    let mut entete_precedente: Option<Entete> = requete_entete_dernier(middleware, nom_coll_str).await?;

    for mut builder in builders {

        // Calculer hachage entete precedente
        match entete_precedente {
            Some(e) => {
                builder.set_backup_precedent(&e)?
            },
            None => (),
        }

        // Creer fichier de transactions
        let mut path_fichier_transactions = workdir.path().to_owned();
        path_fichier_transactions.push(PathBuf::from(builder.get_nomfichier_transactions()));

        let mut curseur = requete_transactions(middleware, &info_backup, &builder).await?;
        let cipher_keys = serialiser_transactions(
            middleware,
            &mut curseur,
            &mut builder,
            path_fichier_transactions.as_path()
        ).await?;

        // Signer et serialiser catalogue
        let (catalogue_horaire, catalogue_signe, commande_cles) = serialiser_catalogue(
            middleware, builder).await?;
        debug!("Nouveau catalogue horaire : {:?}\nCommande maitredescles : {:?}", catalogue_horaire, commande_cles);
        let reponse = uploader_backup(
            middleware,
            path_fichier_transactions.as_path(),
            &catalogue_horaire,
            &catalogue_signe,
            commande_cles
        ).await?;

        if !reponse.status().is_success() {
            Err(format!("Erreur upload fichier : {:?}", reponse))?;
        }

        // Marquer transactions du backup comme completees
        marquer_transaction_backup_complete(
            middleware,
            info_backup.nom_collection_transactions.as_str(),
            &catalogue_horaire
        ).await?;

        entete_precedente = Some(catalogue_signe.entete.clone());
        if !catalogue_horaire.snapshot {
            // Soumettre catalogue horaire sous forme de transaction (domaine Backup)

            let routage = RoutageMessageAction::new("Backup", "catalogueHoraire");
            let reponse_catalogue = middleware.emettre_message_millegrille(
                routage,true, TypeMessageOut::Transaction, catalogue_signe
            ).await?;
            debug!("Reponse soumission catalogue : {:?}", reponse_catalogue);
        }
    }

    if let Err(e) = emettre_evenement_backup(middleware, &info_backup, "backupHoraireTermine", &timestamp_backup).await {
        error!("Erreur emission evenement fin backup : {:?}", e);
    }

    Ok(())
}

pub async fn restaurer<M, T>(middleware: Arc<M>, nom_domaine: &str, nom_collection_transactions: &str, noms_collections_docs: &Vec<String>, processor: &T) -> Result<(), Box<dyn Error>>
where
    M: MongoDao + ValidateurX509 + Dechiffreur + GenerateurMessages + IsConfigNoeud + VerificateurMessage + 'static,
    T: TraiterTransaction,
{
    if let Err(e) = emettre_evenement_restauration(middleware.as_ref(), nom_domaine, "debutRestauration").await {
        error!("Erreur emission message restauration : {:?}", e);
    }

    let workdir = tempfile::tempdir()?;
    info!("Demarrage restauration, utilisation workdir {:?}", workdir);
    let download_result = match download_backup(middleware.clone(), nom_domaine, nom_collection_transactions, workdir.path()).await {
        Ok(()) => Ok(()),
        Err(e) => {
            Err(format!("Erreur download backup : {:?}", e))
        }
    };

    match download_result {
        Ok(()) => (),
        Err(e) => {
            if let Err(e) = emettre_evenement_restauration(middleware.as_ref(), nom_domaine, "erreurDownload").await {
                error!("Erreur emission message restauration : {:?}", e);
            }
            Err(e)?
        }
    }

    debug!("Restauration des transactions termines, debut regeneration {}", nom_collection_transactions);
    let regenerer_result = match regenerer(middleware.as_ref(), nom_collection_transactions, noms_collections_docs, processor).await {
        Ok(()) => Ok(()),
        Err(e) => {
            Err(format!("Erreur regenerer : {:?}", e))
        }
    };

    match regenerer_result {
        Ok(()) => (),
        Err(e) => {
            if let Err(e) = emettre_evenement_restauration(middleware.as_ref(), nom_domaine, "erreurRegeneration").await {
                error!("Erreur emission message restauration : {:?}", e);
            }
            Err(e)?
        }
    }

    info!("Fin regeneration {}", nom_collection_transactions);

    if let Err(e) = emettre_evenement_restauration(middleware.as_ref(), nom_domaine, "restaurationTerminee").await {
        error!("Erreur emission message restauration : {:?}", e);
    }

    Ok(())
}

/// Identifie les sousdomaines/heures a inclure dans le backup.
async fn grouper_backups(middleware: &impl MongoDao, backup_information: &BackupInformation) -> Result<Vec<CatalogueHoraireBuilder>, Box<dyn Error>> {

    let nom_collection = backup_information.nom_collection_transactions.as_str();

    let partition = match backup_information.partition.as_ref() {
        Some(p) => bson!(p),
        None => bson!({"$exists": false})
    };

    let limite_snapshot = {
        let mut limite_snapshot = Utc::now() - Duration::hours(1);
        limite_snapshot.with_minute(0);
        limite_snapshot.with_second(0);
        limite_snapshot.with_nanosecond(0);
        limite_snapshot
    };

    let collection = middleware.get_collection(nom_collection)?;
    let pipeline = vec! [
        doc! {"$match": {
            TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$lt": limite_snapshot},
            TRANSACTION_CHAMP_BACKUP_FLAG: false,
            TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
            TRANSACTION_CHAMP_ENTETE_PARTITION: partition,
        }},

        // Grouper par domaines et heure
        doc! {"$group": {
            "_id": {
                "domaine": "$en-tete.domaine",
                "heure": {
                    "year": {"$year": "$_evenements.transaction_traitee"},
                    "month": {"$month": "$_evenements.transaction_traitee"},
                    "day": {"$dayOfMonth": "$_evenements.transaction_traitee"},
                    "hour": {"$hour": "$_evenements.transaction_traitee"},
                }
            },
        }},

        // Trier par heure
        doc! {"$sort": {"_id.heure": 1}},
    ];

    let mut options = AggregateOptions::builder()
        .hint(Hint::Name(String::from("backup_transactions")))
        .build();

    let mut curseur = collection.aggregate(pipeline, options).await?;

    let mut builders = Vec::new();

    while let Some(entree) = curseur.next().await {
        debug!("Entree aggregation : {:?}", entree);
        let tmp_id = entree?;
        let info_id = tmp_id.get("_id").expect("id").as_document().expect("doc id");

        let domaine = info_id.get("domaine").expect("domaine").as_str().expect("str");
        let doc_heure = info_id.get("heure").expect("heure").as_document().expect("doc heure");
        let annee = doc_heure.get("year").expect("year").as_i32().expect("i32");
        let mois = doc_heure.get("month").expect("month").as_i32().expect("i32") as u32;
        let jour = doc_heure.get("day").expect("day").as_i32().expect("i32") as u32;
        let heure = doc_heure.get("hour").expect("hour").as_i32().expect("i32") as u32;

        let date = DateEpochSeconds::from_heure(annee, mois, jour, heure);

        let builder = CatalogueHoraireBuilder::new(
            date,
            domaine.to_owned(),
            backup_information.uuid_backup.clone(),
            backup_information.chiffrer,
            false,
        );
        builders.push(builder);
    }

    // Ajouter builder pour snapshot
    let date_snapshot = DateEpochSeconds::from(limite_snapshot.clone());
    let builder_snapshot = CatalogueHoraireBuilder::new(
        date_snapshot,
        backup_information.domaine.clone(),
        backup_information.uuid_backup.clone(),
        backup_information.chiffrer,
        true,
    );
    builders.push(builder_snapshot);

    Ok(builders)
}

/// Requete pour obtenir l'entete du dernier backup horaire d'une collection
async fn requete_entete_dernier<M>(middleware: &M, nom_collection: &str) -> Result<Option<Entete>, Box<dyn Error>>
where M: GenerateurMessages
{
    let requete = json!({ "domaine": nom_collection });
    let routage = RoutageMessageAction::new("Backup", "backupDernierHoraire");
    let reponse = middleware.transmettre_requete(routage, &requete).await?;

    let message = match reponse {
        TypeMessage::Valide(m) => m.message.parsed,
        _ => Err(format!("Type reponse invalide"))?,
    };

    let entete: Option<Entete> = match message.map_contenu(Some("dernier_backup")) {
        Ok(e) => Some(e),
        Err(e) => None,
    };

    Ok(entete)
}

async fn requete_transactions(middleware: &impl MongoDao, info: &BackupInformation, builder: &CatalogueHoraireBuilder) -> Result<Cursor<Document>, Box<dyn Error>> {
    let nom_collection = &info.nom_collection_transactions;
    let collection = middleware.get_collection(nom_collection)?;

    let debut_heure = builder.heure.get_datetime();
    let fin_heure = debut_heure.clone() + chrono::Duration::hours(1);

    let doc_transaction_traitee = match builder.snapshot {
        true => doc! {"$exists": true}, // Snapshot, on prend toutes les transactions traitees
        false => doc! {"$gte": debut_heure, "$lt": &fin_heure},  // Backup heure specifique
    };

    let filtre = doc! {
        TRANSACTION_CHAMP_BACKUP_FLAG: false,
        TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
        TRANSACTION_CHAMP_TRANSACTION_TRAITEE: doc_transaction_traitee,
    };

    let sort = doc! {TRANSACTION_CHAMP_EVENEMENT_PERSISTE: 1};
    let find_options = FindOptions::builder()
        .sort(sort)
        .hint(Hint::Name(String::from("backup_transactions")))
        .build();

    let curseur = collection.find(filtre, find_options).await?;

    Ok(curseur)
}

async fn serialiser_transactions<M>(
    middleware: &M,
    curseur: &mut Cursor<Document>,
    builder: &mut CatalogueHoraireBuilder,
    path_transactions: &Path,
) -> Result<(), Box<dyn Error>>
where
    M: ValidateurX509 + Chiffreur,
{

    // Creer i/o stream lzma pour les transactions (avec chiffrage au besoin)
    let mut transaction_writer = match builder.chiffrer {
        true => TransactionWriter::new(path_transactions, Some(middleware)).await?,
        false => TransactionWriter::new(path_transactions, None::<&MiddlewareDb>).await?,
    };

    // Obtenir curseur sur transactions en ordre chronologique de flag complete
    while let Some(Ok(d)) = curseur.next().await {
        let entete = d.get("en-tete").expect("en-tete").as_document().expect("document");
        let uuid_transaction = entete.get(TRANSACTION_CHAMP_UUID_TRANSACTION).expect("uuid-transaction").as_str().expect("str");
        let fingerprint_certificat = entete.get(TRANSACTION_CHAMP_FINGERPRINT_CERTIFICAT).expect("fingerprint certificat").as_str().expect("str");

        // Trouver certificat et ajouter au catalogue
        match middleware.get_certificat(fingerprint_certificat).await {
            Some(c) => {
                // debug!("OK Certificat ajoute : {}", fingerprint_certificat);
                builder.ajouter_certificat(c.as_ref());

                // Valider la transaction avec le certificat
                let mut transaction = MessageSerialise::from_serializable(&d)?;
                debug!("Transaction serialisee pour validation :\n{:?}", transaction);
                let options = ValidationOptions::new(true, true, true);
                let resultat = transaction.valider(middleware, Some(&options)).await?;

                if ! ( resultat.signature_valide && resultat.certificat_valide && resultat.hachage_valide.expect("hachage") ) {
                    warn!("Resultat validation invalide pour {}: {:?}", uuid_transaction, resultat);
                    debug!("Resultat validation invalide pour transaction :\n{}", transaction.get_str());
                    continue;
                }

            },
            None => {
                warn!("Certificat {} inconnu, transaction {} ne peut pas etre mise dans le backup", fingerprint_certificat, uuid_transaction);
                continue;
            },
        }

        // Serialiser transaction
        transaction_writer.write_bson_line(&d).await?;

        // Ajouter uuid_transaction dans catalogue
        builder.ajouter_transaction(uuid_transaction);
    }

    let (hachage, cipher_keys) = transaction_writer.fermer().await?;

    builder.transactions_hachage = hachage;
    match &cipher_keys {
        Some(k) => builder.set_cles(k),
        None => (),
    }

    Ok(())
}

async fn serialiser_catalogue(
    middleware: &(impl FormatteurMessage),
    builder: CatalogueHoraireBuilder
) -> Result<(CatalogueHoraire, MessageMilleGrille, Option<MessageMilleGrille>), Box<dyn Error>> {

    let commande_signee = match &builder.cles {
        Some(cles) => {

            // Signer commande de maitre des cles
            let mut identificateurs_document: HashMap<String, String> = HashMap::new();
            identificateurs_document.insert("domaine".into(), builder.nom_domaine.clone());
            identificateurs_document.insert("heure".into(), format!("{}00", builder.heure.format_ymdh()));
            if builder.snapshot {
                identificateurs_document.insert("snapshot".into(), format!("true"));
            }

            let commande_maitredescles = cles.get_commande_sauvegarder_cles(
                BACKUP_NOM_DOMAINE,
                identificateurs_document,
            );

            let value_commande: Value = serde_json::to_value(commande_maitredescles).expect("commande");
            // let msg_commande = MessageJson::new(value_commande);
            let commande_signee = middleware.formatter_message(
                &value_commande,
                Some(MAITREDESCLES_COMMANDE_NOUVELLE_CLE),
                None,
                None,
                None
            )?;

            Some(commande_signee)
        },
        None => None,
    };

    // Signer et serialiser catalogue
    let catalogue = builder.build();
    let catalogue_value = serde_json::to_value(&catalogue)?;
    // let message_json = MessageJson::new(catalogue_value);
    let domaine_action = format!("{}.{}", BACKUP_NOM_DOMAINE, BACKUP_TRANSACTION_CATALOGUE_HORAIRE);
    let catalogue_signe = middleware.formatter_message(
        &catalogue_value,
        Some(domaine_action.as_str()),
        Some(BACKUP_TRANSACTION_CATALOGUE_HORAIRE),
        None,
        None
    )?;

    Ok((catalogue, catalogue_signe, commande_signee))
}

async fn uploader_backup<M>(
    middleware: &M,
    path_transactions: &Path,
    catalogue: &CatalogueHoraire,
    catalogue_signe: &MessageMilleGrille,
    commande_cles: Option<MessageMilleGrille>
) -> Result<Response, Box<dyn Error>>
where
    M: ConfigMessages + IsConfigurationPki,
{
    let message_serialise = MessageSerialise::from_parsed(catalogue_signe.clone()).expect("ser");

    // Compresser catalogue et commande maitre des cles en XZ
    let mut compresseur_catalogue = CompresseurBytes::new().expect("compresseur");
    compresseur_catalogue.write(message_serialise.get_str().as_bytes()).await.expect("write");
    let (catalogue_bytes, _) = compresseur_catalogue.fermer().expect("finish");

    let commande_bytes = match commande_cles {
        Some(c) => {
            let message_serialise = MessageSerialise::from_parsed(c).expect("ser");
            let mut compresseur_commande = CompresseurBytes::new().expect("compresseur");
            debug!("Commande maitre cles : {}", message_serialise.get_str());
            compresseur_commande.write(message_serialise.get_str().as_bytes()).await.expect("write");
            let (commande_bytes, _) = compresseur_commande.fermer().expect("finish");

            Some(commande_bytes)
        },
        None => None
    };

    // let mut path_transactions = workdir.to_owned();
    // path_transactions.push(PathBuf::from(catalogue.transactions_nomfichier.as_str()));

    if ! path_transactions.exists() {
        Err(format!("Fichier {:?} n'existe pas", path_transactions))?;
    }

    let enveloppe = middleware.get_enveloppe_privee().clone();
    let ca_cert_pem = enveloppe.chaine_pem().last().expect("last cert").as_str();
    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
    let identity = reqwest::Identity::from_pem(enveloppe.clecert_pem.as_bytes())?;

    let fichier_transactions_read = File_tokio::open(path_transactions).await?;

    // Uploader fichiers et contenu backup
    let form = {
        let mut form = reqwest::multipart::Form::new()
            .text("timestamp_backup", catalogue.heure.format_ymdh())
            .part("transactions", file_to_part(catalogue.transactions_nomfichier.as_str(), fichier_transactions_read).await)
            .part("catalogue", bytes_to_part(catalogue.catalogue_nomfichier.as_str(), catalogue_bytes, Some("application/xz")));

        if let Some(b) = commande_bytes {
            form = form.part("cles", bytes_to_part(
                "commande_maitredescles.json", b, Some("text/json")));
        }

        form
    };

    let client = reqwest::Client::builder()
        .add_root_certificate(root_ca)
        .identity(identity)
        .https_only(true)
        .use_rustls_tls()
        .timeout(core::time::Duration::new(20, 0))
        .build()?;

    let mut url = match middleware.get_configuration_noeud().fichiers_url.as_ref() {
        Some(url) => url.to_owned(),
        None => {
            Err("URL fichiers n'est pas configure pour les backups")?
        }
    };

    let path_commande = format!("backup/domaine/{}", catalogue.catalogue_nomfichier);;
    url.set_path(path_commande.as_str());

    debug!("Url backup : {:?}", url);

    // let url_put = format!("https://{}/backup/domaine/{}", "mg-dev4:3021", catalogue.catalogue_nomfichier);
    let mut request = client.put(url).multipart(form);

    let response = request.send().await?;
    debug!("Resultat {} : {:?}", response.status(), response);

    Ok(response)
}

async fn marquer_transaction_backup_complete(middleware: &dyn MongoDao, nom_collection: &str, catalogue_horaire: &CatalogueHoraire) -> Result<(), Box<dyn Error>> {
    debug!("Set flag backup pour transactions de {} : {:?}", nom_collection, catalogue_horaire.uuid_transactions);

    let collection = middleware.get_collection(nom_collection)?;
    let filtre = doc! {
        TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: {"$in": &catalogue_horaire.uuid_transactions}
    };
    let ops = doc! {
        "$set": {TRANSACTION_CHAMP_BACKUP_FLAG: true},
        "$currentDate": {TRANSACTION_CHAMP_BACKUP_HORAIRE: true},
    };

    let r= collection.update_many(filtre, ops, None).await?;
    if r.matched_count as usize != catalogue_horaire.uuid_transactions.len() {
        Err(format!(
            "Erreur mismatch nombre de transactions maj apres backup : {:?} dans le backup != {:?} mises a jour",
            catalogue_horaire.uuid_transactions.len(),
            r.matched_count
        ))?;
    }

    Ok(())
}

async fn download_backup<M>(middleware: Arc<M>, nom_domaine: &str, nom_collection_transactions: &str, workdir: &Path) -> Result<(), Box<dyn Error>>
where M: MongoDao + ValidateurX509 + IsConfigurationPki + IsConfigNoeud + Dechiffreur + VerificateurMessage + 'static {
    let path_fichier = {
        let mut path_fichier = PathBuf::from(workdir);
        path_fichier.push(PathBuf::from("download_backup.tar"));
        path_fichier
    };

    let enveloppe_privee = middleware.get_enveloppe_privee();
    let ca_cert_pem = match enveloppe_privee.chaine_pem().last() {
        Some(cert) => cert.as_str(),
        None => Err(format!("Certificat CA manquant"))?,
    };
    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
    let identity = reqwest::Identity::from_pem(enveloppe_privee.clecert_pem.as_bytes())?;

    let client = reqwest::Client::builder()
        .add_root_certificate(root_ca)
        .identity(identity)
        .https_only(true)
        .use_rustls_tls()
        .build()?;

    let mut url_fichiers = match &middleware.get_configuration_noeud().fichiers_url {
        Some(u) => u.to_owned(),
        None => Err("Erreur backup - configuration serveur fichiers absente")?,
    };
    url_fichiers.set_path(format!("/backup/restaurerDomaine/{}", nom_domaine).as_str());
    debug!("Download backup url : {:?}", url_fichiers);
    let response = client.get(url_fichiers)
        .send()
        .await?;

    debug!("Response get backup {}", response.status());

    // Conserver fichier sur le disque (temporaire)
    // todo Trouver comment streamer en memoire
    {
        let mut stream = response.bytes_stream();
        let mut file_output = File::create(path_fichier.as_path()).await?;
        while let Some(item) = stream.next().await {
            let content = item?;
            file_output.write_all(content.as_ref()).await?;
        }
        file_output.flush().await?;
    }

    let mut fichier_tar = async_std::fs::File::open(path_fichier.as_path()).await?;
    let mut processeur = ProcesseurFichierBackup::new(
        enveloppe_privee.clone(),
        middleware.clone()
    );
    parse_tar(middleware.as_ref(), &mut fichier_tar, &mut processeur).await?;

    // Upload les transactions valides
    processeur.sauvegarder_batch(middleware.as_ref(), nom_collection_transactions).await?;

    Ok(())
}

trait BackupHandler {
    fn run() -> Result<(), String>;
}

/// Struct de backup
#[derive(Debug)]
pub struct BackupInformation {
    /// Nom complet de la collection de transactions mongodb
    nom_collection_transactions: String,
    /// Nom du domaine
    domaine: String,
    /// Partition (groupe logique) du backup.
    partition: Option<String>,
    /// Path de travail pour conserver les fichiers temporaires de chiffrage
    workpath: PathBuf,
    /// Identificateur unique du backup (collateur)
    uuid_backup: String,
    /// Flag de chiffrage
    chiffrer: bool,
    /// Repertoire temporaire qui est supprime automatiquement apres le backup.
    tmp_workdir: Option<TempDir>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogueHoraire {
    /// Heure du backup (minutes = 0, secs = 0)
    pub heure: DateEpochSeconds,
    /// True si c'est un snapshot
    pub snapshot: bool,
    /// Nom du domaine ou sous-domaine
    pub domaine: String,
    /// Identificateur unique du groupe de backup (collateur)
    pub uuid_backup: String,

    /// Collection des certificats presents dans les transactions du backup
    certificats: CollectionCertificatsPem,

    pub catalogue_nomfichier: String,
    pub transactions_nomfichier: String,
    pub transactions_hachage: String,
    pub uuid_transactions: Vec<String>,

    /// En-tete du message de catalogue. Presente uniquement lors de deserialization.
    #[serde(rename = "en-tete", skip_serializing)]
    pub entete: Option<Entete>,

    /// Enchainement backup precedent
    backup_precedent: Option<EnteteBackupPrecedent>,

    /// Cle chiffree avec la cle de MilleGrille (si backup chiffre)
    cle: Option<String>,

    /// IV du contenu chiffre
    iv: Option<String>,

    /// Compute tag du contenu chiffre
    tag: Option<String>,

    /// Format du chiffrage
    format: Option<String>,
}

impl CatalogueHoraire {

    pub fn builder(heure: DateEpochSeconds, nom_domaine: String, uuid_backup: String, chiffrer: bool, snapshot: bool) -> CatalogueHoraireBuilder {
        CatalogueHoraireBuilder::new(heure, nom_domaine, uuid_backup, chiffrer, snapshot)
    }

    pub fn get_cipher_data(&self) -> Result<Mgs2CipherData, Box<dyn Error>> {
        match &self.cle {
            Some(c) => {
                let iv = self.iv.as_ref().expect("iv");
                let tag = self.tag.as_ref().expect("tag");
                Mgs2CipherData::new(
                    c.as_str(),
                    iv,
                    tag
                )
            },
            None => Err("Non chiffre")?,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CatalogueHoraireBuilder {
    heure: DateEpochSeconds,
    nom_domaine: String,
    uuid_backup: String,
    chiffrer: bool,
    snapshot: bool,

    certificats: CollectionCertificatsPem,
    uuid_transactions: Vec<String>,
    transactions_hachage: String,
    cles: Option<Mgs2CipherKeys>,
    backup_precedent: Option<EnteteBackupPrecedent>,
}

impl BackupInformation {

    /// Creation d'une nouvelle structure de backup
    pub fn new<S>(
        domaine: S,
        nom_collection_transactions: S,
        chiffrer: bool,
        workpath: Option<PathBuf>
    ) -> Result<BackupInformation, Box<dyn Error>>
    where S: Into<String>
    {
        let (workpath_inner, tmp_workdir): (PathBuf, Option<TempDir>) = match workpath {
            Some(wp) => (wp, None),
            None => {
                let tmp_workdir = tempdir()?;
                let path_tmp = tmp_workdir.path().to_owned();

                (path_tmp, Some(tmp_workdir))
            },
        };

        let uuid_backup = Uuid::new_v4().to_string();

        Ok(BackupInformation {
            nom_collection_transactions: nom_collection_transactions.into(),
            domaine: domaine.into(),
            partition: None,
            workpath: workpath_inner,
            uuid_backup,
            chiffrer,
            tmp_workdir,
        })
    }

}

impl BackupHandler for BackupInformation {
    fn run() -> Result<(), String> {
        info!("Demarrage backup");
        Ok(())
    }
}

impl CatalogueHoraireBuilder {

    fn new(heure: DateEpochSeconds, nom_domaine: String, uuid_backup: String, chiffrer: bool, snapshot: bool) -> Self {
        CatalogueHoraireBuilder {
            heure, nom_domaine, uuid_backup, chiffrer, snapshot,
            certificats: CollectionCertificatsPem::new(),
            uuid_transactions: Vec::new(),
            transactions_hachage: "".to_owned(),
            cles: None,
            backup_precedent: None,
        }
    }

    fn ajouter_certificat(&mut self, certificat: &EnveloppeCertificat) {
        self.certificats.ajouter_certificat(certificat).expect("certificat");
    }

    fn ajouter_transaction(&mut self, uuid_transaction: &str) {
        self.uuid_transactions.push(String::from(uuid_transaction));
    }

    fn transactions_hachage(&mut self, hachage: String) {
        self.transactions_hachage = hachage;
    }

    fn set_cles(&mut self, cles: &Mgs2CipherKeys) {
        self.cles = Some(cles.clone());
    }

    fn get_nomfichier_catalogue(&self) -> PathBuf {
        let mut date_str = self.heure.format_ymdh();
        match self.snapshot {
            true => date_str = format!("{}-SNAPSHOT", date_str),
            false => (),
        }
        PathBuf::from(format!("{}_{}.json.xz", &self.nom_domaine, date_str))
    }

    fn get_nomfichier_transactions(&self) -> PathBuf {
        let mut date_str = self.heure.format_ymdh();
        match self.snapshot {
            true => date_str = format!("{}-SNAPSHOT", date_str),
            false => (),
        }
        let nom_fichier = match self.chiffrer {
            true => format!("{}_{}.jsonl.xz.mgs2", &self.nom_domaine, date_str),
            false => format!("{}_{}.jsonl.xz", &self.nom_domaine, date_str),
        };
        PathBuf::from(nom_fichier)
    }

    /// Set backup_precedent en calculant le hachage de l'en-tete.
    fn set_backup_precedent(&mut self, entete: &Entete) -> Result<(), Box<dyn Error>> {

        let hachage_entete = hacher_serializable(entete)?;

        let entete_calculee = EnteteBackupPrecedent {
            hachage_entete,
            uuid_transaction: entete.uuid_transaction.clone(),
        };

        self.backup_precedent = Some(entete_calculee);

        Ok(())
    }

    pub fn build(self) -> CatalogueHoraire {

        let date_str = self.heure.format_ymdh();

        // Build collections de certificats
        let transactions_hachage = self.transactions_hachage.clone();
        let transactions_nomfichier = self.get_nomfichier_transactions().to_str().expect("str").to_owned();
        let catalogue_nomfichier = format!("{}_{}.json.xz", &self.nom_domaine, date_str);

        let (format, cle, iv, tag) = match(self.cles) {
            Some(cles) => {
                (Some(cles.get_format()), cles.get_cle_millegrille(), Some(cles.iv), Some(cles.tag))
            },
            None => (None, None, None, None)
        };

        CatalogueHoraire {
            heure: self.heure,
            snapshot: self.snapshot,
            domaine: self.nom_domaine,
            uuid_backup: self.uuid_backup,
            catalogue_nomfichier,

            certificats: self.certificats,

            transactions_hachage,
            transactions_nomfichier,
            uuid_transactions: self.uuid_transactions,

            entete: None,  // En-tete chargee lors de la deserialization

            backup_precedent: self.backup_precedent,
            cle, iv, tag, format,
        }
    }

}

struct TransactionWriter<'a> {
    fichier_writer: FichierWriter<'a>,
}

impl<'a> TransactionWriter<'a> {

    pub async fn new<C>(path_fichier: &'a Path, middleware: Option<&C>) -> Result<TransactionWriter<'a>, Box<dyn Error>>
    where
        C: Chiffreur,
    {
        let fichier_writer = FichierWriter::new(path_fichier, middleware).await?;
        Ok(TransactionWriter{fichier_writer})
    }

    /// Serialise un objet Json (Value) dans le fichier. Ajouter un line feed (\n).
    pub async fn write_json_line(&mut self, contenu: &Value) -> Result<usize, Box<dyn Error>> {
        // Convertir value en bytes
        let mut contenu_bytes = serde_json::to_string(contenu)?.as_bytes().to_owned();

        // Ajouter line feed (\n)
        contenu_bytes.push(NEW_LINE_BYTE);

        // Write dans le fichier
        self.fichier_writer.write(contenu_bytes.as_slice()).await
    }

    pub async fn write_bson_line(&mut self, contenu: &Document) -> Result<usize, Box<dyn Error>> {
        let mut value = serde_json::to_value(contenu)?;

        // S'assurer qu'on a un document (map)
        // Retirer le champ _id si present
        match value.as_object_mut() {
            Some(mut doc) => {
                doc.remove("_id");
                self.write_json_line(&value).await
            },
            None => {
                warn!("Valeur bson fournie en backup n'est pas un _Document_, on l'ignore : {:?}", contenu);
                Ok((0))
            }
        }
    }

    pub async fn fermer(mut self) -> Result<(String, Option<Mgs2CipherKeys>), Box<dyn Error>> {
        self.fichier_writer.fermer().await
    }

}

pub struct TransactionReader<'a> {
    data: Box<dyn AsyncRead + Unpin + 'a>,
    xz_decoder: stream::Stream,
    // hacheur: Hacheur,
    dechiffreur: Option<DecipherMgs2>,
}

impl<'a> TransactionReader<'a> {

    const BUFFER_SIZE: usize = 65535;

    pub fn new(data: Box<impl AsyncRead + Unpin + 'a>, decipher_data: Option<&Mgs2CipherData>) -> Result<Self, Box<dyn Error>> {

        let mut xz_decoder = stream::Stream::new_stream_decoder(u64::MAX, stream::TELL_NO_CHECK).expect("stream");

        let dechiffreur = match decipher_data {
            Some(cd) => {
                let mut dechiffreur = DecipherMgs2::new(cd)?;
                Some(dechiffreur)
            },
            None => None,
        };

        Ok(TransactionReader {
            data,
            xz_decoder,
            // hacheur,
            dechiffreur,
        })
    }

    /// todo Les transactions sont lues en memoire avant d'etre traitees - changer pour iterator async
    pub async fn read_transactions(&mut self) -> Result<Vec<Value>, Box<dyn Error>> {
        let mut buffer = [0u8; TransactionReader::BUFFER_SIZE/2];
        let mut xz_output = Vec::new();
        xz_output.reserve(TransactionReader::BUFFER_SIZE);

        let mut dechiffrage_output = [0u8; TransactionReader::BUFFER_SIZE];

        let mut output_complet = Vec::new();

        loop {
            let mut reader = &mut self.data;
            let len = reader.read(&mut buffer).await.expect("lecture");
            if len == 0 {break}

            // let traiter_bytes = &buffer[..len];

            let traiter_bytes = match &mut self.dechiffreur {
                Some(d) => {
                    d.update(&buffer[..len], &mut dechiffrage_output).expect("update");
                    &dechiffrage_output[..len]
                },
                None => &buffer[..len],
            };

            // debug!("Lu {}\n{:?}", len, traiter_bytes);
            let status = self.xz_decoder.process_vec(traiter_bytes, &mut xz_output, stream::Action::Run).expect("xz-output");
            // debug!("Status xz : {:?}\n{:?}", status, xz_output);

            output_complet.append(&mut xz_output);
        }

        loop {
            let traiter_bytes = [0u8;0];

            let status = self.xz_decoder.process_vec(&traiter_bytes[0..0], &mut xz_output, stream::Action::Run).expect("xz-output");
            output_complet.append(&mut xz_output);
            if status != stream::Status::Ok {
                if status != stream::Status::StreamEnd {
                    Err("Erreur decompression xz")?;
                }
                break
            }
        }

        // Verifier si a on a un newline dans le buffer pour separer les transactions
        // debug!("Output complet : {:?}", output_complet);

        let index_nl = output_complet.as_slice().split(|n| n == &NEW_LINE_BYTE);

        let mapper = index_nl.map(|t| {
            match String::from_utf8(t.to_vec()) {
                Ok(ts) => {
                    match serde_json::from_str::<Value>(ts.as_str()) {
                        Ok(v) => Ok(v),
                        Err(e) => Err(format!("Erreur {:?}", e)),
                    }
                },
                Err(e) => Err(format!("Erreur {:?}", e)),
            }
        });

        let mut transactions = Vec::new();
        for t in mapper {
            match t {
                Ok(tt) => transactions.push(tt),
                Err(e) => error!("Erreur lecture : {:?}", e)
            }
        }

        Ok(transactions)
    }

}

/// Genere une nouvelle Part pour un fichier a uploader dans un form multipart
async fn file_to_part(filename: &str, file: File_tokio) -> Part {
    let metadata = &file.metadata().await.expect("md");
    let len = metadata.len();

    let stream = FramedRead::new(file, BytesCodec::new());
    // let reader = BufReader::new(file);
    let body = Body::wrap_stream(stream);

    Part::stream_with_length(body, len)
        .mime_str("application/octet-stream").expect("mimetype")
        .file_name(filename.to_owned())
}

/// Genere une nouvelle Part pour un fichier a uploader dans un form multipart
fn bytes_to_part(filename: &str, contenu: Vec<u8>, mimetype: Option<&str>) -> Part {

    let mimetype_inner = match mimetype {
        Some(m) => m,
        None => "application/octet-stream"
    };

    let vec_message = Vec::from(contenu);
    Part::bytes(vec_message)
        .mime_str(mimetype_inner).expect("mimetype")
        .file_name(filename.to_owned())
}

struct ProcesseurFichierBackup {
    enveloppe_privee: Arc<EnveloppePrivee>,
    middleware: Arc<dyn ValidateurX509>,
    catalogue: Option<CatalogueHoraire>,
    decipher: Option<DecipherMgs2>,
    batch: Vec<MessageMilleGrille>,
    entete_precedente: Option<Entete>,
}

impl ProcesseurFichierBackup {

    fn new(enveloppe_privee: Arc<EnveloppePrivee>, middleware: Arc<dyn ValidateurX509>) -> Self {
        ProcesseurFichierBackup {
            enveloppe_privee,
            middleware,
            catalogue: None,
            decipher: None,
            batch: Vec::new(),
            entete_precedente: None,
        }
    }

    async fn parse_file<M>(&mut self, middleware: &M, filepath: &async_std::path::Path, stream: &mut (impl futures::io::AsyncRead+Send+Sync+Unpin)) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + Dechiffreur + VerificateurMessage
    {
        debug!("Parse fichier : {:?}", filepath);

        match filepath.extension() {
            Some(e) => {
                let type_ext = e.to_ascii_lowercase();
                match type_ext.to_str().expect("str") {
                    "xz" => {
                        let path_str = filepath.to_str().expect("str");
                        if path_str.ends_with(".json.xz") {
                            // Catalogue
                            self.parse_catalogue(middleware, filepath, stream).await
                        } else if path_str.ends_with(".jsonl.xz") {
                            // Transactions non chiffrees
                            self.parse_transactions(middleware, filepath, stream).await
                        } else {
                            warn ! ("Type fichier inconnu, on skip : {:?}", filepath);
                            Ok(())
                        }
                    },
                    "mgs2" => self.parse_transactions(middleware, filepath, stream).await,
                    _ => {
                        warn ! ("Type fichier inconnu, on skip : {:?}", e);
                        Ok(())
                    }
                }
            },
            None => {
                warn!("Type fichier inconnu, on skip : {:?}", filepath);
                Ok(())
            }
        }
    }

    async fn parse_catalogue<M>(&mut self, middleware: &M, filepath: &async_std::path::Path, stream: &mut (impl futures::io::AsyncRead+Send+Sync+Unpin)) -> Result<(), Box<dyn Error>>
    where M: Dechiffreur + VerificateurMessage + ValidateurX509
    {
        debug!("Parse catalogue : {:?}", filepath);

        let catalogue_message = {
            // Valider le catalogue
            let mut message = {
                let mut decompresseur = DecompresseurBytes::new().expect("decompresseur");
                decompresseur.update_std(stream).await?;
                let catalogue_bytes = decompresseur.finish()?;
                let catalogue_str = String::from_utf8(catalogue_bytes)?;
                debug!("Catalogue extrait\n{}", catalogue_str);
                let mut message = MessageSerialise::from_str(catalogue_str.as_str())?;

                message
            };

            // Charger certiticat
            let fingerprint = message.get_entete().fingerprint_certificat.as_str();
            let option_cert = match message.get_msg().certificat.as_ref() {
                Some(c) => {
                    Some(middleware.charger_enveloppe(c, Some(fingerprint)).await?)
                },
                None => middleware.get_certificat(fingerprint).await
            };
            message.certificat = option_cert;

            let validations_options = ValidationOptions::new(true, true, false);
            let resultat_verification = middleware.verifier_message(&mut message, Some(&validations_options))?;
            if !resultat_verification.signature_valide {
                Err(format!("Catalogue invalide (signature: {:?})\n{}", resultat_verification, message.get_str()))?;
            }

            message
        };

        // Determiner le type de catalogue
        let type_catalogue = {
            // let mut decompresseur = DecompresseurBytes::new().expect("decompresseur");
            // decompresseur.update_std(stream).await?;
            // let catalogue_bytes = decompresseur.finish()?;
            //
            // let catalogue_message: MessageSerialise = serde_json::from_slice(catalogue_bytes.as_slice())?;
            // let entete = catalogue_message.entete.clone();
            // let uuid_transaction = entete.uuid_transaction.clone();

            let domaine = match &catalogue_message.get_entete().domaine {
                Some(d) => d.as_str(),
                None => "",
            };

            let type_catalogue = match domaine {
                "Backup.catalogueQuotidienFinaliser" => TypeCatalogueBackup::Quotidien(catalogue_message),
                "Backup.catalogueHoraire" => {
                    let catalogue: CatalogueHoraire = serde_json::from_str(catalogue_message.get_str())?;
                    TypeCatalogueBackup::Horaire(catalogue)
                },
                _ => {
                    warn!("Type catalogue inconnu, ok skip {:?}", domaine);
                    return Ok(())
                },
            };

            type_catalogue
        };

        match type_catalogue {
            TypeCatalogueBackup::Horaire(catalogue) => {
                //debug!("Catalogue json decipher present? {:?}, Value : {:?}", self.decipher, catalogue);
                let entete_courante = match &catalogue.entete {
                    Some(e) => Some(e.clone()),
                    None => None,
                };
                self.catalogue = Some(catalogue);
                // let catalogue_ref = self.catalogue.as_ref().expect("catalogue");

                // Traiter le catalogue horaire
                self.traiter_catalogue_horaire(middleware, filepath).await?;

                // Conserver en-tete du catalogue courant. Va permettre de verifier le chainage avec prochain fichier.
                if let Some(e) = entete_courante {
                    debug!("En-tete du catalogue charge : {:?}", e);
                    self.entete_precedente = Some(e);
                }

                Ok(())
            },
            TypeCatalogueBackup::Quotidien(m) => {
                // Rien a faire pour catalogue quotidien
                Ok(())
            }
        }

        // if let Some(ep) = &catalogue.backup_precedent {
        //     if let Some(ec) = &self.entete_precedente {
        //         debug!("Entete precedente {:?}\nInfo catalogue predecent {:?}", ec, ep);
        //
        //         // Verifier chaine avec en-tete du catalogue
        //         let uuid_precedent = ep.uuid_transaction.as_str();
        //         let uuid_courant = ec.uuid_transaction.as_str();
        //
        //         if uuid_precedent == uuid_courant {
        //             match hacher_serializable(ec) {
        //                 Ok(hc) => {
        //                     // Calculer hachage en-tete precedente
        //                     let hp = ep.hachage_entete.as_str();
        //                     if hc.as_str() != hp {
        //                         warn!("Chainage au catalogue {:?}: {}/{} est brise (hachage mismatch)", filepath, catalogue.domaine, uuid_catalogue_courant);
        //                     }
        //                 },
        //                 Err(e) => {
        //                     error!("Chainage au catalogue {:?}: {}/{} est brise (erreur calcul hachage)", filepath, catalogue.domaine, uuid_catalogue_courant);
        //                 }
        //             };
        //         } else {
        //             warn!("Chainage au catalogue {:?}: {}/{} est brise (uuid mismatch catalogue precedent {} avec info courante {})",
        //                 filepath, catalogue.domaine, uuid_catalogue_courant, uuid_precedent, uuid_courant);
        //         }
        //     }
        // }
        //
        // // Recuperer cle et creer decipher au besoin
        // self.decipher = match catalogue.cle {
        //     Some(_) => {
        //         let transactions_hachage_bytes = catalogue.transactions_hachage.as_str();
        //         let dechiffreur = middleware.get_decipher(transactions_hachage_bytes).await?;
        //         Some(dechiffreur)
        //     },
        //     None => None,
        // };

        // let mut cle = match catalogue.get_cipher_data() {
        //     Ok(c) => Some(c),
        //     Err(e) => None,
        // };
        //
        // // Tenter de dechiffrer la cle
        // if let Some(mut cipher_data) = cle {
        //     debug!("Creer cipher pour {:?}", cipher_data);
        //     match cipher_data.dechiffrer_cle(self.enveloppe_privee.cle_privee()) {
        //         Ok(_) => {
        //             // Creer Cipher
        //             self.decipher = Some(DecipherMgs2::new(&cipher_data)?);
        //         },
        //         Err(e) => {
        //             error!("Decipher incorrect, transactions ne seront pas lisibles : {:?}", e);
        //         }
        //     };
        // }

        // Ok(())
    }

    async fn traiter_catalogue_horaire<M>(&mut self, middleware: &M, filepath: &async_std::path::Path) -> Result<(), Box<dyn Error>>
    where M: Dechiffreur + VerificateurMessage + ValidateurX509,
    {
        let catalogue = self.catalogue.as_ref().expect("catalogue");
        let uuid_catalogue_courant = match &catalogue.entete {
            Some(e) => e.uuid_transaction.as_str(),
            None => "",
        };

        if let Some(ep) = &catalogue.backup_precedent {
            if let Some(ec) = &self.entete_precedente {
                debug!("Entete precedente {:?}\nInfo catalogue predecent {:?}", ec, ep);

                // Verifier chaine avec en-tete du catalogue
                let uuid_precedent = ep.uuid_transaction.as_str();
                let uuid_courant = ec.uuid_transaction.as_str();

                if uuid_precedent == uuid_courant {
                    match hacher_serializable(ec) {
                        Ok(hc) => {
                            // Calculer hachage en-tete precedente
                            let hp = ep.hachage_entete.as_str();
                            if hc.as_str() != hp {
                                warn!("Chainage au catalogue {:?}: {}/{} est brise (hachage mismatch)", filepath, catalogue.domaine, uuid_catalogue_courant);
                            }
                        },
                        Err(e) => {
                            error!("Chainage au catalogue {:?}: {}/{} est brise (erreur calcul hachage)", filepath, catalogue.domaine, uuid_catalogue_courant);
                        }
                    };
                } else {
                    warn!("Chainage au catalogue {:?}: {}/{} est brise (uuid mismatch catalogue precedent {} avec info courante {})",
                        filepath, catalogue.domaine, uuid_catalogue_courant, uuid_precedent, uuid_courant);
                }
            }
        }

        // Recuperer cle et creer decipher au besoin
        self.decipher = match catalogue.cle {
            Some(_) => {
                let transactions_hachage_bytes = catalogue.transactions_hachage.as_str();
                let dechiffreur = middleware.get_decipher(transactions_hachage_bytes).await?;
                Some(dechiffreur)
            },
            None => None,
        };

        Ok(())
    }

    async fn parse_transactions(&mut self, middleware: &impl ValidateurX509, filepath: &async_std::path::Path, stream: &mut (impl futures::io::AsyncRead+Send+Sync+Unpin)) -> Result<(), Box<dyn Error>> {
        debug!("Parse transactions : {:?}", filepath);

        let mut output = [0u8; 4096];
        let mut output_decipher = [0u8; 4096];
        // let mut vec_total: Vec<u8> = Vec::new();

        let mut decompresseur = DecompresseurBytes::new()?;

        loop {
            let len = stream.read(&mut output).await?;
            if len == 0 {break}

            let buf = match self.decipher.as_mut() {
                Some(mut d) => {
                    d.update(&output[..len], &mut output_decipher);
                    &output_decipher[..len]
                },
                None => {
                    &output[..len]
                }
            };
            // vec_total.extend_from_slice(buf);
            decompresseur.update_bytes(buf)?;
        }

        let transactions_str = String::from_utf8(decompresseur.finish()?)?;
        //debug!("Bytes dechiffres de la transaction : {:?}", transactions_str);

        let tr_iter = transactions_str.split("\n");
        for transaction_str in tr_iter {
            match self.ajouter_transaction(middleware, transaction_str).await {
                Ok(_) => (),
                Err(e) => {
                    error!("Erreur traitement transaction : {:?}, on l'ignore\n{}", e, transaction_str);
                }
            }
        }

        debug!("Soumettre {} transactions pour restauration", self.batch.len());

        Ok(())
    }

    async fn ajouter_transaction(&mut self, middleware: &impl ValidateurX509, transaction_str: &str) -> Result<(), Box<dyn Error>>{
        let mut msg = MessageSerialise::from_str(transaction_str)?;
        let uuid_transaction = msg.get_entete().uuid_transaction.to_owned();
        let fingerprint_certificat = msg.get_entete().fingerprint_certificat.to_owned();

        // Charger le certificat a partir du catalogue
        if let Some(catalogue) = &self.catalogue {
            match catalogue.certificats.get_enveloppe(middleware, fingerprint_certificat.as_str()).await {
                Some(c) => msg.set_certificat(c),
                None => warn!("Pas de PEM charge pour fingerprint {}", fingerprint_certificat)
            }
        }

        let validation_option = ValidationOptions::new(true, true, true);

        let resultat_validation: ResultatValidation = msg.valider(middleware, Some(&validation_option)).await?;
        match resultat_validation.signature_valide {
            true => {
                // Ajouter la transaction a liste de la batch
                // Marquer transaction comme "restauree", avec flag backup = true
                self.batch.push(msg.preparation_restaurer());
                debug!("Restaurer transaction {}", uuid_transaction);
                Ok(())
            },
            false => {
                Err(format!("Signature invalide pour transaction {}, on l'ignore", uuid_transaction))?
            }
        }
    }

    async fn sauvegarder_batch<M>(&mut self, middleware: &M, nom_collection: &str) -> Result<(), Box<dyn Error>>
    where
        M: MongoDao,
    {
        // Deplacer messages vers nouveau vecteur
        let mut transactions = Vec::new();
        transactions.reserve(self.batch.len());
        while let Some(mut t) = self.batch.pop() {
            transactions.push(t);
        }

        // Inserer transactions
        let resultat = sauvegarder_batch(middleware, nom_collection, transactions).await?;
        debug!("Resultat sauvegarder batch : {:?}", resultat);

        Ok(())
    }
}

enum TypeCatalogueBackup {
    Horaire(CatalogueHoraire),
    Quotidien(MessageSerialise),
}

#[async_trait]
impl TraiterFichier for ProcesseurFichierBackup {
    async fn traiter_fichier<M>(&mut self, middleware: &M, nom_fichier: &async_std::path::Path, stream: &mut (impl AsyncRead + Send + Sync + Unpin)) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + Dechiffreur + VerificateurMessage
    {
        self.parse_file(middleware, nom_fichier, stream).await
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EnteteBackupPrecedent {
    hachage_entete: String,
    uuid_transaction: String,
}

async fn backup_quotidien<M>(middleware: &M, info_backup: &BackupInformation) -> Result<(), Box<dyn Error>>
where M: GenerateurMessages
{
    let now = Utc::now() - Duration::days(1);
    let hier = now.
        with_hour(0).expect("hour").
        with_minute(0).expect("minute").
        with_second(0).expect("second").
        with_nanosecond(0).expect("nano");

    let trigger = json!({
        "jour": hier.timestamp(),
        "domaine": &info_backup.domaine,
        "partition": &info_backup.partition,
        "uuid_rapport": &info_backup.uuid_backup,
    });

    let routage = RoutageMessageAction::builder("Backup", "declencherBackupQuotidien")
        .exchanges(vec!(Securite::L3Protege))
        .build();
    middleware.transmettre_commande(routage, &trigger, false).await?;

    Ok(())
}

pub async fn reset_backup_flag<M>(middleware: &M, nom_collection_transactions: &str) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: MongoDao + GenerateurMessages,
{
    let collection = middleware.get_collection(nom_collection_transactions).expect("coll");
    let filtre = doc! { TRANSACTION_CHAMP_BACKUP_FLAG: true };
    let ops = doc! {
        "$set": {TRANSACTION_CHAMP_BACKUP_FLAG: false},
        "$unset": {
            TRANSACTION_CHAMP_BACKUP_HORAIRE: true,
            TRANSACTION_CHAMP_TRANSACTION_RESTAUREE: true,
        },
    };
    let reponse = match collection.update_many(filtre, ops, None).await {
        Ok(r) => {
            middleware.formatter_reponse(json!({"ok": true, "count": r.modified_count}), None)?
        },
        Err(e) => {
            middleware.formatter_reponse(json!({"ok": false, "err": format!("{:?}", e)}), None)?
        }
    };

    Ok(Some(reponse))
}

pub async fn emettre_evenement_backup<M>(
    middleware: &M, info_backup: &BackupInformation, evenement: &str, timestamp: &DateTime<Utc>) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let value = json!({
        "uuid_rapport": info_backup.uuid_backup.as_str(),
        "evenement": evenement,
        "domaine": info_backup.domaine.as_str(),
        "timestamp": timestamp.timestamp(),
    });

    let routage = RoutageMessageAction::builder("Backup", "backupMaj")
        .exchanges(vec![L3Protege])
        .build();

    Ok(middleware.emettre_evenement(routage, &value).await?)
}

pub async fn emettre_evenement_restauration<M>(
    middleware: &M, domaine: &str, evenement: &str) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let value = json!({
        "evenement": evenement,
        "domaine": domaine,
    });

    let routage = RoutageMessageAction::builder("Backup", "restaurationMaj")
        .exchanges(vec![L3Protege])
        .build();

    Ok(middleware.emettre_evenement(routage, &value).await?)
}

// def transmettre_evenement_backup(self, uuid_rapport: str, evenement: str, heure: datetime.datetime, info: dict = None, sousdomaine: str = None):
//     if sousdomaine is None:
//         sousdomaine = self._nom_domaine
//
//     evenement_contenu = {
//         ConstantesBackup.CHAMP_UUID_RAPPORT: uuid_rapport,
//         Constantes.EVENEMENT_MESSAGE_EVENEMENT: evenement,
//         ConstantesBackup.LIBELLE_DOMAINE: sousdomaine,
//         Constantes.EVENEMENT_MESSAGE_EVENEMENT_TIMESTAMP: int(heure.timestamp()),
//         ConstantesBackup.LIBELLE_SECURITE: self.__niveau_securite,
//     }
//     if info:
//         evenement_contenu['info'] = info
//
//     domaine = 'evenement.Backup.' + ConstantesBackup.EVENEMENT_BACKUP_MAJ
//
//     self._contexte.generateur_transactions.emettre_message(
//         evenement_contenu, domaine, exchanges=[Constantes.SECURITE_PROTEGE]
//     )


#[cfg(test)]
mod backup_tests {
    use serde_json::json;

    // use crate::middleware::{CompresseurBytes, preparer_middleware_pki};
    use crate::fichiers::CompresseurBytes;
    use crate::certificats::certificats_tests::{CERT_DOMAINES, CERT_FICHIERS, charger_enveloppe_privee_env, prep_enveloppe};
    use crate::fichiers::fichiers_tests::ChiffreurDummy;
    use crate::test_setup::setup;

    use super::*;

    const NOM_DOMAINE_BACKUP: &str = "Domaine.test";
    const NOM_COLLECTION_BACKUP: &str = "CollectionBackup";

    #[test]
    fn init_backup_information() {
        let info = BackupInformation::new(
            NOM_DOMAINE_BACKUP,
            NOM_COLLECTION_BACKUP,
            false,
            None
        ).expect("init");

        let workpath = info.workpath.to_str().unwrap();

        assert_eq!(&info.nom_collection_transactions, NOM_COLLECTION_BACKUP);
        // assert_eq!(&info.nom_domaine, NOM_DOMAINE_BACKUP);
        assert_eq!(info.chiffrer, false);
        assert_eq!(workpath.starts_with("/tmp/."), true);
    }

    #[test]
    fn init_backup_horaire_builder() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 0);
        let uuid_backup = Uuid::new_v4().to_string();

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup, false, false);

        assert_eq!(catalogue_builder.heure.get_datetime().timestamp(), heure.get_datetime().timestamp());
        assert_eq!(&catalogue_builder.nom_domaine, NOM_DOMAINE_BACKUP);
    }

    #[test]
    fn build_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned(), false, false);

        let catalogue = catalogue_builder.build();

        assert_eq!(catalogue.heure, heure);
        assert_eq!(&catalogue.uuid_backup, uuid_backup);
        assert_eq!(&catalogue.catalogue_nomfichier, "Domaine.test_2021080105.json.xz");
        assert_eq!(&catalogue.transactions_nomfichier, "Domaine.test_2021080105.jsonl.xz");
    }

    #[test]
    fn build_catalogue_params() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let transactions_hachage = "zABCD1234";

        let mut catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned(), false, false);

        catalogue_builder.transactions_hachage(transactions_hachage.to_owned());

        let catalogue = catalogue_builder.build();

        assert_eq!(&catalogue.transactions_hachage, transactions_hachage);
    }

    #[test]
    fn serialiser_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned(), false, false);

        let catalogue = catalogue_builder.build();

        let value = serde_json::to_value(catalogue).expect("value");

        // debug!("Valeur catalogue : {:?}", value);
    }

    #[test]
    fn catalogue_to_json() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned(), false, false);

        let catalogue = catalogue_builder.build();

        let value = serde_json::to_value(catalogue).expect("value");
        let catalogue_str = serde_json::to_string(&value).expect("json");
        // debug!("Json catalogue : {:?}", catalogue_str);

        assert_eq!(catalogue_str.find("1627794000"), Some(9));
        assert_eq!(catalogue_str.find(NOM_DOMAINE_BACKUP), Some(48));
        assert_eq!(catalogue_str.find(uuid_backup), Some(60));
    }

    #[test]
    fn build_catalogue_1certificat() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let mut catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned(), false, false);

        let certificat = prep_enveloppe(CERT_DOMAINES);
        // debug!("!!! Enveloppe : {:?}", certificat);

        catalogue_builder.ajouter_certificat(&certificat);

        let catalogue = catalogue_builder.build();
        // debug!("!!! Catalogue : {:?}", catalogue);
        assert_eq!(catalogue.certificats.len(), 1);
    }

    #[tokio::test]
    async fn roundtrip_json() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions.jsonl.xz");

        let mut writer = TransactionWriter::new(path_fichier.as_path(), None::<&MiddlewareDb>).await.expect("writer");
        let doc_json = json!({
            "contenu": "Du contenu a encoder",
            "valeur": 1234,
            // "date": Utc.timestamp(1629464027, 0),
        });
        writer.write_json_line(&doc_json).await.expect("write");
        writer.write_json_line(&doc_json).await.expect("write");
        writer.write_json_line(&doc_json).await.expect("write");

        let file = writer.fermer().await.expect("fermer");
        // debug!("File du writer : {:?}", file);

        let fichier_cs = Box::new(File::open(path_fichier.as_path()).await.expect("open read"));
        let mut reader = TransactionReader::new(fichier_cs, None).expect("reader");
        let transactions = reader.read_transactions().await.expect("transactions");
        for t in transactions {
            // debug!("Transaction : {:?}", t);
            assert_eq!(&doc_json, &t);
        }

    }

    fn get_doc_reference() -> (String, Document) {
        let doc_bson = doc! {
            "_id": "Un ID dummy qui doit etre retire",
            "contenu": "Du contenu BSON (Document) a encoder",
            "valeur": 5678,
            "date": Utc.timestamp(1629464026, 0),
        };

        (String::from("z8VwDbtozVtX5m6Bh11QvveYwHswft516JqBd8QYRWjVgpXak2MDXDqFV4ugSbVZ4yCQ64SqdPVZiGLbRdHpNqU7csY"), doc_bson)
    }

    #[tokio::test]
    async fn ecrire_transactions_writer_bson() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.xz");
        let mut writer = TransactionWriter::new(path_fichier.as_path(), None::<&MiddlewareDb>).await.expect("writer");

        let (mh_reference, doc_bson) = get_doc_reference();
        writer.write_bson_line(&doc_bson).await.expect("write");

        let (mh, decipher_data) = writer.fermer().await.expect("fermer");
        // debug!("File du writer : {:?}, multihash: {}", file, mh);

        assert_eq!(mh.as_str(), &mh_reference);
    }

    // #[tokio::test]
    // async fn chiffrer_roundtrip_backup() {
    //     let (validateur, enveloppe) = charger_enveloppe_privee_env();
    //
    //     let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.xz.mgs2");
    //     let fp_certs = vec!(FingerprintCertPublicKey::new(
    //         String::from("dummy"),
    //         enveloppe.certificat().public_key().clone().expect("cle"),
    //         true
    //     ));
    //
    //     let chiffreur_dummy = ChiffreurDummy {public_keys: fp_certs};
    //
    //     let mut writer = TransactionWriter::new(
    //         path_fichier.as_path(),
    //         Some(&chiffreur_dummy)
    //     ).await.expect("writer");
    //
    //     let (mh_reference, doc_bson) = get_doc_reference();
    //     writer.write_bson_line(&doc_bson).await.expect("write chiffre");
    //     let (mh, mut decipher_data_option) = writer.fermer().await.expect("fermer");
    //
    //     let decipher_keys = decipher_data_option.expect("decipher data");
    //     let mut decipher_key = decipher_keys.get_cipher_data("dummy").expect("cle");
    //
    //     // Verifier que le hachage n'est pas egal au hachage de la version non chiffree
    //     assert_ne!(mh.as_str(), &mh_reference);
    //
    //     decipher_key.dechiffrer_cle(enveloppe.cle_privee()).expect("dechiffrer");
    //
    //     let fichier_cs = Box::new(File::open(path_fichier.as_path()).await.expect("open read"));
    //     let mut reader = TransactionReader::new(fichier_cs, Some(&decipher_key)).expect("reader");
    //     let transactions = reader.read_transactions().await.expect("transactions");
    //
    //     for t in transactions {
    //         // debug!("Transaction dechiffree : {:?}", t);
    //         let valeur_chiffre = t.get("valeur").expect("valeur").as_i64().expect("val");
    //         assert_eq!(valeur_chiffre, 5678);
    //     }
    //
    // }

    // #[tokio::test]
    // async fn processeur_fichier_backup_catalogue() {
    //     setup("processeur_fichier_backup_catalogue");
    //     let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
    //
    //     let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
    //     let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";
    //
    //     // let message_json = MessageJson::new(catalogue_value);
    //     let message_serialise = {
    //         let catalogue_builder = CatalogueHoraireBuilder::new(
    //             heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned(), false, false);
    //         let catalogue = catalogue_builder.build();
    //         let catalogue_value: Value = serde_json::to_value(catalogue).expect("value");
    //         let catalogue_signe = middleware.formatter_message(
    //             &catalogue_value,
    //             Some("Backup"),
    //             Some(BACKUP_TRANSACTION_CATALOGUE_HORAIRE),
    //             None,
    //             None
    //         ).expect("signer");
    //         MessageSerialise::from_parsed(catalogue_signe)
    //     }.expect("build");
    //
    //     let mut compresseur = CompresseurBytes::new().expect("compresseur");
    //     compresseur.write(message_serialise.get_str().as_bytes()).await;
    //     let (catalogue_xz, _) = compresseur.fermer().expect("xz");
    //
    //     let mut buf_reader = BufReader::new(catalogue_xz.as_slice());
    //     let nom_fichier = async_std::path::PathBuf::from("catalogue.xz");
    //     let enveloppe_privee = middleware.get_enveloppe_privee();
    //     let mut processeur = ProcesseurFichierBackup::new(enveloppe_privee, middleware.clone());
    //
    //     processeur.parse_catalogue(middleware.as_ref(), nom_fichier.as_path(), &mut buf_reader).await.expect("parsed");
    //
    //     assert_eq!(processeur.catalogue.is_none(), false);
    //     debug!("Catalogue charge : {:?}", processeur.catalogue);
    // }

}

// #[cfg(test)]
// mod test_integration {
//     use std::io::Bytes;
//     use std::sync::Arc;
//
//     use async_std::io::BufReader;
//     use futures_util::stream::IntoAsyncRead;
//     use tokio::sync::mpsc::{Receiver, Sender};
//
//     use crate::{charger_transaction, CompresseurBytes, MessageValideAction, parse_tar, TransactionImpl, TypeMessage};
//     use crate::certificats::certificats_tests::{CERT_DOMAINES, CERT_FICHIERS, charger_enveloppe_privee_env, prep_enveloppe};
//     use crate::middleware::preparer_middleware_pki;
//     use crate::middleware::serialization_tests::build;
//     use crate::test_setup::setup;
//
//     use super::*;
//     use crate::transactions::TransactionImpl;
//
//     const NOM_DOMAINE: &str = "CorePki";
//     const NOM_COLLECTION_TRANSACTIONS: &str = "CorePki";
//     const NOM_COLLECTION_CERTIFICATS: &str = "CorePki/certificat";
//
//     #[tokio::test]
//     async fn grouper_transactions() {
//         setup("grouper_transactions");
//         // Connecter mongo
//         let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
//         futures.push(tokio::spawn(async move {
//
//             // Test
//             let info = BackupInformation::new(
//                 NOM_DOMAINE,
//                 NOM_COLLECTION_TRANSACTIONS,
//                 false,
//                 None
//             ).expect("info");
//
//             let workdir = tempfile::tempdir().expect("tmpdir");
//             let groupes = grouper_backups(
//                 middleware.as_ref(),
//                 &info
//             ).await.expect("groupes");
//
//             debug!("Groupes : {:?}", groupes);
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     #[tokio::test]
//     async fn serialiser_transactions_compressees() {
//         setup("serialiser_transactions_compressees");
//
//         // let workdir = tempfile::tempdir().expect("tmpdir");
//         let workdir = PathBuf::from("/tmp");
//
//         // Connecter mongo
//         let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
//         futures.push(tokio::spawn(async move {
//
//             // Test
//             let info = BackupInformation::new(
//                 NOM_DOMAINE, NOM_COLLECTION_TRANSACTIONS, false, None).expect("info");
//             let heure = DateEpochSeconds::from_heure(2021, 09, 12, 12);
//             let mut builder = CatalogueHoraire::builder(
//                 heure, NOM_DOMAINE.into(), NOM_COLLECTION_TRANSACTIONS.into(), false, false);
//
//             let mut transactions = requete_transactions(middleware.as_ref(), &info, &builder).await.expect("transactions");
//
//             let mut path_transactions = workdir.clone();
//             path_transactions.push("extraire_transactions.jsonl.xz");
//             // debug!("Sauvegarde transactions sous : {:?}", path_transactions);
//             let resultat = serialiser_transactions(
//                 middleware.as_ref(),
//                 &mut transactions,
//                 &mut builder,
//                 path_transactions.as_path()
//             ).await.expect("serialiser");
//
//             // debug!("Resultat extraction transactions : {:?}", resultat);
//             assert_eq!(10, builder.uuid_transactions.len());
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     #[tokio::test]
//     async fn serialiser_transactions_chiffrage() {
//         setup("serialiser_transactions_chiffrage");
//
//         // let workdir = tempfile::tempdir().expect("tmpdir");
//         let workdir = PathBuf::from("/tmp");
//         let (validateur, enveloppe) = charger_enveloppe_privee_env();
//
//         let certificats_chiffrage = vec! [
//             FingerprintCertPublicKey::new(
//                 String::from("dummy"),
//                 enveloppe.cle_publique().clone(),
//                 true
//             )
//         ];
//
//         // Connecter mongo
//         let (
//             middleware,
//             mut rx_messages,
//             mut rx_triggers,
//             mut futures
//         ) = preparer_middleware_pki(Vec::new(), None);
//         futures.push(tokio::spawn(async move {
//
//             // Test
//             let info = BackupInformation::new(
//                 NOM_DOMAINE,
//                 NOM_COLLECTION_TRANSACTIONS,
//                 true,
//                 None
//             ).expect("info");
//             let heure = DateEpochSeconds::from_heure(2021, 09, 08, 19);
//             let domaine = "Pki";
//             let mut builder = CatalogueHoraire::builder(
//                 heure.clone(), domaine.into(), NOM_COLLECTION_TRANSACTIONS.into(), true, false);
//
//             // Path fichiers transactions et catalogue
//             let mut path_transactions = workdir.clone();
//             path_transactions.push("extraire_transactions.jsonl.xz.mgs2");
//             let mut path_catalogue = workdir.clone();
//             path_catalogue.push("extraire_transactions_catalogue.json.xz");
//
//             let mut transactions = requete_transactions(middleware.as_ref(), &info, &builder).await.expect("transactions");
//
//             serialiser_transactions(
//                 middleware.as_ref(),
//                 &mut transactions,
//                 &mut builder,
//                 path_transactions.as_path()
//             ).await.expect("serialiser");
//
//             // builder.set_cles(&cles);
//
//             // Signer et serialiser catalogue
//             let (catalogue, catalogue_signe, commande_cles) = serialiser_catalogue(
//                 middleware.as_ref(),
//                 builder,
//             ).await.expect("serialiser");
//
//             let message_serialise = MessageSerialise::from_parsed(catalogue_signe).expect("ser");
//
//             let mut writer_catalogue = FichierWriter::new(path_catalogue.as_path(), None::<&MiddlewareDbPki>)
//                 .await.expect("write catalogue");
//             writer_catalogue.write(message_serialise.get_str().as_bytes()).await.expect("write");
//             let (mh_catalogue, _) = writer_catalogue.fermer().await.expect("fermer");
//
//             debug!("Multihash catalogue : {}", mh_catalogue);
//             debug!("Commande cles : {:?}", commande_cles);
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     #[tokio::test]
//     async fn uploader_backup_horaire() {
//         setup("uploader_backup_horaire");
//         let (validateur, enveloppe) = charger_enveloppe_privee_env();
//
//         let catalogue_heure = DateEpochSeconds::now();
//         let timestamp_backup = catalogue_heure.get_datetime().timestamp().to_string();
//
//         let workdir = PathBuf::from("/tmp");
//
//         let mut path_transactions: PathBuf = workdir.clone();
//         path_transactions.push("upload_transactions.jsonl.xz.mgs2");
//
//         let certificats_chiffrage = vec! [
//             FingerprintCertPublicKey::new(
//                 String::from("dummy"),
//                 enveloppe.cle_publique().clone(),
//                 true
//             )
//         ];
//
//         // Generer transactions, catalogue, commande maitredescles
//         // Test
//         let info = BackupInformation::new(
//             NOM_DOMAINE,
//             NOM_COLLECTION_TRANSACTIONS,
//             true,
//             None
//         ).expect("info");
//         let heure = DateEpochSeconds::from_heure(2021, 09, 08, 19);
//         let domaine = "Pki";
//         let mut builder = CatalogueHoraire::builder(
//             heure.clone(), domaine.into(), NOM_COLLECTION_TRANSACTIONS.into(), false, false);
//
//         // Connecter mongo
//         let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
//         futures.push(tokio::spawn(async move {
//
//             // Path fichiers transactions et catalogue
//             let mut transactions = requete_transactions(middleware.as_ref(), &info, &builder).await.expect("transactions");
//
//             serialiser_transactions(
//                 middleware.as_ref(),
//                 &mut transactions,
//                 &mut builder,
//                 path_transactions.as_path()
//             ).await.expect("serialiser");
//
//             // builder.set_cles(&cles);
//
//             // Signer et serialiser catalogue
//             let (catalogue, catalogue_signe, commande_cles) = serialiser_catalogue(
//                 middleware.as_ref(),
//                 builder,
//             ).await.expect("serialiser");
//
//             let response = uploader_backup(
//                 middleware.as_ref(),
//                 path_transactions.as_path(),
//                 &catalogue,
//                 &catalogue_signe,
//                 commande_cles
//             ).await.expect("upload");
//             debug!("Response upload catalogue : {:?}", response);
//
//         }));
//
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//
//     }
//
//     #[tokio::test]
//     async fn download_backup_test() {
//         setup("download_backup");
//
//         let workdir = PathBuf::from("/tmp");
//
//         let (validateur, enveloppe) = charger_enveloppe_privee_env();
//         let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
//
//         debug!("Attente MQ");
//         tokio::time::sleep(tokio::time::Duration::new(2, 0)).await;
//         debug!("Fin sleep");
//
//         download_backup(
//             middleware.clone(),
//             NOM_DOMAINE,
//             NOM_COLLECTION_TRANSACTIONS,
//             workdir.as_path()
//         ).await.expect("download");
//
//     }
//
//     #[tokio::test]
//     async fn effectuer_backup() {
//         setup("effectuer_backup");
//
//         let (
//             middleware,
//             mut futures,
//             mut tx_messages,
//             mut tx_triggers
//         ) = build().await;
//
//         // Reset backup flags pour le domaine
//         //reset_backup_flag(middleware.as_ref(), NOM_COLLECTION_TRANSACTIONS).await;
//
//         futures.push(tokio::spawn(async move {
//
//             debug!("Attente MQ");
//             tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;
//             debug!("Fin sleep");
//
//             debug!("S'assurer d'avoir les certificats de chiffrage");
//             middleware.charger_certificats_chiffrage().await;
//             debug!("Certificats de chiffrage recus : {:?}", middleware.get_publickeys_chiffrage());
//             assert_eq!(middleware.get_publickeys_chiffrage().len() > 1, true);
//
//             backup(middleware.as_ref(), NOM_DOMAINE, NOM_COLLECTION_TRANSACTIONS, true).await.expect("backup");
//
//         }));
//
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     struct TraiterTransactionsDummy {}
//     #[async_trait]
//     impl TraiterTransaction for TraiterTransactionsDummy {
//         async fn traiter_transaction<M>(&self, middleware: &M, m: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
//             where M: ValidateurX509 + GenerateurMessages + MongoDao
//         {
//             debug!("Traiter transaction : {:?}", m);
//             Ok(None)
//         }
//     }
//
//     // #[tokio::test]
//     // async fn effectuer_restauration() {
//     //     setup("effectuer_backup");
//     //
//     //     let (
//     //         middleware,
//     //         mut futures,
//     //         mut tx_messages,
//     //         mut tx_triggers
//     //     ) = build().await;
//     //
//     //     futures.push(tokio::spawn(async move {
//     //
//     //         debug!("Attente MQ");
//     //         tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;
//     //         debug!("Fin sleep");
//     //
//     //         let mut collections_certificats = Vec::new();
//     //         collections_certificats.push(String::from(NOM_COLLECTION_CERTIFICATS));
//     //
//     //         let mut processeur = TraiterTransactionsDummy {};
//     //
//     //         restaurer(
//     //             middleware.clone(),
//     //             NOM_DOMAINE,
//     //             NOM_COLLECTION_TRANSACTIONS,
//     //             &collections_certificats,
//     //             &processeur
//     //         ).await.expect("backup");
//     //
//     //     }));
//     //
//     //     // Execution async du test
//     //     futures.next().await.expect("resultat").expect("ok");
//     // }
// }