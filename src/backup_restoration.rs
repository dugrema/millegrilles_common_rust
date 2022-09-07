use std::cmp::Ordering;
use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_std::fs::File;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Timelike, Utc};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use log::{debug, error, info, warn};
use mongodb::bson::{doc, Document};
use mongodb::Cursor;
use mongodb::options::{AggregateOptions, FindOptions, Hint};
use reqwest::{Body, Response};
use reqwest::multipart::Part;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tempfile::{TempDir, tempdir};
use tokio::fs::File as File_tokio;
use tokio::sync::mpsc::Sender;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};
use uuid::Uuid;
use xz2::stream;

use crate::certificats::{CollectionCertificatsPem, EnveloppeCertificat, EnveloppePrivee, ValidateurX509};
use crate::chiffrage::{Chiffreur, Dechiffreur, DecipherMgs, MgsCipherKeys};
use crate::chiffrage_streamxchacha20poly1305::{DecipherMgs4, Mgs4CipherData};
// use crate::chiffrage_chacha20poly1305::{CipherMgs3, DecipherMgs3, Mgs3CipherData, Mgs3CipherKeys};
use crate::configuration::{ConfigMessages, IsConfigNoeud};
use crate::constantes::*;
use crate::constantes::Securite::L3Protege;
use crate::fichiers::{CompresseurBytes, DecompresseurBytes, FichierWriter, parse_tar, TraiterFichier};
use crate::formatteur_messages::{DateEpochSeconds, Entete, FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::hachages::hacher_serializable;
use crate::middleware::IsConfigurationPki;
use crate::middleware_db::MiddlewareDb;
use crate::mongo_dao::MongoDao;
use crate::rabbitmq_dao::TypeMessageOut;
use crate::recepteur_messages::TypeMessage;
use crate::tokio::sync::mpsc::Receiver;
use crate::transactions::{regenerer, sauvegarder_batch, TraiterTransaction};
use crate::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage};

pub struct TransactionReader<'a> {
    data: Box<dyn AsyncRead + Unpin + 'a>,
    xz_decoder: stream::Stream,
    // hacheur: Hacheur,
    dechiffreur: Option<DecipherMgs4>,
}

impl<'a> TransactionReader<'a> {

    const BUFFER_SIZE: usize = 65535;

    pub fn new(data: Box<impl AsyncRead + Unpin + 'a>, decipher_data: Option<&Mgs4CipherData>) -> Result<Self, Box<dyn Error>> {
        todo!("fix me")
        // let xz_decoder = stream::Stream::new_stream_decoder(u64::MAX, stream::TELL_NO_CHECK).expect("stream");
        //
        // let dechiffreur = match decipher_data {
        //     Some(cd) => {
        //         let dechiffreur = DecipherMgs3::new(cd)?;
        //         Some(dechiffreur)
        //     },
        //     None => None,
        // };
        //
        // Ok(TransactionReader {
        //     data,
        //     xz_decoder,
        //     // hacheur,
        //     dechiffreur,
        // })
    }

    /// todo Les transactions sont lues en memoire avant d'etre traitees - changer pour iterator async
    pub async fn read_transactions(&mut self) -> Result<Vec<Value>, Box<dyn Error>> {
        let mut buffer = [0u8; TransactionReader::BUFFER_SIZE/2];
        let mut xz_output = Vec::new();
        xz_output.reserve(TransactionReader::BUFFER_SIZE);

        let mut dechiffrage_output = [0u8; TransactionReader::BUFFER_SIZE];

        let mut output_complet = Vec::new();
        // let mut output_file = File::create(PathBuf::from("/tmp/output_dechiffrage.data")).await?;

        loop {
            let reader = &mut self.data;
            let len = reader.read(&mut buffer).await.expect("lecture");
            if len == 0 {break}

            // let traiter_bytes = &buffer[0..len];
            debug!("Lecture data chiffre {:?}", &buffer[0..len]);

            let traiter_bytes = match &mut self.dechiffreur {
                Some(d) => {
                    d.update(&buffer, &mut dechiffrage_output).expect("update");
                    &dechiffrage_output[0..len]
                },
                None => &buffer[0..len],
            };

            // output_file.write(traiter_bytes).await?;  // debug

            debug!("Lu {}\n{:?}", len, traiter_bytes);
            let status = self.xz_decoder.process_vec(traiter_bytes, &mut xz_output, stream::Action::Run)?;
            debug!("Status xz : {:?}\n{:?}", status, xz_output);

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

// struct ProcesseurFichierBackup {
//     enveloppe_privee: Arc<EnveloppePrivee>,
//     middleware: Arc<dyn ValidateurX509>,
//     catalogue: Option<CatalogueHoraire>,
//     decipher: Option<DecipherMgs3>,
//     batch: Vec<MessageMilleGrille>,
//     entete_precedente: Option<Entete>,
//     erreurs_catalogues: u32, // Indique le nombre de catalogues en erreur (e.g. cle manquante)
//     skip_transactions: bool,  // Si true, on skip le prochain fichier de transactions
// }
//
// impl ProcesseurFichierBackup {
//
//     fn new(enveloppe_privee: Arc<EnveloppePrivee>, middleware: Arc<dyn ValidateurX509>) -> Self {
//         ProcesseurFichierBackup {
//             enveloppe_privee,
//             middleware,
//             catalogue: None,
//             decipher: None,
//             batch: Vec::new(),
//             entete_precedente: None,
//             erreurs_catalogues: 0,
//             skip_transactions: false,
//         }
//     }
//
//     async fn parse_file<M>(&mut self, middleware: &M, filepath: &async_std::path::Path, stream: &mut (impl futures::io::AsyncRead+Send+Sync+Unpin)) -> Result<(), Box<dyn Error>>
//     where M: GenerateurMessages + ValidateurX509 + Dechiffreur<DecipherMgs3, Mgs3CipherData> + VerificateurMessage
//     {
//         debug!("ProcesseurFichierBackup.parse_file : {:?}", filepath);
//
//         match filepath.extension() {
//             Some(e) => {
//                 let type_ext = e.to_ascii_lowercase();
//                 match type_ext.to_str().expect("str") {
//                     "xz" => {
//                         let path_str = filepath.to_str().expect("str");
//                         if path_str.ends_with(".json.xz") {
//                             // Catalogue
//                             self.parse_catalogue(middleware, filepath, stream).await
//                         } else if path_str.ends_with(".jsonl.xz") {
//                             // Transactions non chiffrees
//                             self.parse_transactions(middleware, filepath, stream).await
//                         } else {
//                             warn ! ("ProcesseurFichierBackup.parse_file Type fichier inconnu, on skip : {:?}", filepath);
//                             Ok(())
//                         }
//                     },
//                     "mgs2" => {
//                         if self.skip_transactions {
//                             self.skip_transactions = false;  // reset flag
//                             // On va skipper le fichier (manger tous les bytes)
//                             let mut output = [0u8; 4096];
//                             loop {
//                                 let len = stream.read(&mut output).await?;
//                                 if len == 0 { break }
//                             }
//                             Ok(())
//                         } else {
//                             self.parse_transactions(middleware, filepath, stream).await
//                         }
//                     },
//                     _ => {
//                         warn ! ("ProcesseurFichierBackup.parse_file Type fichier inconnu, on skip : {:?}", e);
//                         Ok(())
//                     }
//                 }
//             },
//             None => {
//                 warn!("ProcesseurFichierBackup.parse_file Type fichier inconnu, on skip : {:?}", filepath);
//                 Ok(())
//             }
//         }
//     }
//
//     async fn parse_catalogue<M>(&mut self, middleware: &M, filepath: &async_std::path::Path, stream: &mut (impl futures::io::AsyncRead+Send+Sync+Unpin)) -> Result<(), Box<dyn Error>>
//     where M: GenerateurMessages + Dechiffreur<DecipherMgs3, Mgs3CipherData> + VerificateurMessage + ValidateurX509
//     {
//         debug!("ProcesseurFichierBackup.parse_catalogue : {:?}", filepath);
//
//         let catalogue_message = {
//             // Valider le catalogue
//             let mut message = {
//                 let mut decompresseur = DecompresseurBytes::new().expect("decompresseur");
//                 decompresseur.update_std(stream).await?;
//                 let catalogue_bytes = decompresseur.finish()?;
//                 let catalogue_str = String::from_utf8(catalogue_bytes)?;
//                 debug!("Catalogue extrait\n{}", catalogue_str);
//                 let message = MessageSerialise::from_str(catalogue_str.as_str())?;
//
//                 message
//             };
//
//             // Charger certiticat
//             let fingerprint = message.get_entete().fingerprint_certificat.as_str();
//             let option_cert = match message.get_msg().certificat.as_ref() {
//                 Some(c) => {
//                     Some(middleware.charger_enveloppe(c, Some(fingerprint), None).await?)
//                 },
//                 None => {
//                     info!("ProcesseurFichierBackup.parse_catalogue Catalogue sans _cerficat inclus {:?}", &filepath);
//                     middleware.get_certificat(fingerprint).await
//                 }
//             };
//             message.certificat = option_cert;
//
//             let validations_options = ValidationOptions::new(true, true, false);
//             let resultat_verification = middleware.verifier_message(&mut message, Some(&validations_options))?;
//             if !resultat_verification.signature_valide {
//                 Err(format!("Catalogue invalide (signature: {:?})\n{}", resultat_verification, message.get_str()))?;
//             }
//
//             debug!("Catalogue valide : {:?}", &filepath);
//
//             message
//         };
//
//         // Determiner le type de catalogue
//         let type_catalogue = {
//             // let mut decompresseur = DecompresseurBytes::new().expect("decompresseur");
//             // decompresseur.update_std(stream).await?;
//             // let catalogue_bytes = decompresseur.finish()?;
//             //
//             // let catalogue_message: MessageSerialise = serde_json::from_slice(catalogue_bytes.as_slice())?;
//             // let entete = catalogue_message.entete.clone();
//             // let uuid_transaction = entete.uuid_transaction.clone();
//
//             let action = match &catalogue_message.get_entete().action {
//                 Some(d) => d.as_str(),
//                 None => "",
//             };
//
//             let type_catalogue = match action {
//                 BACKUP_TRANSACTION_CATALOGUE_QUOTIDIEN => TypeCatalogueBackup::Quotidien(catalogue_message),
//                 BACKUP_TRANSACTION_CATALOGUE_HORAIRE => {
//                     let catalogue: CatalogueHoraire = serde_json::from_str(catalogue_message.get_str())?;
//                     TypeCatalogueBackup::Horaire(catalogue)
//                 },
//                 _ => {
//                     warn!("Type catalogue inconnu, ok skip {:?}", action);
//                     return Ok(())
//                 },
//             };
//
//             type_catalogue
//         };
//
//         match type_catalogue {
//             TypeCatalogueBackup::Horaire(catalogue) => {
//                 //debug!("Catalogue json decipher present? {:?}, Value : {:?}", self.decipher, catalogue);
//                 let entete_courante = match &catalogue.entete {
//                     Some(e) => Some(e.clone()),
//                     None => None,
//                 };
//                 self.catalogue = Some(catalogue);
//                 // let catalogue_ref = self.catalogue.as_ref().expect("catalogue");
//
//                 // Traiter le catalogue horaire
//                 match self.traiter_catalogue_horaire(middleware, filepath).await {
//                     Ok(()) => {
//                     },
//                     Err(_e) => {
//                         debug!("Erreur traitement catalogue, on assume probleme de dechiffrage transactions");
//                         self.skip_transactions = true;
//                         self.erreurs_catalogues += 1;
//                     }
//                 }
//
//                 // Conserver en-tete du catalogue courant. Va permettre de verifier le chainage avec prochain fichier.
//                 if let Some(e) = entete_courante {
//                     debug!("En-tete du catalogue charge : {:?}", e);
//                     self.entete_precedente = Some(e);
//                 }
//
//                 Ok(())
//             },
//             TypeCatalogueBackup::Quotidien(_) => {
//                 // Rien a faire pour catalogue quotidien
//                 Ok(())
//             }
//         }
//
//         // if let Some(ep) = &catalogue.backup_precedent {
//         //     if let Some(ec) = &self.entete_precedente {
//         //         debug!("Entete precedente {:?}\nInfo catalogue predecent {:?}", ec, ep);
//         //
//         //         // Verifier chaine avec en-tete du catalogue
//         //         let uuid_precedent = ep.uuid_transaction.as_str();
//         //         let uuid_courant = ec.uuid_transaction.as_str();
//         //
//         //         if uuid_precedent == uuid_courant {
//         //             match hacher_serializable(ec) {
//         //                 Ok(hc) => {
//         //                     // Calculer hachage en-tete precedente
//         //                     let hp = ep.hachage_entete.as_str();
//         //                     if hc.as_str() != hp {
//         //                         warn!("Chainage au catalogue {:?}: {}/{} est brise (hachage mismatch)", filepath, catalogue.domaine, uuid_catalogue_courant);
//         //                     }
//         //                 },
//         //                 Err(e) => {
//         //                     error!("Chainage au catalogue {:?}: {}/{} est brise (erreur calcul hachage)", filepath, catalogue.domaine, uuid_catalogue_courant);
//         //                 }
//         //             };
//         //         } else {
//         //             warn!("Chainage au catalogue {:?}: {}/{} est brise (uuid mismatch catalogue precedent {} avec info courante {})",
//         //                 filepath, catalogue.domaine, uuid_catalogue_courant, uuid_precedent, uuid_courant);
//         //         }
//         //     }
//         // }
//         //
//         // // Recuperer cle et creer decipher au besoin
//         // self.decipher = match catalogue.cle {
//         //     Some(_) => {
//         //         let transactions_hachage_bytes = catalogue.transactions_hachage.as_str();
//         //         let dechiffreur = middleware.get_decipher(transactions_hachage_bytes).await?;
//         //         Some(dechiffreur)
//         //     },
//         //     None => None,
//         // };
//
//         // let mut cle = match catalogue.get_cipher_data() {
//         //     Ok(c) => Some(c),
//         //     Err(e) => None,
//         // };
//         //
//         // // Tenter de dechiffrer la cle
//         // if let Some(mut cipher_data) = cle {
//         //     debug!("Creer cipher pour {:?}", cipher_data);
//         //     match cipher_data.dechiffrer_cle(self.enveloppe_privee.cle_privee()) {
//         //         Ok(_) => {
//         //             // Creer Cipher
//         //             self.decipher = Some(DecipherMgs3::new(&cipher_data)?);
//         //         },
//         //         Err(e) => {
//         //             error!("Decipher incorrect, transactions ne seront pas lisibles : {:?}", e);
//         //         }
//         //     };
//         // }
//
//         // Ok(())
//     }
//
//     async fn traiter_catalogue_horaire<M>(&mut self, middleware: &M, filepath: &async_std::path::Path) -> Result<(), Box<dyn Error>>
//     where M: GenerateurMessages + Dechiffreur<DecipherMgs3, Mgs3CipherData> + VerificateurMessage + ValidateurX509,
//     {
//         let catalogue = self.catalogue.as_ref().expect("catalogue");
//         let uuid_catalogue_courant = match &catalogue.entete {
//             Some(e) => e.uuid_transaction.as_str(),
//             None => "",
//         };
//
//         debug!("ProcesseurFichierBackup.traiter_catalogue_horaire Traiter catalogue horaire {:?}/{}", filepath, &uuid_catalogue_courant);
//
//         // if let Some(ep) = &catalogue.backup_precedent {
//         //     if let Some(ec) = &self.entete_precedente {
//         //         debug!("ProcesseurFichierBackup.traiter_catalogue_horaire Entete precedente {:?}\nInfo catalogue predecent {:?}", ec, ep);
//         //
//         //         // Verifier chaine avec en-tete du catalogue
//         //         let uuid_precedent = ep.uuid_transaction.as_str();
//         //         let uuid_courant = ec.uuid_transaction.as_str();
//         //
//         //         if uuid_precedent == uuid_courant {
//         //             match hacher_serializable(ec) {
//         //                 Ok(hc) => {
//         //                     // Calculer hachage en-tete precedente
//         //                     let hp = ep.hachage_entete.as_str();
//         //                     if hc.as_str() != hp {
//         //                         warn!("ProcesseurFichierBackup.traiter_catalogue_horaire Chainage au catalogue {:?}: {}/{} est brise (hachage mismatch)", filepath, catalogue.domaine, uuid_catalogue_courant);
//         //                     }
//         //                 },
//         //                 Err(e) => {
//         //                     error!("ProcesseurFichierBackup.traiter_catalogue_horaire Chainage au catalogue {:?}: {}/{} est brise (erreur calcul hachage) : Err {:?}", filepath, catalogue.domaine, uuid_catalogue_courant, e);
//         //                 }
//         //             };
//         //         } else {
//         //             warn!("ProcesseurFichierBackup.traiter_catalogue_horaire Chainage au catalogue {:?}: {}/{} est brise (uuid mismatch catalogue precedent {} avec info courante {})",
//         //                 filepath, catalogue.domaine, uuid_catalogue_courant, uuid_precedent, uuid_courant);
//         //         }
//         //     }
//         // }
//
//         // Recuperer cle et creer decipher au besoin
//         self.decipher = match catalogue.cle {
//             Some(_) => {
//                 debug!("ProcesseurFichierBackup.traiter_catalogue_horaire Le catalogue {:?} est chiffre, on recupere la cle", filepath);
//                 let transactions_hachage_bytes = catalogue.transactions_hachage.as_str();
//                 let resultat = match middleware.get_decipher(transactions_hachage_bytes).await {
//                     Ok(d) => Ok(d),
//                     Err(e) => {
//                         Err(format!("ProcesseurFichierBackup.traiter_catalogue_horaire Erreur recuperation cle {} pour backup horaire {:?} : {:?}", transactions_hachage_bytes, filepath, e))
//                     }
//                 };
//
//                 let dechiffreur = match resultat {
//                     Ok(d) => d,
//                     Err(e) => {
//                         debug!{"Erreur reception cle pour catalogue ({}), on emet une commande de sauvegarde de la cle", transactions_hachage_bytes};
//                         //emettre_cle_catalogue(middleware, &catalogue).await?;
//                         Err(e)?  // Emettre erreur originale
//                     }
//                 };
//
//                 debug!("ProcesseurFichierBackup.traiter_catalogue_horaire Cles pour le dechiffreur recues pour {:?}", filepath);
//                 Some(dechiffreur)
//             },
//             None => None,
//         };
//
//         Ok(())
//     }
//
//     async fn parse_transactions<M, T>(&mut self, middleware: &M, filepath: &async_std::path::Path, stream: &mut T)
//         -> Result<(), Box<dyn Error>>
//         where
//             M: ValidateurX509,
//             T: futures::io::AsyncRead + Send + Sync + Unpin
//     {
//         debug!("Parse transactions : {:?}", filepath);
//
//         let mut output = [0u8; 4096];
//         let mut output_decipher = [0u8; 4096];
//         // let mut vec_total: Vec<u8> = Vec::new();
//
//         let mut decompresseur = DecompresseurBytes::new()?;
//
//         loop {
//             let len = stream.read(&mut output).await?;
//             if len == 0 {break}
//
//             let buf = match self.decipher.as_mut() {
//                 Some(d) => {
//                     d.update(&output[0..len], &mut output_decipher)?;
//                     &output_decipher[0..len]
//                 },
//                 None => {
//                     &output[0..len]
//                 }
//             };
//             // vec_total.extend_from_slice(buf);
//             decompresseur.update_bytes(buf)?;
//         }
//
//         let transactions_str = String::from_utf8(decompresseur.finish()?)?;
//         //debug!("Bytes dechiffres de la transaction : {:?}", transactions_str);
//
//         let tr_iter = transactions_str.split("\n");
//         for transaction_str in tr_iter {
//             if transaction_str.len() == 0 {
//                 // On a termine, ligne vide
//                 continue
//             }
//             match self.ajouter_transaction(middleware, transaction_str).await {
//                 Ok(_) => (),
//                 Err(e) => {
//                     error!("Erreur traitement transaction : {:?}, on l'ignore\n{}", e, transaction_str);
//                 }
//             }
//         }
//
//         debug!("Soumettre {} transactions pour restauration", self.batch.len());
//
//         Ok(())
//     }
//
//     async fn ajouter_transaction(&mut self, middleware: &impl ValidateurX509, transaction_str: &str) -> Result<(), Box<dyn Error>>{
//         let mut msg = MessageSerialise::from_str(transaction_str)?;
//         let uuid_transaction = msg.get_entete().uuid_transaction.to_owned();
//         let fingerprint_certificat = msg.get_entete().fingerprint_certificat.to_owned();
//
//         // Charger le certificat a partir du catalogue
//         if let Some(catalogue) = &self.catalogue {
//             match catalogue.certificats.get_enveloppe(middleware, fingerprint_certificat.as_str()).await {
//                 Some(c) => msg.set_certificat(c),
//                 None => warn!("Pas de PEM charge pour fingerprint {}", fingerprint_certificat)
//             }
//         }
//
//         let validation_option = ValidationOptions::new(true, true, true);
//
//         let resultat_validation: ResultatValidation = msg.valider(middleware, Some(&validation_option)).await?;
//         match resultat_validation.signature_valide {
//             true => {
//                 // Ajouter la transaction a liste de la batch
//                 // Marquer transaction comme "restauree", avec flag backup = true
//                 self.batch.push(msg.preparation_restaurer());
//                 debug!("Restaurer transaction {}", uuid_transaction);
//                 Ok(())
//             },
//             false => {
//                 Err(format!("Signature invalide pour transaction {}, on l'ignore", uuid_transaction))?
//             }
//         }
//     }
//
//     async fn sauvegarder_batch<M>(&mut self, middleware: &M, nom_collection: &str) -> Result<(), Box<dyn Error>>
//     where
//         M: MongoDao,
//     {
//         // Deplacer messages vers nouveau vecteur
//         let mut transactions = Vec::new();
//         transactions.reserve(self.batch.len());
//         while let Some(t) = self.batch.pop() {
//             transactions.push(t);
//         }
//
//         if transactions.len() > 0 {
//             // Inserer transactions
//             let resultat = sauvegarder_batch(middleware, nom_collection, transactions).await?;
//             debug!("Resultat sauvegarder batch : {:?}", resultat);
//         }
//
//         Ok(())
//     }
// }
//
// enum TypeCatalogueBackup {
//     Horaire(CatalogueHoraire),
//     Quotidien(MessageSerialise),
// }
//
// #[async_trait]
// impl TraiterFichier for ProcesseurFichierBackup {
//     async fn traiter_fichier<M>(&mut self, middleware: &M, nom_fichier: &async_std::path::Path, stream: &mut (impl AsyncRead + Send + Sync + Unpin)) -> Result<(), Box<dyn Error>>
//         where M: GenerateurMessages + ValidateurX509 + Dechiffreur<DecipherMgs3, Mgs3CipherData> + VerificateurMessage
//     {
//         self.parse_file(middleware, nom_fichier, stream).await
//     }
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct EnteteBackupPrecedent {
//     hachage_entete: String,
//     uuid_transaction: String,
// }

// /// Download les fichiers de backup du domaine et restaure les transactions
// async fn download_backup<M, P>(middleware: Arc<M>, nom_domaine: &str, partition: Option<P>, nom_collection_transactions: &str, workdir: &Path)
//     -> Result<(), Box<dyn Error>>
//     where
//         M: GenerateurMessages + MongoDao + ValidateurX509 + IsConfigurationPki + IsConfigNoeud + Dechiffreur<DecipherMgs3, Mgs3CipherData> + VerificateurMessage + 'static,
//         P: AsRef<str>
// {
//     let enveloppe_privee = middleware.get_enveloppe_privee();
//     let ca_cert_pem = match enveloppe_privee.chaine_pem().last() {
//         Some(cert) => cert.as_str(),
//         None => Err(format!("Certificat CA manquant"))?,
//     };
//     let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
//     let identity = reqwest::Identity::from_pem(enveloppe_privee.clecert_pem.as_bytes())?;
//
//     let client = reqwest::Client::builder()
//         .add_root_certificate(root_ca)
//         .identity(identity)
//         .https_only(true)
//         .use_rustls_tls()
//         // .http1_only()
//         .http2_adaptive_window(true)
//         .build()?;
//
//     let url_fichiers = match &middleware.get_configuration_noeud().fichiers_url {
//         Some(u) => u.to_owned(),
//         None => Err("Erreur backup - configuration serveur fichiers absente")?,
//     };
//
//     let url_fichiers_str = match partition {
//         Some(p) => format!("/{}.{}", nom_domaine, p.as_ref()),
//         None => nom_domaine.to_owned()
//     };
//
//     // Recuperer la liste de fichiers de backup du domaine
//     let mut url_liste_fichiers = url_fichiers.clone();
//     let url_liste_fichiers_str = format!("/backup/listeFichiers/{}", url_fichiers_str.as_str());
//     url_liste_fichiers.set_path(url_liste_fichiers_str.as_str());
//     debug!("Download liste fichiers pour backup url : {:?}", url_liste_fichiers);
//     let response_liste_fichiers = client.get(url_liste_fichiers).send().await?;
//     let reponse_liste_fichiers_status = &response_liste_fichiers.status();
//     let reponse_liste_fichiers_text = response_liste_fichiers.text().await?;
//     let reponse_val = {
//         let mut reponse: ReponseListeFichiersBackup = serde_json::from_str(&reponse_liste_fichiers_text)?;
//         reponse.trier_fichiers();
//         info!("Traiter restauration {} avec liste\n{:?}", nom_domaine, reponse.fichiers);
//         reponse
//     };
//     debug!("Liste fichiers du domaine {} code: {:?} : {:?}", url_liste_fichiers_str, reponse_liste_fichiers_status, reponse_val);
//
//     for fichier in &reponse_val.fichiers {
//         let mut copie_url_fichiers = url_fichiers.clone();
//         let path_fichier_courant = PathBuf::from(fichier);
//         let nom_fichier = path_fichier_courant.file_name().expect("nom fichier").to_str().expect("str");
//
//         let url_fichiers_complet_str = format!("/backup/fichier/{}/{}", url_fichiers_str.as_str(), fichier);
//
//         copie_url_fichiers.set_path(url_fichiers_complet_str.as_str());
//         debug!("Download backup url : {:?}", url_fichiers_complet_str);
//
//         let mut path_fichier = PathBuf::from(workdir);
//         path_fichier.push(nom_fichier);
//         debug!("Sauvegarder fichier backup sous : {:?}", path_fichier);
//         let mut file_output = File::create(path_fichier.as_path()).await?;
//
//         let mut response = client.get(copie_url_fichiers).send().await?;
//         info!("Response get backup {} = {}, headers: {:?}", url_fichiers_complet_str, response.status(), response.headers());
//
//         while let Some(content) = response.chunk().await? {
//             debug!("Write content {}", content.len());
//             file_output.write_all(content.as_ref()).await?;
//         }
//         file_output.flush().await?;
//         debug!("Fichier backup sauvegarde : {:?}", path_fichier);
//     }
//
//     // Parcourir tous les fichiers en ordre (verifie le chainage)
//     let mut processeur = ProcesseurFichierBackup::new(
//         enveloppe_privee.clone(),
//         middleware.clone()
//     );
//     for fichier in &reponse_val.fichiers {
//         let copie_url_fichiers = url_fichiers.clone();
//         let path_fichier_courant = PathBuf::from(fichier);
//         let nom_fichier = path_fichier_courant.file_name().expect("nom fichier").to_str().expect("str");
//         let mut path_fichier = PathBuf::from(workdir);
//         path_fichier.push(nom_fichier);
//
//         if nom_fichier.ends_with(".tar") {
//             info!("backup.download_backup Restaurer fichier tar {:?}", path_fichier);
//             let mut fichier_tar = async_std::fs::File::open(path_fichier.as_path()).await?;
//             parse_tar(middleware.as_ref(), &mut fichier_tar, &mut processeur).await?;
//         } else if nom_fichier.contains(".jsonl.xz") {
//             // Trouver le nom du catalogue associe, soit catalogue.json.xz soit [NOMDOMAINE_PARTITION].json.xz
//             let nom_fichier_catalogue = if nom_fichier.starts_with("transactions.jsonl.xz") {
//                 // Snapshot
//                 String::from("catalogue.json.xz")
//             } else {
//                 // Fichier horaire
//                 let nom_fichier = nom_fichier.replace(".jsonl.xz.mgs3", ".json.xz");
//                 nom_fichier.replace(".jsonl.xz", ".json.xz")
//             };
//
//             info!("backup.download_backup Restaurer catalogue {} et archive {:?}", nom_fichier_catalogue, path_fichier);
//             let mut path_fichier_catalogue = async_std::path::PathBuf::from(path_fichier.as_path());
//             path_fichier_catalogue.set_file_name(nom_fichier_catalogue);
//             let path_fichier_transactions = async_std::path::PathBuf::from(path_fichier.as_path());
//             let mut fichier_transactions = async_std::fs::File::open(path_fichier.as_path()).await?;
//
//             // Charger catalogue
//             let mut fichier_catalogue = async_std::fs::File::open(path_fichier_catalogue.as_path()).await?;
//             debug!("Parse catalogue {:?}", path_fichier_catalogue);
//             processeur.parse_catalogue(middleware.as_ref(), path_fichier_catalogue.as_path(), &mut fichier_catalogue).await?;
//
//             // Charger et traiter transactions
//             debug!("Parse transactions {:?}", path_fichier_transactions);
//             processeur.parse_transactions(middleware.as_ref(), path_fichier_transactions.as_path(), &mut fichier_transactions).await?;
//         } else {
//             debug!("Skip fichier {}", nom_fichier);
//         }
//
//         processeur.sauvegarder_batch(middleware.as_ref(), nom_collection_transactions).await?;
//     }
//
//     Ok(())
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct ReponseListeFichiersBackup {
//     domaine: String,
//     fichiers: Vec<String>
// }
//
// impl ReponseListeFichiersBackup {
//     fn trier_fichiers(&mut self) {
//         self.fichiers.sort_by(|a, b| {
//
//             if a == b { return Ordering::Equal }
//
//             // Verifier si .tar ou catalogue ou transaction
//             let a_tar = a.ends_with(".tar");
//             let b_tar = b.ends_with(".tar");
//
//             if a_tar && b_tar {
//                 // Trier .tar par date (ordre str)
//                 return a.cmp(b)
//             }
//             if a_tar && !b_tar { return Ordering::Less }
//             if !a_tar && b_tar { return Ordering::Greater }
//
//             // Catalogue en premier, transaction apres
//             let a_catalogue = a.ends_with(".json.xz");
//             let b_catalogue = b.ends_with(".json.xz");
//
//             // Snapshot doit passer en premier, catalogue puis transaction
//             let a_snapshot = a.starts_with("snapshot/");
//             let b_snapshot = b.starts_with("snapshot/");
//
//             if a_snapshot == b_snapshot {
//                 // 2 snapshots ou 2 horaires, on tri par type
//                 if a_catalogue == b_catalogue { a.cmp(b) }
//                 else if a_catalogue && !b_catalogue { Ordering::Less }
//                 else if !a_catalogue && b_catalogue { Ordering::Greater }
//                 else { panic!("backup.ReponseListeFichiersBackup Erreur logique comparaison") }
//             }
//             else if a_snapshot && !b_snapshot { Ordering::Greater }
//             else if !a_snapshot && b_snapshot { Ordering::Less }
//             else { panic!("backup.ReponseListeFichiersBackup Erreur logique comparaison") }
//         });
//     }
// }
