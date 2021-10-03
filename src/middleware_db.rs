use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use log::{debug, info, error};
use mongodb::Database;
use openssl::x509::store::X509Store;
use openssl::x509::X509;
use serde::Serialize;
use serde_json::json;
use tokio::sync::{mpsc, mpsc::Receiver};
use tokio::task::JoinHandle;

use crate::certificats::{emettre_commande_certificat_maitredescles, EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ValidateurX509, ValidateurX509Impl, VerificateurPermissions};
use crate::chiffrage::{Chiffreur, Dechiffreur, Mgs2CipherData};
use crate::configuration::{ConfigMessages, ConfigurationMessagesDb, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use crate::constantes::*;
use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl, RoutageMessageAction, RoutageMessageReponse};
use crate::middleware::{configurer, EmetteurCertificat, formatter_message_certificat, IsConfigurationPki, Middleware, ReponseDechiffrageCle, ReponseCertificatMaitredescles};
use crate::mongo_dao::{MongoDao, MongoDaoImpl};
use crate::rabbitmq_dao::{Callback, EventMq, QueueType, TypeMessageOut};
use crate::recepteur_messages::{recevoir_messages, task_requetes_certificats, TypeMessage};
use crate::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage, verifier_message};

// Middleware avec MongoDB
pub struct MiddlewareDb {
    configuration: Arc<ConfigurationMessagesDb>,
    mongo: Arc<MongoDaoImpl>,
    validateur: Arc<ValidateurX509Impl>,
    generateur_messages: Arc<GenerateurMessagesImpl>,
    pub cles_chiffrage: Mutex<HashMap<String, FingerprintCertPublicKey>>,
}

impl MiddlewareDb {
}

impl Middleware for MiddlewareDb {
}

#[async_trait]
impl ValidateurX509 for MiddlewareDb {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        self.validateur.charger_enveloppe(chaine_pem, fingerprint).await
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
        self.validateur.cacher(certificat).await
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        self.validateur.get_certificat(fingerprint).await
    }

    fn idmg(&self) -> &str {
        self.validateur.idmg()
    }

    fn ca_pem(&self) -> &str {
        self.validateur.ca_pem()
    }

    fn ca_cert(&self) -> &X509 {
        self.validateur.ca_cert()
    }

    fn store(&self) -> &X509Store {
        self.validateur.store()
    }

    fn store_notime(&self) -> &X509Store {
        self.validateur.store_notime()
    }

    async fn entretien_validateur(&self) {
        self.validateur.entretien_validateur().await;
    }
}

#[async_trait]
impl GenerateurMessages for MiddlewareDb {

    async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<(), String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.emettre_evenement( routage, message).await
    }

    async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<TypeMessage, String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.transmettre_requete(routage, message).await
    }

    async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.soumettre_transaction(routage, message, blocking).await
    }

    async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.transmettre_commande(routage, message, blocking).await
    }

    async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String> {
        self.generateur_messages.repondre(routage, message).await
    }

    async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool)
        -> Result<Option<TypeMessage>, String>
    {
        self.generateur_messages.emettre_message(routage, type_message, message,  blocking).await
    }

    async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille)
        -> Result<Option<TypeMessage>, String>
    {
        self.generateur_messages.emettre_message_millegrille(routage, blocking, type_message, message).await
    }

    fn mq_disponible(&self) -> bool {
        self.generateur_messages.mq_disponible()
    }

    fn set_regeneration(&self) {
        self.generateur_messages.set_regeneration();
    }

    fn reset_regeneration(&self) {
        self.generateur_messages.reset_regeneration();
    }

    fn get_mode_regeneration(&self) -> bool {
        self.generateur_messages.as_ref().get_mode_regeneration()
    }
}

impl IsConfigurationPki for MiddlewareDb {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        self.configuration.get_configuration_pki().get_enveloppe_privee()
    }
}

impl ConfigMessages for MiddlewareDb {
    fn get_configuration_mq(&self) -> &ConfigurationMq {
        self.configuration.get_configuration_mq()
    }

    fn get_configuration_pki(&self) -> &ConfigurationPki {
        self.configuration.get_configuration_pki()
    }
}

impl FormatteurMessage for MiddlewareDb {}

#[async_trait]
impl MongoDao for MiddlewareDb {
    fn get_database(&self) -> Result<Database, String> {
        self.mongo.get_database()
    }
}

impl IsConfigNoeud for MiddlewareDb {
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud {
        self.configuration.get_configuration_noeud()
    }
}

#[async_trait]
impl Chiffreur for MiddlewareDb {
    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
        let guard = self.cles_chiffrage.lock().expect("lock");

        // Copier les cles (extraire du mutex), retourner dans un vecteur
        let vals: Vec<FingerprintCertPublicKey> = guard.iter().map(|v| v.1.to_owned()).collect();

        vals
    }

    async fn charger_certificats_chiffrage(&self) -> Result<(), Box<dyn Error>> {
        debug!("Charger les certificats de maitre des cles pour chiffrage");
        emettre_commande_certificat_maitredescles(self).await?;

        // Donner une chance aux certificats de rentrer
        tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;

        // Verifier si on a au moins un certificat
        let nb_certs = self.cles_chiffrage.lock().expect("lock").len();
        if nb_certs <= 1 {  // 1 => le cert millegrille est deja charge
            Err(format!("Echec, aucuns certificats de maitre des cles recus"))?
        } else {
            debug!("On a {} certificats de maitre des cles valides", nb_certs);
        }

        Ok(())
    }

    async fn recevoir_certificat_chiffrage<'a>(&'a self, message: &MessageSerialise) -> Result<(), Box<dyn Error + 'a>> {
        let cert_chiffrage = match &message.certificat {
            Some(c) => c.clone(),
            None => {
                Err(format!("recevoir_certificat_chiffrage Message de certificat de MilleGrille recu, certificat n'est pas extrait"))?
            }
        };

        // Valider le certificat
        if ! cert_chiffrage.presentement_valide {
            Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'est pas presentement valide - rejete"))?;
        }

        if ! cert_chiffrage.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
            Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'a pas le role MaitreCles' - rejete"))?;
        }

        info!("Certificat maitre des cles accepte {}", cert_chiffrage.fingerprint());

        // Stocker cles chiffrage du maitre des cles
        {
            let fps = cert_chiffrage.fingerprint_cert_publickeys()?;
            let mut guard = self.cles_chiffrage.lock()?;
            for fp in fps.iter().filter(|f| ! f.est_cle_millegrille) {
                guard.insert(fp.fingerprint.clone(), fp.clone());
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Dechiffreur for MiddlewareDb {

    async fn get_cipher_data(&self, hachage_bytes: &str) -> Result<Mgs2CipherData, Box<dyn Error>> {
        let requete = {
            let mut liste_hachage_bytes = Vec::new();
            liste_hachage_bytes.push(hachage_bytes);
            json!({
                "liste_hachage_bytes": liste_hachage_bytes,
            })
        };
        let routage = RoutageMessageAction::new("MaitreDesCles", "dechiffrage");
        let reponse_cle_rechiffree = self.transmettre_requete(routage, &requete).await?;

        error!("Reponse reechiffrage cle : {:?}", reponse_cle_rechiffree);

        let contenu_dechiffrage = match reponse_cle_rechiffree {
            TypeMessage::Valide(m) => m.message.get_msg().map_contenu::<ReponseDechiffrageCle>(None)?,
            _ => Err(format!("Mauvais type de reponse : {:?}", reponse_cle_rechiffree))?
        };

        contenu_dechiffrage.to_cipher_data()
    }
}

impl VerificateurMessage for MiddlewareDb {
    fn verifier_message(&self, message: &mut MessageSerialise, options: Option<&ValidationOptions>) -> Result<ResultatValidation, Box<dyn Error>> {
        verifier_message(message, self, options)
    }
}

#[async_trait]
impl EmetteurCertificat for MiddlewareDb {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), String> {
        let enveloppe_privee = self.configuration.get_configuration_pki().get_enveloppe_privee();
        let message = formatter_message_certificat(enveloppe_privee.enveloppe.as_ref());
        let exchanges = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);

        let routage = RoutageMessageAction::builder("certificat", "infoCertificat")
            .exchanges(exchanges)
            .build();

        match generateur_message.emettre_evenement(routage, &message).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Erreur emettre_certificat: {:?}", e)),
        }
    }
}


/// Version speciale du middleware avec un acces a MongoDB
pub fn preparer_middleware_db(
    queues: Vec<QueueType>,
    listeners: Option<Mutex<Callback<'static, EventMq>>>
) -> (Arc<MiddlewareDb>, Receiver<TypeMessage>, Receiver<TypeMessage>, FuturesUnordered<JoinHandle<()>>) {
    let (
        configuration,
        validateur,
        mongo,
        mq_executor,
        generateur_messages
    ) = configurer(queues, listeners);

    let generateur_messages_arc = Arc::new(generateur_messages);

    // Extraire le cert millegrille comme base pour chiffrer les cles secretes
    let cles_chiffrage = {
        let env_privee = configuration.get_configuration_pki().get_enveloppe_privee();
        let cert_local = env_privee.enveloppe.as_ref();
        let fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");

        let mut map: HashMap<String, FingerprintCertPublicKey> = HashMap::new();
        for f in fp_certs.iter().filter(|c| c.est_cle_millegrille).map(|c| c.to_owned()) {
            map.insert(f.fingerprint.clone(), f);
        }

        map
    };

    let middleware = Arc::new(MiddlewareDb {
        configuration,
        mongo,
        validateur: validateur.clone(),
        generateur_messages: generateur_messages_arc.clone(),
        cles_chiffrage: Mutex::new(cles_chiffrage),
    });

    let (tx_messages_verifies, rx_messages_verifies) = mpsc::channel(3);
    let (tx_triggers, rx_triggers) = mpsc::channel(3);

    let (tx_certificats_manquants, rx_certificats_manquants) = mpsc::channel(10);

    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor.rx_messages,
        tx_messages_verifies.clone(),
        tx_certificats_manquants.clone()
    )));

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor.rx_triggers,
        tx_triggers,
        tx_certificats_manquants.clone()
    )));

    // Thread requete certificats manquants
    futures.push(tokio::spawn(task_requetes_certificats(
        middleware.clone(),
        rx_certificats_manquants,
        mq_executor.tx_interne.clone(),
        false
    )));

    (middleware, rx_messages_verifies, rx_triggers, futures)
}
