#[cfg(test)]
mod rabbitmq_dao_tests {
    use std::error::Error;
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::Utc;
    use futures_util::stream::FuturesUnordered;
    use log::debug;
    use openssl::x509::store::X509Store;
    use openssl::x509::X509;
    use serde::Serialize;
    use tokio::sync::mpsc;
    use tokio_stream::StreamExt;

    use crate::certificats::{EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ValidateurX509};
    use crate::chiffrage::{ChiffrageFactoryImpl, CleChiffrageHandler};
    use crate::configuration::{charger_configuration, ConfigMessages, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
    use crate::constantes::Securite;
    use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
    use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
    use crate::middleware::{ChiffrageFactoryTrait, IsConfigurationPki};
    use crate::rabbitmq_dao::*;
    use crate::recepteur_messages::TypeMessage;
    use crate::test_setup::setup;

    use super::*;

    #[tokio::test]
    async fn connecter_mq() {
        setup("connecter");
        debug!("Connecter");

        let config = charger_configuration().expect("config");
        let connexion = connecter(&config).await.expect("connexion");

        // debug!("Sleep 5 secondes");
        // tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;

        let status = connexion.status();
        debug!("Connexion status : {:?}", status);
        assert_eq!(status.connected(), true);
    }

    #[tokio::test]
    async fn listen_mq() {
        setup("listen_mq");
        debug!("listen_mq");

        let config = charger_configuration().expect("config");
        let rabbitmq = RabbitMqExecutor::new(None);
        let middleware = Arc::new(MiddlewareStub::new());

        let mut futures = FuturesUnordered::new();
        let rabbitmq_arc = Arc::new(rabbitmq);
        futures.push(tokio::spawn(run_rabbitmq(middleware.clone(), rabbitmq_arc.clone(), Arc::new(Box::new(config)))));
        futures.push(tokio::spawn(sleep_thread(5)));

        futures.next().await;

        debug!("Pass 2");
        futures.push(tokio::spawn(sleep_thread(5)));
        futures.next().await;

        let reply_q = rabbitmq_arc.reply_q.lock().expect("lock").clone();

        todo!("fix me");
        // let message_millegrille = MessageMilleGrille::new();
        // let correlation = message_millegrille.entete.uuid_transaction.clone();
        // let attente_expiration = Utc::now() + chrono::Duration::seconds(9);
        // let message = MessageOut::new(
        //     "test", "action", None::<&str>, message_millegrille,
        //     TypeMessageOut::Commande, Some(vec![Securite::L1Public]),
        //     reply_q, Some(correlation), Some(attente_expiration)
        // );
        // rabbitmq_arc.as_ref().send_out(message).await.expect("send");
        //
        // debug!("Pass 3");
        // futures.push(tokio::spawn(sleep_thread(20)));
        // futures.next().await;
        //
        // // match timeout(tokio::time::Duration::new(15, 0), rabbitmq_thread).await {
        // //     Ok(result) => (),
        // //     Err(t) => {
        // //         debug!("Timeout - OK");
        // //     }
        // // }
        //
        // // let mut executor = executer_mq(
        // //     Arc::new(config),
        // //     Some(queues),
        // //     None,
        // //     Securite::L3Protege
        // // ).expect("executer_mq");
        // //
        // // let mut named_queues_guard = executor.rx_named_queues.lock().expect("lock");
        // // let config_test_queue = ConfigQueue {
        // //     nom_queue: "test_named_queue".to_string(),
        // //     routing_keys: vec![
        // //         ConfigRoutingExchange { routing_key: "commande.CorePki.testMoi".to_string(), exchange: Securite::L3Protege }
        // //     ],
        // //     ttl: None,
        // //     durable: false
        // // };
        // // let test_named_queue = NamedQueue::new(config_test_queue, None);
        // // named_queues_guard.insert("test_named_queue".to_string(), test_named_queue);
        // //
        // // let (_tx_reply, rx_reply) = mpsc::channel(1);
        // // let (tx_messages_verif_reply, rx_messages_verif_reply) = mpsc::channel(1);
        // // let (tx_certificats_manquants, rx_certificats_manquants) = mpsc::channel(1);
        // //
        // // let middleware_stub = Arc::new(MiddlewareStub::new());
        // //
        // // let mut futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
        // // futures.push(tokio::spawn(recevoir_messages(
        // //     middleware_stub.clone(),
        // //     rx_reply,
        // //     tx_messages_verif_reply.clone(),
        // //     tx_certificats_manquants.clone()
        // // )));
        // //
        // // match timeout(tokio::time::Duration::new(5, 0), futures.next()).await {
        // //     Ok(result) => {
        // //         result.expect("next").expect("reponse next");
        // //     },
        // //     Err(t) => {
        // //         debug!("Timeout - OK");
        // //     }
        // // }

    }

    #[tokio::test]
    async fn listen_named_queues() {
        setup("listen_named_queues");
        debug!("listen_named_queues");

        let config = charger_configuration().expect("config");
        let rabbitmq = RabbitMqExecutor::new(None);
        let middleware = Arc::new(MiddlewareStub::new());

        let mut futures = FuturesUnordered::new();
        let rabbitmq_arc = Arc::new(rabbitmq);

        let (tx_certificat, _rx_certificat) = mpsc::channel(1);

        // Ajouter named queues
        let named_queue_triggers = NamedQueue::new(
            QueueType::Triggers("CorePki".into(), Securite::L4Secure),
            tx_certificat.clone(),
            Some(5),
            None
        );
        rabbitmq_arc.ajouter_named_queue("Triggers.CorePki", named_queue_triggers);

        let named_queue_test1 = NamedQueue::new(
            QueueType::ExchangeQueue(
                ConfigQueue {
                    nom_queue: "CorePki/test1".to_string(),
                    routing_keys: vec![
                        ConfigRoutingExchange{
                            routing_key: "commande.CorePki.test1".to_string(),
                            exchange: Securite::L3Protege
                        },
                    ],
                    ttl: None,
                    durable: false,
                    autodelete: true,
                }
            ),
            tx_certificat.clone(),
            Some(1),
            None
        );
        rabbitmq_arc.ajouter_named_queue("CorePki/test1", named_queue_test1);

        futures.push(tokio::spawn(run_rabbitmq(middleware.clone(), rabbitmq_arc.clone(), Arc::new(Box::new(config)))));
        futures.push(tokio::spawn(sleep_thread(10)));

        futures.next().await;

        // Ajouter nouvelle Q
        let named_queue_test2 = NamedQueue::new(
            QueueType::ExchangeQueue(
                ConfigQueue {
                    nom_queue: "CorePki/test2".to_string(),
                    routing_keys: vec![
                        ConfigRoutingExchange{
                            routing_key: "commande.CorePki.test2".to_string(),
                            exchange: Securite::L3Protege
                        },
                    ],
                    ttl: None,
                    durable: false,
                    autodelete: true,
                }
            ),
            tx_certificat.clone(),
            Some(1),
            None
        );

        rabbitmq_arc.ajouter_named_queue("CorePki/test2", named_queue_test2);
        futures.push(tokio::spawn(sleep_thread(20)));
        futures.next().await;

    }

    struct MiddlewareStub {

    }

    impl MiddlewareStub {
        fn new() -> Self {
            Self {}
        }
    }

    #[async_trait]
    impl ValidateurX509 for MiddlewareStub {
        async fn charger_enveloppe(&self, _chaine_pem: &Vec<String>, _fingerprint: Option<&str>, _ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
            todo!()
        }

        async fn cacher(&self, _certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, bool) {
            todo!()
        }

        fn set_flag_persiste(&self, fingerprint: &str) {
            todo!()
        }

        async fn get_certificat(&self, _fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
            todo!()
        }

        fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
            todo!()
        }

        fn idmg(&self) -> &str {
            todo!()
        }

        fn ca_pem(&self) -> &str {
            todo!()
        }

        fn ca_cert(&self) -> &X509 {
            todo!()
        }

        fn store(&self) -> &X509Store {
            todo!()
        }

        fn store_notime(&self) -> &X509Store {
            todo!()
        }

        async fn entretien_validateur(&self) {
            todo!()
        }
    }

    impl FormatteurMessage for MiddlewareStub {
        fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee> {
            todo!()
        }

        fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>) {
            todo!()
        }
    }

    #[async_trait]
    impl GenerateurMessages for MiddlewareStub {
        async fn emettre_evenement<M>(&self, _routage: RoutageMessageAction, _message: &M) -> Result<(), String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn transmettre_requete<M>(&self, _routage: RoutageMessageAction, _message: &M) -> Result<TypeMessage, String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn soumettre_transaction<M>(&self, _routage: RoutageMessageAction, _message: &M, _blocking: bool) -> Result<Option<TypeMessage>, String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn transmettre_commande<M>(&self, _routage: RoutageMessageAction, _message: &M, _blocking: bool) -> Result<Option<TypeMessage>, String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn repondre(&self, _routage: RoutageMessageReponse, _message: MessageMilleGrille) -> Result<(), String> {
            todo!()
        }

        async fn emettre_message(&self, _routage: RoutageMessageAction, _type_message: TypeMessageOut, _message: &str, _blocking: bool) -> Result<Option<TypeMessage>, String> {
            todo!()
        }

        async fn emettre_message_millegrille(&self, _routage: RoutageMessageAction, _blocking: bool, _type_message: TypeMessageOut, _message: MessageMilleGrille) -> Result<Option<TypeMessage>, String> {
            todo!()
        }

        fn mq_disponible(&self) -> bool {
            todo!()
        }

        fn set_regeneration(&self) {
            todo!()
        }

        fn reset_regeneration(&self) {
            todo!()
        }

        fn get_mode_regeneration(&self) -> bool {
            todo!()
        }

        fn get_securite(&self) -> &Securite {
            todo!()
        }
    }

    impl IsConfigurationPki for MiddlewareStub {
        fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
            todo!()
        }
    }

    #[async_trait]
    impl CleChiffrageHandler for MiddlewareStub {
        fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
            todo!()
        }

        async fn charger_certificats_chiffrage<M>(&self, _middleware: &M) -> Result<(), Box<dyn Error>> where M: GenerateurMessages {
            todo!()
        }

        async fn recevoir_certificat_chiffrage<M>(&self, _middleware: &M, _message: &MessageSerialise) -> Result<(), String> where M: ConfigMessages {
            todo!()
        }
    }

    impl ChiffrageFactoryTrait for MiddlewareStub {
        fn get_chiffrage_factory(&self) -> &ChiffrageFactoryImpl {
            todo!()
        }
    }

    impl IsConfigNoeud for MiddlewareStub {
        fn get_configuration_noeud(&self) -> &ConfigurationNoeud {
            todo!()
        }
    }

    impl ConfigMessages for MiddlewareStub {
        fn get_configuration_mq(&self) -> &ConfigurationMq {
            todo!()
        }

        fn get_configuration_pki(&self) -> &ConfigurationPki {
            todo!()
        }
    }

}

async fn sleep_thread(secs: u64) {
    tokio::time::sleep(tokio::time::Duration::new(secs, 0)).await;
}
