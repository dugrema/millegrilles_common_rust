use crate::certificats::ValidateurX509;
use crate::configuration::{ConfigurationMq, ConfigurationPki};
use crate::error::Error as CommonError;
use crate::v3::ConfigService;
use lapin::tcp::{OwnedIdentity, OwnedTLSConfig};
use lapin::{Channel, Connection, ConnectionProperties};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

// --- Constants ---

const ATTENTE_RECONNEXION: Duration = Duration::from_millis(15_000);

// --- Internal Components ---

pub struct RabbitConnectionManager {
    connection: Mutex<Option<Arc<Connection>>>,
    // notify_connection_ready: Arc<Notify>,
    config: Arc<dyn ConfigService>,
}

impl RabbitConnectionManager {
    pub fn new(config: Arc<dyn ConfigService>) -> Self {
        Self {
            connection: Mutex::new(None),
            // notify_connection_ready: Arc::new(Notify::new()),
            config,
        }
    }

    pub async fn connect(&self) -> Result<Arc<Connection>, CommonError> {
        let config_mq = self.config.get_configuration_mq();
        let idmg = self.config.get_configuration_pki().get_validateur().idmg().to_owned();
        let addr = format!(
            "amqps://{}:{}/{}?auth_mechanism=external",
            config_mq.host,
            config_mq.port,
            idmg
        );

        debug!("Connecting to AMQP server at {}", &addr);

        let tls_config = self.get_tls_config();
        let connection = Arc::new(Connection::connect_with_config(&addr, ConnectionProperties::default(), tls_config).await?);

        {
            let mut guard = self.connection.lock().unwrap();
            *guard = Some(connection.clone());
        }

        register_mq_account(self.config.get_configuration_mq(), self.config.get_configuration_pki()).await?;

        Ok(connection)
    }

    fn get_tls_config(&self) -> OwnedTLSConfig {
        let mq_config = self.config.get_configuration_mq();

        let cert_chain = self.config.get_configuration_pki().get_validateur().ca_pem().to_owned();
        let der = mq_config.p12_keycert.clone();
        let password = mq_config.p12_password.clone();

        OwnedTLSConfig {
            identity: Some(OwnedIdentity {
                der,
                password,
            }),
            cert_chain: Some(cert_chain),
        }
    }

    pub async fn get_channel(&self) -> Result<Channel, crate::error::Error> {
        match self.get_connection() {
            Some(connection) => Ok(connection.create_channel().await?),
            None => Err(crate::error::Error::Str("Not connected"))
        }
    }

    fn get_connection(&self) -> Option<Arc<Connection>> {
        self.connection.lock().expect("connexion lock").clone()
    }

    // fn notify_ready(&self) {
    //     self.notify_connection_ready.notify_waiters();
    // }

    // async fn wait_for_ready(&self) {
    //     self.notify_connection_ready.notified().await;
    // }

    pub async fn run(self: Arc<Self>) {
        loop {
            // TODO - maintain connection, attempt to reconnect when needed
            tokio::time::sleep(ATTENTE_RECONNEXION).await;
        }
    }

    // async fn close(&self) {
    //     let connection = {
    //         let mut guard = self.connection.lock().unwrap();
    //         guard.take()
    //     };
    //     if let Some(connection) = connection {
    //         connection.close(200, "Closing").await.ok();
    //     }
    // }
}

async fn register_mq_account(
    mq: &ConfigurationMq,
    pki: &ConfigurationPki,
) -> Result<(), CommonError> {
    const MTLS_PORT: u16 = 444;
    const COMMANDE: &str = "administration/ajouterCompte";

    let mut hosts = Vec::new();
    hosts.push(Url::parse("https://midcompte:2444")?);
    hosts.push(Url::parse(format!("https://{}:{}", mq.host, MTLS_PORT).as_str())?);
    hosts.push(Url::parse(format!("https://nginx:{}", MTLS_PORT).as_str())?);

    info!("Attempt creating MQ account with hosts {:?}", hosts);

    let enveloppe = pki.get_enveloppe_privee().clone();
    let ca_cert_pem = enveloppe.ca_pem.as_str();
    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;

    for host in hosts {
        debug!("MQ account creation with host : {}", host);

        let pem_cert = enveloppe.chaine_pem.join("\n");
        let pem_cle = enveloppe.cle_privee_pem.as_str();
        let clecert_pem = format!("{}\n{}", pem_cle, pem_cert);
        let identity = reqwest::Identity::from_pem(clecert_pem.as_bytes())?;

        let client = reqwest::Client::builder()
            .add_root_certificate(root_ca.clone())
            .identity(identity)
            .https_only(true)
            .use_rustls_tls()
            .timeout(core::time::Duration::new(5, 0))
            .danger_accept_invalid_certs(true)
            .build()?;

        let url = format!("{}{}", host, COMMANDE);
        match client.post(url).send().await {
            Ok(r) => {
                let status_code = r.status().as_u16();
                if r.status().is_success() {
                    if status_code == 201 {
                        debug!("Account created : {:?}", r);
                        return Ok(())
                    } else {
                        info!("Account crated (status:{})", status_code);
                    }
                }
            },
            Err(e) => {
                warn!("Error attempting to create MQ account : {:?}", e);
            }
        }
    }

    Err("Echec creation de compte avec certificat sur MQ".into())
}
