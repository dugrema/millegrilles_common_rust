use crate::backup_v2::FichierArchiveBackup;
use crate::common_messages::{FilehostForInstanceRequest, RequestFilehostForInstanceResponse, RequeteFilehostItem};
use crate::constantes::{BACKUP_FINAL_VERSION_VALUE, DOMAINE_TOPOLOGIE, REQUETE_FICHE_MILLEGRILLE, REQUETE_GET_FILEHOST_FOR_INSTANCE, Securite};
use crate::error::Error as CommonError;
use crate::fiche_systeme::{FichePublique, RequeteFicheMillegrille};
use crate::generateur_messages::RoutageMessageAction;
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::models::FilehostClient;
use crate::v3::{ConfigService, FilehostService, FormatService};
use async_trait::async_trait;
use chrono::Utc;
use millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_cryptographie::x509::EnveloppePrivee;
use reqwest::Body;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio_util::io::ReaderStream;
use tracing::{debug, info, warn};

pub struct FilehostServiceImpl {
    config: Arc<dyn ConfigService>,
    format: Arc<dyn FormatService>,
    outbound: Arc<MessageOutboundFacade>,
    session: Mutex<Option<FilehostClient>>,
}

impl FilehostServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        outbound: Arc<MessageOutboundFacade>,
    ) -> Self {
        Self {
            config,
            format,
            outbound,
            session: Mutex::new(None),
        }
    }
}

#[async_trait]
impl FilehostService for FilehostServiceImpl {
    async fn connect(&self) -> Result<FilehostClient, CommonError> {
        // Get the client from the mutex if already built. Return immediately.
        {
            let now = Utc::now();  // Get time before mutex lock (slow)
            let mut guard = self.session.lock().unwrap();
            if let Some(client) = guard.as_mut() {
                client.last_usage = now;
                return Ok(client.clone())
            }
        }

        // Build new client
        let signing_key = self.config.get_configuration_pki().get_enveloppe_privee();
        let filehost_info = get_filehost_server(self.config.as_ref(), self.outbound.as_ref()).await?;
        let filehost = build_client(signing_key.as_ref(), &filehost_info).await?;

        // Authenticate
        let filehost_url = url::Url::parse(filehost.url.as_str())?;
        let authentication_url = filehost_url.join("/filehost/authenticate")?;
        debug!("preparer_client_consignation Authentication url: {:?}", authentication_url.as_str());
        let routage = RoutageMessageAction::builder("filehost", "authenticate", vec!{})
            .ajouter_ca(true)
            .build();
        let nomessage = json!({"auth": true});
        // let authentication_message = middleware.build_message_action(MessageKind::Commande, routage, nomessage)?.0;
        let authentication_message = self.format.build_action_message(MessageKind::Commande, &routage, nomessage)?.0;
        let result = filehost.client.post(authentication_url).body(authentication_message.buffer).send().await?.error_for_status()?;
        info!("preparer_client_consignation Result: {:?}", result);

        // // Test the connection by fetching the filehost status (quick)
        // let status_url = format!("{}/filehost/status", filehost.url);
        // debug!("Connecting to {}", status_url);
        // filehost.client.get(status_url).send().await?.error_for_status()?;

        // Client authentication OK, set it in the mutex for reuse
        {
            let mut guard = self.session.lock().unwrap();
            *guard = Some(filehost.clone());
        }

        Ok(filehost)
    }

    async fn put_backup_file(&self, file: &FichierArchiveBackup, version: Option<&String>) -> Result<(), CommonError> {
        let (file_type, version) = match file.header.type_archive.as_str() {
            "F" => (BACKUP_FINAL_VERSION_VALUE, BACKUP_FINAL_VERSION_VALUE.to_string()),
            "C" => ("concatene", file.digest_suffix.clone()),
            "I" => match version.as_ref() {
                Some(version) => ("incremental", version.to_string()),
                None => return Err(CommonError::Str("Incremental files need the matching Concatene suffix as version"))
            },
            _ => return Err(CommonError::Str("Unsupported backup file type"))
        };

        let filename = match file.path_fichier.file_name() {
            Some(filename) => filename.to_string_lossy(),
            None => return Err(CommonError::Str("Error getting filename of backup file"))
        };

        let connection = self.connect().await?;
        let url_upload = format!(
            "{}/filehost/backup_v2/{}/{}/{}/{}",
            connection.url,
            file.header.domaine.as_str(),
            file_type,
            version,
            filename
        );

        let file_reader = tokio::io::BufReader::new(tokio::fs::File::open(file.path_fichier.as_path()).await?);
        let file_stream = ReaderStream::new(file_reader);
        debug!("PUT file at {}", url_upload.as_str());
        let resultat_upload = connection.client.put(url_upload)
            .body(Body::wrap_stream(file_stream))
            .header("Content-Length", file.len)
            .send().await?;

        match resultat_upload.status().as_u16() {
            200 | 201 | 202 => Ok(()),
            409 => {
                debug!("File already present on server and OK (status: 409): {:?}", file.path_fichier);
                Ok(())
            },
            _ => Err(CommonError::String(format!("Backup file upload error {:?}, status : {}", file.path_fichier, resultat_upload.status())))
        }
    }
}

async fn build_client(private_key: &EnveloppePrivee, filehost: &RequeteFilehostItem) -> Result<FilehostClient, CommonError> {
    let ca = private_key.enveloppe_ca.as_ref();
    let cert_ca = ca.chaine_pem()?;
    let ca_cert_pem = match cert_ca.last() {
        Some(cert) => cert.as_str(),
        None => Err(format!("Certificat CA manquant"))?
    };

    let mut client_builder = reqwest::Client::builder()
        .https_only(true)
        .use_native_tls()
        // .use_rustls_tls()  // Note: cause des problemes de connexion intermittents avec nginx
        .connect_timeout(core::time::Duration::new(20, 0))
        .http2_adaptive_window(true)
        .cookie_store(true);  // Requis pour authentification

    let url_string = match filehost.url_external.as_ref() {
        Some(inner) => {
            // Using external connection. Check the kind of security check
            if let Some(tls_external) = filehost.tls_external.as_ref() {
                if tls_external.as_str() == "millegrille" {
                    debug!("preparer_client_consignation Using external connection with millegrille client TLS authentication");
                    // MilleGrille client TLS authentication
                    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
                    let cle_privee_pem = private_key.cle_privee_pem.as_str();
                    let mut cert_pem_list = private_key.chaine_pem.clone();
                    cert_pem_list.insert(0, cle_privee_pem.to_string());
                    let pem_keycert = cert_pem_list.join("\n");
                    let cert = pem_keycert.as_bytes();
                    let key = cle_privee_pem.as_bytes();
                    let pkcs8 = reqwest::Identity::from_pkcs8_pem(&cert, &key)?;

                    client_builder = client_builder
                        .add_root_certificate(root_ca)
                        .identity(pkcs8);
                } else if tls_external.as_str() == "external" {
                    debug!("preparer_client_consignation Using external connection with internet authority server TLS check");
                } else {
                    // No certificate check
                    debug!("preparer_client_consignation Using external connection with **NO** TLS check");
                    client_builder = client_builder
                        .danger_accept_invalid_certs(true)
                        .danger_accept_invalid_hostnames(true);
                }
            } else {
                // No certificate check
                debug!("preparer_client_consignation Using external connection with **NO** TLS check");
                client_builder = client_builder
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true);
            }

            // Return the external url
            inner.as_str()
        },
        None => Err("preparer_client_consignation filehost with no configured URL")?
    };

    let timestamp = Utc::now();
    Ok(FilehostClient {
        client: client_builder.build()?,
        url: url_string.to_string(),
        last_usage: timestamp.clone(),
        last_test: timestamp,
    })
}

async fn get_filehost_server(
    config: &dyn ConfigService,
    outbound: &MessageOutboundFacade
) -> Result<RequeteFilehostItem, CommonError> {
    // Fetch filehost information from CoreTopologie
    let routing = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, REQUETE_GET_FILEHOST_FOR_INSTANCE, vec![Securite::L1Public]).build();
    let requete = FilehostForInstanceRequest {instance_id: None, filehost_id: None};
    let response = outbound.send_request(routing, requete).await?;
    if let (true, e) = response.is_err()? {
        return Err(CommonError::String(format!("Error fetching the filehost: {:?}", e)))
    }

    let filehost_info: RequestFilehostForInstanceResponse = response.message.deserialize()?;
    let mut filehost = filehost_info.filehost;

    debug!("Filehost information received: {:?}", filehost);

    let certificate = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.clone();
    let idmg = certificate.idmg()?;

    if let Some(instance_id) = filehost.instance_id.as_ref() {
        if let Ok(common_name) = certificate.get_common_name() {
            if instance_id == &common_name {
                if config.get_configuration_instance().dev {
                    // Same host dev mode, use localhost:444 (hard coded mtls port)
                    filehost.url_external = Some("https://localhost:444".to_string());
                    filehost.tls_external = Some("millegrille".to_string());
                    debug!("Choosing internal-dev filehost");
                } else {
                    // Same host, inject hard-coded internal docker hostname
                    filehost.url_external = Some("https://filehost:1443".to_string());
                    filehost.tls_external = Some("millegrille".to_string());
                    debug!("Choosing internal-docker filehost");
                }
            } else {
                // Need to fetch the instance's hostname/mtls_port
                let routage = RoutageMessageAction::builder(
                    DOMAINE_TOPOLOGIE, REQUETE_FICHE_MILLEGRILLE, vec![Securite::L1Public]).build();
                let requete = RequeteFicheMillegrille {idmg: idmg.clone()};
                let response = outbound.send_request(routage, requete).await?;
                let fiche_response: FichePublique = response.message.deserialize()?;
                debug!("backup_v2 Using filehost information on instance: {} for backup, received: {:?}", instance_id, fiche_response);
                if let Some(instances) = fiche_response.instances.get(instance_id) {
                    if let Some(domaines) = instances.domaines.as_ref() {
                        if let Some(hostname) = domaines.get(0) {
                            if let Some(mtls_port) = instances.ports.get("https_mtls") {
                                filehost.url_external = Some(format!("https://{}:{}", hostname, mtls_port));
                                filehost.tls_external = Some("millegrille".to_string());
                            } else {
                                warn!("backup_v2 Missing filehost https_mtls port");
                            }
                        } else {
                            warn!("backup_v2 Missing instance {} hostname for backup", instance_id);
                        }
                    } else {
                        warn!("backup_v2 No domains received in fiche, unable to get filhost information for backup");
                    }
                } else {
                    warn!("backup_v2 Instance id {} not found in fiche, unable to get filehost information for backup", instance_id);
                }
            }
        }
    }

    Ok(filehost)
}
