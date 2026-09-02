use tracing::warn;
use crate::backup_v2::{CommandeEnregistrerCleidBackup, ReponseCleIdBackup, RequeteCleIdBackup};
use crate::constantes::{Securite, DOMAINE_TOPOLOGIE};
use crate::generateur_messages::RoutageMessageAction;
use crate::messages_generiques::ReponseCommande;
use crate::v3::ChiffrageService;
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::models::DecryptedKey;
use std::pin::Pin;
use std::task::{Context, Poll};
use millegrilles_cryptographie::chiffrage_mgs4::CipherMgs4;
use millegrilles_cryptographie::chiffrage_cles::Cipher;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use crate::error::Error as CommonError;

/// Loads or generates a domain backup key
pub async fn get_domain_backup_key(
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain_name: &str,
) -> Result<DecryptedKey, CommonError> {

    // Request key information from CoreTopologie
    let routing = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE,
        "getCleidBackupDomaine",
        vec![Securite::L3Protege]
    ).build();
    let key_request = RequeteCleIdBackup { domaine: domain_name.to_owned() };
    let response = outbound.send_request(routing, key_request).await?;

    // Figure out if we get an existing key or generate a new one
    let key_information: ReponseCleIdBackup = response.message.deserialize()?;
    let backup_key = match key_information.cle_id {
        Some(key_id) => {
            load_backup_key(chiffrage, key_id.as_str()).await?
        },
        None => {
            warn!("Error requesting domain backup key, will generate a new one: {:?}", key_information.err);
            generate_backup_key_for_domain(outbound, chiffrage, domain_name).await?
        }
    };

    Ok(backup_key)
}

async fn load_backup_key(chiffrage: &dyn ChiffrageService, key_id: &str) -> Result<DecryptedKey, CommonError> {
    let reponse = chiffrage.get_keys(vec![key_id.to_string()]).await?;
    match reponse.into_iter().next() {
        Some(key) => Ok(key),
        None => Err(CommonError::String(format!("Backup key id {} not found", key_id)))
    }
}

async fn generate_backup_key_for_domain(
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain: &str
) -> Result<DecryptedKey, CommonError> {
    let new_key = chiffrage.generate_new_key(&vec![domain.to_string()]).await?;

    // Save the new backup key immediately
    chiffrage.save_keys(vec![new_key.clone()]).await?;

    // Send the key id to CoreTopologie for usage in this domain
    let routing = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE,
        "setCleidBackupDomaine",
        vec![Securite::L3Protege]
    ).build();
    let command = CommandeEnregistrerCleidBackup {
        domaine: domain.to_string(),
        cle_id: Some(new_key.key_id.clone()),
        reset: None,
    };
    match outbound.send_command(routing, command).await? {
        Some(response) => {
            let command_response: ReponseCommande = response.message.deserialize()?;
            if Some(true) != command_response.ok {
                return Err(CommonError::String(format!("Error when saving new key_id for domain: {:?}", command_response.err)))
            }
        },
        None => {
            return Err(CommonError::Str("No response provided when setting new key_id for domain backup"))
        }
    };

    Ok(new_key.try_into()?)
}

/// An AsyncWrite decorator that encrypts data on the fly.
pub struct AsyncEncryptionWriterMgs4<W> {
    inner: W,
    cipher: Option<CipherMgs4>,
    output_buffer: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> AsyncEncryptionWriterMgs4<W> {
    pub fn new(inner: W, cipher: CipherMgs4) -> Self {
        Self {
            inner,
            cipher: Some(cipher),
            output_buffer: Vec::with_capacity(64 * 1024),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncEncryptionWriterMgs4<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // 1. If there's leftover data in the output buffer, flush it first.
        // This handles the case where a previous poll_write returned Poll::Pending.
        if !this.output_buffer.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.output_buffer) {
                Poll::Ready(Ok(n)) => {
                    if n == this.output_buffer.len() {
                        this.output_buffer.clear();
                    } else {
                        this.output_buffer.drain(0..n);
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // 2. Encrypt the new data.
        // Since the cipher is guaranteed to consume all input, we can use a temporary buffer.
        let mut temp_out = [0u8; 4096];
        let cipher = this.cipher
            .as_mut()
            .ok_or_else(|| {
                return std::io::Error::new(std::io::ErrorKind::Other,  CommonError::Str("Cipher was already taken in poll_shutdown"))
            })?;

        let produced = match cipher.update(buf, &mut temp_out) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))),
        };

        if produced > 0 {
            this.output_buffer.extend_from_slice(&temp_out[0..produced]);
        }

        // 3. Attempt to write the newly encrypted data to the inner sink.
        if this.output_buffer.is_empty() {
            // Nothing was produced (e.g. not enough data for a block)
            return Poll::Ready(Ok(buf.len()));
        }

        match Pin::new(&mut this.inner).poll_write(cx, &this.output_buffer) {
            Poll::Ready(Ok(n)) => {
                if n == this.output_buffer.len() {
                    this.output_buffer.clear();
                } else {
                    this.output_buffer.drain(0..n);
                }
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Flush output buffer first
        if !this.output_buffer.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.output_buffer) {
                Poll::Ready(Ok(n)) => {
                    if n == this.output_buffer.len() {
                        this.output_buffer.clear();
                    } else {
                        this.output_buffer.drain(0..n);
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // 1. Finalize encryption.
        // let cipher = this.cipher.take().expect("Cipher already taken during shutdown");
        let cipher = this.cipher
            .take()
            .ok_or_else(|| {
                return std::io::Error::new(std::io::ErrorKind::Other,  CommonError::Str("Cipher was already taken in poll_shutdown"))
            })?;

        let mut temp_out = [0u8; 4096];

        let final_len = match cipher.finalize(&mut temp_out) {
            Ok(res) => res.len,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )))
            }
        };

        if final_len > 0 {
            this.output_buffer.extend_from_slice(&temp_out[0..final_len]);
        }

        // 2. Flush remaining output buffer.
        while !this.output_buffer.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.output_buffer) {
                Poll::Ready(Ok(n)) => {
                    if n == this.output_buffer.len() {
                        this.output_buffer.clear();
                    } else {
                        this.output_buffer.drain(0..n);
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // 3. Shutdown the inner sink.
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
