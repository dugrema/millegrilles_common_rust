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
use millegrilles_cryptographie::chiffrage_cles::{Cipher, CipherResult};
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
    pub result: Option<CipherResult<32>>
}

impl<W: AsyncWrite + Unpin> AsyncEncryptionWriterMgs4<W> {
    pub fn new(inner: W, cipher: CipherMgs4) -> Self {
        Self {
            inner,
            cipher: Some(cipher),
            output_buffer: Vec::with_capacity(128 * 1024),
            result: None,
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
        let mut temp_out = [0u8; 128 * 1024];
        let cipher = this.cipher
            .as_mut()
            .ok_or_else(|| {
                return std::io::Error::new(std::io::ErrorKind::Other,  CommonError::Str("poll_write: Cipher was already taken in poll_shutdown"))
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

        // The cipher is stateful, ensure we only call finalize once before the result is produced
        if this.result.is_none() {
            // 1. Finalize encryption.
            let cipher = this.cipher
                .take()
                .ok_or_else(|| {
                    return std::io::Error::new(std::io::ErrorKind::Other, CommonError::Str("poll_shutdown: Cipher was already taken"))
                })?;

            let mut temp_out = [0u8; 64 * 1024];

            let final_len = match cipher.finalize(&mut temp_out) {
                Ok(res) => {
                    let length_result = res.len;
                    this.result = Some(res);
                    length_result
                },
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

#[cfg(test)]
mod test {
    use millegrilles_cryptographie::chiffrage_cles::{CleDechiffrageStruct, Decipher};
    use millegrilles_cryptographie::chiffrage_mgs4::DecipherMgs4;
    use super::*;

    #[test]
    fn test_base_mgs4_encrypt_decrypt() {
        // Generate a kew for the cipher
        let mut cipher = CipherMgs4::new().expect("cipher");
        let mut buffer_in = [56u8;16];  // 16 bytes with value 56
        let mut buffer_out = [0u8;64];
        let out_len = cipher.update(buffer_in.as_mut(), &mut buffer_out).expect("cipher");
        if out_len > 0 {panic!("Buffer should not be output yet");}
        let result = cipher.finalize(&mut buffer_out).expect("output");
        let out_len = result.len;

        let encrypted_value = Vec::from(&buffer_out[0..out_len]);

        let secret_key = result.cles;
        let decipher_key = CleDechiffrageStruct {
            cle_chiffree: "NA".to_string(),
            cle_secrete: Some(secret_key.cle_secrete),
            format: secret_key.format,
            nonce: secret_key.nonce,
            verification: None,
        };

        let mut decipher = DecipherMgs4::new(&decipher_key).expect("decipher");
        let out_len = decipher.update(encrypted_value.as_slice(), &mut buffer_out).expect("decipher");
        if out_len > 0 {panic!("Buffer should not be output yet");}
        let out_len = decipher.finalize(&mut buffer_out).expect("output");
        let decrypted_value = Vec::from(&buffer_out[0..out_len]);

        assert_eq!(buffer_in, decrypted_value.as_slice());
    }

    #[tokio::test]
    async fn test_async_writer_file_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        use tokio::fs::File;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tempfile::NamedTempFile; // Assuming tempfile is available
        use millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, DecipherMgs4};
        use millegrilles_cryptographie::chiffrage_cles::{CleDechiffrageStruct, Decipher};

        let original_data = b"Hello, world! This is a test of the async encryption writer.";

        // 1. Create a temporary file
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path().to_owned();
        let file = File::create(&path).await?;

        // 2. Initialize Cipher and Writer
        let cipher = CipherMgs4::new().expect("Failed to create cipher");
        let mut writer = AsyncEncryptionWriterMgs4::new(file, cipher);

        // 3. Write data to the encrypted writer
        for i in 0..10000 {
            writer.write(original_data).await?;
        }
        writer.write_all(original_data).await?;

        // 4. Shutdown the writer (this finalizes encryption and flushes buffers)
        writer.shutdown().await?;

        // 5. Retrieve the key from the writer (Requires Option A modification)
        // let secret_key = writer.take_cipher().expect("Failed to take cipher").finalize(&mut [0u8; 4096])?.cles;
        let result = writer.result.expect("Failed to take cipher result");
        let secret_key = result.cles;
        let decipher_key = CleDechiffrageStruct {
            cle_chiffree: "NA".to_string(),
            cle_secrete: Some(secret_key.cle_secrete),
            format: secret_key.format,
            nonce: secret_key.nonce,
            verification: None,
        };

        // 6. Read the file back
        let mut file_content = Vec::new();
        let mut file_reader = File::open(&path).await?;
        file_reader.read_to_end(&mut file_content).await?;

        // 7. Decrypt the data
        let mut decrypted_data = Vec::new();
        let mut read_buffer = [0u8; 8192];   // 8KB read buffer
        let mut decrypt_buffer = [0u8; 64*1024]; // 8KB decryption buffer
        let mut file = File::open(&path).await?;
        let mut decipher = DecipherMgs4::new(&decipher_key).expect("Failed to create decipher");

        loop {
            let n_read = file.read(&mut read_buffer).await?;
            if n_read == 0 {
                break; // End of file reached
            }

            // Decrypt the chunk we just read.
            // Note: update() may return 0 if it hasn't reached a block boundary.
            let n_decrypted = decipher.update(&read_buffer[..n_read], &mut decrypt_buffer)
                .expect("Decryption update failed");

            if n_decrypted > 0 {
                decrypted_data.extend_from_slice(&decrypt_buffer[..n_decrypted]);
            }
        }

        // Finalize the cipher to capture the last remaining bytes (the "tail").
        let n_final = decipher.finalize(&mut decrypt_buffer).expect("Decryption finalize failed");
        if n_final > 0 {
            decrypted_data.extend_from_slice(&decrypt_buffer[..n_final]);
        }

        // 8. Assert equality
        let original_len = original_data.len();
        let decrypted_data_len = decrypted_data.len();
        assert_eq!(original_data.to_vec(), decrypted_data[0..original_len]);
        assert_eq!(original_data.to_vec(), decrypted_data[decrypted_data_len-original_len..]);

        // Cleanup
        std::fs::remove_file(path)?;
        Ok(())
    }
}
