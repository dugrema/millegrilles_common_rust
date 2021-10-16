use std::error::Error;
use {redis::Client};
use log::{debug, error, info, warn};
use crate::certificats::EnveloppeCertificat;

const TTL_CERTIFICAT: i32 = 48 * 60 * 60;  // 48 heures en secondes

struct RedisDao {
    url_connexion: String,
    client: Client,
}

impl RedisDao {
    pub fn new<T>(url_connexion: Option<T>) -> Result<Self, Box<dyn Error>>
        where T: Into<String>
    {
        let url = match url_connexion {
            Some(u) => u.into(),
            None => String::from("redis://redis:6379/")
        };
        info!("Connexion redis client sur {}", url.as_str());

        let client = Client::open(url.as_str())?;
        let connexion_info = client.get_connection_info();
        info!("Connexion redis info : {:?}", connexion_info);

        Ok(RedisDao {
            url_connexion: url,
            client,
        })
    }

    pub async fn liste_certificats_fingerprints(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut con = self.client.get_async_connection().await?;
        // let resultat: String = redis::cmd("GET").arg("certificat:zQmYZfSGuY86wTDBPM6MdYzRGWSqrYtWdbXfquMVG5buxrm").query_async(&mut con).await?;
        let resultat: Vec<String> = redis::cmd("KEYS").arg("certificat:*").query_async(&mut con).await?;
        debug!("Resultat : {:?}", resultat);
        Ok(resultat)
    }

    pub async fn get_certificat<S>(&self, fingerprint: S) -> Result<Option<Vec<String>>, Box<dyn Error>>
        where S: AsRef<str>
    {
        let mut con = self.client.get_async_connection().await?;
        let cle = format!("certificat:{}", fingerprint.as_ref());
        let resultat: Option<String> = redis::cmd("GET").arg(cle).query_async(&mut con).await?;

        match resultat {
            Some(r) => {
                let liste_pems: Vec<String> = serde_json::from_str(r.as_str())?;
                Ok(Some(liste_pems))
            },
            None => Ok(None)
        }
    }

    pub async fn save_certificat<S>(&self, certificat: S) -> Result<(), Box<dyn Error>>
        where S: AsRef<EnveloppeCertificat>
    {
        let mut con = self.client.get_async_connection().await?;
        let cert_ref = certificat.as_ref();

        // Verifier si le certificat existe (reset le TTL a 48h s'il existe deja)
        let cle_cert = format!("certificat:{}", cert_ref.fingerprint);
        debug!("Verifier presence {}, reset TTL", cle_cert);
        let ttl_info : i32 = redis::cmd("EXPIRE").arg(cle_cert.as_str()).arg(TTL_CERTIFICAT).query_async(&mut con).await?;
        debug!("Presence {}, reponse ttl reset {}", cle_cert, ttl_info);

        if ttl_info == 0 {
            // Reponse 0 = certificat n'existe pas
            debug!("Conserver certificat {} dans redis", cle_cert.as_str());

            // Preparer cle, pems en format json str
            let pems: Vec<String> = cert_ref.get_pem_vec().into_iter().map(|c| { c.pem }).collect();
            let pems_value = serde_json::to_value(pems)?;
            let cert_json = serde_json::to_string(&pems_value)?;

            // Conserver certificat
            let _: () = redis::cmd("SET").arg(cle_cert).arg(cert_json).query_async(&mut con).await?;
        }

        Ok(())
    }

}

#[cfg(test)]
mod test_integration_redis_dao {
    use super::*;
    use crate::test_setup::setup;
    use crate::certificats::certificats_tests::charger_enveloppe_privee_env;

    const URL_REDIS: &str = "redis://localhost:6379";

    #[tokio::test]
    async fn connecter_redis() {
        setup("connecter_redis");
        let client = RedisDao::new(Some(URL_REDIS)).expect("client");
        // let mut con = client.get_async_connection().await?;
        let resultat = client.liste_certificats_fingerprints().await.expect("resultat");
        info!("Resultat : {:?}", resultat);
    }

    #[tokio::test]
    async fn get_certificat() {
        setup("get_certificat");
        let client = RedisDao::new(Some(URL_REDIS)).expect("client");
        let resultat = client.get_certificat("zQmdmwoc9cync8afXBXvnBar2yHyZihVnHvYrt3zSG4wHoX").await.expect("resultat");
        info!("Resultat : {:?}", resultat);
    }

    #[tokio::test]
    async fn set_certificat() {
        setup("set_certificat");
        let (_, enveloppe) = charger_enveloppe_privee_env();
        let cert = enveloppe.enveloppe;

        let client = RedisDao::new(Some(URL_REDIS)).expect("client");

        let _ = client.save_certificat(cert).await.expect("resultat");
    }
}
