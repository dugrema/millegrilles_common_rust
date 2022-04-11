use std::error::Error;
use {redis::Client};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::certificats::EnveloppeCertificat;
use crate::configuration::ConfigurationNoeud;

const TTL_CERTIFICAT: i32 = 48 * 60 * 60;  // 48 heures en secondes
const CLE_CERTIFICAT: &str = "certificat_v1";

pub struct RedisConfiguration {
    url: Option<Url>,
    username: Option<String>,
    password: Option<String>,
}

impl From<ConfigurationNoeud> for RedisConfiguration {
    fn from(config: ConfigurationNoeud) -> Self {
        RedisConfiguration {
            url: config.redis_url.clone(),
            username: config.redis_username.clone(),
            password: config.redis_password.clone(),
        }
    }
}

pub struct RedisDao {
    _url_connexion: String,
    client: Client,
}

impl RedisDao {
    pub fn new<T>(configuration: T) -> Result<Self, Box<dyn Error>>
        where T: Into<RedisConfiguration>
    {
        let config = configuration.into();
        let mut url = match config.url {
            Some(u) => u.clone(),
            None => Url::parse("rediss://client_rust@redis:6379#insecure")?,
        };

        if let Some(user) = config.username {
            let r = url.set_username(user.as_str());
            if r.is_err() { Err(format!("erreur set username : {:?}", r))? }
        }
        info!("Connexion redis client sur {:?}", url);

        if let Some(password) = config.password {
            let r = url.set_password(Some(password.as_str()));
            if r.is_err() { Err(format!("erreur set_password : {:?}", r))? }
        }

        let url_string: String = url.into();
        debug!("Connexion redis client sur (INSECURE) {}", url_string);

        let client = Client::open(url_string.as_str())?;
        let connexion_info = client.get_connection_info();
        info!("Connexion redis info : {:?}", connexion_info);

        Ok(RedisDao {
            _url_connexion: url_string,
            client,
        })
    }

    pub async fn liste_certificats_fingerprints(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut con = self.client.get_async_connection().await?;
        // let resultat: String = redis::cmd("GET").arg("certificat:zQmYZfSGuY86wTDBPM6MdYzRGWSqrYtWdbXfquMVG5buxrm").query_async(&mut con).await?;
        let resultat: Vec<String> = redis::cmd("KEYS").arg(format!("{}:*", CLE_CERTIFICAT)).query_async(&mut con).await?;
        debug!("Resultat : {:?}", resultat);
        Ok(resultat)
    }

    pub async fn get_certificat<S>(&self, fingerprint: S) -> Result<Option<RediCertificatV1>, Box<dyn Error>>
        where S: AsRef<str>
    {
        let mut con = self.client.get_async_connection().await?;
        let cle = format!("{}:{}", CLE_CERTIFICAT, fingerprint.as_ref());
        let resultat: Option<String> = redis::cmd("GET").arg(cle).query_async(&mut con).await?;

        match resultat {
            Some(r) => {
                let valeur_cache: RediCertificatV1 = serde_json::from_str(r.as_str())?;
                // let liste_pems: Vec<String> = serde_json::from_str(r.as_str())?;
                Ok(Some(valeur_cache))
            },
            None => Ok(None)
        }
    }

    pub async fn save_certificat(&self, certificat: &EnveloppeCertificat) -> Result<(), Box<dyn Error>> {
        let mut con = self.client.get_async_connection().await?;

        // Verifier si le certificat existe (reset le TTL a 48h s'il existe deja)
        let cle_cert = format!("{}:{}", CLE_CERTIFICAT, certificat.fingerprint);
        debug!("Verifier presence {}, reset TTL", cle_cert);
        let ttl_info : i32 = redis::cmd("EXPIRE").arg(cle_cert.as_str()).arg(TTL_CERTIFICAT).query_async(&mut con).await?;
        debug!("Presence {}, reponse ttl reset {}", cle_cert, ttl_info);

        if ttl_info == 0 {
            // Reponse 0 = certificat n'existe pas
            debug!("Conserver certificat {} dans redis", cle_cert.as_str());

            // Preparer cle, pems en format json str
            let pems: Vec<String> = certificat.get_pem_vec().into_iter().map(|c| { c.pem }).collect();
            let ca = certificat.get_pem_ca()?;
            let certificat_redis = RediCertificatV1 {
                pems,
                ca
            };
            // let pems_value = serde_json::to_value(pems)?;
            let cert_json = serde_json::to_string(&certificat_redis)?;

            // Conserver certificat
            let _: () = redis::cmd("SET")
                .arg(cle_cert).arg(cert_json)
                .arg("NX")
                .arg("EX").arg(TTL_CERTIFICAT)  // TTL certificat
                .query_async(&mut con).await?;
        }

        Ok(())
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RediCertificatV1 {
    pub pems: Vec<String>,
    pub ca: Option<String>,
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

        let _ = client.save_certificat(cert.as_ref()).await.expect("resultat");
    }
}
