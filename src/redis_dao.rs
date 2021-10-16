use std::error::Error;
use {redis::Client};
use log::{debug, error, info, warn};

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
            None => String::from("redis://localhost:6379/")
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
}

#[cfg(test)]
mod test_integration_redis_dao {
    use super::*;
    use crate::test_setup::setup;

    #[tokio::test]
    async fn connecter_redis() {
        setup("connecter_redis");
        let client = RedisDao::new(None::<&str>).expect("client");
        // let mut con = client.get_async_connection().await?;
        let resultat = client.liste_certificats_fingerprints().await.expect("resultat");
        info!("Resultat : {:?}", resultat);
    }

    #[tokio::test]
    async fn get_certificat() {
        setup("get_certificat");
        let client = RedisDao::new(None::<&str>).expect("client");
        let resultat = client.get_certificat("zQmYZfSGuY86wTDBPM6MdYzRGWSqrYtWdbXfquMVG5buxrm").await.expect("resultat");
        info!("Resultat : {:?}", resultat);
    }
}
