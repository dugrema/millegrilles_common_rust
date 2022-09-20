use std::error::Error;

use log::{debug, info};
use redis::aio::Connection;
use redis::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::certificats::{EnveloppeCertificat, EnveloppePrivee};
use crate::configuration::ConfigurationNoeud;

const TTL_CERTIFICAT: i32 = 48 * 60 * 60;  // 48 heures en secondes
const CLE_CERTIFICAT: &str = "certificat_v1";
const REDIS_DB_ID: &str = "3";

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

    pub async fn save_cle_maitredescles(&self, enveloppe_privee: &EnveloppePrivee, hachage_bytes: &str, contenu: &Value, connexion: &mut Connection) -> Result<(), Box<dyn Error>> {
        // let mut con = self.client.get_async_connection().await?;

        let fingerprint = enveloppe_privee.fingerprint();
        let expiration = enveloppe_privee.enveloppe.not_valid_after()?.timestamp();

        // Verifier si le certificat existe (reset le TTL a 48h s'il existe deja)
        let cle_label = format!("cle:{}:{}", fingerprint, hachage_bytes);
        let ca_cle_manquante = format!("cle_manquante:{}", fingerprint);
        // debug!("Verifier presence {}, reset TTL", cle_cert);
        // let ttl_info : i32 = redis::cmd("EXPIRE").arg(cle_cert.as_str()).arg(TTL_CERTIFICAT).query_async(&mut con).await?;
        // debug!("Presence {}, reponse ttl reset {}", cle_cert, ttl_info);

        debug!("Conserver cle {} dans redis", cle_label.as_str());

        let contenu_json = serde_json::to_string(contenu)?;

        // Selectioner DB 3 pour cles
        redis::cmd("SELECT").arg(REDIS_DB_ID).query_async(connexion).await?;

        // Conserver certificat
        let resultat: Option<String> = redis::cmd("SET")
            .arg(cle_label).arg(contenu_json)
            .arg("NX")
            .arg("EXAT").arg(expiration)  // Timestamp d'expiration du certificat
            .query_async(connexion).await?;

        if let Some(code) = resultat {
            if code == "OK" {
                let ca_transfert_label = format!("cle_versCA:{}", fingerprint);
                debug!("Ajout {} dans {}", hachage_bytes, ca_transfert_label);
                // La cle n'existait pad
                // Conserver reference de confirmation vers CA
                let _: () = redis::cmd("SADD")
                    .arg(&ca_transfert_label).arg(hachage_bytes)
                    .query_async(connexion).await?;
                let _: () = redis::cmd("EXPIREAT")
                    .arg(&ca_transfert_label).arg(expiration)
                    .query_async(connexion).await?;
            }
        }

        // Retirer flag de certificat manquant si applicable
        // let _: () = redis::cmd("DEL").arg(ca_cle_manquante).query_async(&mut con).await?;
        let _: () = redis::cmd("SREM")
            .arg(ca_cle_manquante)
            .arg(hachage_bytes)
            .query_async(connexion).await?;

        Ok(())
    }

    pub async fn get_cle<S,T>(&self, fingerprint: S, hachage_bytes: T) -> Result<Option<String>, Box<dyn Error>>
        where S: AsRef<str>,
              T: AsRef<str>
    {
        let cle = format!("cle:{}:{}", fingerprint.as_ref(), hachage_bytes.as_ref());

        let mut con = self.client.get_async_connection().await?;

        // Selectioner DB 3 pour cles
        redis::cmd("SELECT").arg(REDIS_DB_ID).query_async(&mut con).await?;

        let resultat: Option<String> = redis::cmd("GET").arg(cle).query_async(&mut con).await?;

        Ok(resultat)
    }

    /// Wrapper pour get_async_connection (expose la connexion async)
    pub async fn get_async_connection(&self) -> Result<Connection, Box<dyn Error>> {
        let mut con = self.client.get_async_connection().await?;
        // Selectioner DB 3 pour cles
        redis::cmd("SELECT").arg(REDIS_DB_ID).query_async(&mut con).await?;
        Ok(con)
    }

    // pub async fn get_cleversca_batch<S>(&self, fingerprint: S, taille_batch: Option<usize>) -> Result<CurseurRedis<'static>, Box<dyn Error>>
    //     where S: AsRef<str>
    // {
    //     let cle = format!("cle_versCA:{}", fingerprint.as_ref());
    //     let taille_batch_effective = match taille_batch {
    //         Some(t) => t,
    //         None => 1000
    //     };
    //
    //     let mut con = self.client.get_async_connection().await?;
    //
    //     // Selectioner DB 3 pour cles
    //     redis::cmd("SELECT").arg(REDIS_DB_ID).query_async(&mut con).await?;
    //
    //     CurseurRedis::try_new(con, cle).await
    //
    //     // let mut iter_scan: redis::AsyncIter<String> = redis::cmd("SSCAN")
    //     //     .arg(cle).cursor_arg(0).clone().iter_async(&mut con).await?;
    //     //
    //     // Ok(iter_scan)
    //
    //     // let mut cles = Vec::new();
    //     // while let Some(hachage_bytes) = iter_scan.next_item().await {
    //     //     cles.push(hachage_bytes);
    //     //     if cles.len() >= taille_batch_effective {
    //     //         break
    //     //     }
    //     // }
    //     //
    //     // Ok(cles)
    // }

    pub async fn ajouter_cle_manquante<S>(&self, enveloppe_privee: &EnveloppePrivee, hachage_bytes: S) -> Result<(), Box<dyn Error>>
        where S: AsRef<str>
    {
        let expiration = enveloppe_privee.enveloppe.not_valid_after()?.timestamp();
        let fingerprint = enveloppe_privee.fingerprint().as_str();
        let label_cle = format!("cle_manquante:{}", fingerprint);

        let mut con = self.client.get_async_connection().await?;

        // Selectioner DB 3 pour cles
        redis::cmd("SELECT").arg(REDIS_DB_ID).query_async(&mut con).await?;

        let _: () = redis::cmd("SADD")
            .arg(&label_cle).arg(hachage_bytes.as_ref())
            .query_async(&mut con).await?;
        let _: () = redis::cmd("EXPIREAT")
            .arg(&label_cle).arg(expiration)
            .query_async(&mut con).await?;

        Ok(())
    }


    pub async fn retirer_cleca_manquante<S,T>(&self, fingerprint: S, hachage_bytes: T) -> Result<(), Box<dyn Error>>
        where S: AsRef<str>,
              T: AsRef<str>
    {
        let cle = format!("cle_versCA:{}", fingerprint.as_ref());

        let mut con = self.client.get_async_connection().await?;

        // Selectioner DB 3 pour cles
        redis::cmd("SELECT").arg(REDIS_DB_ID).query_async(&mut con).await?;

        let _: () = redis::cmd("SREM")
            .arg(cle)
            .arg(hachage_bytes.as_ref())
            .query_async(&mut con).await?;

        Ok(())
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RediCertificatV1 {
    pub pems: Vec<String>,
    pub ca: Option<String>,
}

// pub struct CurseurRedis<'a> {
//     con: Connection,
//     pub iter: Option<redis::AsyncIter<'a, String>>,
// }
//
// impl<'a> CurseurRedis<'a> {
//
//     pub async fn try_new<S>(mut con: Connection, cle_param: S) -> Result<CurseurRedis<'a>, Box<dyn Error>>
//         where S: Into<String>
//     {
//         let cle = cle_param.into();
//
//         let mut curseur = CurseurRedis { con, iter: None };
//
//         let iter_scan: redis::AsyncIter<String> = redis::cmd("SSCAN")
//             .arg(cle).cursor_arg(0).clone().iter_async::<'a>(&mut curseur.con).await?;
//         curseur.iter = Some(iter_scan);
//
//         Ok(curseur)
//     }
// }

// #[cfg(test)]
// mod test_integration_redis_dao {
//     use super::*;
//     use crate::test_setup::setup;
//     use crate::certificats::certificats_tests::charger_enveloppe_privee_env;
//
//     const URL_REDIS: &str = "redis://localhost:6379";
//
//     #[tokio::test]
//     async fn connecter_redis() {
//         setup("connecter_redis");
//         let client = RedisDao::new(Some(URL_REDIS)).expect("client");
//         // let mut con = client.get_async_connection().await?;
//         let resultat = client.liste_certificats_fingerprints().await.expect("resultat");
//         info!("Resultat : {:?}", resultat);
//     }
//
//     #[tokio::test]
//     async fn get_certificat() {
//         setup("get_certificat");
//         let client = RedisDao::new(Some(URL_REDIS)).expect("client");
//         let resultat = client.get_certificat("zQmdmwoc9cync8afXBXvnBar2yHyZihVnHvYrt3zSG4wHoX").await.expect("resultat");
//         info!("Resultat : {:?}", resultat);
//     }
//
//     #[tokio::test]
//     async fn set_certificat() {
//         setup("set_certificat");
//         let (_, enveloppe) = charger_enveloppe_privee_env();
//         let cert = enveloppe.enveloppe;
//
//         let client = RedisDao::new(Some(URL_REDIS)).expect("client");
//
//         let _ = client.save_certificat(cert.as_ref()).await.expect("resultat");
//     }
// }
