use std::collections::HashMap;
use chrono::{Utc, Timelike, Datelike, DateTime};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageCedule {
    /// Date en secondes epoch
    pub estampille: usize,
    pub date_string: String,
    pub flag_heure: bool,
    pub flag_jour: bool,
    pub flag_mois: bool,
    pub flag_annee: bool,
    pub flag_semaine: bool,
}
impl MessageCedule {
    pub fn now() -> Self {
        let now = Utc::now();

        let time = &now.time();
        let date = &now.date();

        let flag_heure = time.minute() == 0;
        let flag_jour = flag_heure && time.hour() == 0;
        let flag_mois = flag_jour && date.day() == 1;
        let flag_annee = flag_mois && date.month() == 1;
        let flag_semaine = flag_jour && date.weekday().num_days_from_sunday() == 0;

        let date_string = now.format("%+").to_string();

        MessageCedule {
            estampille: now.timestamp() as usize,
            date_string,
            flag_heure,
            flag_jour,
            flag_mois,
            flag_annee,
            flag_semaine,
        }
    }

    pub fn get_date(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.estampille as i64, 0).expect("datetime")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandePostmasterPoster {
    pub idmg: String,
    pub message_id: String,
    pub fiche: FicheMillegrilleApplication,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FicheMillegrilleApplication {
    pub idmg: String,
    // pub adresses: Vec<String>,
    pub application: Vec<FicheApplication>,
    pub ca: Option<String>,
    pub chiffrage: Option<Vec<Vec<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FicheApplication {
    pub application: String,
    pub nature: String,
    pub url: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationTransmission {
    pub message_id: String,
    pub idmg: String,
    pub code: u16,
    pub adresses: Option<HashMap<String, u16>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeDechiffrerCle {
    pub cle: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeCleRechiffree {
    pub ok: bool,
    pub cle: Option<String>,
}

pub trait CommandeUsager<'a> {
    fn get_user_id(&'a self) -> Option<&'a str>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseCommande<'a> {
    pub ok: Option<bool>,
    pub message: Option<&'a str>,
    pub err: Option<&'a str>,
}
