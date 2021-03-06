use chrono::{Utc, Timelike, Datelike};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageCedule {
    /// Date en secondes epoch
    estampille: usize,
    date_string: String,
    flag_heure: bool,
    flag_jour: bool,
    flag_mois: bool,
    flag_annee: bool,
    flag_semaine: bool,
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
}
