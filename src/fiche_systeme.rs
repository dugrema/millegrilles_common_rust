use std::collections::HashMap;
use jwt_simple::prelude::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationApplicationInstance {
    pub pathname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationsV2 {
    pub instances: HashMap<String, InformationApplicationInstance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<HashMap<String, String>>,
    pub securite: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supporte_usager: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationInstance {
    pub domaines: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onion: Option<Vec<String>>,
    pub ports: HashMap<String, u16>,
    pub securite: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FichePublique {
    #[serde(rename = "applicationsV2")]
    pub applications_v2: HashMap<String, ApplicationsV2>,
    pub chiffrage: Option<Vec<Vec<String>>>,
    pub ca: Option<String>,
    pub idmg: String,
    pub instances: HashMap<String, InformationInstance>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteFicheMillegrille {
    pub idmg: String,
}
