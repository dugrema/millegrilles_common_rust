use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::fs::read_to_string;
use std::ops::Deref;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use chrono::{DateTime, ParseResult};
use chrono::prelude::*;
use log::{debug, error, info, warn};
use multibase::{Base, encode};
use multicodec::Codec::Sha2_256 as MCSha2_256;
use multihash::{Code, Multihash};
use num_traits::cast::ToPrimitive;
use openssl::asn1::Asn1TimeRef;
use openssl::error::ErrorStack;
use openssl::hash::{DigestBytes, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::stack::{Stack, StackRef};
use openssl::x509::{X509, X509Name, X509Ref, X509StoreContext, X509v3Context};
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use serde_json::{json, Map, Value};
use x509_parser::parse_x509_certificate;

use crate::constantes::*;

use crate::hachages::hacher_bytes;

// OID des extensions x509v3 de MilleGrille
const OID_EXCHANGES: &str = "1.2.3.4.0";
const OID_ROLES: &str = "1.2.3.4.1";
const OID_DOMAINES: &str = "1.2.3.4.2";
const OID_USERID: &str = "1.2.3.4.3";
const OID_DELEGATION_GLOBALE: &str = "1.2.3.4.4";
const OID_DELEGATION_DOMAINES: &str = "1.2.3.4.5";

pub fn charger_certificat(pem: &str) -> X509 {
    let cert_x509 = X509::from_pem(pem.as_bytes()).unwrap();
    cert_x509
}

pub fn charger_chaine(pem: &str) -> Result<Vec<X509>, ErrorStack> {
    let stack = X509::stack_from_pem(pem.as_bytes());
    debug!("Stack certs : {:?}", stack);

    stack
}

pub fn charger_enveloppe(pem: &str, store: Option<&X509Store>) -> Result<EnveloppeCertificat, ErrorStack> {
    let chaine_x509 = charger_chaine(pem)?;

    // Calculer fingerprint du certificat
    let cert: &X509 = chaine_x509.get(0).unwrap();
    let fingerprint = calculer_fingerprint(cert)?;
    debug!("Fingerprint certificat : {:?}", fingerprint);

    // let chaine_pem: Vec<String> = Vec::new();
    // Pousser les certificats intermediaires (pas le .0, ni le dernier)
    let mut intermediaire: Stack<X509> = Stack::new().unwrap();
    for cert_idx in 1..chaine_x509.len() {
        let _ = intermediaire.push(chaine_x509.get(cert_idx).unwrap().to_owned());
    }

    // Verifier la chaine avec la date courante.
    let mut presentement_valide = false;
    match store {
        Some(s) => {
            presentement_valide = verifier_certificat(cert, &intermediaire, s)?;
        },
        None => (),
    }

    let cle_publique = cert.public_key().unwrap();

    let cert_der = cert.to_der().expect("Erreur exporter cert format DEV");
    let extensions = parse_x509(cert_der.as_slice()).expect("Erreur preparation extensions X509 MilleGrille");

    Ok(EnveloppeCertificat {
        certificat: cert.clone(),
        chaine: chaine_x509,
        cle_publique,
        intermediaire,
        presentement_valide,
        fingerprint,
        date_enveloppe: Instant::now(),
        extensions_millegrille: extensions,
    })
}

pub fn verifier_certificat(cert: &X509, chaine_pem: &StackRef<X509>, store: &X509Store) -> Result<bool, ErrorStack> {
    let mut store_context = X509StoreContext::new()?;
    store_context.init(store, cert, chaine_pem, |c| {
        let mut resultat = c.verify_cert()?;

        if resultat == true {
            // Verifier que l'organisation du certificat correspond au idmg du CA
            let organization = match cert.subject_name().entries_by_nid(Nid::ORGANIZATIONNAME).next() {
                Some(o) => {
                    let data = o.data().as_slice().to_vec();
                    match String::from_utf8(data) {
                        Ok(o) => Some(o),
                        Err(_) => None,
                    }
                },
                None => None,
            };

            if let Some(organization) = organization {
                // Verifier le idmg
                let chaine = match c.chain() {
                    Some(mut s) => {
                        match s.iter().last() {
                            Some(ca) => {
                                match calculer_idmg_ref(ca) {
                                    Ok(idmg_ca) => {
                                        debug!("Sujet organization cert : {}, idmg cert CA {} trouve durant validation : {:?}", organization, idmg_ca, ca.subject_name());
                                        resultat = idmg_ca == organization;
                                    },
                                    Err(e) => {
                                        warn!("Erreur calcul idmg CA : {:?}", e);
                                        resultat = false;
                                    }
                                };
                            },
                            None => {
                                warn!("Cert CA absent, verification false");
                                resultat = false;
                            }
                        }
                    },
                    None => {
                        warn!("La chaine n'a pas ete produite suite a la validation, verif idmg impossible");
                        resultat = false;
                    },
                };
            } else {
                warn!("Organization manquante du certificat, on le considere invalide");
                resultat = false;
            }
        } else {
            debug!("Certificat store considere le certificat invalide");
        }

        Ok(resultat)
    })
}

fn calculer_fingerprint(cert: &X509) -> Result<String, ErrorStack> {
    let fingerprint = cert.digest(MessageDigest::sha256())?;

    let mh = Multihash::wrap(MCSha2_256.code().into(), fingerprint.as_ref()).unwrap();
    let mh_bytes: Vec<u8> = mh.to_bytes();

    Ok(encode(Base::Base58Btc, mh_bytes))
}

fn calculer_fingerprint_pk(pk: &PKey<Public>) -> Result<String, String> {
    let pk_der = pk.public_key_to_der().expect("Erreur conversion PK vers format DER");
    Ok(hacher_bytes(pk_der.as_slice(), Some(Code::Sha2_256), Some(Base::Base64)))
}

pub fn calculer_idmg(cert: &X509) -> Result<String, String> {
    calculer_idmg_ref(cert.deref())
}

pub fn calculer_idmg_ref(cert: &X509Ref) -> Result<String, String> {
    let fingerprint: DigestBytes = cert.digest(MessageDigest::sha256()).unwrap();

    // Multihash
    let mh = Multihash::wrap(MCSha2_256.code().into(), fingerprint.as_ref()).unwrap();
    let mh_bytes: Vec<u8> = mh.to_bytes();

    // Preparation slice du IDMG, 39 bytes
    let mut idmg_slice: [u8; 39] = [0; 39];

    // Version
    idmg_slice[0] = 0x2;

    // SHA-256
    idmg_slice[5..39].clone_from_slice(mh_bytes.as_slice());

    // Date expiration ( ceil(epoch sec/1000) )
    let not_after: &Asn1TimeRef = cert.not_after();
    let date_parsed = EnveloppeCertificat::formatter_date_epoch(not_after).expect("Erreur parsing date expiration pour calculer_idmg");

    // Calculer expiration avec ceil(epoch / 1000), permet de reduire la date a u32.
    let epoch_ts: f64 = date_parsed.timestamp().to_f64().unwrap();
    let epoch_ts: u32 = (epoch_ts / 1000.0).ceil().to_u32().unwrap();

    idmg_slice[1..5].clone_from_slice(&epoch_ts.to_le_bytes());

    let val: String = encode(Base::Base58Btc, idmg_slice);

    Ok(val)
}

pub fn build_store_path(ca_path: &Path) -> Result<ValidateurX509Impl, ErrorStack> {
    let ca_pem: String = read_to_string(ca_path).unwrap();
    let ca_cert: X509 = charger_certificat(&ca_pem);
    let store: X509Store = build_store(&ca_cert, true)?;
    let store_notime: X509Store = build_store(&ca_cert, false)?;

    let enveloppe_ca = charger_enveloppe(&ca_pem, Some(&store)).unwrap();

    // Calculer idmg
    let idmg: String = calculer_idmg(&ca_cert).unwrap();
    debug!("Store charge avec certificat IDMG {}", idmg);

    let validateur = ValidateurX509Impl::new(store, store_notime, idmg, ca_pem, ca_cert);

    // Conserver l'enveloppe dans le cache
    validateur.cacher(enveloppe_ca);

    Ok(validateur)
}

pub fn build_store(ca_cert: &X509, check_time: bool) -> Result<X509Store, ErrorStack> {

    let mut builder = X509StoreBuilder::new()?;
    let ca_cert = ca_cert.clone();  // Requis par methode add_cert
    let _ = builder.add_cert(ca_cert);

    if check_time == false {
        // Verification manuelle de la date de validite.
        builder.set_flags(X509VerifyFlags::NO_CHECK_TIME);
    }

    Ok(builder.build())
}

pub fn charger_enveloppe_privee(path_cert: &Path, path_cle: &Path, validateur: Arc<Box<impl ValidateurX509>>) -> Result<EnveloppePrivee, ErrorStack> {
    let pem_cle = read_to_string(path_cle).unwrap();
    let cle_privee = Rsa::private_key_from_pem(pem_cle.as_bytes())?;
    let cle_privee: PKey<Private> = PKey::from_rsa(cle_privee)?;

    let pem_cert = read_to_string(path_cert).unwrap();
    let enveloppe = charger_enveloppe(&pem_cert, Some(validateur.store()))?;

    // Recreer la chaine de certificats avec les PEM.
    let mut chaine_pem: Vec<String> = Vec::new();
    let cert_pem = String::from_utf8(enveloppe.certificat().to_pem().unwrap()).unwrap();
    chaine_pem.push(cert_pem);
    for cert_intermediaire in &enveloppe.intermediaire {
        let pem = cert_intermediaire.to_pem().unwrap();
        let cert_pem = String::from_utf8(pem).unwrap();
        chaine_pem.push(cert_pem);
    }

    let enveloppe_privee = EnveloppePrivee {
        enveloppe,
        cle_privee,
        chaine_pem,
    };

    Ok(enveloppe_privee)
}

pub struct EnveloppeCertificat {
    certificat: X509,
    chaine: Vec<X509>,
    cle_publique: PKey<Public>,
    intermediaire: Stack<X509>,
    pub presentement_valide: bool,
    pub fingerprint: String,
    date_enveloppe: Instant,
    extensions_millegrille: ExtensionsMilleGrille,
}

impl EnveloppeCertificat {

    /// Retourne le certificat de l'enveloppe.
    pub fn certificat(&self) -> &X509 { &self.certificat }

    pub fn presentement_valide(&self) -> bool { self.presentement_valide }

    pub fn fingerprint(&self) -> &String { &self.fingerprint }

    pub fn get_pem_vec(&self) -> Vec<FingerprintCert> {
        let mut vec = Vec::new();
        for c in &self.chaine {
            let p = String::from_utf8(c.to_pem().unwrap()).unwrap();
            let fp = calculer_fingerprint(c).unwrap();
            vec.push(FingerprintCert{fingerprint: fp, pem: p});
        }
        vec
    }

    pub fn not_valid_before(&self) -> Result<DateTime<Utc>, String> {
        let not_before: &Asn1TimeRef = self.certificat.not_before();
        match EnveloppeCertificat::formatter_date_epoch(not_before) {
            Ok(date) => Ok(date),
            Err(e) => Err(format!("Parsing erreur certificat not_valid_before : {:?}", e))
        }
    }

    pub fn not_valid_after(&self) -> Result<DateTime<Utc>, String> {
        let not_after: &Asn1TimeRef = self.certificat.not_after();
        match EnveloppeCertificat::formatter_date_epoch(not_after) {
            Ok(date) => Ok(date),
            Err(e) => Err(format!("Parsing erreur certificat not_valid_after : {:?}", e))
        }
    }

    pub fn idmg(&self) -> Result<String, String> {
        let certificat = &self.certificat;
        let subject_name = certificat.subject_name();
        for entry in subject_name.entries_by_nid(Nid::ORGANIZATIONNAME) {
            let data = entry.data().as_slice().to_vec();
            return Ok(String::from_utf8(data).expect("Erreur chargement IDMG"))
        }

        Err("IDMG non present sur certificat (OrganizationName)".into())
    }

    pub fn subject(&self) -> Result<HashMap<String, String>, String> {
        let certificat = &self.certificat;
        let subject_name = certificat.subject_name();

        let mut resultat = HashMap::new();
        for entry in subject_name.entries() {
            // debug!("Entry : {:?}", entry);
            let cle: String = entry.object().nid().long_name().expect("Erreur chargement Nid de subject").into();
            let data = entry.data().as_slice().to_vec();
            let valeur = String::from_utf8(data).expect("Erreur chargement IDMG");
            resultat.insert(cle, valeur);
        }

        Ok(resultat)
    }

    pub fn formatter_date_epoch(date: &Asn1TimeRef) -> ParseResult<DateTime<Utc>> {
        let str_date = date.to_string();
        Utc.datetime_from_str(&str_date, "%b %d %T %Y %Z")
    }

    pub fn fingerprint_pk(&self) -> Result<String, String> {
        let pk = self.certificat.public_key().expect("Erreur extraction cle publique pour fingerprint_pk");
        calculer_fingerprint_pk(&pk)
    }

    pub fn get_exchanges(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.exchanges) }
    pub fn get_roles(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.roles) }
    pub fn get_domaines(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.domaines) }
    pub fn get_user_id(&self) -> Result<&Option<String>, String> { Ok(&self.extensions_millegrille.user_id) }
    pub fn get_delegation_globale(&self) -> Result<&Option<String>, String> { Ok(&self.extensions_millegrille.delegation_globale) }
    pub fn get_delegation_domaines(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.delegation_domaines) }

}

impl Debug for EnveloppeCertificat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Enveloppe certificat {}", self.fingerprint)
    }
}

#[derive(Clone, Debug)]
pub struct FingerprintCert {
    pub fingerprint: String,
    pub pem: String,
}

/// Enveloppe avec cle pour cle et certificat combine
pub struct EnveloppePrivee {
    pub enveloppe: EnveloppeCertificat,
    cle_privee: PKey<Private>,
    chaine_pem: Vec<String>,
}

impl EnveloppePrivee {

    pub fn certificat(&self) -> &X509 { &self.enveloppe.certificat }

    pub fn chaine_pem(&self) -> &Vec<String> { &self.chaine_pem }

    pub fn cle_privee(&self) -> &PKey<Private> { &self.cle_privee }

    pub fn cle_publique(&self) -> &PKey<Public> { &self.enveloppe.cle_publique }

    pub fn presentement_valide(&self) -> bool { self.enveloppe.presentement_valide }

    pub fn fingerprint(&self) -> &String { self.enveloppe.fingerprint() }

    pub fn intermediaire(&self) -> &Stack<X509> { &self.enveloppe.intermediaire }

    pub fn get_pem_vec(&self) -> Vec<FingerprintCert> { self.enveloppe.get_pem_vec() }

    pub fn idmg(&self) -> Result<String, String> { self.enveloppe.idmg() }

    pub fn subject(&self) -> Result<HashMap<String, String>, String> { self.enveloppe.subject() }

    pub fn not_valid_before(&self) -> Result<DateTime<Utc>, String> { self.enveloppe.not_valid_before() }

    pub fn not_valid_after(&self) -> Result<DateTime<Utc>, String> { self.enveloppe.not_valid_after() }

    pub fn fingerprint_pk(&self) -> Result<String, String> { self.enveloppe.fingerprint_pk() }

    pub fn get_exchanges(&self) -> Result<&Option<Vec<String>>, String> { self.enveloppe.get_exchanges() }
    pub fn get_roles(&self) -> Result<&Option<Vec<String>>, String> { self.enveloppe.get_roles() }
    pub fn get_domaines(&self) -> Result<&Option<Vec<String>>, String> {  self.enveloppe.get_domaines() }
    pub fn get_user_id(&self) -> Result<&Option<String>, String> {  self.enveloppe.get_user_id() }
    pub fn get_delegation_globale(&self) -> Result<&Option<String>, String> {  self.enveloppe.get_delegation_globale() }
    pub fn get_delegation_domaines(&self) -> Result<&Option<Vec<String>>, String> {  self.enveloppe.get_delegation_domaines() }

}

impl Debug for EnveloppePrivee {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Enveloppe privee {}", self.fingerprint()).as_str())
    }
}

#[async_trait]
pub trait ValidateurX509: Send + Sync {

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String>;

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat>;

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>>;

    fn idmg(&self) -> &String;

    fn ca_pem(&self) -> &String;

    fn ca_cert(&self) -> &X509;

    fn store(&self) -> &X509Store;

    /// Store avec le flag X509VerifyFlags::NO_CHECK_TIME
    /// Permet de valider une date specifique
    /// Todo: utiliser OpenSSL lorsque verif params disponibles
    fn store_notime(&self) -> &X509Store;

    /// Invoquer regulierement pour faire l'entretien du cache.
    async fn entretien(&self);

    fn valider_pour_date(&self, enveloppe: &EnveloppeCertificat, date: &DateTime<Utc>) -> Result<bool, String> {
        {
            let before = enveloppe.not_valid_before()?;
            let after = enveloppe.not_valid_after()?;
            let inclus = date >= &before && date <= &after;
            if inclus == false {
                // La date n'est pas dans le range du certificat
                debug!("Pas inclus, date {:?} n'est pas entre {:?} et {:?}", date, before, after);
                return Ok(false)
            }
        }

        // let resultat_notime = verifier_certificat(enveloppe.certificat(), enveloppe.intermediaire(), validateur.store_notime());

        let certificat = &enveloppe.certificat;
        let chaine = &enveloppe.intermediaire;
        let store = self.store_notime();
        match verifier_certificat(certificat, chaine, store) {
            Ok(b) => {
                debug!("Verifier certificat result apres check date OK : {}", b);
                Ok(b)
            },
            Err(e) => Err(format!("Erreur verification certificat avec no time : {:?}", e)),
        }
    }

}

pub struct ValidateurX509Impl {
    store: X509Store,
    store_notime: X509Store,
    idmg: String,
    ca_pem: String,
    ca_cert: X509,
    cache_certificats: Mutex<HashMap<String, Arc<EnveloppeCertificat>>>,
}

impl ValidateurX509Impl {

    pub fn new(store: X509Store, store_notime: X509Store, idmg: String, ca_pem: String, ca_cert: X509) -> ValidateurX509Impl {
        let cache_certificats: Mutex<HashMap<String, Arc<EnveloppeCertificat>>> = Mutex::new(HashMap::new());
        ValidateurX509Impl {store, store_notime, idmg, ca_pem, ca_cert, cache_certificats}
    }

    /// Expose la fonction pour creer un certificat
    fn charger_certificat(pem: &str) -> Result<(X509, String), ErrorStack> {
        let cert = charger_certificat(pem);
        let fingerprint = calculer_fingerprint(&cert)?;
        Ok((cert, fingerprint))
    }

}

#[async_trait]
impl ValidateurX509 for ValidateurX509Impl {

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {

        let fp: String = match fingerprint {
            Some(fp) => Ok(String::from(fp)),
            None => {
                debug!("Charger le _certificat pour trouver fingerprint");
                match chaine_pem.get(0) {
                    Some(pem) => {
                        match ValidateurX509Impl::charger_certificat(pem.as_str()) {
                            Ok(r) => Ok(r.1),
                            Err(e) => Err(format!("Erreur chargement enveloppe certificat : {:?}", e)),
                        }
                    },
                    None => Err(String::from("Aucun certificat n'est present")),
                }
            }
        }?;

        debug!("Fingerprint du certificat de l'enveloppe a charger : {}", fp);

        // Verifier si le certificat est present dans le cache
        match self.get_certificat(fp.as_str()).await {
            Some(e) => Ok(e),
            None => {
                // Creer l'enveloppe et conserver dans le cache local
                let pem_str: String = chaine_pem.join("\n");
                debug!("Alignement du _certificat en string concatenee\n{}", pem_str);
                match charger_enveloppe(pem_str.as_str(), Some(&self.store)) {
                    Ok(e) => {
                        Ok(self.cacher(e).await)
                    },
                    Err(e) => Err(format!("Erreur chargement certificat : {:?}", e))
                }
            }
        }
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {

        let fingerprint = certificat.fingerprint().to_owned();

        // Creer reference atomique pour l'enveloppe
        let enveloppe_arc = Arc::new(certificat);

        // Conserver dans le cache
        let mut mutex = self.cache_certificats.lock().unwrap();
        mutex.insert(fingerprint.to_owned(), enveloppe_arc.clone());

        debug!("Certificat {} ajoute au cache ({:} entrees)", fingerprint, mutex.len());

        // Retourner la nouvelle reference
        enveloppe_arc
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.cache_certificats.lock().unwrap().get(fingerprint) {
            Some(e) => Some(e.clone()),
            None => None,
        }
    }

    fn idmg(&self) -> &String { &self.idmg }

    fn ca_pem(&self) -> &String { &self.ca_pem }

    fn ca_cert(&self) -> &X509 { &self.ca_cert }

    fn store(&self) -> &X509Store { &self.store }

    fn store_notime(&self) -> &X509Store { &self.store_notime }

    async fn entretien(&self) { debug!("Entretien cache certificats"); }

}

impl Debug for ValidateurX509Impl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("validateur X509")
    }
}

fn parse_x509(cert: &[u8]) -> Result<ExtensionsMilleGrille, String> {
    let (_, cert_parsed) = parse_x509_certificate(&cert).expect("Erreur parsing X509");
    debug!("Certificat X509 parsed : {:?}", cert_parsed);

    let extensions = cert_parsed.extensions();

    let mut exchanges = None;
    let mut roles = None;
    let mut domaines = None;
    let mut user_id = None;
    let mut delegation_globale = None;
    let mut delegation_domaines = None;

    for ext in extensions {
        debug!("Extension ext = {:?}", ext);
        match ext.oid.to_id_string().as_str() {
            OID_EXCHANGES => { exchanges = Some(extraire_vec_strings(ext.value).expect("Erreur extraction exchanges")) },
            OID_ROLES => { roles = Some(extraire_vec_strings(ext.value).expect("Erreur extraction roles")) },
            OID_DOMAINES => { domaines = Some(extraire_vec_strings(ext.value).expect("Erreur extraction domaines")) },
            OID_USERID => { user_id = Some(String::from_utf8(ext.value.to_vec()).expect("Erreur extraction user_id")) },
            OID_DELEGATION_GLOBALE => { delegation_globale = Some(String::from_utf8(ext.value.to_vec()).expect("Erreur extraction delegation_globale")) },
            OID_DELEGATION_DOMAINES => { delegation_domaines = Some(extraire_vec_strings(ext.value).expect("Erreur extraction delegation_domaines")) },
            _ => (), // Inconnu
        }
    }

    Ok(ExtensionsMilleGrille {exchanges, roles, domaines, user_id, delegation_globale, delegation_domaines})
}

#[derive(Clone, Debug)]
struct ExtensionsMilleGrille {
    exchanges: Option<Vec<String>>,
    roles: Option<Vec<String>>,
    domaines: Option<Vec<String>>,
    user_id: Option<String>,
    delegation_globale: Option<String>,
    delegation_domaines: Option<Vec<String>>,
}

fn extraire_vec_strings(data: &[u8]) -> Result<Vec<String>, String> {
    let value= String::from_utf8(data.to_vec()).expect("Erreur lecture exchanges");
    let split = value.split(",");
    let mut vec = Vec::new();
    for v in split {
        vec.push(String::from(v));
    }

    Ok(vec)
}