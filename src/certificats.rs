use std::collections::{HashMap, BTreeMap, HashSet};
use std::error;
use std::fmt::{Debug, Formatter};
use std::fs::read_to_string;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use chrono::{DateTime, ParseResult};
use chrono::prelude::*;
use log::{debug, info, error, warn};
use multibase::{Base, encode};
use multicodec::Codec::Blake2s_256;
use multihash::{Code, Multihash};
use num_traits::cast::ToPrimitive;
use openssl::asn1::Asn1TimeRef;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
//use openssl::rsa::Rsa;
use openssl::stack::{Stack, StackRef};
use openssl::x509::{X509, X509Ref, X509Req, X509ReqRef, X509StoreContext};
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::json;
use x509_parser::parse_x509_certificate;
use blake2::{Blake2s256, Digest};

use crate::constantes::*;
use crate::hachages::hacher_bytes;
// use std::error::Error;
use crate::constantes::Securite::L1Public;
use std::convert::TryInto;
use millegrilles_cryptographie::ed25519_dalek::{SecretKey, SigningKey};
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesRef, MessageValidable};
use millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee, ExtensionsMilleGrille};
use crate::error::Error;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::recepteur_messages::{ErreurValidation, ErreurVerification, MessageValide, TypeMessage};
use crate::verificateur::charger_regles_verification;

// OID des extensions x509v3 de MilleGrille
const OID_EXCHANGES: &str = "1.2.3.4.0";
const OID_ROLES: &str = "1.2.3.4.1";
const OID_DOMAINES: &str = "1.2.3.4.2";
const OID_USERID: &str = "1.2.3.4.3";
const OID_DELEGATION_GLOBALE: &str = "1.2.3.4.4";
const OID_DELEGATION_DOMAINES: &str = "1.2.3.4.5";

const TAILLE_CACHE_MAX: usize = 250;      // Limite a ne pas depasser dans le cache
const TAILLE_CACHE_NETTOYER: usize = 50;  // Trigger un nettoyage regulier du cache

/// Conserve un certificat dans le cache en memoire
struct CacheCertificat {
    /// Certificat
    enveloppe: Arc<EnveloppeCertificat>,
    /// Date du dernier acces (pour mode MRU)
    dernier_acces: DateTime<Utc>,
    /// Nombre d'acces depuis mise en cache (pour mode LFU)
    compte_acces: usize,
    /// True si le certificat a ete persiste localement (redis ou mongodb)
    persiste: bool,
}

impl CacheCertificat {
    fn new(enveloppe: Arc<EnveloppeCertificat>) -> Self {
        Self {
            enveloppe,
            //date_creation: Utc::now(),
            dernier_acces: Utc::now(),
            compte_acces: 0,
            persiste: false,
        }
    }
}

pub fn charger_certificat(pem: &str) -> Result<X509, ErrorStack> {
    X509::from_pem(pem.as_bytes())
}

pub fn charger_csr(pem: &str) -> Result<X509Req, String> {
    match X509Req::from_pem(pem.as_bytes()) {
        Ok(c) => Ok(c),
        Err(e) => Err(format!("Erreur chargement CSR : {:?}", e))
    }
}

pub fn csr_calculer_fingerprintpk(pem: &str) -> Result<String, Error> {
    let csr_parsed = charger_csr(pem)?;
    // let cle_publique = csr_parsed.public_key()?;
    // let fingerprint = calculer_fingerprint_pk(&cle_publique)?;
    // Ok(fingerprint)

    let cle_publique = csr_parsed.public_key()?.raw_public_key()?;
    let cle_hex = hex::encode(cle_publique);
    Ok(cle_hex)
}

pub fn charger_chaine(pem: &str) -> Result<Vec<X509>, ErrorStack> {
    let stack = X509::stack_from_pem(pem.as_bytes());
    debug!("Stack certs : {:?}", stack);

    stack
}

pub fn charger_enveloppe(pem: &str, store: Option<&X509Store>, ca_pem: Option<&str>) -> Result<EnveloppeCertificat, Error> {
    debug!("Charger enveloppe : {}", pem);
    let chaine_x509 = charger_chaine(pem)?;
    debug!("Chaine X.509 : {:?}", chaine_x509);

    let millegrille = match ca_pem {
        Some(c) => X509::stack_from_pem(c.as_bytes())?.pop(),
        None => None
    };

    // Calculer fingerprint du certificat
    let cert: &X509 = match chaine_x509.get(0) {
        Some(inner) => inner,
        None => Err("charger_enveloppe Certificat non parse")?
    };
    let fingerprint = calculer_fingerprint(cert).expect("fingerprint");
    debug!("Fingerprint certificat : {:?}", fingerprint);

    // let chaine_pem: Vec<String> = Vec::new();
    // Pousser les certificats intermediaires (pas le .0, ni le dernier)
    let mut intermediaire: Stack<X509> = Stack::new()?;
    for cert_idx in 1..chaine_x509.len() {
        let _ = intermediaire.push(chaine_x509.get(cert_idx).expect("charger_enveloppe intermediaire").to_owned());
    }

    // Verifier la chaine avec la date courante.
    let mut presentement_valide = false;
    match store {
        Some(s) => {
            presentement_valide = verifier_certificat(cert, &intermediaire, s)?;
        },
        None => (),
    }

    // let cle_publique = cert.public_key().unwrap();

    let cert_der = cert.to_der()?;  //.expect("Erreur exporter cert format DEV");
    // let extensions = parse_x509(cert_der.as_slice()).expect("Erreur preparation extensions X509 MilleGrille");

    Ok(EnveloppeCertificat {
        certificat: cert.clone(),
        chaine: chaine_x509,
        // cle_publique,
        // intermediaire,
        millegrille,
        // presentement_valide,
        // fingerprint,
        // date_enveloppe: Instant::now(),
        // extensions_millegrille: extensions,
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
                match c.chain() {
                    Some(s) => {
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
                let common_name = match cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
                    Some(o) => {
                        let data = o.data().as_slice().to_vec();
                        match String::from_utf8(data) {
                            Ok(o) => Some(o),
                            Err(_) => None,
                        }
                    },
                    None => None,
                };
                if common_name != Some("MilleGrille".to_string()) {
                    warn!("Organization manquante du certificat, on le considere invalide\n{:?}", cert);
                    resultat = false;
                }
            }
        } else {
            debug!("Certificat store considere le certificat invalide");
        }

        Ok(resultat)
    })
}

pub fn calculer_fingerprint(cert: &X509) -> Result<String, String> {
    // let fingerprint = cert.digest(MessageDigest::sha256())?;

    // let fingerprint = {
    //     let der = match cert.to_der() {
    //         Ok(v) => v,
    //         Err(e) => Err(format!("calculer_fingerprint fingerprint error : {:?}", e))?
    //     };
    //     let mut hasher = Blake2s256::new();
    //     hasher.update(der);
    //     hasher.finalize()
    // };

    // let mh = match Multihash::wrap(Blake2s_256.code().into(), fingerprint.as_ref()) {
    //     Ok(m) => m,
    //     Err(e) => Err(format!("calculer_fingerprint multihash error : {:?}", e))?
    // };
    // let mh_bytes: Vec<u8> = mh.to_bytes();

    // Ok(encode(Base::Base58Btc, mh_bytes))

    // refact 2023.5.0 - le fingerprint (pubkey) correspond a la cle publique
    // note : risque de poisoning si cle privee est reutilisee dans plusieurs certificats
    match cert.public_key() {
        Ok(inner) => calculer_fingerprint_pk(&inner),
        Err(e) => Err(format!("certificats.calculer_fingerprint Erreur public_key() {:?}", e))?
    }
}

// fn calculer_fingerprint_ref(cert: &X509Ref) -> Result<String, ErrorStack> {
//     let fingerprint = cert.digest(MessageDigest::sha256())?;
//
//     let mh = Multihash::wrap(MCSha2_256.code().into(), fingerprint.as_ref()).unwrap();
//     let mh_bytes: Vec<u8> = mh.to_bytes();
//
//     Ok(encode(Base::Base58Btc, mh_bytes))
// }

pub fn calculer_fingerprint_pk(pk: &PKey<Public>) -> Result<String, String> {
    // let pk_der = pk.public_key_to_der().expect("Erreur conversion PK vers format DER");
    // let pk_raw = match pk.raw_public_key() {
    //     Ok(k) => k,
    //     Err(e) => Err(format!("certificats.calculer_fingerprint_pk Erreur extraction raw public key : {:?}", e))?
    // };
    // Ok(hacher_bytes(&pk_raw[..], Some(Code::Blake2s256), Some(Base::Base58Btc)))

    let cle_publique = match pk.raw_public_key() {
        Ok(inner) => inner,
        Err(e) => Err(format!("certificats.calculer_fingerprint_pk Erreur raw_public_key() {:?}", e))?
    };
    let cle_hex = hex::encode(cle_publique);
    Ok(cle_hex)
}

pub fn calculer_idmg(cert: &X509) -> Result<String, String> {
    calculer_idmg_ref(cert.deref())
}

pub fn calculer_idmg_ref(cert: &X509Ref) -> Result<String, String> {
    // let fingerprint: DigestBytes = cert.digest(MessageDigest::sha256()).unwrap();

    let fingerprint = {
        let der = match cert.to_der() {
            Ok(v) => v,
            Err(e) => Err(format!("calculer_idmg_ref fingerprint error : {:?}", e))?
        };
        let mut hasher = Blake2s256::new();
        hasher.update(der);
        hasher.finalize()
    };

    // Multihash
    let mh = Multihash::wrap(Blake2s_256.code().into(), fingerprint.as_ref()).unwrap();
    let mh_bytes: Vec<u8> = mh.to_bytes();

    // Preparation slice du IDMG, 41 bytes
    let mut idmg_slice: [u8; 41] = [0; 41];

    // Version
    idmg_slice[0] = 0x2;

    // SHA-256
    idmg_slice[5..41].clone_from_slice(mh_bytes.as_slice());

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
    let ca_cert: X509 = charger_certificat(&ca_pem)?;
    let store: X509Store = build_store(&ca_cert, true)?;
    let store_notime: X509Store = build_store(&ca_cert, false)?;

    let enveloppe_ca = charger_enveloppe(&ca_pem, Some(&store), None).unwrap();

    // Calculer idmg
    let idmg: String = calculer_idmg(&ca_cert).unwrap();
    debug!("Store charge avec certificat IDMG {}", idmg);

    let validateur = ValidateurX509Impl::new(store, store_notime, idmg, ca_pem, ca_cert);

    // Conserver l'enveloppe dans le cache
    let _ = validateur.cacher(enveloppe_ca);

    Ok(validateur)
}

pub fn build_store(ca_cert: &X509, check_time: bool) -> Result<X509Store, ErrorStack> {
    let mut builder = X509StoreBuilder::new()?;
    let ca_cert = ca_cert.to_owned();
    builder.add_cert(ca_cert)?;

    if check_time == false {
        // Verification manuelle de la date de validite.
        builder.set_flags(X509VerifyFlags::NO_CHECK_TIME)?;
    }

    Ok(builder.build())
}

pub fn charger_enveloppe_privee<V>(path_cert: &Path, path_cle: &Path, validateur: Arc<V>)
    -> Result<EnveloppePrivee, Error>
    where V: ValidateurX509
{
    let path_cle_str = format!("cle : {:?}", path_cle);
    let pem_cle = read_to_string(path_cle).expect(path_cle_str.as_str());
    // let cle_privee = Rsa::private_key_from_pem(pem_cle.as_bytes())?;
    // let cle_privee: PKey<Private> = PKey::from_rsa(cle_privee)?;
    let cle_privee = PKey::private_key_from_pem(pem_cle.as_bytes())?;

    let pem_cert = read_to_string(path_cert).unwrap();
    let enveloppe = charger_enveloppe(&pem_cert, Some(validateur.store()), None)?;

    let clecert_pem = format!("{}\n{}", pem_cle, pem_cert);

    // Recreer la chaine de certificats avec les PEM.
    let chaine_pem = enveloppe.chaine_pem();
    // let mut chaine_pem: Vec<String> = Vec::new();
    // let cert_pem = String::from_utf8(enveloppe.certificat().to_pem().unwrap()).unwrap();
    // chaine_pem.push(cert_pem);
    // for cert_intermediaire in &enveloppe.chaine {
    //     let pem = cert_intermediaire.to_pem().unwrap();
    //     let cert_pem = String::from_utf8(pem).unwrap();
    //     chaine_pem.push(cert_pem);
    // }

    let ca_pem = validateur.ca_pem().to_owned();
    let enveloppe_ca = charger_enveloppe(&ca_pem, Some(validateur.store()), None)?;
    let chaine_pem = enveloppe.chaine_pem()?;
    let enveloppe_privee = EnveloppePrivee {
        enveloppe_pub: Arc::new(enveloppe),
        enveloppe_ca: Arc::new(enveloppe_ca),
        cle_privee,
        // chaine_pem,
        // clecert_pem,
        // ca: ca_pem,
        chaine_pem,
        ca_pem,
        // enveloppe_ca,
        cle_privee_pem: pem_cle,
    };

    Ok(enveloppe_privee)
}

// pub struct EnveloppeCertificat {
//     certificat: X509,
//     chaine: Vec<X509>,
//     pub cle_publique: PKey<Public>,
//     intermediaire: Stack<X509>,
//     millegrille: Option<X509>,
//     // pub presentement_valide: bool,
//     pub fingerprint: String,
//     date_enveloppe: Instant,
//     extensions_millegrille: ExtensionsMilleGrille,
// }
//
// impl EnveloppeCertificat {
//
//     /// Retourne le certificat de l'enveloppe.
//     pub fn certificat(&self) -> &X509 { &self.certificat }
//
//     // pub fn certificat_millegrille(&self) -> &X509 {
//     //     &self.chaine.iter().last().expect("cert")
//     // }
//
//     // pub fn presentement_valide(&self) -> bool { self.presentement_valide }
//
//     pub fn fingerprint(&self) -> &String { &self.fingerprint }
//
//     pub fn get_pem_vec(&self) -> Vec<FingerprintCert> {
//         let mut vec = Vec::new();
//         for c in &self.chaine {
//             let p = String::from_utf8(c.to_pem().unwrap()).unwrap();
//             let fp = calculer_fingerprint(c).unwrap();
//             vec.push(FingerprintCert{fingerprint: fp, pem: p});
//         }
//         vec
//     }
//
//     /// Extrait les pems et retourne dans un Vec<String>
//     pub fn get_pem_vec_extracted(&self) -> Vec<String> {
//         self.chaine_fingerprint_pem()?.iter().map(|p| p.pem.clone()).collect()
//     }
//
//     pub fn get_pem_ca(&self) -> Result<Option<String>,String> {
//         match &self.millegrille {
//             Some(c) => match c.to_pem() {
//                 Ok(c) => match String::from_utf8(c) {
//                     Ok(c) => Ok(Some(c)),
//                     Err(e) => Err(format!("certificats.get_pem_ca Erreur conversion pem CA : {:?}", e))
//                 },
//                 Err(e) => Err(format!("certificats.get_pem_ca Erreur conversion pem CA : {:?}", e))
//             },
//             None => Ok(None)
//         }
//     }
//
//     pub fn not_valid_before(&self) -> Result<DateTime<Utc>, String> {
//         let not_before: &Asn1TimeRef = self.certificat.not_before();
//         match EnveloppeCertificat::formatter_date_epoch(not_before) {
//             Ok(date) => Ok(date),
//             Err(e) => Err(format!("Parsing erreur certificat not_valid_before : {:?}", e))
//         }
//     }
//
//     pub fn not_valid_after(&self) -> Result<DateTime<Utc>, String> {
//         let not_after: &Asn1TimeRef = self.certificat.not_after();
//         match EnveloppeCertificat::formatter_date_epoch(not_after) {
//             Ok(date) => Ok(date),
//             Err(e) => Err(format!("Parsing erreur certificat not_valid_after : {:?}", e))
//         }
//     }
//
//     pub fn idmg(&self) -> Result<String, String> {
//         let certificat = &self.certificat;
//         let subject_name = certificat.subject_name();
//         for entry in subject_name.entries_by_nid(Nid::ORGANIZATIONNAME) {
//             let data = entry.data().as_slice().to_vec();
//             return Ok(String::from_utf8(data).expect("Erreur chargement IDMG"))
//         }
//
//         Err("IDMG non present sur certificat (OrganizationName)".into())
//     }
//
//     /// Calcule le idmg pour ce certificat
//     pub fn calculer_idmg(&self) -> Result<String, String> {
//         match self.idmg() {
//             Ok(i) => Ok(i),
//             Err(_) => calculer_idmg(&self.certificat)
//         }
//     }
//
//     pub fn subject(&self) -> Result<HashMap<String, String>, String> {
//         let certificat = &self.certificat;
//         let subject_name = certificat.subject_name();
//
//         let mut resultat = HashMap::new();
//         for entry in subject_name.entries() {
//             // debug!("Entry : {:?}", entry);
//             let cle: String = entry.object().nid().long_name().expect("Erreur chargement Nid de subject").into();
//             let data = entry.data().as_slice().to_vec();
//             let valeur = String::from_utf8(data).expect("Erreur chargement IDMG");
//             resultat.insert(cle, valeur);
//         }
//
//         Ok(resultat)
//     }
//
//     pub fn get_common_name(&self) -> Result<String, String> {
//         let subject = self.subject()?;
//         match subject.get("commonName") {
//             Some(cn) => Ok(cn.to_owned()),
//             None => Err("certificats.EnveloppeCertificat.get_common_name : commonName absent du subject".into())
//         }
//     }
//
//     pub fn issuer(&self) -> Result<HashMap<String, String>, String> {
//         let certificat = &self.certificat;
//         let subject_name = certificat.issuer_name();
//
//         let mut resultat = HashMap::new();
//         for entry in subject_name.entries() {
//             // debug!("Entry : {:?}", entry);
//             let cle: String = entry.object().nid().long_name().expect("Erreur chargement Nid de subject").into();
//             let data = entry.data().as_slice().to_vec();
//             let valeur = String::from_utf8(data).expect("Erreur chargement IDMG");
//             resultat.insert(cle, valeur);
//         }
//
//         Ok(resultat)
//     }
//
//     pub fn est_ca(&self) -> Result<bool, String> {
//         let subject = self.subject()?;
//         let issuer = self.issuer()?;
//
//         Ok(subject == issuer)
//     }
//
//     pub fn formatter_date_epoch(date: &Asn1TimeRef) -> ParseResult<DateTime<Utc>> {
//         let str_date = date.to_string();
//         Utc.datetime_from_str(&str_date, "%b %d %T %Y %Z")
//     }
//
//     pub fn fingerprint_pk(&self) -> Result<String, String> {
//         let pk = self.certificat.public_key().expect("Erreur extraction cle publique pour fingerprint_pk");
//         calculer_fingerprint_pk(&pk)
//     }
//
//     pub fn publickey_bytes(&self) -> Result<String, String> {
//         let pk = match self.certificat.public_key() {
//             Ok(pk) => pk,
//             Err(e) => Err(format!("certificat.public_bytes Erreur public_key() {:?}", e))?
//         };
//         match pk.raw_public_key() {
//             Ok(b) => Ok(multibase::encode(Base::Base64, b)),
//             Err(e) => Err(format!("certificat.public_bytes Erreur raw_private_key() {:?}", e))?
//         }
//     }
//
//     pub fn publickey_bytes_encoding(&self, base: Base, strip: bool) -> Result<String, String> {
//         let pk = match self.certificat.public_key() {
//             Ok(pk) => pk,
//             Err(e) => Err(format!("certificat.public_bytes Erreur public_key() {:?}", e))?
//         };
//         match pk.raw_public_key() {
//             Ok(b) => {
//                 let encoded_string: String = multibase::encode(base, b);
//                 match strip {
//                     true => {
//                         let encoded_remove_id = &encoded_string[1..];
//                         Ok(encoded_remove_id.to_string())
//                     },
//                     false => Ok(encoded_string)
//                 }
//             },
//             Err(e) => Err(format!("certificat.public_bytes Erreur raw_private_key() {:?}", e))?
//         }
//     }
//
//     /// Retourne la cle publique pour le certificat (leaf) et le CA (millegrille)
//     /// Utilise pour chiffrage de cles secretes
//     pub fn fingerprint_cert_publickeys(&self) -> Result<Vec<FingerprintCertPublicKey>, Error> {
//         let cert_leaf = self.chaine.get(0).expect("leaf");
//         let fp_leaf = calculer_fingerprint(cert_leaf)?;
//         let fpleaf = FingerprintCertPublicKey { fingerprint: fp_leaf, public_key: cert_leaf.public_key()?, est_cle_millegrille: false };
//
//         let cert_mg = self.chaine.last().expect("cert inter");
//         let fp_mg = calculer_fingerprint(cert_mg)?;
//         let fpmg = FingerprintCertPublicKey { fingerprint: fp_mg, public_key: cert_mg.public_key()?, est_cle_millegrille: false };
//
//         Ok(vec!(fpleaf, fpmg))
//     }
//
//     // /// Retourne le fingerprint du certificat CA (certificat de MilleGrille)
//     // pub fn fingerprint_ca(&self) -> Option<String> {
//     //     let pem_vec = self.chaine_fingerprint_pem()?;
//     //     let conversion = pem_vec.into_iter().last().map(|p| p.fingerprint);
//     //     conversion
//     // }
//
//     pub fn get_exchanges(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.exchanges) }
//     pub fn get_roles(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.roles) }
//     pub fn get_domaines(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.domaines) }
//     pub fn get_user_id(&self) -> Result<&Option<String>, String> { Ok(&self.extensions_millegrille.user_id) }
//     pub fn get_delegation_globale(&self) -> Result<&Option<String>, String> { Ok(&self.extensions_millegrille.delegation_globale) }
//     pub fn get_delegation_domaines(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.delegation_domaines) }
//
// }
//
// impl Clone for EnveloppeCertificat {
//
//     fn clone(&self) -> Self {
//
//         let mut intermediaire: Stack<X509> = Stack::new().expect("stack");
//         for cert in &self.intermediaire {
//             intermediaire.push(cert.to_owned()).expect("push");
//         }
//
//         EnveloppeCertificat {
//             certificat: self.certificat.clone(),
//             chaine: self.chaine.clone(),
//             cle_publique: self.cle_publique.clone(),
//             intermediaire,
//             millegrille: self.millegrille.clone(),
//             // presentement_valide: self.presentement_valide,
//             fingerprint: self.fingerprint.clone(),
//             date_enveloppe: self.date_enveloppe.clone(),
//             extensions_millegrille: self.extensions_millegrille.clone(),
//         }
//     }
//
//     fn clone_from(&mut self, source: &Self) {
//
//         let mut intermediaire = Stack::new().expect("stack");
//         for cert in &source.intermediaire {
//             intermediaire.push(cert.to_owned()).expect("push");
//         }
//
//         self.certificat = source.certificat.clone();
//         self.chaine = source.chaine.clone();
//         self.cle_publique = source.cle_publique.clone();
//         self.intermediaire = intermediaire;
//         self.millegrille = source.millegrille.clone();
//         // self.presentement_valide = source.presentement_valide;
//         self.fingerprint = source.fingerprint.clone();
//         self.date_enveloppe = source.date_enveloppe.clone();
//         self.extensions_millegrille = source.extensions_millegrille.clone();
//     }
//
// }
//
// impl Debug for EnveloppeCertificat {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         write!(f, "Enveloppe certificat {}", self.fingerprint)
//     }
// }

// #[derive(Clone, Debug)]
// pub struct FingerprintCert {
//     pub fingerprint: String,
//     pub pem: String,
// }

// #[derive(Clone, Debug)]
// pub struct FingerprintCertPublicKey {
//     pub fingerprint: String,
//     pub public_key: PKey<Public>,
//     pub est_cle_millegrille: bool,
// }

// impl FingerprintCertPublicKey {
//     pub fn new(fingerprint: String, public_key: PKey<Public>, est_cle_millegrille: bool) -> Self {
//         FingerprintCertPublicKey { fingerprint, public_key, est_cle_millegrille }
//     }
// }

/// Enveloppe avec cle pour cle et certificat combine
// #[derive(Clone)]
// pub struct EnveloppePrivee {
//     pub enveloppe: Arc<EnveloppeCertificat>,
//     cle_privee: PKey<Private>,
//     chaine_pem: Vec<String>,
//     pub clecert_pem: String,
//     pub ca: String,
//     pub enveloppe_ca: Arc<EnveloppeCertificat>,
// }
//
//
// impl EnveloppePrivee {
//
//     pub fn new(
//         enveloppe: Arc<EnveloppeCertificat>,
//         cle_privee: PKey<Private>,
//         chaine_pem: Vec<String>,
//         clecert_pem: String,
//         ca: String,
//         enveloppe_ca: Arc<EnveloppeCertificat>
//     ) -> Self {
//         Self { enveloppe, cle_privee, chaine_pem, clecert_pem, ca, enveloppe_ca }
//     }
//
//     pub fn certificat(&self) -> &X509 { &self.enveloppe.certificat }
//
//     pub fn chaine_pem(&self) -> &Vec<String> { &self.chaine_pem }
//
//     pub fn cle_privee(&self) -> &PKey<Private> { &self.cle_privee }
//
//     pub fn cle_publique(&self) -> &PKey<Public> { &self.enveloppe.cle_publique }
//
//     // pub fn presentement_valide(&self) -> bool { self.enveloppe.presentement_valide }
//
//     pub fn fingerprint(&self) -> &String { self.enveloppe.fingerprint() }
//
//     pub fn intermediaire(&self) -> &Stack<X509> { &self.enveloppe.intermediaire }
//
//     pub fn get_pem_vec(&self) -> Vec<FingerprintCert> { self.enveloppe.chaine_fingerprint_pem()? }
//
//     pub fn idmg(&self) -> Result<String, String> { self.enveloppe.idmg() }
//
//     pub fn subject(&self) -> Result<HashMap<String, String>, String> { self.enveloppe.subject() }
//
//     pub fn not_valid_before(&self) -> Result<DateTime<Utc>, String> { self.enveloppe.not_valid_before() }
//
//     pub fn not_valid_after(&self) -> Result<DateTime<Utc>, String> { self.enveloppe.not_valid_after() }
//
//     pub fn fingerprint_pk(&self) -> Result<String, String> { self.enveloppe.fingerprint_pk() }
//
//     /// Retourne le fingerprint du certificat CA (certificat de MilleGrille)
//     // pub fn fingerprint_ca(&self) -> Option<String> {
//     //     let pem_vec = self.chaine_fingerprint_pem()?;
//     //     let conversion = pem_vec.into_iter().last().map(|p| p.fingerprint);
//     //     conversion
//     // }
//
//     pub fn get_exchanges(&self) -> Result<&Option<Vec<String>>, String> { self.enveloppe.get_exchanges() }
//     pub fn get_roles(&self) -> Result<&Option<Vec<String>>, String> { self.enveloppe.get_roles() }
//     pub fn get_domaines(&self) -> Result<&Option<Vec<String>>, String> {  self.enveloppe.get_domaines() }
//     pub fn get_user_id(&self) -> Result<&Option<String>, String> {  self.enveloppe.get_user_id() }
//     pub fn get_delegation_globale(&self) -> Result<&Option<String>, String> {  self.enveloppe.get_delegation_globale() }
//     pub fn get_delegation_domaines(&self) -> Result<&Option<Vec<String>>, String> {  self.enveloppe.get_delegation_domaines() }
//
// }
//
// impl Debug for EnveloppePrivee {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         f.write_str(format!("Enveloppe privee {}", self.fingerprint()).as_str())
//     }
// }
//
// impl TryInto<SigningKey> for &EnveloppePrivee {
//
//     type Error = Error;
//
//     fn try_into<'a>(self) -> Result<SigningKey, Error> {
//         let mut cle_privee_u8 = SecretKey::default();
//         match self.cle_privee().raw_private_key() {
//             Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
//             Err(e) => Err(Error::String(format!("TryInto<SigningKey> for &EnveloppePrivee Erreur raw_private_key {:?}", e)))?
//         };
//         Ok(SigningKey::from_bytes(&cle_privee_u8))
//     }
//
// }

// impl Clone for EnveloppePrivee {
//     fn clone(&self) -> Self {
//         EnveloppePrivee {
//             enveloppe: self.enveloppe.clone(),
//             cle_privee: self.cle_privee.clone(),
//             chaine_pem: self.chaine_pem.clone(),
//             clecert_pem: self.clecert_pem.clone(),
//         }
//     }
// }

/// Parse et retourne une map avec le subject du CSR
pub fn get_csr_subject(csr: &X509ReqRef) -> Result<HashMap<String, String>, String> {
    let subject_name = csr.subject_name();

    let mut resultat = HashMap::new();
    for entry in subject_name.entries() {
        let cle: String = entry.object().nid().long_name().expect("Erreur chargement Nid de subject").into();
        let data = entry.data().as_slice().to_vec();
        let valeur = String::from_utf8(data).expect("Erreur chargement IDMG");
        resultat.insert(cle, valeur);
    }

    Ok(resultat)
}

/// Valide le certificat de MilleGrillesRef pour le message.
pub async fn valider_certificat<'a, M, V>(
    middleware: &M,
    message: &'a V,
    verifier_date_courante: bool
)
    -> Result<Arc<EnveloppeCertificat>, crate::error::Error>
    where M: ValidateurX509 + ?Sized, V: MessageValidable<'a>
{
    // Recuperer le certificat du message.
    let pubkey = message.pubkey();
    let certificat_pem = message.certificat()?;

    let enveloppe = if middleware.est_cache(pubkey) || certificat_pem.is_none() {
        // Utiliser le middleware pour recuperer le certificat
        match middleware.get_certificat(pubkey).await {
            Some(inner) => inner,
            None => Err(ErreurVerification::CertificatInconnu(pubkey.into()))?
        }
    } else {
        // Charger le certificat recu avec le message
        let vec_pem: Vec<String> = certificat_pem.unwrap().iter().map(|s| s.to_string()).collect();
        match middleware.charger_enveloppe(&vec_pem, Some(pubkey), message.millegrille()).await {
            Ok(inner) => inner,
            Err(_) => Err(ErreurVerification::CertificatInvalide)?
        }
    };

    match middleware.valider_chaine(enveloppe.as_ref(), None, verifier_date_courante) {
        Ok(inner) => {
            if ! inner {
                Err(ErreurVerification::CertificatInvalide)?
            }
        },
        Err(e) => Err(ErreurVerification::CertificatInvalide)?
    }

    match middleware.valider_pour_date(enveloppe.as_ref(), message.estampille()) {
        Ok(inner) => match inner {
            true => Ok(enveloppe),
            false => Err(ErreurVerification::CertificatInvalide)?
        },
        Err(e) => Err(ErreurVerification::CertificatInvalide)?
    }
}

pub async fn valider_certificat_regle<'a, M, V>(
    middleware: &M,
    message: &'a V,
    regle: &str
)
    -> Result<Arc<EnveloppeCertificat>, crate::error::Error>
    where M: ValidateurX509 + ?Sized, V: MessageValidable<'a>
{
    // Recuperer la chaine de certificat du message.
    let certificat_pem = match message.certificat()? {
        Some(inner) => inner,
        None => {
            error!("valider_certificat_regle Certificat PEM manquant");
            Err(ErreurVerification::CertificatInvalide)?
        }
    };
    let millegrille_pem = match message.millegrille() {
        Some(inner) => inner,
        None => {
            error!("valider_certificat_regle Certificat de millegrille manquant");
            Err(ErreurVerification::CertificatInvalide)?
        }
    };

    // Charger la regle de validation
    let mut regles = match charger_regles_verification(&PathBuf::from(PATH_REGLES_VALIDATION)) {
        Ok(inner) => inner,
        Err(e) => {
            error!("valider_certificat_regle Erreur chargement fichier idmg_validation.json : {:?}", e);
            Err(ErreurVerification::ErreurGenerique)?
        }
    };
    let regle = match regles.regles.remove(regle) {
        Some(inner) => inner,
        None => {
            error!("valider_certificat_regle Regle {} absente du fichier idmg_validation.json", regle);
            Err(ErreurVerification::ErreurGenerique)?
        }
    };

    let pubkey_message = message.pubkey();

    // Charger une enveloppe avec les PEMs
    let vec_pem: Vec<String> = certificat_pem.iter().map(|s| s.to_string()).collect();
    debug!("valider_certificat_regle Charger certificat\n{:?}", vec_pem);
    let enveloppe = match charger_enveloppe(certificat_pem.join("\n").as_str(), None, Some(millegrille_pem)) {
    //let enveloppe = match middleware.charger_enveloppe(&vec_pem, Some(pubkey_message), Some(millegrille_pem)).await {
        Ok(inner) => inner,
        Err(e) => {
            error!("valider_certificat_regle Erreur chargement enveloppe : {:?}", e);
            Err(ErreurVerification::CertificatInvalide)?
        }
    };
    let millegrille_pem_unescaped = millegrille_pem.replace("\\n", "\n");
    debug!("valider_certificat_regle Charger certificat millegrille\n{:?}", millegrille_pem_unescaped);
    let enveloppe_millegrille = match charger_enveloppe(millegrille_pem_unescaped.as_str(), None, None) {
    // let enveloppe_millegrille = match middleware.charger_enveloppe(&vec![millegrille_pem.to_string()], None, None).await {
        Ok(inner) => inner,
        Err(e) => {
            error!("valider_certificat_regle Erreur chargement enveloppe millegrille : {:?}", e);
            Err(ErreurVerification::CertificatInvalide)?
        }
    };
    match enveloppe_millegrille.est_ca() {
        Ok(inner) => {
            if ! inner {
                warn!("valider_certificat_regle Certificat de MilleGrille n'est pas CA");
                Err(ErreurVerification::CertificatInvalide)?
            }
        },
        Err(e) => {
            warn!("valider_certificat_regle Certificat de MilleGrille n'est pas CA");
            Err(ErreurVerification::CertificatInvalide)?
        }
    }

    // Verifier que la pubkey correspond
    let pubkey_enveloppe = match enveloppe.fingerprint_pk() {
        Ok(inner) => inner,
        Err(e) => {
            warn!("valider_certificat_regle Erreur chargement pubkey de l'enveloppe");
            Err(ErreurVerification::SignatureInvalide)?
        }
    };
    if pubkey_enveloppe.as_str() != pubkey_message {
        warn!("valider_certificat_regle Pubkey mismatch avec message");
        Err(ErreurVerification::SignatureInvalide)?
    }

    let idmg = match enveloppe_millegrille.calculer_idmg() {
        Ok(inner) => inner,
        Err(e) => {
            warn!("valider_certificat_regle Erreur calcul idmg : {:?}", e);
            Err(ErreurVerification::CertificatInvalide)?
        }
    };
    if let Some(liste_idmg) = regle.idmg.as_ref() {
        if ! liste_idmg.contains(&idmg) {
            warn!("valider_certificat_regle Certificat de MilleGrille n'est pas dans la liste");
            Err(ErreurVerification::CertificatInvalide)?
        }
        debug!("valider_certificat_regle Idmg valide : {}", idmg);
    }

    let valider_date_courante = regle.date_courante.unwrap_or_else(||false);

    // Build store pour verifier le certificat avec la date du message
    let cert_millegrille = &enveloppe_millegrille.certificat;
    let store = match build_store(cert_millegrille, valider_date_courante) {
        Ok(inner) => inner,
        Err(e) => {
            warn!("valider_certificat_regle Erreur preparation store (no date)");
            Err(ErreurVerification::CertificatInvalide)?
        }
    };

    let certificat_x509 = &enveloppe.certificat;
    let chaine_x509 = &enveloppe.intermediaire_stack()?;
    debug!("Valider certificat (chaine: {})\n{:?}", chaine_x509.len(), certificat_x509);
    match verifier_certificat(certificat_x509, chaine_x509.as_ref(), &store) {
        Ok(inner) => {
            if ! inner {
                warn!("valider_certificat_regle Certificat invalide");
                Err(ErreurVerification::CertificatInvalide)?
            }
        },
        Err(e) => {
            warn!("valider_certificat_regle Erreur verification certificat : {:?}", e);
            Err(ErreurVerification::CertificatInvalide)?
        }
    }

    // Verifier date de validite du certificat par rapport au message
    let estampille = message.estampille();
    match valider_pour_date(&enveloppe, estampille) {
        Ok(inner) => {
            if ! inner {
                warn!("valider_certificat_regle Date certificat leaf invalide pour message");
                Err(ErreurVerification::CertificatInvalide)?
            }
        },
        Err(e) => {
            warn!("valider_certificat_regle Erreur verification date message avec certificat : {:?}", e);
            Err(ErreurVerification::CertificatInvalide)?
        }
    }

    Ok(Arc::new(enveloppe))
}

#[async_trait]
pub trait ValidateurX509: Send + Sync {

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>)
        -> Result<Arc<EnveloppeCertificat>, crate::error::Error>;

    /// Conserve un certificat dans le cache
    /// retourne le certificat et un bool qui indique si le certificat a deja ete persiste (true)
    async fn cacher(&self, certificat: EnveloppeCertificat) -> Result<(Arc<EnveloppeCertificat>, bool), Error>;

    /// Set le flag persiste a true pour le certificat correspondant a fingerprint
    fn set_flag_persiste(&self, fingerprint: &str);

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>>;

    /// Retourne true si le certificat est deja dans le cache.
    fn est_cache(&self, fingerprint: &str) -> bool;

    /// Retourne une liste de certificats qui n'ont pas encore ete persiste.
    fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>>;

    fn idmg(&self) -> &str;

    fn ca_pem(&self) -> &str;

    fn ca_cert(&self) -> &X509;

    fn store(&self) -> &X509Store;

    /// Store avec le flag X509VerifyFlags::NO_CHECK_TIME
    /// Permet de valider une date specifique
    /// Todo: utiliser OpenSSL lorsque verif params disponibles
    fn store_notime(&self) -> &X509Store;

    /// Invoquer regulierement pour faire l'entretien du cache.
    async fn entretien_validateur(&self);

    fn valider_chaine(&self, enveloppe: &EnveloppeCertificat, certificat_millegrille: Option<&EnveloppeCertificat>, verifier_date_courante: bool)
        -> Result<bool, crate::error::Error>
    {
        let certificat = &enveloppe.certificat;
        let chaine = &enveloppe.intermediaire_stack()?;
        match certificat_millegrille {
            Some(cm) => {
                debug!("Idmg tiers, on bati un store on the fly : CA {:?}", cm.chaine);
                let cert_ca = &cm.certificat;
                // let cert_ca = chaine[chaine.len()-1].to_owned();
                let store = match build_store(cert_ca, false) {
                    Ok(s) => s,
                    Err(_e) => Err(format!("certificats.valider_chaine Erreur preparation store pour certificat {:?}", certificat))?
                };
                match verifier_certificat(certificat, chaine, &store) {
                    Ok(b) => {
                        debug!("Verifier certificat result : valide = {}, cert {:?}", b, certificat);
                        Ok(b)
                    },
                    Err(e) => Err(format!("certificats.valider_chaine Erreur verification certificat idmg {:?} : {:?}", certificat, e))?,
                }
            },
            None => {
                let store = match verifier_date_courante {
                    true => self.store(),
                    false => self.store_notime()
                };

                match verifier_certificat(certificat, chaine, store) {
                    Ok(b) => {
                        debug!("Verifier certificat result apres check date OK : {}", b);
                        Ok(b)
                    },
                    Err(e) => Err(format!("certificats.valider_chaine Erreur verification certificat avec no time : {:?}", e))?,
                }
            }
        }
    }

    /// Valider le certificat pour une fourchette de date.
    /// Note : ne valide pas la chaine
    fn valider_pour_date(&self, enveloppe: &EnveloppeCertificat, date: &DateTime<Utc>) -> Result<bool, Error> {
        valider_pour_date(enveloppe, date)
    }

    /// Valide le certificat en fonction de la date du message.
    /// Option : verifie aussi la validite de la chaine avec la date courante.
    async fn valider_certificat_message<'a, V>(
        &self,
        message: &'a V,
        verifier_date_courante: bool
    )
        -> Result<Arc<EnveloppeCertificat>, Error>
        where V: MessageValidable<'a>
    {
        valider_certificat(self, message, verifier_date_courante).await
    }

    /// Valide le certificat en fonction d'une regle dans configuration/idmg_validation.json
    /// Les champs certificat et millegrille du message doivent etre remplis.
    async fn valider_certificat_idmg<'a, V>(
        &self,
        message: &'a V,
        regle: &str
    )
        -> Result<Arc<EnveloppeCertificat>, Error>
        where V: MessageValidable<'a>
    {
        valider_certificat_regle(self, message, regle).await
    }
}

/// Valider le certificat pour une fourchette de date.
/// Note : ne valide pas la chaine
pub fn valider_pour_date(enveloppe: &EnveloppeCertificat, date: &DateTime<Utc>) -> Result<bool, Error> {
    let before = enveloppe.not_valid_before()?;
    let after = enveloppe.not_valid_after()?;
    let valide = date >= &before && date <= &after;
    match valide {
        true => Ok(true),
        false => Err(Error::Str("Certificat invalide"))?
    }
}

pub struct ValidateurX509Impl {
    store: X509Store,
    store_notime: X509Store,
    idmg: String,
    ca_pem: String,
    ca_cert: X509,
    cache_certificats: Mutex<HashMap<String, CacheCertificat>>,
}

impl ValidateurX509Impl {

    pub fn new(store: X509Store, store_notime: X509Store, idmg: String, ca_pem: String, ca_cert: X509) -> ValidateurX509Impl {
        let cache_certificats: Mutex<HashMap<String, CacheCertificat>> = Mutex::new(HashMap::new());
        ValidateurX509Impl {store, store_notime, idmg, ca_pem, ca_cert, cache_certificats}
    }

    /// Expose la fonction pour creer un certificat
    fn charger_certificat(pem: &str) -> Result<(X509, String), Error> {
        let cert = charger_certificat(pem)?;
        let fingerprint = calculer_fingerprint(&cert)?;
        Ok((cert, fingerprint))
    }

}

#[async_trait]
impl ValidateurX509 for ValidateurX509Impl {

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>)
        -> Result<Arc<EnveloppeCertificat>, Error>
    {

        let fp: String = match fingerprint {
            Some(fp) => Ok(String::from(fp)),
            None => {
                debug!("charger_enveloppe Charger le _certificat pour trouver fingerprint");
                match chaine_pem.get(0) {
                    Some(pem) => {
                        let pem_str = pem.replace("\\n", "\n");
                        match ValidateurX509Impl::charger_certificat(pem_str.as_str()) {
                            Ok(r) => Ok(r.1),
                            Err(e) => Err(format!("Erreur chargement enveloppe certificat : {:?}", e)),
                        }
                    },
                    None => Err(String::from("Aucun certificat n'est present")),
                }
            }
        }?;

        debug!("charger_enveloppe Fingerprint du certificat de l'enveloppe a charger : {}", fp);

        // Verifier si le certificat est present dans le cache
        match self.get_certificat(fp.as_str()).await {
            Some(e) => Ok(e),
            None => {
                // Creer l'enveloppe et conserver dans le cache local
                let pem_str: String = chaine_pem.iter()
                    .map(|c|c.replace("\\n", "\n").replace("\\r", "\r"))
                    .collect::<Vec<String>>()
                    .join("\n");
                debug!("charger_enveloppe Alignement du _certificat en string concatenee\n{}", pem_str);
                match charger_enveloppe(pem_str.as_str(), Some(&self.store), ca_pem) {
                    Ok(e) => {

                        // Verifier si on a un certificat de millegrille tierce (doit avoir CA)
                        let idmg_local = self.idmg.as_str();
                        if e.est_ca()? {
                            // Certificat CA, probablement d'une millegrille tierce. Accepter inconditionnellement.
                            Ok(self.cacher(e).await?.0)
                        } else {
                            // Verifier si le certificat est local (CA n'est pas requis)
                            // Pour tiers, le CA doit etre inclus dans l'enveloppe.
                            let idmg_certificat = e.idmg()?;
                            if idmg_local == idmg_certificat.as_str() || e.millegrille.is_some() {
                                Ok(self.cacher(e).await?.0)
                            } else {
                                info!("certificats.charger_enveloppe Erreur chargement certificat {} : certificat CA manquant pour millegrille {} tierce", fp, idmg_certificat);
                                Err(ErreurVerification::CertificatCaManquant(idmg_certificat))?
                            }
                        }
                    },
                    Err(e) => Err(format!("certificats.charger_enveloppe Erreur chargement certificat {} : {:?}", fp, e))?
                }
            }
        }
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Result<(Arc<EnveloppeCertificat>, bool), Error> {

        let fingerprint = certificat.fingerprint()?;

        let mut mutex = self.cache_certificats.lock().expect("lock");
        match mutex.get_mut(fingerprint.as_str()) {
            Some(e) => {
                // Incrementer compteur, maj date acces
                e.compte_acces = e.compte_acces + 1;
                e.dernier_acces = Utc::now();

                Ok((e.enveloppe.clone(), e.persiste))
            },
            None => {
                let enveloppe = Arc::new(certificat);

                if mutex.len() < TAILLE_CACHE_MAX {
                    // Certificat inconnu, sauvegarder dans le cache
                    let cache_entry = CacheCertificat::new(enveloppe.clone());
                    mutex.insert(fingerprint, cache_entry);
                } else {
                    debug!("Cache certificat plein, on ne conserve pas le certificat en memoire");
                }

                // Retourne l'enveloppe et indicateur que le certificat n'est pas persiste
                Ok((enveloppe, false))
            }
        }
    }

    fn set_flag_persiste(&self, fingerprint: &str) {
        let mut mutex = self.cache_certificats.lock().expect("lock");
        if let Some(certificat) = mutex.get_mut(fingerprint) {
            certificat.persiste = true;
        }
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.cache_certificats.lock().unwrap().get_mut(fingerprint) {
            Some(e) => {
                // Incrementer compteur, maj date acces
                e.compte_acces = e.compte_acces + 1;
                e.dernier_acces = Utc::now();

                // Retourner clone de l'enveloppe
                Some(e.enveloppe.clone())
            },
            None => None,
        }
    }

    fn est_cache(&self, fingerprint: &str) -> bool {
        let mut mutex = self.cache_certificats.lock().expect("lock");
        mutex.contains_key(fingerprint)
    }

    /// Retourne une liste de certificats qui n'ont pas encore ete persiste.
    fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
        let mut mutex = self.cache_certificats.lock().expect("lock");
        mutex.iter()
            .filter(|(_,c)| !c.persiste)
            .map(|e| e.1.enveloppe.clone())
            .collect()
    }

    fn idmg(&self) -> &str { self.idmg.as_str() }

    fn ca_pem(&self) -> &str { self.ca_pem.as_str() }

    fn ca_cert(&self) -> &X509 { &self.ca_cert }

    fn store(&self) -> &X509Store { &self.store }

    fn store_notime(&self) -> &X509Store { &self.store_notime }

    async fn entretien_validateur(&self) {
        debug!("Entretien cache certificats");

        {
            let mut mutex = self.cache_certificats.lock().expect("lock");
            if mutex.len() > TAILLE_CACHE_NETTOYER {
                // Retirer tous les certificats avec une date d'acces expiree (cache mode MRU)
                let expiration = Utc::now() - chrono::Duration::minutes(30);
                mutex.retain(|_, val| val.dernier_acces < expiration);

                if mutex.len() > TAILLE_CACHE_MAX {
                    // Meme apres nettoyage d'expiration, le cache est plus grand que la limite max
                    mutex.clear();  // On fait juste clearer le cache. TODO faire un menage correct
                }
            }
        }
    }

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

// #[derive(Clone, Debug)]
// pub struct ExtensionsMilleGrille {
//     exchanges: Option<Vec<String>>,
//     roles: Option<Vec<String>>,
//     domaines: Option<Vec<String>>,
//     pub user_id: Option<String>,
//     delegation_globale: Option<String>,
//     delegation_domaines: Option<Vec<String>>,
// }
// impl ExtensionsMilleGrille {
//     /// Retourne le plus haut niveau de securite (echange) supporte par ce certificat
//     pub fn exchange_top(&self) -> Option<Securite> {
//         match self.exchanges.as_ref() {
//             Some(e) => {
//                 let mut sec = L1Public;
//                 for s in e {
//                     if let Ok(inner_sec) = securite_enum(s.as_str()) {
//                         let rk_courant = sec.get_rank();
//                         let rk_inner = inner_sec.get_rank();
//                         if rk_courant < rk_inner {
//                             sec = inner_sec;
//                         }
//                     }
//                 }
//
//                 Some(sec)
//             },
//             None => None,
//         }
//     }
// }

fn extraire_vec_strings(data: &[u8]) -> Result<Vec<String>, String> {
    let value= String::from_utf8(data.to_vec()).expect("Erreur lecture exchanges");
    let split = value.split(",");
    let mut vec = Vec::new();
    for v in split {
        vec.push(String::from(v));
    }

    Ok(vec)
}

pub fn ordered_map<S>(value: &HashMap<String, String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}

/// Structure qui permet d'exporter en Json plusieurs certificats en format PEM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionCertificatsPem {
    certificats: Vec<Vec<String>>,
    #[serde(serialize_with = "ordered_map")]
    pems: HashMap<String, String>,
}

impl CollectionCertificatsPem {

    pub fn new() -> Self {
        CollectionCertificatsPem {
            pems: HashMap::new(),
            certificats: Vec::new(),
        }
    }

    pub fn ajouter_certificat(&mut self, certificat: &EnveloppeCertificat) -> Result<(), Error> {
        let fingerprint = certificat.fingerprint()?;

        match self.pems.get(fingerprint.as_str()) {
            Some(_) => {
                // Ok, rien a faire
                return Ok(())
            },
            None => ()
        }

        let mut chaine_fp = Vec::new();
        for fp_cert in certificat.chaine_fingerprint_pem()? {
            chaine_fp.push(fp_cert.fingerprint.clone());
            self.pems.insert(fp_cert.fingerprint, fp_cert.pem);
        }

        self.certificats.push(chaine_fp);

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.certificats.len()
    }

    pub async fn get_enveloppe(&self, validateur: &impl ValidateurX509, fingerprint_certificat: &str) -> Option<Arc<EnveloppeCertificat>> {
        // Trouver la chaine avec le fingerprint (position 0)
        let res_chaine = self.certificats.iter().filter(|chaine| {
            if let Some(fp) = chaine.get(0) {
                fp.as_str() == fingerprint_certificat
            } else {
                false
            }
        }).next();

        // Generer enveloppe a partir des PEMs individuels
        if let Some(chaine) = res_chaine {
            debug!("Fingerprints trouves (chaine): {:?}", chaine);
            let pems: Vec<String> = chaine.into_iter().map(|fp| self.pems.get(fp.as_str()).expect("pem").to_owned()).collect();
            match validateur.charger_enveloppe(&pems, Some(fingerprint_certificat), None).await {
                Ok(e) => Some(e),
                Err(e) => {
                    error!("Erreur chargement enveloppe {} : {:?}", fingerprint_certificat, e);
                    None
                },
            }
        } else {
            None
        }

    }
}

pub trait VerificateurPermissions {
    fn get_extensions(&self) -> Result<Option<ExtensionsMilleGrille>, Error>;

    fn get_user_id(&self) -> Result<Option<String>, Error> {
        match self.get_extensions()? {
            Some(e) => {
                Ok(e.user_id.to_owned())
            },
            None => Ok(None)
        }
    }

    fn verifier(&self, exchanges: Option<Vec<Securite>>, roles: Option<Vec<RolesCertificats>>) -> Result<bool, Error> {
        let mut valide = true;

        if let Some(e) = exchanges {
            valide = valide && self.verifier_exchanges(e)?;
        }

        if let Some(r) = roles {
            valide = valide && self.verifier_roles(r)?;
        }

        Ok(valide)
    }

    fn verifier_usager<S>(&self, user_id: S) -> Result<bool, Error>
        where S: AsRef<str>
    {
        let extensions = match self.get_extensions()? {
            Some(e) => e,
            None => return Ok(false)
        };

        match &extensions.user_id {
            Some(u) => Ok(u.as_str() == user_id.as_ref()),
            None => Ok(false)
        }
    }

    fn verifier_delegation_globale<S>(&self, delegation: S) -> Result<bool, Error>
        where S: AsRef<str>
    {
        let extensions = match self.get_extensions()? {
            Some(e) => e,
            None => return Ok(false)
        };

        match &extensions.delegation_globale {
            Some(inner) => Ok(inner.as_str() == delegation.as_ref()),
            None => Ok(false)
        }
    }

    fn verifier_exchanges(&self, exchanges_permis: Vec<Securite>) -> Result<bool, Error> {
        // Valider certificat.
        let exchanges_string: Vec<String> = exchanges_permis.into_iter().map(|s| s.try_into().expect("securite")).collect();
        self.verifier_exchanges_string(exchanges_string)
    }

    fn verifier_exchanges_string(&self, exchanges_permis: Vec<String>) -> Result<bool, Error> {
        // Valider certificat.
        let extensions = match self.get_extensions()? {
            Some(e) => e,
            None => return Ok(false)
        };
        debug!("verifier_exchanges_string Extensions cert : {:?}", extensions);

        let mut hs_param= HashSet::new();
        hs_param.extend(exchanges_permis);

        let hs_cert = match extensions.exchanges.clone() {
            Some(ex) => {
                let mut hs_cert = HashSet::new();
                hs_cert.extend(ex);
                hs_cert
            },
            None => return Ok(false),
        };

        let res: Vec<&String> = hs_param.intersection(&hs_cert).collect();
        // let res: Vec<&String> = exchanges_permis.iter().filter(|c| ex.contains(c)).collect();
        if res.len() == 0 {
            return Ok(false)
        }

        Ok(true)
    }

    /// Verifie les roles des certificats
    fn verifier_roles(&self, roles_permis: Vec<RolesCertificats>) -> Result<bool, Error> {
        let roles_string: Vec<String> = roles_permis.into_iter().map(|s| s.try_into().expect("securite")).collect();
        self.verifier_roles_string(roles_string)
    }

    fn verifier_roles_string(&self, roles_permis: Vec<String>) -> Result<bool, Error> {
        // Valider certificat.
        let extensions = match self.get_extensions()? {
            Some(e) => e,
            None => return Ok(false)
        };

        let mut hs_param= HashSet::new();
        hs_param.extend(roles_permis);

        let hs_cert = match extensions.roles.clone() {
            Some(ex) => {
                let mut hs_cert = HashSet::new();
                hs_cert.extend(ex);
                hs_cert
            },
            None => return Ok(false)
        };

        let res: Vec<&String> = hs_param.intersection(&hs_cert).collect();
        if res.len() == 0 {
            return Ok(false)
        }

        Ok(true)
    }

    fn verifier_domaines(&self, domaines_permis: Vec<String>) -> Result<bool, Error> {
        // Valider certificat.
        let extensions = match self.get_extensions()? {
            Some(e) => e,
            None => return Ok(false)
        };

        let mut hs_param= HashSet::new();
        hs_param.extend(domaines_permis);

        let hs_cert = match extensions.domaines.clone() {
            Some(ex) => {
                let mut hs_cert = HashSet::new();
                hs_cert.extend(ex);
                hs_cert
            },
            None => return Ok(false),
        };

        let res: Vec<&String> = hs_param.intersection(&hs_cert).collect();
        if res.len() == 0 {
            return Ok(false)
        }

        Ok(true)
    }

}

impl VerificateurPermissions for EnveloppeCertificat {
    fn get_extensions(&self) -> Result<Option<ExtensionsMilleGrille>, Error> {
        Ok(Some(self.extensions()?))
    }
}

/// Message global (domaine certificat) utilise pour echanger certificats directement entre modules
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageInfoCertificat {
    pub chaine_pem: Option<Vec<String>>,
    pub fingerprint: Option<String>,
}

pub async fn emettre_commande_certificat_maitredescles<G>(middleware: &G)
    -> Option<TypeMessage>
    where G: GenerateurMessages
{
    debug!("Charger les certificats de maitre des cles pour chiffrage");
    let requete = json!({});
    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, REQUETE_CERT_MAITREDESCLES, vec![Securite::L1Public])
        .timeout_blocking(7500)
        .build();

    match middleware.transmettre_requete(routage, &requete).await {
        Ok(inner) => match inner {
            Some(reponse) => {
                if let TypeMessage::Valide(mva) = &reponse {
                    info!("emettre_commande_certificat_maitredescles Reponse certificat maitredescles : {:?}", mva.type_message);
                    Some(reponse)
                } else {
                    warn!("emettre_commande_certificat_maitredescles Reponse de mauvais type");
                    None
                }
            },
            None => {
                warn!("Aucune reponse transmettre_requete maitredescles");
                None
            }
        },
        Err(e) => {
            info!("Timeout transmettre_commande maitredescles (OK, reponse en evenement) : {}", e);
            None
        }
    }
}

// #[derive(Debug)]
// pub struct VerificateurRegles<'a> {
//     /// Regles "or", une seule regle doit etre valide
//     pub regles_disjointes: Option<Vec<Box<dyn RegleValidation + 'a>>>,
//     /// Regles "and", toutes doivent etre valides
//     pub regles_conjointes: Option<Vec<Box<dyn RegleValidation + 'a>>>
// }
//
// impl<'a> VerificateurRegles<'a> {
//
//     pub fn new() -> Self {
//         VerificateurRegles { regles_disjointes: None, regles_conjointes: None }
//     }
//
//     pub fn ajouter_conjointe<R>(&mut self, regle: R) where R: RegleValidation + 'a {
//         let regles = match &mut self.regles_conjointes {
//             Some(r) => r,
//             None => {
//                 self.regles_conjointes = Some(Vec::new());
//                 match &mut self.regles_conjointes { Some(r) => r, None => panic!("vec mut")}
//             }
//         };
//         regles.push(Box::new(regle));
//     }
//
//     pub fn ajouter_disjointe<R>(&mut self, regle: R) where R: RegleValidation + 'a {
//         let regles = match &mut self.regles_disjointes {
//             Some(r) => r,
//             None => {
//                 self.regles_disjointes = Some(Vec::new());
//                 match &mut self.regles_disjointes { Some(r) => r, None => panic!("vec mut")}
//             }
//         };
//         regles.push(Box::new(regle));
//     }
//
//     pub fn verifier(&self, certificat: &EnveloppeCertificat) -> bool {
//         // Verifier conjonction
//         if let Some(regles) = &self.regles_conjointes {
//             for r in regles {
//                 if ! r.verifier(certificat) {
//                     return false;  // Court-circuit
//                 }
//             }
//             // Toutes les regles sont true
//         }
//
//         // Verifier disjonction
//         if let Some(regles) = &self.regles_disjointes {
//             for r in regles {
//                 if r.verifier(certificat) {
//                     return true;  // Court-circuit
//                 }
//             }
//
//             // Aucunes des regles "or" n'a ete true
//             return false
//         }
//
//         // Toutes les regles "and" et "or" sont true
//         true
//     }
//
// }
//
// pub trait RegleValidation: Debug + Send + Sync {
//     /// Retourne true si la regle est valide pour ce certificat
//     fn verifier(&self, certificat: &EnveloppeCertificat) -> bool;
// }
//
// /// Regle de validation pour un IDMG tiers
// #[derive(Debug)]
// pub struct RegleValidationIdmg { pub idmg: String }
// impl RegleValidation for RegleValidationIdmg {
//     fn verifier(&self, certificat: &EnveloppeCertificat) -> bool {
//         match certificat.idmg() {
//             Ok(i) => i.as_str() == self.idmg.as_str(),
//             Err(e) => {
//                 info!("RegleValidationIdmg Erreur verification idmg : {:?}", e);
//                 false
//             }
//         }
//     }
// }

// #[cfg(test)]
// pub mod certificats_tests {
//     use std::path::PathBuf;
//     // Note this useful idiom: importing names from outer (for mod tests) scope.
//     use super::*;
//     use crate::test_setup::setup;
//
//     pub const CERT_MILLEGRILLE: &str = r#"
// -----BEGIN CERTIFICATE-----
// MIIBQzCB9qADAgECAgoHBykXJoaCCWAAMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs
// ZUdyaWxsZTAeFw0yMjAxMTMyMjQ3NDBaFw00MjAxMTMyMjQ3NDBaMBYxFDASBgNV
// BAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAnnixameVCZAzfx4dO+L63DOk/34I
// /TC4fIA1Rxn19+KjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G
// A1UdDgQWBBTTiP/MFw4DDwXqQ/J2LLYPRUkkETAfBgNVHSMEGDAWgBTTiP/MFw4D
// DwXqQ/J2LLYPRUkkETAFBgMrZXADQQBSb0vXhw3pw25qrWoMjqROjawe7/kMlu7p
// MJyb/Ppa2C6PraSVPgJGWKl+/5S5tBr58KFNg+0H94CH4d1VCPwI
// -----END CERTIFICATE-----
// "#;
//
//     pub const CERT_CORE: &str = r#"
// -----BEGIN CERTIFICATE-----
// MIICFTCCAcegAwIBAgIUDgk2RY9xKdhV9H2sbaRwuV7tSB8wBQYDK2VwMHIxLTAr
// BgNVBAMTJDI2MmVhZTMzLTI1ZTQtNDRiNy04ZmNkLTQ0NjcxMTdhMmZmZTFBMD8G
// A1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6
// WHJwMjJiQXR3R203SmYwHhcNMjIwMTE0MTkzODI2WhcNMjIwMjA0MTk0MDI2WjBk
// MUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpGdUhHNzk2ZVN2Q1RXRTRN
// NDMyaXpYcnAyMmJBdHdHbTdKZjENMAsGA1UECwwEY29yZTEQMA4GA1UEAwwHbWct
// ZGV2NTAqMAUGAytlcAMhAOZNry7yvtjalT4jAc8OpwI+ysCgtS6SaW5SIBYUnP/z
// o30wezAdBgNVHQ4EFgQUzzXqIfw8aogDTo5LZboRMLnasmAwHwYDVR0jBBgwFoAU
// MkSbvTt6igrEK2uRJ/coCRhLd6kwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBPAw
// EAYEKgMEAAQINC5zZWN1cmUwDAYEKgMEAQQEY29yZTAFBgMrZXADQQACgFhgYbZI
// a3sgHcgS6fbaxGq4oVj+1CEaI6Lx/CMH6pHKreAKMcfVl8WCRsaYCWPk45R/DY7I
// a4ik+RVCK1sK
// -----END CERTIFICATE-----
// -----BEGIN CERTIFICATE-----
// MIIBozCCAVWgAwIBAgIKBgaEZ0OASVdwADAFBgMrZXAwFjEUMBIGA1UEAxMLTWls
// bGVHcmlsbGUwHhcNMjIwMTE0MTk0MDE4WhcNMjMwNzI2MTk0MDE4WjByMS0wKwYD
// VQQDEyQyNjJlYWUzMy0yNWU0LTQ0YjctOGZjZC00NDY3MTE3YTJmZmUxQTA/BgNV
// BAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy
// cDIyYkF0d0dtN0pmMCowBQYDK2VwAyEA6UoxhuJKARsV5XeovcX91+eFFlwxU3CP
// fZ1+xCvs7GCjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G
// A1UdDgQWBBQyRJu9O3qKCsQra5En9ygJGEt3qTAfBgNVHSMEGDAWgBTTiP/MFw4D
// DwXqQ/J2LLYPRUkkETAFBgMrZXADQQC3BaK5TWjXole4f/TP9Fzsb4lsYyJJi/q+
// JCQEOXZ1kF5F+NRyI/fYmOoac59S4kna0YXn/eb3qwm8uQ5a6kMO
// -----END CERTIFICATE-----
// "#;
//
//     pub const CERT_FICHIERS: &str = r#"
// -----BEGIN CERTIFICATE-----
// MIICqTCCAlugAwIBAgIUE9zbINmwer1nFwGPiCF+MBF6avYwBQYDK2VwMHIxLTAr
// BgNVBAMTJDI2MmVhZTMzLTI1ZTQtNDRiNy04ZmNkLTQ0NjcxMTdhMmZmZTFBMD8G
// A1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6
// WHJwMjJiQXR3R203SmYwHhcNMjIwMTE0MTkzODI2WhcNMjIwMjA0MTk0MDI2WjBo
// MUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpGdUhHNzk2ZVN2Q1RXRTRN
// NDMyaXpYcnAyMmJBdHdHbTdKZjERMA8GA1UECwwIZmljaGllcnMxEDAOBgNVBAMM
// B21nLWRldjUwKjAFBgMrZXADIQC/U7Ip/+ztO3s4ZDjkw6TeGq53Qr75Qrb2Nkcs
// u56icKOCAQswggEHMB0GA1UdDgQWBBSTsPpP4VRI1AM/b5EI4di3bt4DuDAfBgNV
// HSMEGDAWgBQyRJu9O3qKCsQra5En9ygJGEt3qTAMBgNVHRMBAf8EAjAAMAsGA1Ud
// DwQEAwIE8DAiBgQqAwQABBoxLnB1YmxpYywyLnByaXZlLDMucHJvdGVnZTAXBgQq
// AwQBBA9maWNoaWVycyxiYWNrdXAwbQYDVR0RBGYwZIIIZmljaGllcnOCBmJhY2t1
// cIIkMjYyZWFlMzMtMjVlNC00NGI3LThmY2QtNDQ2NzExN2EyZmZlgglsb2NhbGhv
// c3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAGCB21nLWRldjUwBQYDK2VwA0EAMHW/
// nCFEzeTK04+CKqJDummtzg4FuMrvXm6jZPK+yy5BIVI4MUqGG9gNooQ3mVaGRcsH
// 1HNbIPtAIMhlubcXBg==
// -----END CERTIFICATE-----
// -----BEGIN CERTIFICATE-----
// MIIBozCCAVWgAwIBAgIKBgaEZ0OASVdwADAFBgMrZXAwFjEUMBIGA1UEAxMLTWls
// bGVHcmlsbGUwHhcNMjIwMTE0MTk0MDE4WhcNMjMwNzI2MTk0MDE4WjByMS0wKwYD
// VQQDEyQyNjJlYWUzMy0yNWU0LTQ0YjctOGZjZC00NDY3MTE3YTJmZmUxQTA/BgNV
// BAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy
// cDIyYkF0d0dtN0pmMCowBQYDK2VwAyEA6UoxhuJKARsV5XeovcX91+eFFlwxU3CP
// fZ1+xCvs7GCjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G
// A1UdDgQWBBQyRJu9O3qKCsQra5En9ygJGEt3qTAfBgNVHSMEGDAWgBTTiP/MFw4D
// DwXqQ/J2LLYPRUkkETAFBgMrZXADQQC3BaK5TWjXole4f/TP9Fzsb4lsYyJJi/q+
// JCQEOXZ1kF5F+NRyI/fYmOoac59S4kna0YXn/eb3qwm8uQ5a6kMO
// -----END CERTIFICATE-----
// "#;
//
//     pub fn charger_enveloppe_privee_env() -> (Arc<ValidateurX509Impl>, EnveloppePrivee) {
//         const CA_CERT_PATH: &str = "/var/opt/millegrilles/configuration/pki.millegrille.cert";
//         const DOMAINES_CERT_PATH: &str = "/var/opt/millegrilles/secrets/pki.core.cert";
//         const DOMAINES_KEY_PATH: &str = "/var/opt/millegrilles/secrets/pki.core.cle";
//         let validateur = build_store_path(PathBuf::from(CA_CERT_PATH).as_path()).expect("store");
//         let validateur = Arc::new(validateur);
//         let enveloppe_privee = charger_enveloppe_privee(
//             PathBuf::from(DOMAINES_CERT_PATH).as_path(),
//             PathBuf::from(DOMAINES_KEY_PATH).as_path(),
//             validateur.clone()
//         ).expect("privee");
//
//         (validateur, enveloppe_privee)
//     }
//
//     pub fn prep_enveloppe(pem: &str) -> EnveloppeCertificat {
//         let ca_x509 = charger_certificat(CERT_MILLEGRILLE);
//         let store = build_store(&ca_x509, false).expect("store");
//         charger_enveloppe(pem, Some(&store), None).expect("enveloppe")
//     }
//
//     #[test]
//     fn calculer_idmg() {
//         let ca_x509 = charger_certificat(CERT_MILLEGRILLE);
//         let idmg = calculer_idmg_ref(ca_x509.as_ref()).expect("idmg");
//         assert_eq!(idmg, "zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf");
//     }
//
//     #[test]
//     fn test_charger_enveloppe() {
//         let enveloppe = prep_enveloppe(CERT_CORE);
//         assert_eq!(enveloppe.fingerprint, "z2i3XjxDSREuw2h9thRXe9kAo1YJWECjDaEVEzmt44HMdBwpgzS");
//     }
//
//     #[test]
//     fn collection_pems_1cert() {
//         let certificat = prep_enveloppe(CERT_CORE);
//         let mut collection_pems = CollectionCertificatsPem::new();
//         collection_pems.ajouter_certificat(&certificat).expect("ajouter_certificat");
//
//         // println!("!!! Collection pems {:?}", collection_pems);
//         assert_eq!(collection_pems.certificats.len(), 1);
//         assert_eq!(collection_pems.pems.len(), 2);
//
//         // Test presence certificat (via fingerprint)
//         let _ = collection_pems.pems.get(&certificat.fingerprint).expect("cert");
//     }
//
//     #[test]
//     fn collection_pems_2cert() {
//         let certificat_domaines = prep_enveloppe(CERT_CORE);
//         let certificat_fichiers = prep_enveloppe(CERT_FICHIERS);
//         let mut collection_pems = CollectionCertificatsPem::new();
//         collection_pems.ajouter_certificat(&certificat_domaines).expect("ajouter");
//         collection_pems.ajouter_certificat(&certificat_fichiers).expect("ajouter");
//
//         // println!("!!! Collection pems {:?}", collection_pems);
//         assert_eq!(collection_pems.certificats.len(), 2);
//         assert_eq!(collection_pems.pems.len(), 3);
//
//         // Test presence certificat (via fingerprint)
//         let _ = collection_pems.pems.get(&certificat_domaines.fingerprint).expect("cert");
//         let _ = collection_pems.pems.get(&certificat_fichiers.fingerprint).expect("cert");
//     }
//
//     #[test]
//     fn collection_serialiser() {
//         let certificat = prep_enveloppe(CERT_CORE);
//         let mut collection_pems = CollectionCertificatsPem::new();
//         collection_pems.ajouter_certificat(&certificat).expect("ajouter");
//
//         let value = serde_json::to_value(collection_pems).expect("json");
//
//         println!("Value certificats : {:?}", value);
//     }
//
//     #[tokio::test]
//     async fn recuperer_enveloppe() {
//         setup("recuperer_enveloppe");
//         const CA_CERT_PATH: &str = "/home/mathieu/mgdev/certs/pki.millegrille";
//         const FINGERPRINT: &str = "z2i3XjxDSREuw2h9thRXe9kAo1YJWECjDaEVEzmt44HMdBwpgzS";
//         let validateur = Arc::new(build_store_path(PathBuf::from(CA_CERT_PATH).as_path()).expect("store"));
//
//         let certificat = prep_enveloppe(CERT_CORE);
//         let mut collection_pems = CollectionCertificatsPem::new();
//         collection_pems.ajouter_certificat(&certificat).expect("ajouter");
//
//         assert_eq!(FINGERPRINT, certificat.fingerprint);
//
//         let enveloppe = collection_pems.get_enveloppe(
//             validateur.as_ref(),
//             FINGERPRINT
//         ).await.expect("enveloppe");
//
//         debug!("Enveloppe chargee : {:?}", enveloppe);
//         assert_eq!(enveloppe.fingerprint, FINGERPRINT);
//     }
//
// }