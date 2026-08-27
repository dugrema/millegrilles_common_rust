use crate::generateur_messages::RoutageMessageAction;
use tracing::debug;
use millegrilles_cryptographie::chiffrage_mgs4::CipherMgs4;
use millegrilles_cryptographie::ed25519_dalek::{SecretKey, SigningKey};
use millegrilles_cryptographie::heapless;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesBuilderDefault, RoutageMessage};
use millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub fn build_reponse<M>(message: M, enveloppe_privee: &EnveloppePrivee)
                        -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
    where M: Serialize + Send + Sync
{
    let contenu = match serde_json::to_string(&message) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur serde::to_vec : {:?}", e))?
    };

    let mut cle_privee_u8 = SecretKey::default();
    match enveloppe_privee.cle_privee.raw_private_key() {
        Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
        Err(e) => Err(format!("build_reponse Erreur raw_private_key {:?}", e))?
    };
    let signing_key = SigningKey::from_bytes(&cle_privee_u8);

    let pem_vec = &enveloppe_privee.chaine_pem;

    // Allouer un Vec et serialiser le message signe.
    let mut buffer = Vec::new();
    let message_id = {
        let mut certificat: heapless::Vec<&str, 4> = heapless::Vec::new();
        certificat.extend(pem_vec.iter().map(|s| s.as_str()));

        let generateur = MessageMilleGrillesBuilderDefault::new(
            millegrilles_cryptographie::messages_structs::MessageKind::Reponse, contenu.as_str())
            .signing_key(&signing_key)
            .certificat(certificat);

        let message_ref = generateur.build_into_alloc(&mut buffer)?;
        message_ref.id.to_owned()
    };

    // Retourner le nouveau message
    Ok((MessageMilleGrillesBufferDefault::from(buffer), message_id))
}

pub fn build_reponse_chiffree<M>(message: M, enveloppe_privee: &EnveloppePrivee, certificat_demandeur: &EnveloppeCertificat)
    -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
    where M: Serialize + Send + Sync
{
    let contenu = match serde_json::to_string(&message) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur serde::to_vec : {:?}", e))?
    };

    let mut cle_privee_u8 = SecretKey::default();
    match enveloppe_privee.cle_privee.raw_private_key() {
        Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
        Err(e) => Err(format!("build_reponse Erreur raw_private_key {:?}", e))?
    };
    let signing_key = SigningKey::from_bytes(&cle_privee_u8);

    let pem_vec = &enveloppe_privee.chaine_pem;

    // Allouer un Vec et serialiser le message signe.
    let mut buffer = Vec::new();
    let message_id = {
        let mut certificat: heapless::Vec<&str, 4> = heapless::Vec::new();
        certificat.extend(pem_vec.iter().map(|s| s.as_str()));

        let generateur = MessageMilleGrillesBuilderDefault::new(
            millegrilles_cryptographie::messages_structs::MessageKind::ReponseChiffree, contenu.as_str())
            .signing_key(&signing_key)
            .cles_chiffrage(vec![certificat_demandeur])
            .certificat(certificat);

        // Chiffrer le contenu et signer le message
        let cipher = CipherMgs4::new()?;
        let message_ref = generateur.encrypt_into_alloc(&mut buffer, cipher)?;
        message_ref.id.to_owned()
    };

    // Retourner le nouveau message
    Ok((MessageMilleGrillesBufferDefault::from(buffer), message_id))
}

pub fn build_message_action<R,M>(type_message: millegrilles_cryptographie::messages_structs::MessageKind,
                                 routage: R, message: M, enveloppe_privee: &EnveloppePrivee)
                                 -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
    where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync
{
    let routage = routage.into();
    let contenu = match serde_json::to_string(&message) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur serde::to_vec : {:?}", e))?
    };

    let cert_ca = match &routage.ajouter_ca {
        true => {
            let ca = enveloppe_privee.enveloppe_ca.as_ref();
            let chaine_pem = ca.chaine_pem()?;
            match chaine_pem.get(0) {
                Some(inner) => Some(inner.to_string()),
                None => None
            }
        },
        false => None
    };

    let routage_message: RoutageMessage = (&routage).into();

    let mut cle_privee_u8 = SecretKey::default();
    match enveloppe_privee.cle_privee.raw_private_key() {
        Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
        Err(e) => Err(format!("build_message_action Erreur raw_private_key {:?}", e))?
    };
    let signing_key = SigningKey::from_bytes(&cle_privee_u8);

    let pem_vec = &enveloppe_privee.chaine_pem;

    let mut buffer = Vec::new();
    let message_id = {
        let mut certificat: heapless::Vec<&str, 4> = heapless::Vec::new();
        certificat.extend(pem_vec.iter().map(|s| s.as_str()));

        let mut generateur = MessageMilleGrillesBuilderDefault::new(
            type_message, contenu.as_str())
            .routage(routage_message)
            .signing_key(&signing_key)
            .certificat(certificat);
        if let Some(ca) = cert_ca.as_ref() {
            generateur = generateur.millegrille(ca.as_str());
        }

        // Allouer un Vec et serialiser le message signe.
        let message_ref = generateur.build_into_alloc(&mut buffer)?;
        message_ref.id.to_owned()
    };

    // Retourner le nouveau message
    Ok((MessageMilleGrillesBufferDefault::from(buffer), message_id))
}

pub fn build_message_action_chiffre<R,M>(
    type_message: millegrilles_cryptographie::messages_structs::MessageKind, routage: R, message: M,
    enveloppe_privee: &EnveloppePrivee, cles_chiffrage: Vec<&EnveloppeCertificat>
)
    -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
    where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync
{
    let routage = routage.into();
    let contenu = match serde_json::to_string(&message) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur serde::to_vec : {:?}", e))?
    };

    let routage_message: RoutageMessage = (&routage).into();

    let enveloppe_ca = enveloppe_privee.enveloppe_ca.as_ref();
    let idmg = enveloppe_ca.idmg()?;
    let cipher = CipherMgs4::with_ca(enveloppe_ca).unwrap();

    let mut cle_privee_u8 = SecretKey::default();
    match enveloppe_privee.cle_privee.raw_private_key() {
        Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
        Err(e) => Err(format!("build_message_action Erreur raw_private_key {:?}", e))?
    };
    let signing_key = SigningKey::from_bytes(&cle_privee_u8);

    let pem_vec = &enveloppe_privee.chaine_pem;

    let mut buffer = Vec::new();
    let message_id = {
        let mut certificat: heapless::Vec<&str, 4> = heapless::Vec::new();
        certificat.extend(pem_vec.iter().map(|s| s.as_str()));

        let generateur = MessageMilleGrillesBuilderDefault::new(
            type_message, contenu.as_str())
            .routage(routage_message)
            .signing_key(&signing_key)
            .certificat(certificat)
            .origine(idmg.as_str())
            .cles_chiffrage(cles_chiffrage);

        // Allouer un Vec et serialiser le message signe.
        // let message_ref = generateur.build_into_alloc(&mut buffer)?;
        let message_ref = generateur.encrypt_into_alloc(&mut buffer, cipher).unwrap();
        message_ref.id.to_owned()
    };

    // Retourner le nouveau message
    Ok((MessageMilleGrillesBufferDefault::from(buffer), message_id))
}

#[derive(Serialize)]
struct ReponseMessage<'a> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<&'a str>,
}

pub trait FormatteurMessage {
    /// Retourne l'enveloppe privee utilisee pour signer le message
    fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee>;

    /// Permet de modifier l'enveloppe utilisee pour la signature de messages
    fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>);

    fn build_message_action<R, M>(&self, type_message: millegrilles_cryptographie::messages_structs::MessageKind, routage: R, message: M)
                                  -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
        where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
        let enveloppe_privee = self.get_enveloppe_signature();
        build_message_action(type_message, routage, message, enveloppe_privee.as_ref())
    }

    fn build_message_action_chiffre<R, M, E>(
        &self, type_message: millegrilles_cryptographie::messages_structs::MessageKind,
        routage: R, message: M, cles_chiffrage: Vec<E>
    )
        -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
        where
            R: Into<RoutageMessageAction>, M: Serialize + Send + Sync,
            E: AsRef<EnveloppeCertificat>
    {
        let cles_chiffrage_ref = cles_chiffrage.iter().map(|v| v.as_ref()).collect();
        let enveloppe_privee = self.get_enveloppe_signature();
        build_message_action_chiffre(type_message, routage, message, enveloppe_privee.as_ref(), cles_chiffrage_ref)
    }

    fn build_reponse<M>(&self, message: M)
                        -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
        where M: Serialize + Send + Sync {
        let enveloppe_privee = self.get_enveloppe_signature();
        build_reponse(message, enveloppe_privee.as_ref())
    }

    fn build_reponse_chiffree<M>(&self, message: M, certificat_demandeur: &EnveloppeCertificat)
    -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
        where M: Serialize + Send + Sync
    {
        let enveloppe_privee = self.get_enveloppe_signature();
        build_reponse_chiffree(message, enveloppe_privee.as_ref(), certificat_demandeur)
    }

    // fn formatter_inter_millegrille<M,S>(
    //     &self,
    //     middleware: &M,
    //     contenu: S,
    //     certificat_demandeur: &EnveloppeCertificat
    // ) -> Result<MessageMilleGrille, crate::error::Error>
    // where
    //     M: ChiffrageFactoryTrait + FormatteurMessage,
    //     S: Serialize,
    // {
    //     let enveloppe = self.get_enveloppe_signature();
    //     let reponse_chiffree = MessageInterMillegrille::new(
    //         middleware, contenu, Some(vec![certificat_demandeur]))?;
    //     MessageMilleGrille::new_signer(
    //         enveloppe.as_ref(), MessageKind::ReponseChiffree, &reponse_chiffree,
    //         None::<&str>, None::<&str>, None::<&str>, None::<&str>, None::<i32>, false)
    // }

    fn reponse_ok<O>(&self, code: O, message: Option<&str>)
        -> Result<MessageMilleGrillesBufferDefault, crate::error::Error>
        where O: Into<Option<i64>>
    {
        let code = code.into();
        let message = match message { Some(inner) => { Some(inner.into()) }, None => None };
        let reponse = ReponseMessage { ok: true, code, message, err: None };
        match self.build_reponse(reponse) {
            Ok(m) => Ok(m.0),
            Err(e) => Err(format!("Erreur preparation reponse_ok : {:?}", e))?
        }
    }

    fn reponse_err<O>(&self, code: O, message: Option<&str>, err: Option<&str>)
        -> Result<MessageMilleGrillesBufferDefault, crate::error::Error>
        where O: Into<Option<i64>>
    {
        let code = code.into();
        let message = match message { Some(inner) => { Some(inner.into()) }, None => None };
        let err = match err { Some(inner) => { Some(inner.into()) }, None => None };

        let reponse = ReponseMessage { ok: false, code, message, err };

        match self.build_reponse(reponse) {
            Ok(m) => Ok(m.0),
            Err(e) => Err(format!("Erreur preparation reponse_ok : {:?}", e))?
        }
    }

}

pub fn preparer_btree_recursif(contenu: Map<String, Value>) -> Result<Map<String, Value>, crate::error::Error> {
    let iter: serde_json::map::IntoIter = contenu.into_iter();
    preparer_btree_recursif_into_iter(iter)
}

/// Preparer recursivement le contenu en triant les cles.
fn preparer_btree_recursif_into_iter(mut iter: serde_json::map::IntoIter) -> Result<Map<String, Value>, crate::error::Error> {
    let mut ordered: BTreeMap<String, Value> = BTreeMap::new();

    // Copier dans une BTreeMap (via trier les keys)
    // let mut iter: serde_json::map::IntoIter = contenu.into_iter();
    while let Some((k, v)) = iter.next() {
        let value = map_valeur_recursif(v)?;
        ordered.insert(k, value);
    }

    // Reconvertir en Map<String, Value> (flag preserve_order est actif)
    let mut map_ordered = Map::new();
    let mut iter_ordered = ordered.into_iter();
    while let Some((k, v)) = iter_ordered.next() {
        map_ordered.insert(k, v);
    }

    Ok(map_ordered)
}

pub fn map_valeur_recursif(v: Value) -> Result<Value, crate::error::Error> {
    let res = match v {
        Value::Object(o) => {
            let map = preparer_btree_recursif(o)?;
            Value::Object(map)
        },
        Value::Array(o) => {
            // Parcourir array recursivement
            let mut arr = o.into_iter();
            let mut vec_values = Vec::new();

            while let Some(v) = arr.next() {
                vec_values.push(map_valeur_recursif(v)?)
            }

            // Retourner le nouvel array
            Value::Array(vec_values)
        },
        Value::Bool(o) => Value::Bool(o),
        Value::Number(o) => {
            // Return entiers immediatement
            if o.is_i64() || o.is_u64() { Value::Number(o) }
            else {
                debug!("Number pas int/uint : {:?}", o);
                // Correctif pour 0.0
                match o.is_f64() {
                    true => {
                        // Traiter un float, on converti en i64 si le nombre fini en .0
                        match o.as_f64() {
                            Some(float_num) => {
                                let int_num = float_num.floor() as i64;
                                match int_num as f64 == float_num {
                                    true => {
                                        // Float fini par .0, on transforme en i64
                                        Value::from(int_num)
                                    },
                                    // partie fractionnaire presente. Note : parfois f32 match javascript
                                    false => Value::Number(o),
                                }
                            },
                            None => Value::Number(o)
                        }
                    },
                    false => Value::Number(o)
                }
            }
        },
        Value::String(o) => Value::String(o),
        Value::Null => Value::Null,
    };

    Ok(res)
}

pub fn ordered_map<S>(value: &HashMap<String, String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}
