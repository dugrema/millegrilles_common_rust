#[macro_export(local_inner_macros)]
macro_rules! get_domaine_action {
    ($type_message:expr) => {
        {
            {
                match &$type_message {
                    TypeMessageOut::Requete(r) |
                    TypeMessageOut::Commande(r) |
                    TypeMessageOut::Transaction(r) |
                    TypeMessageOut::Evenement(r) => {
                        (r.domaine.clone(), r.action.clone())
                    },
                    _ => {
                        Err(Error::Str("Type de message non supporte"))?
                    }
                }
            }
        }
    }
}

// let (correlation_id, reply_q) = match &message.type_message {
//             TypeMessageOut::Requete(r) |
//             TypeMessageOut::Commande(r) |
//             TypeMessageOut::Transaction(r) => {
//                 let correlation_id = match &r.correlation_id {
//                     Some(inner) => Some(inner.clone()),
//                     None => None,
//                 };
//                 let reply_q = match &r.reply_to {
//                     Some(inner) => Some(inner.clone()),
//                     None => None,
//                 };
//                 (correlation_id, reply_q)
//             }
//             TypeMessageOut::Reponse(_) |
//             TypeMessageOut::Evenement(_) => (None, None)
//         };
#[macro_export(local_inner_macros)]
macro_rules! get_replyq_correlation {
    ($type_message:expr) => {
        {
            {
                match &$type_message {
                    TypeMessageOut::Requete(r) |
                    TypeMessageOut::Commande(r) => {
                        let correlation_id = match &r.correlation_id {
                            Some(inner) => inner.clone(),
                            None => Err("get_replyq_correlation No correlation id")?,
                        };
                        let reply_q = match &r.reply_to {
                            Some(inner) => inner.clone(),
                            None => Err("get_replyq_correlation No reply queue")?,
                        };
                        (reply_q, correlation_id)
                    },
                    _ => {
                        Err(Error::Str("Type de message non supporte"))?
                    }
                }
            }
        }
    }
}