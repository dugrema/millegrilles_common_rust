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
