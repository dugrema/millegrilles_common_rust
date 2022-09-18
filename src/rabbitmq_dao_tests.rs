#[cfg(test)]
mod rabbitmq_dao_tests {
    use log::debug;
    use crate::configuration::charger_configuration;
    use crate::test_setup::setup;
    use crate::rabbitmq_dao::*;

    use super::*;

    #[tokio::test]
    async fn connecter_mq() {
        setup("connecter");
        debug!("Connecter");

        let config = charger_configuration().expect("config");
        let connexion = connecter(&config).await.expect("connexion");

        // debug!("Sleep 5 secondes");
        // tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;

        let status = connexion.status();
        debug!("Connexion status : {:?}", status);
        assert_eq!(status.connected(), true);
    }

}