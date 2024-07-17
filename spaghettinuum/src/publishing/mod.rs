use {
    crate::{
        interface::wire,
        utils::{
            identity_secret::IdentitySigner,
            publish_util,
        },
    },
    async_trait::async_trait,
    http::Uri,
    loga::Log,
    std::sync::{
        Arc,
        Mutex,
    },
};

#[async_trait]
pub trait Publisher: Send + Sync {
    async fn publish(
        &self,
        log: &Log,
        identity_signer: Arc<Mutex<dyn IdentitySigner>>,
        content: wire::api::publish::latest::PublishRequestContent,
    ) -> Result<(), loga::Error>;
}

pub struct RemotePublisher {
    pub urls: Vec<Uri>,
}

#[async_trait]
impl Publisher for RemotePublisher {
    async fn publish(
        &self,
        log: &Log,
        identity_signer: Arc<Mutex<dyn IdentitySigner>>,
        content: wire::api::publish::latest::PublishRequestContent,
    ) -> Result<(), loga::Error> {
        publish_util::publish(log, &self.urls, identity_signer, content).await?;
        return Ok(());
    }
}
