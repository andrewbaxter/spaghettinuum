use {
    crate::{
        bb,
        interface::{
            config::ENV_PUBLISHER_URLS,
            wire,
        },
        resolving::{
            system_resolver_url_pairs,
            UrlPair,
        },
        utils::{
            identity_secret::IdentitySigner,
            publish_util,
        },
    },
    async_trait::async_trait,
    http::Uri,
    loga::{
        ea,
        Log,
        ResultContext,
    },
    std::{
        env,
        os::unix::ffi::OsStringExt,
        str::FromStr,
        sync::{
            Arc,
            Mutex,
        },
    },
};

pub fn system_publisher_url_pairs(log: &Log) -> Result<Vec<UrlPair>, loga::Error> {
    bb!{
        let Some(raw_publishers) = env:: var_os(ENV_PUBLISHER_URLS) else {
            break;
        };
        let raw_publishers =
            String::from_utf8(
                raw_publishers.into_vec(),
            ).map_err(
                |x| loga::err_with(
                    "Publishers env var isn't valid utf-8",
                    ea!(
                        err = x.utf8_error(),
                        env = ENV_PUBLISHER_URLS,
                        value = String::from_utf8_lossy(x.as_bytes())
                    ),
                ),
            )?;
        let mut publishers = vec![];
        for p in raw_publishers.split(",") {
            publishers.push(UrlPair {
                address: None,
                url: Uri::from_str(p).context_with("Couldn't parse publisher url", ea!(url = p))?,
            });
        }
        if publishers.is_empty() {
            return Err(loga::err_with("Publisher env set but empty", ea!(env = ENV_PUBLISHER_URLS)));
        }
        return Ok(publishers);
    };

    return Ok(system_resolver_url_pairs(log)?);
}

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
    pub resolver_urls: Vec<UrlPair>,
    pub publisher_urls: Vec<UrlPair>,
}

#[async_trait]
impl Publisher for RemotePublisher {
    async fn publish(
        &self,
        log: &Log,
        identity_signer: Arc<Mutex<dyn IdentitySigner>>,
        content: wire::api::publish::latest::PublishRequestContent,
    ) -> Result<(), loga::Error> {
        publish_util::publish(log, &self.resolver_urls, &self.publisher_urls, identity_signer, content).await?;
        return Ok(());
    }
}
