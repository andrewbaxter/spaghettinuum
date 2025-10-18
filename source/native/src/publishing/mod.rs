use {
    crate::{
        interface::config::ENV_PUBLISHER_URLS,
        resolving::{
            default_resolver_url_pairs,
            UrlPair,
        },
        utils::{
            identity_secret::IdentitySigner,
            publish_util,
        },
    },
    async_trait::async_trait,
    flowcontrol::shed,
    http::Uri,
    loga::{
        ea,
        Log,
        ResultContext,
    },
    std::{
        collections::HashSet,
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
    shed!{
        let Some(raw_publishers) = env::var_os(ENV_PUBLISHER_URLS) else {
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
        let mut publishers = HashSet::new();
        for p in raw_publishers.split(",") {
            publishers.insert(UrlPair {
                address: None,
                url: Uri::from_str(p).context_with("Couldn't parse publisher url", ea!(url = p))?,
            });
        }
        if publishers.is_empty() {
            return Err(loga::err_with("Publisher env set but empty", ea!(env = ENV_PUBLISHER_URLS)));
        }
        return Ok(publishers.into_iter().collect());
    };
    return Ok(default_resolver_url_pairs(log)?);
}

#[async_trait]
pub trait Publisher: Send + Sync {
    async fn publish(
        &self,
        log: &Log,
        identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
        content: publish_util::PublishArgs,
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
        identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
        content: publish_util::PublishArgs,
    ) -> Result<(), loga::Error> {
        publish_util::remote_publish(
            log,
            &self.resolver_urls,
            &self.publisher_urls,
            identity_signer,
            content,
        ).await?;
        return Ok(());
    }
}
