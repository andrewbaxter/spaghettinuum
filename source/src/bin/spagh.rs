use {
    aargvark::Aargvark,
    htwrap::htreq,
    loga::Log,
    spaghettinuum::{
        publishing::system_publisher_url_pairs,
        resolving::{
            connect_publisher_node,
            connect_resolver_node,
            default_resolver_url_pairs,
        },
    },
    std::collections::HashMap,
};

pub mod spaghlib;

#[derive(Aargvark)]
pub struct PingArgs {
    /// Ping publishers instead of resolver
    pub publisher: Option<()>,
}

#[derive(Aargvark)]
#[vark(break_help)]
pub enum Command {
    /// Simple liveness check
    Ping(PingArgs),
    /// Request values associated with provided identity and keys from a resolver
    Get(crate::spaghlib::cli_resolve::Args),
    Http(crate::spaghlib::cli_http::Args),
    Ssh(crate::spaghlib::cli_ssh::Args),
    /// Commands for managing identities
    Identity(crate::spaghlib::cli_identity::Args),
    /// Commands for publishing data
    Publish(crate::spaghlib::cli_publish::Args),
    /// Commands for node administration
    Admin(crate::spaghlib::cli_admin::Args),
    /// Run a spaghettinuum instance
    Demon(crate::spaghlib::demon::Args),
}

/// A small CLI for querying, publishing, and administrating spaghettinuum.
#[derive(Aargvark)]
pub struct Args {
    pub debug: Option<()>,
    pub command: Command,
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = aargvark::vark::<Args>();
        let log = Log::new_root(match args.debug {
            Some(_) => loga::DEBUG,
            None => loga::INFO,
        });
        let log = &log;
        match args.command {
            Command::Ping(args) => {
                let resolvers = default_resolver_url_pairs(log)?;
                if args.publisher.is_none() {
                    for pair in resolvers {
                        let pair = pair.join("health");
                        htreq::get(
                            log,
                            &mut connect_resolver_node(&pair).await?,
                            &pair.url,
                            &HashMap::new(),
                            100,
                        ).await?;
                    }
                } else {
                    for pair in system_publisher_url_pairs(log)? {
                        let pair = pair.join("health");
                        htreq::get(
                            log,
                            &mut connect_publisher_node(log, &resolvers, &pair).await?,
                            &pair.url,
                            &HashMap::new(),
                            100,
                        ).await?;
                    }
                }
            },
            Command::Get(args) => {
                spaghlib::cli_resolve::run_get(log, args).await?;
            },
            Command::Http(args) => {
                spaghlib::cli_http::run(log, args).await?;
            },
            Command::Ssh(args) => {
                spaghlib::cli_ssh::run(log, args).await?;
            },
            Command::Publish(args) => {
                spaghlib::cli_publish::run(log, args).await?;
            },
            Command::Identity(args) => {
                spaghlib::cli_identity::run(log, args).await?;
            },
            Command::Admin(args) => {
                spaghlib::cli_admin::run(log, args).await?;
            },
            Command::Demon(args) => {
                spaghlib::demon::run(log, args).await?;
            },
        }
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
