use {
    htwrap::htreq,
    loga::Log,
    spaghettinuum::{
        publishing::system_publisher_url_pairs,
        resolving::{
            connect_publisher_node,
            connect_resolver_node,
            system_resolver_url_pairs,
        },
    },
    std::collections::HashMap,
};

pub mod spaghlib;

mod args {
    use {
        aargvark::Aargvark,
    };

    #[derive(Aargvark)]
    pub struct Ping {
        /// Ping publishers instead of resolver
        pub publisher: Option<()>,
    }

    #[derive(Aargvark)]
    #[vark(break_help)]
    pub enum Command {
        /// Simple liveness check
        Ping(Ping),
        /// Request values associated with provided identity and keys from a resolver
        Get(crate::spaghlib::cli_resolve::args::Query),
        Http(crate::spaghlib::cli_http::args::Http),
        Ssh(crate::spaghlib::cli_ssh::args::Ssh),
        /// Commands for managing identities
        Identity(crate::spaghlib::cli_identity::args::Identity),
        /// Commands for publishing data
        Publish(crate::spaghlib::cli_publish::args::Publish),
        /// Commands for node administration
        Admin(crate::spaghlib::cli_admin::args::Admin),
    }

    #[derive(Aargvark)]
    pub struct Args {
        pub debug: Option<()>,
        pub command: Command,
    }
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = aargvark::vark::<args::Args>();
        let log = Log::new_root(match args.debug {
            Some(_) => loga::DEBUG,
            None => loga::INFO,
        });
        let log = &log;
        match args.command {
            args::Command::Ping(args) => {
                let resolvers = system_resolver_url_pairs(log)?;
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
            args::Command::Get(args) => {
                spaghlib::cli_resolve::run_get(log, args).await?;
            },
            args::Command::Http(args) => {
                spaghlib::cli_http::run(log, args).await?;
            },
            args::Command::Ssh(args) => {
                spaghlib::cli_ssh::run(log, args).await?;
            },
            args::Command::Publish(args) => {
                spaghlib::cli_publish::run(log, args).await?;
            },
            args::Command::Identity(args) => {
                spaghlib::cli_identity::run(log, args).await?;
            },
            args::Command::Admin(args) => {
                spaghlib::cli_admin::run(log, args).await?;
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
