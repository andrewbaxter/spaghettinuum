//! The server executable.  This takes a json config with the schema:
#![doc= "```"]
#![doc= include_str !("../../server_config.schema.json")]
#![doc= "```"]

use aargvark::{
    Aargvark,
    AargvarkJson,
};
use itertools::Itertools;
use loga::{
    ea,
    ResultContext,
};
use poem::{
    Route,
    Server,
    listener::TcpListener,
};
use spaghettinuum::{
    config::Config,
    data::node::protocol::{
        NodeInfo,
        SerialAddr,
    },
    node::Node,
    publisher,
    resolver,
};

#[derive(Aargvark)]
struct Args {
    pub config: Option<AargvarkJson<Config>>,
    pub debug: Option<()>,
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = aargvark::vark::<Args>();
        let log = &loga::new(if args.debug.is_some() {
            loga::Level::Debug
        } else {
            loga::Level::Info
        });
        let config = if let Some(p) = args.config {
            p.value
        } else if let Some(c) = match std::env::var(spaghettinuum::data::standard::ENV_CONFIG) {
            Ok(c) => Some(c),
            Err(e) => match e {
                std::env::VarError::NotPresent => None,
                std::env::VarError::NotUnicode(_) => {
                    return Err(
                        loga::err_with(
                            "Error parsing env var as unicode",
                            ea!(env = spaghettinuum::data::standard::ENV_CONFIG),
                        ),
                    )
                },
            },
        } {
            let log = log.fork(ea!(source = "env"));
            serde_json::from_str::<Config>(&c).log_context(&log, "Parsing config")?
        } else {
            return Err(
                log.new_err_with(
                    "No config passed on command line, and no config set in env var",
                    ea!(env = spaghettinuum::data::standard::ENV_CONFIG),
                ),
            );
        };
        let tm = taskmanager::TaskManager::new();
        let node =
            Node::new(log, tm.clone(), config.node.bind_addr, &config.node.bootstrap.into_iter().map(|e| NodeInfo {
                id: e.id,
                address: SerialAddr(e.addr.1),
            }).collect_vec(), config.node.persist_path).await?;
        let mut public_endpoints = Route::new();
        let mut private_endpoints = Route::new();
        let mut has_public_endpoints = false;
        let mut has_private_endpoints = false;
        if let Some(publisher) = config.publisher {
            let endpoints = publisher::start(&tm, log, publisher, node.clone()).await?;
            const PREFIX: &'static str = "/publish";
            if let Some(endpoints) = endpoints.public {
                public_endpoints = public_endpoints.nest(PREFIX, endpoints);
                has_public_endpoints = true;
            }
            if let Some(endpoints) = endpoints.private {
                private_endpoints = private_endpoints.nest(PREFIX, endpoints);
                has_private_endpoints = true;
            }
        }
        if let Some(resolver) = config.resolver {
            let endpoints = resolver::start(&tm, log, resolver, node.clone()).await?;
            const PREFIX: &'static str = "/resolve";
            if let Some(endpoints) = endpoints.public {
                public_endpoints = public_endpoints.nest(PREFIX, endpoints);
                has_public_endpoints = true;
            }
            if let Some(endpoints) = endpoints.private {
                private_endpoints = private_endpoints.nest(PREFIX, endpoints);
                has_private_endpoints = true;
            }
        }
        if has_public_endpoints {
            let bind_addr =
                config
                    .public_http_addr
                    .log_context(
                        log,
                        "Configuration defines public http endpoints, but no public http bind address present in config",
                    )?;
            tm.critical_task({
                let log = log.fork(ea!(subsys = "public_http"));
                let tm1 = tm.clone();
                async move {
                    match tm1.if_alive(Server::new(TcpListener::bind(&bind_addr.1)).run(public_endpoints)).await {
                        Some(r) => {
                            return r.log_context_with(&log, "Exited with error", ea!(addr = bind_addr));
                        },
                        None => {
                            return Ok(());
                        },
                    }
                }
            });
        }
        if has_private_endpoints {
            let bind_addr =
                config
                    .private_http_addr
                    .log_context(
                        log,
                        "Configuration defines private http endpoints, but no private http bind address present in config",
                    )?;
            tm.critical_task({
                let log = log.fork(ea!(subsys = "private_http"));
                let tm1 = tm.clone();
                async move {
                    match tm1
                        .if_alive(Server::new(TcpListener::bind(&bind_addr.1)).run(private_endpoints))
                        .await {
                        Some(r) => {
                            return r.log_context_with(&log, "Exited with error", ea!(addr = bind_addr));
                        },
                        None => {
                            return Ok(());
                        },
                    }
                }
            });
        }
        tm.join().await?;
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
