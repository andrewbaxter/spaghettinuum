use clap::Parser;
use itertools::Itertools;
use loga::{
    ea,
    Log,
    ResultContext,
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
use std::{
    fs,
    path::PathBuf,
};

#[derive(Parser)]
struct Args {
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub debug: bool,
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = Args::parse();
        let log = &Log::new(if args.debug {
            loga::Level::Debug
        } else {
            loga::Level::Info
        });
        let config = if let Some(p) = args.config {
            let log = log.fork(ea!(path = p.to_string_lossy()));
            serde_json::from_slice::<Config>(
                &fs::read(p).log_context(&log, "Reading config", ea!())?,
            ).log_context(&log, "Parsing config", ea!())?
        } else if let Some(c) = match std::env::var(spaghettinuum::data::standard::ENV_CONFIG) {
            Ok(c) => Some(c),
            Err(e) => match e {
                std::env::VarError::NotPresent => None,
                std::env::VarError::NotUnicode(_) => {
                    return Err(
                        loga::Error::new(
                            "Error parsing env var as unicode",
                            ea!(env = spaghettinuum::data::standard::ENV_CONFIG),
                        ),
                    )
                },
            },
        } {
            let log = log.fork(ea!(source = "env"));
            serde_json::from_str::<Config>(&c).log_context(&log, "Parsing config", ea!())?
        } else {
            return Err(
                log.new_err(
                    "No config passed on command line, and no config set in env var",
                    ea!(env = spaghettinuum::data::standard::ENV_CONFIG),
                ),
            );
        };
        let tm = taskmanager::TaskManager::new();
        let node =
            Node::new(log, tm.clone(), config.node.bind_addr, &config.node.bootstrap.into_iter().map(|e| NodeInfo {
                id: e.id,
                address: SerialAddr(e.addr),
            }).collect_vec(), config.node.persist_path).await?;
        if let Some(publisher) = config.publisher {
            publisher::start(&tm, log, publisher, node.clone()).await?;
        }
        if let Some(resolver) = config.resolver {
            resolver::start(&tm, log, resolver, node.clone()).await?;
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
