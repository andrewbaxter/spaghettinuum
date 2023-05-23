use std::{
    path::PathBuf,
    fs,
};
use clap::Parser;
use itertools::Itertools;
use loga::{
    Log,
    ea,
    ResultContext,
};
use spaghettinuum::{
    node::{
        Node,
        model::{
            protocol::{
                NodeInfo,
                Addr,
            },
        },
    },
    publisher,
    resolver,
    model::config::Config,
};

#[derive(Parser)]
struct Args {
    pub config: PathBuf,
}

#[tokio::main]
async fn main() {
    let log = Log::new(loga::Level::Info);

    async fn inner(log: &Log) -> Result<(), loga::Error> {
        let args = Args::parse();
        let config = {
            let log = log.fork(ea!(path = args.config.to_string_lossy()));
            serde_json::from_slice::<Config>(
                &fs::read(args.config).log_context(&log, "Reading config", ea!())?,
            ).log_context(&log, "Parsing config", ea!())?
        };
        let tm = taskmanager::TaskManager::new();
        let node =
            Node::new(log, tm.clone(), config.node.bind_addr, &config.node.bootstrap.into_iter().map(|e| NodeInfo {
                id: e.id,
                address: Addr(e.addr),
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

    match inner(&log).await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
