//! Launch 1000 nodes and try putting a key on one node and getting a key on
//! another. Test with a faulty network like
//!
//! ```bash
//! set -xeu
//! # 3 bands have default rules for classifying packets based on tos bits
//! # 4th band is unmapped by default
//! tc qdisc add dev lo root handle 1: prio bands 4
//! # add a dest to band 4
//! tc qdisc add dev lo parent 1:4 handle 2: netem delay 100ms 100ms distribution normal loss 4% 25%
//! #tc qdisc add dev lo parent 1:4 handle 2: netem delay 100ms 20ms distribution normal loss 0.3% 25%
//! # add a filter on prio to jump packets directly to 4th band
//! tc filter add dev lo parent 1: protocol ip prio 1 basic match "cmp(u8 at 16 layer network eq 127) and cmp(u8 at 18 layer network gt 0)" flowid 1:4
//! ```
//!
//! Clean it up with
//!
//! ```bash
//! qdisc del dev lo root
//! ```
use std::{
    net::{
        SocketAddr,
        SocketAddrV4,
        Ipv4Addr,
    },
    env::current_dir,
};
use chrono::{
    Utc,
    Duration,
};
use ipnet::IpAdd;
use itertools::Itertools;
use spaghettinuum::{
    node::{
        ValueArgs,
        Node,
    },
    interface::{
        spagh_cli::{
            PORT_NODE,
            StrSocketAddr,
            BackedIdentityLocal,
        },
        node_protocol::latest::{
            NodeInfo,
            SerialAddr,
            ValueBody,
        },
    },
};
use tokio::fs::create_dir_all;

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let root = current_dir().unwrap().join("piatto_test");
        create_dir_all(&root).await.unwrap();
        let tm = taskmanager::TaskManager::new();
        let mut nodes = vec![];
        let mut prev_node = None;
        for i in 0 .. 1000 {
            let log = &if i == 0 {
                loga::new(loga::Level::Debug)
            } else {
                loga::new(loga::Level::Warn)
            };
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 1, 1).saturating_add(i), PORT_NODE));
            let path = root.join(format!("node_{}", i));
            create_dir_all(&path).await.unwrap();
            let node =
                Node::new(
                    log,
                    tm.clone(),
                    StrSocketAddr::from(addr.clone()),
                    &prev_node.take().map(|(addr, id)| NodeInfo {
                        address: addr,
                        id: id,
                    }).into_iter().collect_vec(),
                    &path,
                ).await?;
            nodes.push(node.clone());
            prev_node = Some((SerialAddr(addr), node.identity()));
        }
        tm.if_alive(tokio::time::sleep(Duration::seconds(60).to_std().unwrap())).await;
        let (ident, ident_secret) = BackedIdentityLocal::new();
        let message_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(169, 168, 167, 165), 1111));
        let message = ValueBody {
            addr: SerialAddr(message_addr.clone()),
            cert_hash: vec![],
            published: Utc::now(),
        }.to_bytes();
        match tm.if_alive(nodes.get(0).unwrap().put(ident.clone(), ValueArgs {
            signature: ident_secret.sign(&message),
            message: message,
        })).await {
            None => return Ok(()),
            Some(_) => { },
        };
        let mut i = 0;
        let found = loop {
            match tm.if_alive(nodes.get(1).unwrap().get(ident.clone())).await {
                None => return Ok(()),
                Some(x) => match x {
                    Some(x) => break x,
                    None => {
                        if i > 10 {
                            panic!("value never found");
                        }
                        tm.if_alive(tokio::time::sleep(Duration::seconds(10).to_std().unwrap())).await;
                        i += 1;
                    },
                },
            };
        };
        assert_eq!(found.addr.0, message_addr);
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
