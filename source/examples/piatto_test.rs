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
use loga::Log;
use spaghettinuum::{
    interface::{
        config::{
            identity::LocalIdentitySecret,
            shared::StrSocketAddr,
        },
        stored::{
            self,
            announcement::latest::{
                AnnouncementContent,
                AnnouncementPublisher,
            },
            shared::SerialAddr,
        },
        wire::node::latest::NodeInfo,
    },
    service::node::Node,
    utils::{
        blob::Blob,
        signed::IdentSignatureMethods,
    },
};
use tokio::{
    fs::create_dir_all,
    select,
};

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let root = current_dir().unwrap().join("piatto_test");
        create_dir_all(&root).await.unwrap();
        let tm = taskmanager::TaskManager::new();
        let mut nodes = vec![];
        let mut prev_node = None;
        for i in 0 .. 1000 {
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 1, 1).saturating_add(i), 43890));
            let path = root.join(format!("node_{}", i));
            create_dir_all(&path).await.unwrap();
            let node =
                Node::new(
                    &Log::new(),
                    &tm,
                    StrSocketAddr::from(addr.clone()),
                    &prev_node.take().map(|(addr, id)| NodeInfo {
                        address: addr,
                        ident: id,
                    }).into_iter().collect_vec(),
                    &path,
                ).await?;
            nodes.push(node.clone());
            prev_node = Some((SerialAddr(addr), node.node_identity()));
        }

        select!{
            _ = tm.until_terminate() => {
                return Ok(());
            },
            _ = tokio:: time:: sleep(Duration::seconds(60).to_std().unwrap()) => {
            }
        }

        let (ident, mut ident_secret) = LocalIdentitySecret::new();
        let message_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(169, 168, 167, 165), 1111));
        let (_, message_signature) =
            stored::announcement::latest::Announcement::sign(&mut ident_secret, AnnouncementContent {
                publishers: vec![AnnouncementPublisher {
                    addr: SerialAddr(message_addr),
                    cert_hash: Blob::new(0),
                }],
                announced: Utc::now(),
            }).unwrap();

        select!{
            _ = tm.until_terminate() => {
                return Ok(());
            },
            _ = nodes.get(
                0
            ).unwrap().put(ident.clone(), stored::announcement::Announcement::V1(message_signature)) =>(),
        };

        let mut i = 0;
        let found = loop {
            let x = select!{
                _ = tm.until_terminate() => {
                    return Ok(());
                },
                r = nodes.get(1).unwrap().get(ident.clone()) => r,
            };
            match x {
                Some(x) => break x,
                None => {
                    if i > 10 {
                        panic!("value never found");
                    }

                    select!{
                        _ = tm.until_terminate() => {
                        },
                        _ = tokio:: time:: sleep(Duration::seconds(10).to_std().unwrap()) => {
                        }
                    }

                    i += 1;
                },
            }
        };
        let found_addr = match found {
            stored::announcement::Announcement::V1(a) => {
                a.parse_unwrap().publishers.get(0).unwrap().addr.0
            },
        };
        assert_eq!(found_addr, message_addr);
        tm.join(&Log::new_root(loga::INFO)).await?;
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
