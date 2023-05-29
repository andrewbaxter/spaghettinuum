use std::net::{
    SocketAddr,
    SocketAddrV4,
    Ipv4Addr,
};
use chrono::{
    DateTime,
    Utc,
    Duration,
};
use ipnet::IpAdd;
use itertools::Itertools;
use loga::Log;
use spaghettinuum::{
    standard::PORT_NODE,
    node::{
        Node,
        model::protocol::{
            NodeInfo,
            SerialAddr,
            Value,
            ValueBody,
        },
    },
    model::identity::{
        Identity,
        IdentitySecretVersionMethods,
    },
};

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let tm = taskmanager::TaskManager::new();
        let mut nodes = vec![];
        let mut prev_node = None;
        for i in 0 .. 1000 {
            let log = &if i == 0 {
                Log::new(loga::Level::Debug)
            } else {
                Log::new(loga::Level::Warn)
            };
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 1, 1).saturating_add(i), PORT_NODE));
            let node = Node::new(log, tm.clone(), addr.clone(), &prev_node.take().map(|(addr, id)| NodeInfo {
                address: addr,
                id: id,
            }).into_iter().collect_vec(), None).await?;
            nodes.push(node.clone());
            prev_node = Some((SerialAddr(addr), node.identity()));
        }
        tm.if_alive(tokio::time::sleep(Duration::seconds(60).to_std().unwrap())).await;
        let (ident, ident_secret) = Identity::new();
        let message_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(169, 168, 167, 165), 1111));
        let message = ValueBody {
            addr: SerialAddr(message_addr.clone()),
            cert_hash: vec![],
            expires: <DateTime<Utc>>::MAX_UTC,
        }.to_bytes();
        match tm.if_alive(nodes.get(0).unwrap().put(ident.clone(), Value {
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
