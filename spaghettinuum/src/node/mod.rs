use crate::interface::stored::shared::SerialAddr;
use crate::interface::wire::node::latest::FindGoal;
use crate::interface::wire::node::v1::DhtCoord;
use crate::{
    bb,
    cap_fn,
};
use crate::interface::config::shared::StrSocketAddr;
use crate::interface::stored::identity::Identity;
use crate::interface::stored::node_identity::{
    self,
    NodeIdentityMethods,
    NodeSecretMethods,
    NodeIdentity,
};
use crate::interface::{
    stored,
    wire,
};
use crate::utils::signed::{
    IdentSignatureMethods,
    NodeIdentSignatureMethods,
};
use crate::utils::blob::{
    Blob,
};
use crate::utils::time_util::ToInstant;
use constant_time_eq::constant_time_eq;
use tokio::select;
use tokio::time::sleep;
use crate::utils::db_util::setup_db;
use chrono::{
    Utc,
    DateTime,
    Duration,
};
use futures::channel::mpsc::unbounded;
use futures::channel::mpsc::UnboundedSender;
use generic_array::ArrayLength;
use generic_array::GenericArray;
use loga::{
    ea,
    DebugDisplay,
    ErrContext,
    Log,
    ResultContext,
};
use manual_future::ManualFuture;
use manual_future::ManualFutureCompleter;
use rand::RngCore;
use taskmanager::TaskManager;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use std::collections::hash_map::Entry;
use std::collections::{
    HashMap,
    HashSet,
};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{
    AtomicUsize,
    AtomicBool,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::net::UdpSocket;

pub mod db;

// Number of bits in hash, minus the number of bits in size of bucket
// (neighborhood)
const NEIGHBORHOOD_BITS: usize = 3;
const NEIGHBORHOOD: usize = 1 << NEIGHBORHOOD_BITS;
const HASH_BITS: usize = 256;
const BUCKET_COUNT: usize = HASH_BITS - NEIGHBORHOOD_BITS + 1;
const PARALLEL: usize = 3;

fn req_timeout() -> Duration {
    return Duration::seconds(2);
}

// Republish stored values once an hour
fn store_fresh_duration() -> Duration {
    return Duration::hours(1);
}

// All stored values expire after 24h
fn store_expire_duration() -> Duration {
    return Duration::hours(24);
}

fn dist_<N: ArrayLength<u8>>(a: &GenericArray<u8, N>, b: &GenericArray<u8, N>) -> (usize, GenericArray<u8, N>) {
    let mut leading_zeros = 0usize;
    let mut first_one = false;
    let mut out: GenericArray<u8, N> = GenericArray::default();
    for i in 0 .. N::to_usize() {
        out[i] = a[i] ^ b[i];
        if !first_one {
            let byte_leading_zeros = out[i].leading_zeros();
            leading_zeros += byte_leading_zeros as usize;
            if byte_leading_zeros < 8 {
                first_one = true;
            }
        }
    }
    return (leading_zeros, out);
}

fn dist(a: &DhtCoord, b: &DhtCoord) -> (usize, DhtCoord) {
    let (leading_zeros, out) = dist_(&a.0, &b.0);
    return (leading_zeros.min(BUCKET_COUNT - 1), DhtCoord(out));
}

#[cfg(test)]
mod dist_tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    type SmallBytes = GenericArray<u8, generic_array::typenum::U2>;

    #[test]
    fn test_same() {
        let (lz, d) = dist_(SmallBytes::from_slice(&[0u8, 0u8]), SmallBytes::from_slice(&[0u8, 0u8]));
        assert_eq!(lz, 16);
        assert_eq!(d.as_slice(), &[0u8, 0u8]);
    }

    #[test]
    fn test_lsb_dist() {
        let (lz, d) = dist_(SmallBytes::from_slice(&[0u8, 1u8]), SmallBytes::from_slice(&[0u8, 0u8]));
        assert_eq!(lz, 15);
        assert_eq!(d.as_slice(), &[0u8, 1u8]);
    }

    #[test]
    fn test_msb_dist() {
        let (lz, d) = dist_(SmallBytes::from_slice(&[128u8, 0u8]), SmallBytes::from_slice(&[0u8, 0u8]));
        assert_eq!(lz, 0);
        assert_eq!(d.as_slice(), &[128u8, 0u8]);
    }

    #[test]
    fn assert_nearest_bucket_size_at_least_k() {
        // All zeros
        let self_coord = DhtCoord(GenericArray::default());

        fn coord_from_int(n: usize) -> DhtCoord {
            let mut n = n.to_le_bytes().to_vec();
            n.resize(HASH_BITS / 8, 0u8);
            n.reverse();
            return DhtCoord(GenericArray::<u8, generic_array::typenum::U32>::from_slice(&n).to_owned());
        }

        // Nearest 8 go in last bucket
        for n in 0 .. NEIGHBORHOOD {
            assert_eq!(dist(&coord_from_int(n), &self_coord).0, BUCKET_COUNT - 1);
        }

        // Next 8 go in semi-last bucket (next bit flipped, 1 prefix of same size)
        for n in NEIGHBORHOOD .. (NEIGHBORHOOD * 2) {
            assert_eq!(dist(&coord_from_int(n), &self_coord).0, BUCKET_COUNT - 2);
        }

        // Next goes in next higher bucket
        assert_eq!(dist(&coord_from_int(NEIGHBORHOOD * 2), &self_coord).0, BUCKET_COUNT - 3);
    }
}

fn node_ident_coord(x: &NodeIdentity) -> DhtCoord {
    return DhtCoord(<sha2::Sha256 as Digest>::digest(x.to_bytes()));
}

fn ident_coord(x: &Identity) -> DhtCoord {
    return DhtCoord(<sha2::Sha256 as Digest>::digest(x.to_bytes()));
}

#[derive(Debug)]
struct NextFindTimeout {
    updated: DateTime<Utc>,
    key: (FindGoal, usize),
}

#[derive(Clone)]
struct ValueState {
    value: stored::announcement::Announcement,
    received: DateTime<Utc>,
    updated: DateTime<Utc>,
}

struct NextPingTimeout {
    end: DateTime<Utc>,
    key: (node_identity::NodeIdentity, usize),
}

struct NextChallengeTimeout {
    end: DateTime<Utc>,
    key: (node_identity::NodeIdentity, usize),
}

struct Buckets {
    buckets: [Vec<wire::node::latest::NodeState>; BUCKET_COUNT],
    addrs: HashMap<SocketAddr, NodeIdentity>,
}

struct NodeInner {
    log: Log,
    own_ident: node_identity::NodeIdentity,
    own_coord: DhtCoord,
    own_secret: node_identity::NodeSecret,
    buckets: Mutex<Buckets>,
    store: Mutex<HashMap<Identity, ValueState>>,
    dirty: AtomicBool,
    socket: UdpSocket,
    next_req_id: AtomicUsize,
    find_timeouts: UnboundedSender<NextFindTimeout>,
    find_states: Mutex<HashMap<FindGoal, FindState>>,
    ping_states: Mutex<HashMap<node_identity::NodeIdentity, PingState>>,
    challenge_timeouts: UnboundedSender<NextChallengeTimeout>,
    challenge_states: Mutex<HashMap<node_identity::NodeIdentity, ChallengeState>>,
}

#[derive(Clone)]
pub struct Node(Arc<NodeInner>);

#[derive(Clone, Debug)]
struct OutstandingNodeEntry {
    dist: DhtCoord,
    bucket_i: usize,
    challenge: Blob,
    node: wire::node::latest::NodeInfo,
}

#[derive(Clone)]
enum NearestNodeEntryNode {
    Self_,
    Node(wire::node::latest::NodeInfo),
}

#[derive(Clone)]
struct NearestNodeEntry {
    dist: DhtCoord,
    node: NearestNodeEntryNode,
}

struct FindState {
    req_id: usize,
    goal: FindGoal,
    updated: DateTime<Utc>,
    nearest: Vec<NearestNodeEntry>,
    outstanding: Vec<OutstandingNodeEntry>,
    seen: HashSet<node_identity::NodeIdentity>,
    // For storing value, or retrieving value. Only used for identity searches (None
    // otherwise).
    value: Option<stored::announcement::Announcement>,
    futures: Vec<ManualFutureCompleter<FindResult>>,
}

struct FindResult {
    nearest: Vec<NearestNodeEntry>,
    value: Option<stored::announcement::Announcement>,
}

struct PingState {
    req_id: usize,
    bucket_i: usize,
}

struct ChallengeState {
    req_id: usize,
    challenge: Blob,
    node: wire::node::latest::NodeInfo,
}

fn generate_challenge() -> Blob {
    let mut out = Blob::new(32);
    rand::thread_rng().fill_bytes(out.as_mut());
    return out;
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct Persisted {
    own_secret: node_identity::NodeSecret,
    initial_buckets: Vec<Vec<wire::node::latest::NodeState>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HealthDetail {
    pub responsive_neighbors: usize,
    pub unresponsive_neighbors: usize,
    pub active_finds: usize,
    pub active_challenges: usize,
    pub active_pings: usize,
}

impl Node {
    /// Creates and starts a new node within the task manager. Waits until the socket
    /// is open. Bootstrapping is asynchronous; you should wait until a sufficient
    /// number of peers are found before doing anything automatically.
    ///
    /// * `bootstrap`: Nodes to connect to to join network. Ignored if restoring persisted
    ///   data. Ignores own id if present.
    ///
    /// * `persist_path`: Save state to this file before shutting down to make next startup
    ///   faster
    pub async fn new(
        log: Log,
        tm: TaskManager,
        bind_addr: StrSocketAddr,
        bootstrap: &[wire::node::latest::NodeInfo],
        persistent_path: &Path,
    ) -> Result<Node, loga::Error> {
        let mut do_bootstrap = false;
        let own_ident;
        let own_secret;
        let mut initial_buckets = Buckets {
            buckets: array_init::array_init(|_| vec![]),
            addrs: HashMap::new(),
        };
        let db_pool =
            setup_db(&persistent_path.join("node.sqlite3"), db::migrate)
                .await
                .stack_context(&log, "Error initializing database")?;
        let db = db_pool.get().await.stack_context(&log, "Error getting database connection")?;
        match db
            .interact(|conn| db::secret_get(&conn))
            .await
            .stack_context(&log, "Error interacting with database")?
            .stack_context(&log, "Error retrieving secret")? {
            Some(s) => {
                own_ident = s.get_identity();
                own_secret = s;
            },
            None => {
                (own_ident, own_secret) = node_identity::NodeIdentity::new();
            },
        }
        let own_coord = node_ident_coord(&own_ident);
        {
            let mut no_neighbors = true;
            for e in db
                .interact(|conn| db::neighbors_get(&conn))
                .await
                .stack_context(&log, "Error interacting with database")?
                .stack_context(&log, "Error retrieving old neighbors")? {
                let state = match e {
                    wire::node::NodeState::V1(s) => s,
                };
                let (leading_zeros, _) = dist(&node_ident_coord(&state.node.ident), &own_coord);
                match initial_buckets.addrs.entry(state.node.address.0) {
                    Entry::Occupied(v) => {
                        log.log_with(
                            loga::WARN,
                            "Duplicate neighbor address in database, skipping",
                            ea!(addr = state.node.address, ident1 = state.node.ident, ident2 = v.get()),
                        );
                        continue;
                    },
                    Entry::Vacant(v) => {
                        v.insert(state.node.ident);
                    },
                }
                log.log_with(
                    loga::DEBUG,
                    "Restoring neighbor",
                    ea!(ident = state.node.ident, addr = state.node.address),
                );
                initial_buckets.buckets[leading_zeros].push(state);
                no_neighbors = false;
            }
            if no_neighbors {
                do_bootstrap = true;
            }
        }
        log.log_with(loga::INFO, "Starting", ea!(own_node_ident = own_ident));
        let sock = {
            let log = log.fork(ea!(addr = bind_addr));
            UdpSocket::bind(bind_addr.resolve()?).await.stack_context(&log, "Failed to open node UDP port")?
        };
        let (find_timeout_write, find_timeout_recv) = unbounded::<NextFindTimeout>();
        let (ping_timeout_write, ping_timeout_recv) = unbounded::<NextPingTimeout>();
        let (challenge_timeout_write, challenge_timeout_recv) = unbounded::<NextChallengeTimeout>();
        let dir = Node(Arc::new(NodeInner {
            log: log.clone(),
            own_ident: node_identity::NodeIdentity::V1(match own_ident {
                node_identity::NodeIdentity::V1(i) => i,
            }),
            own_secret: node_identity::NodeSecret::V1(match own_secret {
                node_identity::NodeSecret::V1(s) => s,
            }),
            own_coord: own_coord,
            buckets: Mutex::new(initial_buckets),
            dirty: AtomicBool::new(do_bootstrap),
            store: Mutex::new(HashMap::new()),
            socket: sock,
            next_req_id: AtomicUsize::new(0),
            find_timeouts: find_timeout_write,
            find_states: Mutex::new(HashMap::new()),
            ping_states: Mutex::new(HashMap::new()),
            challenge_timeouts: challenge_timeout_write,
            challenge_states: Mutex::new(HashMap::new()),
        }));
        if do_bootstrap {
            log.log_with(loga::DEBUG, "No neighbors, bootstrapping", ea!(count = bootstrap.len()));
            for b in bootstrap {
                if b.ident == dir.0.own_ident {
                    continue;
                }
                if !dir.add_good_node(b.ident.clone(), Some(b.clone())) {
                    panic!("");
                }
            }
        }

        // Periodically save
        tm.periodic("Node - persist state", Duration::minutes(10).to_std().unwrap(), cap_fn!(()(log, dir, db_pool) {
            if !dir.0.dirty.swap(false, Ordering::Relaxed) {
                return;
            }
            let db_pool = db_pool.clone();
            match async {
                db_pool.get().await.context("Error getting db connection")?.interact(move |conn| {
                    db::secret_ensure(conn, &dir.0.own_secret)?;
                    db::neighbors_clear(conn)?;
                    for bucket in dir.0.buckets.lock().unwrap().buckets.clone().into_iter() {
                        for n in bucket {
                            db::neighbors_insert(conn, &wire::node::NodeState::V1(n))?;
                        }
                    }
                    return Ok(()) as Result<_, loga::Error>;
                }).await??;
                return Ok(()) as Result<_, loga::Error>;
            }.await {
                Ok(_) => { },
                Err(e) => log.log_err(loga::WARN, e.context("Failed to persist state")),
            }
        }));

        // Find timeouts
        tm.stream("Node - finish timed requests", find_timeout_recv, cap_fn!((e)(dir) {
            let deadline = e.updated + req_timeout();
            tokio::time::sleep_until(deadline.to_instant()).await;
            let state = {
                let mut borrowed_states = dir.0.find_states.lock().unwrap();
                let mut state_entry = match borrowed_states.entry(e.key.0) {
                    Entry::Occupied(s) => s,
                    Entry::Vacant(_) => return,
                };
                let state = state_entry.get_mut();
                if state.req_id != e.key.1 {
                    // for old request, out of date
                    return;
                }
                if state.updated + req_timeout() > Utc::now() {
                    // time pushed back while this timeout was in the queue
                    return;
                }
                dir.0.log.log_with(loga::DEBUG, "Find timed out", ea!(key = &e.key.0.dbg_str()));
                state_entry.remove()
            };
            for o in &state.outstanding {
                dir.mark_node_unresponsive(o.node.ident, o.bucket_i, true);
            }
            dir.complete_state(state).await;
        }));

        // Stored data expiry or maybe re-propagation
        tm.periodic("Node - re-propagate/expire stored data", Duration::hours(1).to_std().unwrap(), cap_fn!(()(dir) {
            let mut unfresh = vec![];
            let now = Utc::now();
            dir.0.store.lock().unwrap().retain(|k, v| {
                if v.received + store_expire_duration() < now {
                    return false;
                }
                if v.updated + store_fresh_duration() < now {
                    v.updated = now;
                    unfresh.push((k.clone(), v.value.clone()));
                }
                return true;
            });
            for (k, v) in unfresh {
                dir.put(k, v).await;
            }
        }));

        // Pings
        tm.periodic("Node - neighbor aliveness", Duration::minutes(10).to_std().unwrap(), cap_fn!(()(dir, ping_timeout_write) {
            for i in 0 .. NEIGHBORHOOD {
                for leading_zeros in 0 .. BUCKET_COUNT {
                    let (id, addr) =
                        if let Some(node) = dir.0.buckets.lock().unwrap().buckets[leading_zeros].get(i) {
                            (node.node.ident.clone(), node.node.address.clone())
                        } else {
                            continue;
                        };
                    let req_id = dir.0.next_req_id.fetch_add(1, Ordering::Relaxed);
                    match dir.0.ping_states.lock().unwrap().entry(id.clone()) {
                        Entry::Occupied(_) => continue,
                        Entry::Vacant(e) => e.insert(PingState {
                            req_id: req_id,
                            bucket_i: leading_zeros,
                        }),
                    };
                    dir.send(&addr.0, wire::node::Protocol::V1(wire::node::latest::Message::Ping)).await;
                    ping_timeout_write.unbounded_send(NextPingTimeout {
                        end: Utc::now() + req_timeout(),
                        key: (id, req_id),
                    }).unwrap();
                }
            }
        }));

        // Ping timeouts
        tm.stream("Node - ping timeouts", ping_timeout_recv, cap_fn!((e)(dir) {
            tokio::time::sleep_until(e.end.to_instant()).await;
            let state = {
                let mut borrowed_states = dir.0.ping_states.lock().unwrap();
                let mut state_entry = match borrowed_states.entry(e.key.0.clone()) {
                    Entry::Occupied(s) => s,
                    Entry::Vacant(_) => return,
                };
                let state = state_entry.get_mut();
                if state.req_id != e.key.1 {
                    // for old request, out of date
                    return;
                }
                state_entry.remove()
            };
            dir.mark_node_unresponsive(e.key.0, state.bucket_i, true);
        }));

        // Challenge timeouts
        tm.stream("Node - challenge timeouts", challenge_timeout_recv, cap_fn!((e)(dir) {
            tokio::time::sleep_until(e.end.to_instant()).await;
            let mut borrowed_states = dir.0.challenge_states.lock().unwrap();
            let mut state_entry = match borrowed_states.entry(e.key.0.clone()) {
                Entry::Occupied(s) => s,
                Entry::Vacant(_) => return,
            };
            let state = state_entry.get_mut();
            if state.req_id != e.key.1 {
                // for old request, out of date
                return;
            }
            state_entry.remove();
        }));

        // Listen loop
        tm.task("Node - socket", {
            let log = log.fork(ea!(subsys = "listen"));
            let dir = dir.clone();
            let tm = tm.clone();
            async move {
                let mut buf = [0u8; 1024];
                loop {
                    let packet = select!{
                        _ = tm.until_terminate() => {
                            return;
                        }
                        p = dir.0.as_ref().socket.recv_from(&mut buf) => p,
                    };
                    match packet {
                        Ok((len, addr)) => {
                            match match wire::node::Protocol::from_bytes(&buf[..len]) {
                                Ok(ver) => match dir.handle(ver, &addr).await {
                                    Ok(()) => Ok(()),
                                    Err(e) => Err(e),
                                },
                                Err(e) => Err(e.context("Failed to bincode deserialize packet")),
                            } {
                                Ok(()) => { },
                                Err(e) => {
                                    log.log_err(
                                        loga::DEBUG,
                                        e.context_with("Received invalid directory message", ea!(addr = addr)),
                                    );
                                },
                            }
                        },
                        Err(e) => {
                            log.log_err(loga::WARN, e.context("Error receiving packet"));
                        },
                    };
                }
            }
        });
        dir.start_find(FindGoal::Coord(node_ident_coord(&dir.0.own_ident)), None).await;

        // If running in a container or at boot, packets may be lost immediately after
        // getting an ip address so do it again in a minute.
        tm.task("Node - retry startup find once", {
            let dir = dir.clone();
            async move {
                sleep(Duration::seconds(60).to_std().unwrap()).await;
                dir.start_find(FindGoal::Coord(node_ident_coord(&dir.0.own_ident)), None).await;
            }
        });
        return Ok(dir);
    }

    pub fn health_detail(&self) -> HealthDetail {
        let mut responsive = 0;
        let mut unresponsive = 0;
        for bucket in self.0.buckets.lock().unwrap().buckets.clone().into_iter() {
            for n in bucket {
                if n.unresponsive {
                    unresponsive += 1;
                } else {
                    responsive += 1;
                }
            }
        }
        return HealthDetail {
            responsive_neighbors: responsive,
            unresponsive_neighbors: unresponsive,
            active_challenges: self.0.challenge_states.lock().unwrap().len(),
            active_finds: self.0.find_states.lock().unwrap().len(),
            active_pings: self.0.ping_states.lock().unwrap().len(),
        };
    }

    /// Identity of node
    pub fn node_identity(&self) -> node_identity::NodeIdentity {
        return self.0.own_ident.clone();
    }

    /// Look up a value in the network
    pub async fn get(&self, key: Identity) -> Option<stored::announcement::Announcement> {
        let (f, c) = ManualFuture::new();
        self.start_find(FindGoal::Identity(key), Some(c)).await;
        return f.await.value;
    }

    /// Store a value in the network. `value` message must be `ValueBody::to_bytes()`
    /// and `signature` is the signature of those bytes using the corresponding
    /// `IdentitySecret`
    pub async fn put(
        &self,
        key: Identity,
        value: stored::announcement::Announcement,
    ) -> Option<stored::announcement::Announcement> {
        let (f, c) = ManualFuture::new();
        self.start_find(FindGoal::Identity(key), Some(c)).await;
        let res = f.await;

        bb!{
            'skip_store _;
            match &res.value {
                Some(accepted) => match accepted {
                    stored::announcement::Announcement::V1(accepted) => {
                        let new_announced = match &value {
                            stored::announcement::Announcement::V1(a) => {
                                a.parse_unwrap().announced
                            },
                        };
                        if accepted.parse_unwrap().announced >= new_announced {
                            break 'skip_store;
                        }
                    },
                },
                _ => (),
            }
            for nearest in res.nearest {
                match nearest.node {
                    NearestNodeEntryNode::Self_ => {
                        self
                            .0
                            .log
                            .log_with(loga::DEBUG, "Own store request, storing locally", ea!(value = key.dbg_str()));
                        self.0.store.lock().unwrap().insert(key.clone(), ValueState {
                            value: value.clone(),
                            received: Utc::now(),
                            updated: Utc::now(),
                        });
                    },
                    NearestNodeEntryNode::Node(node) => {
                        self
                            .send(
                                &node.address.0,
                                wire::node::Protocol::V1(
                                    wire::node::latest::Message::Store(wire::node::latest::StoreRequest {
                                        key: key.clone(),
                                        value: value.clone(),
                                    }),
                                ),
                            )
                            .await;
                    },
                }
            }
        };

        return res.value;
    }

    fn mark_node_unresponsive(&self, key: node_identity::NodeIdentity, bucket_i: usize, unresponsive: bool) {
        let mut buckets = self.0.buckets.lock().unwrap();
        let bucket = &mut buckets.buckets[bucket_i];
        for n in bucket {
            if n.node.ident == key {
                n.unresponsive = unresponsive;
                return;
            }
        }
        self.0.dirty.store(true, Ordering::Relaxed);
    }

    async fn start_challenge(&self, id: node_identity::NodeIdentity, addr: &SocketAddr) {
        // store state by key, with futures
        let timeout = Utc::now() + req_timeout();
        let (challenge, req_id) = {
            let mut borrowed_states = self.0.challenge_states.lock().unwrap();
            let (challenge, state) = match borrowed_states.entry(id.clone()) {
                Entry::Occupied(_) => {
                    return;
                },
                Entry::Vacant(e) => {
                    let challenge = generate_challenge();
                    (challenge.clone(), e.insert(ChallengeState {
                        challenge: challenge,
                        req_id: self.0.next_req_id.fetch_add(1, Ordering::Relaxed),
                        node: wire::node::latest::NodeInfo {
                            ident: id.clone(),
                            address: SerialAddr(addr.clone()),
                        },
                    }))
                },
            };
            (challenge, state.req_id)
        };
        self.send(addr, wire::node::Protocol::V1(wire::node::latest::Message::Challenge(challenge))).await;
        self.0.challenge_timeouts.unbounded_send(NextChallengeTimeout {
            end: timeout,
            key: (id, req_id),
        }).unwrap();
    }

    async fn start_find(&self, goal: FindGoal, fut: Option<ManualFutureCompleter<FindResult>>) {
        let goal_coord = match goal {
            FindGoal::Coord(c) => c,
            FindGoal::Identity(i) => ident_coord(&i),
        };

        // store state by key, with futures
        let updated = Utc::now();
        let mut defer = vec![];
        let req_id = {
            let mut borrowed_states = self.0.find_states.lock().unwrap();
            let state = match borrowed_states.entry(goal) {
                Entry::Occupied(mut e) => {
                    if let Some(f) = fut {
                        e.get_mut().futures.push(f);
                    }
                    return;
                },
                Entry::Vacant(e) => e.insert(FindState {
                    req_id: self.0.next_req_id.fetch_add(1, Ordering::Relaxed),
                    goal: goal,
                    updated: updated.clone(),
                    nearest: vec![NearestNodeEntry {
                        dist: dist(&goal_coord, &self.0.own_coord).1,
                        node: NearestNodeEntryNode::Self_,
                    }],
                    outstanding: vec![],
                    seen: HashSet::new(),
                    value: match &goal {
                        FindGoal::Coord(_) => None,
                        FindGoal::Identity(i) => match self
                            .0
                            .store
                            .lock()
                            .unwrap()
                            .get(i)
                            .map(|x| x.value.clone()) {
                            Some(v) => {
                                self
                                    .0
                                    .log
                                    .log_with(
                                        loga::DEBUG,
                                        "Starting find with initial value",
                                        ea!(value = v.dbg_str(), goal = goal.dbg_str()),
                                    );
                                Some(v)
                            },
                            None => {
                                self
                                    .0
                                    .log
                                    .log_with(loga::DEBUG, "Starting find with no value", ea!(goal = goal.dbg_str()));
                                None
                            },
                        },
                    },
                    futures: vec![],
                }),
            };
            if let Some(f) = fut {
                state.futures.push(f);
            }
            let closest_peers = self.get_closest_peers(goal_coord, PARALLEL);
            for p in closest_peers {
                let challenge = generate_challenge();
                let (bucket_i, dist) = dist(&node_ident_coord(&p.ident), &goal_coord);
                state.outstanding.push(OutstandingNodeEntry {
                    dist: dist,
                    bucket_i: bucket_i,
                    challenge: challenge.clone(),
                    node: p.clone(),
                });

                struct Defer {
                    challenge: Blob,
                    addr: SocketAddr,
                }

                defer.push(Defer {
                    challenge: challenge,
                    addr: p.address.0.clone(),
                });
            }
            state.req_id
        };
        for d in defer {
            self
                .send(
                    &d.addr,
                    wire::node::Protocol::V1(
                        wire::node::latest::Message::FindRequest(wire::node::latest::FindRequest {
                            challenge: d.challenge,
                            goal: goal,
                            sender: self.0.own_ident.clone(),
                        }),
                    ),
                )
                .await;
        }
        match self.0.find_timeouts.unbounded_send(NextFindTimeout {
            updated: updated,
            key: (goal, req_id),
        }) {
            Ok(_) => { },
            Err(e) => {
                let e = e.into_send_error();
                if e.is_disconnected() {
                    // nop
                } else if e.is_full() {
                    unreachable!();
                } else {
                    unreachable!();
                }
            },
        };
    }

    async fn complete_state(&self, state: FindState) {
        match &state.value {
            Some(v) => self
                .0
                .log
                .log_with(
                    loga::DEBUG,
                    "Completing state with value",
                    ea!(value = v.dbg_str(), goal = state.goal.dbg_str()),
                ),
            None => self
                .0
                .log
                .log_with(loga::DEBUG, "Completing state with no value", ea!(goal = state.goal.dbg_str())),
        }
        for f in state.futures {
            f.complete(FindResult {
                value: state.value.clone(),
                nearest: state.nearest.clone(),
            }).await;
        }
    }

    async fn handle_challenge_resp(&self, resp: wire::node::latest::ChallengeResponse) {
        let log = self.0.log.fork(ea!(action = "challenge_response", from_node_ident = resp.sender.dbg_str()));

        // Lookup request state
        let mut borrowed_states = self.0.challenge_states.lock().unwrap();
        let state_entry = match borrowed_states.entry(resp.sender.clone()) {
            Entry::Occupied(s) => s,
            Entry::Vacant(_) => {
                // Happens normally if outgoing replaced for a better peer and then the request is
                // resolved before resp comes back
                return;
            },
        };
        let state = state_entry.get();

        // Confirm sender is legit routable, add to own routing table
        if resp.sender.verify(&state.challenge, &resp.signature).is_err() {
            log.log(loga::DEBUG, "Bad sender signature");
            return;
        }
        let state = state_entry.remove();
        self.add_good_node(resp.sender.clone(), Some(state.node));
    }

    async fn handle_find_resp(&self, resp: wire::node::latest::FindResponse) {
        let Ok(content) = resp.content.verify(&resp.sender) else {
            self.0.log.log(loga::DEBUG, "Find response has invalid signature");
            return;
        };
        let log: Log = self.0.log.fork(ea!(action = "find_response", from_node_ident = resp.sender.dbg_str()));
        let goal;
        let mut defer_next_req = vec![];
        let mut transfer_stored_addr: Option<SocketAddr> = None;
        let state = {
            // Lookup request state, discard if unsolicited (or obsolete) find response
            let mut borrowed_states = self.0.find_states.lock().unwrap();
            let mut state_entry = match borrowed_states.entry(content.goal.clone()) {
                Entry::Occupied(s) => s,
                Entry::Vacant(_) => {
                    log.log(loga::DEBUG, "No request state matching response target");
                    return;
                },
            };
            let state = state_entry.get_mut();
            goal = state.goal;
            let mut outstanding_entry: Option<OutstandingNodeEntry> = None;
            state.outstanding.retain(|e| {
                if e.node.ident == resp.sender {
                    if constant_time_eq(&content.challenge, &e.challenge) {
                        outstanding_entry = Some(e.clone());
                        return false;
                    } else {
                        log.log_with(
                            loga::DEBUG,
                            "Wrong challenge",
                            ea!(want = e.challenge, got = content.challenge),
                        );
                    }
                }
                return true;
            });
            let outstanding_entry = match outstanding_entry {
                Some(e) => e,
                None => {
                    // 1. May have been dropped because there are better candidates
                    //
                    // 2. Entry skipped because wrong challenge
                    return;
                },
            };

            // Confirm sender is legit routable, possibly add to own routing table
            let (_, sender_dist) = dist(&node_ident_coord(&outstanding_entry.node.ident), &self.0.own_coord);
            if self.add_good_node(outstanding_entry.node.ident.clone(), Some(outstanding_entry.node.clone())) {
                if !self
                    .get_closest_peers(self.0.own_coord, NEIGHBORHOOD)
                    .iter()
                    .any(|p| dist(&node_ident_coord(&p.ident), &self.0.own_coord).1 < sender_dist) {
                    // Incidental work; added sender as a close peer, and sender is the closest peer
                    // so need to replicate all state to it (i.e. it is one of N closest nodes to all
                    // data on this node)
                    transfer_stored_addr = Some(outstanding_entry.node.address.0.clone());
                }
            }

            // The node responded and is legit, add it to the nearest node set
            loop {
                let mut replace_nearest = false;
                if state.nearest.len() == NEIGHBORHOOD {
                    if sender_dist >= state.nearest.last().unwrap().dist {
                        break;
                    }
                    replace_nearest = true;
                }
                if state.nearest.iter().any(|e| match &e.node {
                    NearestNodeEntryNode::Self_ => self.0.own_ident == outstanding_entry.node.ident,
                    NearestNodeEntryNode::Node(f) => f.ident == outstanding_entry.node.ident,
                }) {
                    break;
                }
                if replace_nearest {
                    state.nearest.pop();
                }
                state.nearest.push(NearestNodeEntry {
                    dist: sender_dist,
                    node: NearestNodeEntryNode::Node(outstanding_entry.node.clone()),
                });
                state.nearest.sort_by_key(|e| e.dist);
                break;
            }

            // Send requests to each of the next hop nodes that are closer than what we've
            // seen + that don't already have outgoing requests...
            let goal_coord = match &goal {
                FindGoal::Coord(c) => *c,
                FindGoal::Identity(i) => ident_coord(i),
            };
            for n in content.nodes {
                if !state.seen.insert(n.ident.clone()) {
                    // Already considered/requested this node previously - this overlaps info in
                    // nearest/outstanding partially, but if we reject a response (ex: bad signature)
                    // it will never go into the nearest/outstanding collections so we could request
                    // it repeatedly. This is an explicit check on that.
                    continue;
                }
                let candidate_hash = node_ident_coord(&n.ident);
                let (bucket_i, candidate_dist) = dist(&candidate_hash, &goal_coord);

                // If nearest list is full and found node is farther away than any current nodes,
                // drop it
                if state.nearest.len() == NEIGHBORHOOD && candidate_dist >= state.nearest.last().unwrap().dist {
                    continue;
                }

                // If outstanding list is full and found node is farther away than any current
                // nodes, drop it
                let mut replace_outstanding = false;
                if state.outstanding.len() == PARALLEL {
                    if candidate_dist >= state.outstanding.last().unwrap().dist {
                        continue;
                    }

                    // Not farther away, we can pop the farther one off and add the found node below
                    replace_outstanding = true;
                }

                // If found node already in nearest, drop (ignore) it
                if state.nearest.iter().any(|e| n.ident == *match &e.node {
                    NearestNodeEntryNode::Self_ => &self.0.own_ident,
                    NearestNodeEntryNode::Node(f) => &f.ident,
                }) {
                    continue;
                }

                // If found node already in outstanding, drop (ignore) it
                if state.outstanding.iter().any(|e| e.node.ident == n.ident) {
                    continue;
                }
                let challenge = generate_challenge();
                if replace_outstanding {
                    state.outstanding.pop();
                }
                state.outstanding.push(OutstandingNodeEntry {
                    dist: candidate_dist,
                    challenge: challenge.clone(),
                    node: n.clone(),
                    bucket_i,
                });
                state.outstanding.sort_by_key(|e| e.dist);

                struct Defer {
                    challenge: Blob,
                    addr: SocketAddr,
                }

                defer_next_req.push(Defer {
                    challenge: challenge,
                    addr: n.address.0.clone(),
                });
            }

            // Process received value
            if let (Some(value), FindGoal::Identity(goal_identity)) = (content.value, goal) {
                bb!{
                    let found_published;
                    match &value {
                        stored::announcement::Announcement::V1(found) => {
                            let Ok(content) = found.verify(&goal_identity) else {
                                log.log(loga::DEBUG, "Got value with bad signature");
                                break;
                            };
                            found_published = content.announced;
                        },
                    }
                    match &mut state.value {
                        Some(state_value) => {
                            let have_published;
                            match state_value {
                                stored::announcement::Announcement::V1(have_value) => {
                                    have_published = have_value.parse_unwrap().announced;
                                },
                            }
                            if have_published > found_published {
                                log.log_with(
                                    loga::DEBUG,
                                    "Received value older than one we already have",
                                    ea!(
                                        have_published = have_published.to_rfc3339(),
                                        found_published = found_published.to_rfc3339()
                                    ),
                                );
                                break;
                            }
                        },
                        _ => (),
                    }
                    log.log_with(
                        loga::DEBUG,
                        "Found better value for find, replacing",
                        ea!(old = state.value.dbg_str(), new = state.value.dbg_str(), goal = state.goal.dbg_str()),
                    );
                    state.value = Some(value);
                };
            }

            // If done, cleanup or else update timeouts
            if state.outstanding.is_empty() {
                // Remove outstanding state to complete it
                Some(state_entry.remove())
            } else {
                // New things to do, bump updated time and re-queue
                state.updated = Utc::now();
                match self.0.find_timeouts.unbounded_send(NextFindTimeout {
                    updated: state.updated,
                    key: (state.goal.clone(), state.req_id),
                }) {
                    Ok(_) => { },
                    Err(e) => {
                        let e = e.into_send_error();
                        if e.is_disconnected() {
                            // nop
                        } else if e.is_full() {
                            unreachable!();
                        } else {
                            unreachable!();
                        }
                    },
                };
                None
            }
        };

        // Send deferred messages now that locks are released
        if let Some(addr) = transfer_stored_addr {
            let mut store = HashMap::new();
            {
                let lock = self.0.store.lock().unwrap();
                store.extend(lock.iter().map(|(k, v)| (k.clone(), v.value.clone())));
            }
            for (k, v) in store.into_iter() {
                self
                    .send(
                        &addr,
                        wire::node::Protocol::V1(wire::node::latest::Message::Store(wire::node::latest::StoreRequest {
                            key: k,
                            value: v,
                        })),
                    )
                    .await;
            }
        }
        if let Some(s) = state {
            self.complete_state(s).await;
        }
        for d in defer_next_req {
            self
                .send(
                    &d.addr,
                    wire::node::Protocol::V1(
                        wire::node::latest::Message::FindRequest(wire::node::latest::FindRequest {
                            challenge: d.challenge,
                            goal: goal,
                            sender: self.0.own_ident.clone(),
                        }),
                    ),
                )
                .await;
        }
    }

    fn get_closest_peers(&self, goal_coord: DhtCoord, count: usize) -> Vec<wire::node::latest::NodeInfo> {
        let buckets = self.0.buckets.lock().unwrap();
        let (bucket_i, _) = dist(&goal_coord, &self.0.own_coord);
        let mut nodes: Vec<wire::node::latest::NodeInfo> = vec![];

        bb!{
            'full _;
            // 1. Start with nodes in the same k-bucket, since all nodes in a bucket are in a
            //    distinct subtree from all higher and lower-k buckets, so nodes in that bucket will
            //    naturally be closest. (All k-buckets are distinct subtrees of increasing distance
            //    from the current node).
            //
            // 2. Failing that, try buckets nearer to the current node (higher leading zeros)
            //    because all nearer buckets form a combined distinct subtree than any more distant
            //    nodes
            for bucket in bucket_i .. BUCKET_COUNT {
                for state in &buckets.buckets[bucket] {
                    if state.unresponsive {
                        continue;
                    }
                    nodes.push(state.node.clone());
                    if nodes.len() >= count {
                        break 'full;
                    }
                }
            }
            // 3. Failing that, try more distant buckets
            if bucket_i > 0 {
                for bucket in (0 .. bucket_i - 1).rev() {
                    for state in &buckets.buckets[bucket] {
                        if state.unresponsive {
                            continue;
                        }
                        nodes.push(state.node.clone());
                        if nodes.len() >= count {
                            break 'full;
                        }
                    }
                }
            }
        }

        return nodes;
    }

    async fn handle(&self, m: wire::node::Protocol, reply_to: &SocketAddr) -> Result<(), loga::Error> {
        let log = self.0.log.fork(ea!(from_addr = reply_to, message = m.dbg_str()));
        log.log(loga::DEBUG, "Received");
        match m {
            wire::node::Protocol::V1(v1) => match v1 {
                wire::node::latest::Message::FindRequest(m) => {
                    let body = wire::node::latest::FindResponseContent {
                        challenge: m.challenge,
                        goal: m.goal,
                        sender: self.0.own_ident.clone(),
                        nodes: self.get_closest_peers(match m.goal {
                            FindGoal::Coord(c) => c,
                            FindGoal::Identity(i) => ident_coord(&i),
                        }, NEIGHBORHOOD),
                        value: bb!{
                            let FindGoal:: Identity(ident) = m.goal else {
                                break None;
                            };
                            break self.0.store.lock().unwrap().get(&ident).map(|v| v.value.clone());
                        },
                    };
                    self
                        .send(
                            reply_to,
                            wire::node::Protocol::V1(
                                wire::node::latest::Message::FindResponse(wire::node::latest::FindResponse {
                                    sender: self.0.own_ident.clone(),
                                    content: <wire
                                    ::node
                                    ::latest
                                    ::BincodeSignature<wire::node::latest::FindResponseContent, NodeIdentity>>::sign(
                                        &self.0.own_secret,
                                        body,
                                    ),
                                }),
                            ),
                        )
                        .await;
                    if self.add_good_node(m.sender.clone(), None) {
                        self.start_challenge(m.sender, reply_to).await;
                    }
                },
                wire::node::latest::Message::FindResponse(m) => {
                    self.handle_find_resp(m).await;
                },
                wire::node::latest::Message::Store(m) => {
                    log.log_with(loga::DEBUG, "Storing", ea!(value = m.key.dbg_str()));
                    let new_announced;
                    match &m.value {
                        stored::announcement::Announcement::V1(value) => {
                            let Ok(new_content) = value.verify(&m.key) else {
                                return Err(log.err("Store request failed signature validation"));
                            };
                            new_announced = new_content.announced;
                        },
                    }
                    if new_announced > Utc::now() + Duration::minutes(1) {
                        return Err(log.err("Store request published date too far in the future"));
                    }
                    match self.0.store.lock().unwrap().entry(m.key) {
                        Entry::Occupied(mut e) => {
                            let have_published;
                            match &e.get().value {
                                stored::announcement::Announcement::V1(have_value) => {
                                    have_published = have_value.parse_unwrap().announced;
                                },
                            }
                            if new_announced >= have_published {
                                e.insert(ValueState {
                                    value: m.value,
                                    received: Utc::now(),
                                    updated: Utc::now(),
                                });
                            }
                        },
                        Entry::Vacant(e) => {
                            e.insert(ValueState {
                                value: m.value,
                                received: Utc::now(),
                                updated: Utc::now(),
                            });
                        },
                    };
                },
                wire::node::latest::Message::Ping => {
                    self
                        .send(
                            reply_to,
                            wire::node::Protocol::V1(wire::node::latest::Message::Pung(self.0.own_ident.clone())),
                        )
                        .await;
                },
                wire::node::latest::Message::Pung(k) => {
                    let state = match self.0.ping_states.lock().unwrap().entry(k.clone()) {
                        Entry::Occupied(s) => s.remove(),
                        Entry::Vacant(_) => return Ok(()),
                    };
                    self.mark_node_unresponsive(k, state.bucket_i, false);
                },
                wire::node::latest::Message::Challenge(challenge) => {
                    self
                        .send(
                            reply_to,
                            wire::node::Protocol::V1(
                                wire::node::latest::Message::ChallengeResponse(wire::node::latest::ChallengeResponse {
                                    sender: self.0.own_ident.clone(),
                                    signature: self.0.own_secret.sign(&challenge),
                                }),
                            ),
                        )
                        .await;
                },
                wire::node::latest::Message::ChallengeResponse(resp) => {
                    self.handle_challenge_resp(resp).await;
                },
            },
        };
        Ok(())
    }

    /// Add a node, or check if adding a node would be new (returns whether id is new)
    fn add_good_node(&self, id: node_identity::NodeIdentity, node: Option<wire::node::latest::NodeInfo>) -> bool {
        let log = self.0.log.fork(ea!(activity = "add_good_node", node = id.dbg_str()));
        let log = &log;
        if id == self.0.own_ident {
            log.log(loga::DEBUG, "Own node id, ignoring");
            return false;
        }
        let (bucket_i, _) = dist(&node_ident_coord(&id), &self.0.own_coord);
        let mut buckets = self.0.buckets.lock().unwrap();
        let buckets = &mut *buckets;

        fn store_addr(
            log: &Log,
            buckets: &mut Buckets,
            own_coord: &DhtCoord,
            addr: SocketAddr,
            new_ident: NodeIdentity,
        ) {
            if let Some(old) = buckets.addrs.get(&addr) {
                let (bucket_i, _) = dist(&node_ident_coord(old), own_coord);
                let bucket = &mut buckets.buckets[bucket_i];
                for i in 0 .. bucket.len() {
                    let n = &mut bucket[i];
                    if &n.node.ident == old {
                        log.log_with(
                            loga::DEBUG,
                            "Replaced node with same addr",
                            ea!(addr = addr, old_ident = old, new_ident = new_ident),
                        );
                        bucket.remove(i);
                        break;
                    }
                }
            };
            buckets.addrs.insert(addr, new_ident);
        }

        let new_node = 'logic : loop {
            let bucket = &mut buckets.buckets[bucket_i];
            let mut last_unresponsive: Option<usize> = None;

            // Updated or already known
            for i in 0 .. bucket.len() {
                let bucket_entry = &mut bucket[i];
                if bucket_entry.node.ident == id {
                    if let Some(node) = node {
                        if bucket_entry.unresponsive {
                            bucket_entry.unresponsive = false;
                        }
                        buckets.addrs.remove(&bucket_entry.node.address.0);
                        let new_state = wire::node::latest::NodeState {
                            node: node.clone(),
                            unresponsive: false,
                        };
                        let changed = *bucket_entry == new_state;
                        *bucket_entry = new_state;
                        if changed {
                            self.0.dirty.store(true, Ordering::Relaxed);
                        }
                        log.log(loga::DEBUG, "Updated existing node");
                        store_addr(log, buckets, &self.0.own_coord, node.address.0, node.ident);
                    }
                    break 'logic false;
                }
                if bucket_entry.unresponsive {
                    last_unresponsive = Some(i);
                }
            }

            // Empty slot
            if bucket.len() < NEIGHBORHOOD {
                if let Some(node) = node {
                    bucket.insert(0, wire::node::latest::NodeState {
                        node: node.clone(),
                        unresponsive: false,
                    });
                    self.0.dirty.store(true, Ordering::Relaxed);
                    log.log(loga::DEBUG, "Added node to empty slot");
                    store_addr(log, buckets, &self.0.own_coord, node.address.0, node.ident);
                }
                break true;
            }

            // Replacing dead
            if let Some(i) = last_unresponsive {
                if let Some(node) = node {
                    buckets.addrs.remove(&bucket[i].node.address.0);
                    bucket.remove(i);
                    bucket.push(wire::node::latest::NodeState {
                        node: node.clone(),
                        unresponsive: false,
                    });
                    self.0.dirty.store(true, Ordering::Relaxed);
                    log.log(loga::DEBUG, "Replaced dead node");
                    store_addr(log, buckets, &self.0.own_coord, node.address.0, node.ident);
                }
                break 'logic true;
            }
            log.log(loga::DEBUG, "Nowhere to place, dropping");
            break false;
        };
        return new_node;
    }

    async fn send(&self, addr: &SocketAddr, data: wire::node::Protocol) {
        let bytes = data.to_bytes();
        self.0.log.log_with(loga::DEBUG, "Sending", ea!(to_addr = addr, message = data.dbg_str()));
        self.0.socket.send_to(&bytes, addr).await.unwrap();
    }
}
