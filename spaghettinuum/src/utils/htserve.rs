use {
    super::blob::{
        Blob,
        ToBlob,
    },
    futures::Future,
    http_body_util::BodyExt,
    htwrap::htserve::{
        body_full,
        response_200,
        response_400,
        response_401,
        response_404,
        response_503,
        response_503_text,
        Body,
    },
    hyper::body::Incoming,
    itertools::Itertools,
    loga::{
        ea,
        DebugDisplay,
        ErrContext,
        Log,
    },
    serde::Serialize,
    sha2::{
        Digest,
        Sha256,
    },
    std::{
        collections::HashMap,
        convert::Infallible,
        pin::Pin,
        sync::Arc,
    },
};

pub fn auth_hash(s: &str) -> Blob {
    return <Sha256 as Digest>::digest(s.as_bytes()).blob();
}

pub fn auth(want: &[u8], got: &Option<String>) -> bool {
    let Some(got) = got.as_ref() else {
        return false;
    };
    return auth_hash(got).as_ref() == want;
}

pub struct Request {
    pub path: Vec<String>,
    pub query: String,
    pub body: Blob,
    pub auth_bearer: Option<String>,
}

pub enum Response {
    Ok,
    AuthErr,
    InternalErr,
    ExternalErr(String),
    UserErr(String),
    Json(Blob),
}

impl Response {
    pub fn external_err(s: impl ToString) -> Self {
        return Self::ExternalErr(s.to_string());
    }

    pub fn user_err(s: impl ToString) -> Self {
        return Self::UserErr(s.to_string());
    }

    pub fn json(s: impl Serialize) -> Self {
        return Self::Json(serde_json::to_vec(&s).unwrap().blob());
    }
}

type Method = Box<dyn Send + Sync + Fn(Request) -> Pin<Box<dyn Send + Future<Output = Response>>>>;

pub struct Leaf {
    get: Option<Method>,
    post: Option<Method>,
    delete: Option<Method>,
}

impl Leaf {
    pub fn new() -> Self {
        return Leaf {
            get: None,
            post: None,
            delete: None,
        }
    }

    pub fn get<
        T: 'static + Send + Future<Output = Response>,
        F: 'static + Send + Sync + Fn(Request) -> T,
    >(mut self, f: F) -> Leaf {
        self.get = Some(Box::new(move |r| Box::pin(f(r))));
        self
    }

    pub fn post<
        T: 'static + Send + Future<Output = Response>,
        F: 'static + Send + Sync + Fn(Request) -> T,
    >(mut self, f: F) -> Leaf {
        self.post = Some(Box::new(move |r| Box::pin(f(r))));
        self
    }

    pub fn delete<
        T: 'static + Send + Future<Output = Response>,
        F: 'static + Send + Sync + Fn(Request) -> T,
    >(mut self, f: F) -> Leaf {
        self.delete = Some(Box::new(move |r| Box::pin(f(r))));
        self
    }
}

pub enum Tree {
    Branch(HashMap<String, Box<Tree>>),
    Leaf(Leaf),
}

struct Handler_ {
    root: Tree,
    log: Log,
}

#[derive(Clone)]
pub struct Handler(Arc<Handler_>);

pub async fn handle(handler: Handler, req: hyper::Request<Incoming>) -> Result<hyper::Response<Body>, Infallible> {
    let method = req.method().clone();
    let url = req.uri().to_string();
    let headers = req.headers().clone();
    let bearer =
        headers
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| v.to_string());
    let path;
    let query;
    match req.uri().path_and_query() {
        Some(pq) => {
            let path0 = pq.path().trim_matches('/');
            if path0 == "" {
                path = vec![];
            } else {
                path = path0.split("/").map(str::to_string).collect();
            }
            match pq.query() {
                Some(q) => query = q.to_string(),
                None => query = "".to_string(),
            }
        },
        None => {
            path = vec![];
            query = "".to_string();
        },
    }
    let body = match req.into_body().collect().await {
        Ok(b) => b,
        Err(e) => {
            handler.0.log.log_err(loga::DEBUG, e.context("Error reading request body"));
            return Ok(response_400("Error reading body"));
        },
    }.to_bytes().blob();
    handler
        .0
        .log
        .log_with(
            loga::DEBUG,
            "Receive",
            ea!(
                method = method,
                url = url,
                headers = headers.pretty_dbg_str(),
                body = String::from_utf8_lossy(&body)
            ),
        );
    let mut i = 0;
    let mut at = &handler.0.root;
    let leaf = 'recurse : loop {
        match at {
            Tree::Branch(b) => {
                if i >= path.len() {
                    handler
                        .0
                        .log
                        .log_with(loga::DEBUG, "Path matching ended at branch", ea!(path = path.dbg_str(), seg = i));
                    return Ok(response_404());
                }
                match b.get(&path[i]) {
                    Some(t) => {
                        at = t.as_ref();
                        i += 1;
                    },
                    None => {
                        handler
                            .0
                            .log
                            .log_with(
                                loga::DEBUG,
                                "No route for path segment in parent branch",
                                ea!(path = path.dbg_str(), seg = i),
                            );
                        return Ok(response_404());
                    },
                }
            },
            Tree::Leaf(l) => {
                match method.as_str() {
                    "GET" => {
                        let Some(m) =& l.get else {
                            handler
                                .0
                                .log
                                .log_with(loga::DEBUG, "No GET handler", ea!(path = path.dbg_str(), seg = i));
                            return Ok(response_404());
                        };
                        break 'recurse m;
                    },
                    "POST" => {
                        let Some(m) =& l.post else {
                            handler
                                .0
                                .log
                                .log_with(loga::DEBUG, "No POST handler", ea!(path = path.dbg_str(), seg = i));
                            return Ok(response_404());
                        };
                        break 'recurse m;
                    },
                    "DELETE" => {
                        let Some(m) =& l.delete else {
                            handler
                                .0
                                .log
                                .log_with(loga::DEBUG, "No DELETE handler", ea!(path = path.dbg_str(), seg = i));
                            return Ok(response_404());
                        };
                        break 'recurse m;
                    },
                    _ => {
                        return Ok(response_404());
                    },
                }
            },
        }
    };
    let resp = match leaf(Request {
        path: path[i..].to_vec(),
        query: query,
        body: body,
        auth_bearer: bearer,
    }).await {
        Response::Ok => response_200(),
        Response::AuthErr => response_401(),
        Response::InternalErr => response_503(),
        Response::ExternalErr(e) => response_503_text(e),
        Response::UserErr(e) => response_400(e),
        Response::Json(b) => hyper::Response::builder().status(200).body(body_full(b.to_vec())).unwrap(),
    };
    return Ok(resp);
}

pub struct Routes(Option<Tree>);

impl Routes {
    pub fn new() -> Self {
        return Self(None);
    }

    pub fn add(&mut self, path: &str, l: Leaf) -> &mut Self {
        if path.starts_with("/") || path.ends_with("/") {
            panic!("Path must not have start/end slashes");
        }
        let mut path = if path == "" {
            vec![]
        } else {
            path.split("/").map(str::to_string).collect_vec()
        };
        path.reverse();

        fn insert(b: &mut HashMap<String, Box<Tree>>, mut path: Vec<String>, l: Leaf) {
            let key = match path.pop() {
                Some(k) => k,
                None => {
                    panic!("Path occupied");
                },
            };
            match b.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    if path.is_empty() {
                        panic!("Path occupied");
                    }
                    match e.get_mut().as_mut() {
                        Tree::Branch(b) => {
                            insert(b, path, l);
                        },
                        Tree::Leaf(_) => {
                            panic!("Path occupied");
                        },
                    }
                },
                std::collections::hash_map::Entry::Vacant(e) => {
                    if path.is_empty() {
                        e.insert(Box::new(Tree::Leaf(l)));
                    } else {
                        let mut b = HashMap::new();
                        insert(&mut b, path, l);
                        e.insert(Box::new(Tree::Branch(b)));
                    }
                },
            }
        }

        match self.0.as_mut() {
            Some(mut t) => match &mut t {
                Tree::Branch(b) => {
                    insert(b, path, l);
                },
                Tree::Leaf(_) => panic!("Path occupied"),
            },
            None => {
                if path.is_empty() {
                    self.0 = Some(Tree::Leaf(l));
                } else {
                    let mut b = HashMap::new();
                    insert(&mut b, path, l);
                    self.0 = Some(Tree::Branch(b));
                }
            },
        }
        return self;
    }

    pub fn nest(&mut self, path: &str, other: Routes) -> &mut Self {
        let Some(other) = other.0 else {
            return self;
        };
        if path.starts_with("/") || path.ends_with("/") {
            panic!("Path must not have start/end slashes");
        }
        let mut path = path.split("/").map(str::to_string).collect_vec();
        path.reverse();

        fn insert(b: &mut HashMap<String, Box<Tree>>, mut path: Vec<String>, l: Tree) {
            let key = match path.pop() {
                Some(k) => k,
                None => {
                    panic!("Path occupied");
                },
            };
            match b.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    if path.is_empty() {
                        panic!("Path occupied");
                    }
                    match e.get_mut().as_mut() {
                        Tree::Branch(b) => {
                            insert(b, path, l);
                        },
                        Tree::Leaf(_) => {
                            panic!("Path occupied");
                        },
                    }
                },
                std::collections::hash_map::Entry::Vacant(e) => {
                    if path.is_empty() {
                        e.insert(Box::new(l));
                    } else {
                        let mut b = HashMap::new();
                        insert(&mut b, path, l);
                        e.insert(Box::new(Tree::Branch(b)));
                    }
                },
            }
        }

        path.reverse();
        match self.0.as_mut() {
            Some(mut t) => match &mut t {
                Tree::Branch(b) => {
                    insert(b, path, other);
                },
                Tree::Leaf(_) => panic!("Path occupied"),
            },
            None => {
                if path.is_empty() {
                    self.0 = Some(other);
                } else {
                    let mut b = HashMap::new();
                    insert(&mut b, path, other);
                    self.0 = Some(Tree::Branch(b));
                }
            },
        }
        return self;
    }

    pub fn build(&mut self, log: Log) -> Handler {
        fn compact(t: &mut Tree) {
            match t {
                Tree::Branch(b) => {
                    for (_, v) in b.iter_mut() {
                        compact(v.as_mut());
                    }
                    b.shrink_to_fit();
                },
                Tree::Leaf { .. } => (),
            }
        }

        let mut t = self.0.take().unwrap();
        compact(&mut t);
        return Handler(Arc::new(Handler_ {
            root: t,
            log: log,
        }));
    }
}
