use std::{
    collections::HashMap,
    pin::Pin,
};
use futures::Future;
use itertools::Itertools;
use loga::{
    ea,
    DebugDisplay,
};
use poem::{
    Endpoint,
    async_trait,
    http::{
        StatusCode,
        header::AUTHORIZATION,
    },
    IntoResponse,
};
use serde::Serialize;
use super::{
    blob::{
        Blob,
        ToBlob,
    },
    log::{
        Log,
        Flags,
    },
};

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

pub struct Handler {
    root: Tree,
    debug_flag: Flags,
    log: Log,
}

#[async_trait]
impl Endpoint for Handler {
    type Output = poem::Response;

    async fn call(&self, req: poem::Request) -> poem::Result<Self::Output> {
        let path;
        let query;
        match req.uri().path_and_query() {
            Some(pq) => {
                let path0 = pq.path().trim_matches(['/']);
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
        let bearer =
            req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|v| v.to_string());
        let method = req.method().clone();
        let body = req.into_body().into_bytes().await?.blob();
        let mut i = 0;
        let mut at = &self.root;
        let leaf = 'recurse : loop {
            match at {
                Tree::Branch(b) => {
                    if i >= path.len() {
                        self
                            .log
                            .log_with(
                                self.debug_flag,
                                "No such path, too deep",
                                ea!(path = path.dbg_str(), index = i),
                            );
                        return Ok(StatusCode::NOT_FOUND.into_response());
                    }
                    match b.get(&path[i]) {
                        Some(t) => {
                            at = t.as_ref();
                            i += 1;
                        },
                        None => {
                            self
                                .log
                                .log_with(self.debug_flag, "No such path", ea!(path = path.dbg_str(), index = i));
                            return Ok(StatusCode::NOT_FOUND.into_response());
                        },
                    }
                },
                Tree::Leaf(l) => {
                    match method.as_str() {
                        "GET" => {
                            let Some(m) =& l.get else {
                                self
                                    .log
                                    .log_with(
                                        self.debug_flag,
                                        "No GET handler",
                                        ea!(path = path.dbg_str(), index = i),
                                    );
                                return Ok(StatusCode::NOT_FOUND.into_response());
                            };
                            break 'recurse m;
                        },
                        "POST" => {
                            let Some(m) =& l.post else {
                                self
                                    .log
                                    .log_with(
                                        self.debug_flag,
                                        "No POST handler",
                                        ea!(path = path.dbg_str(), index = i),
                                    );
                                return Ok(StatusCode::NOT_FOUND.into_response());
                            };
                            break 'recurse m;
                        },
                        "DELETE" => {
                            let Some(m) =& l.delete else {
                                self
                                    .log
                                    .log_with(
                                        self.debug_flag,
                                        "No DELETE handler",
                                        ea!(path = path.dbg_str(), index = i),
                                    );
                                return Ok(StatusCode::NOT_FOUND.into_response());
                            };
                            break 'recurse m;
                        },
                        _ => {
                            return Ok(StatusCode::NOT_FOUND.into_response());
                        },
                    }
                },
            }
        };
        match leaf(Request {
            path: path[i..].to_vec(),
            query: query,
            body: body,
            auth_bearer: bearer,
        }).await {
            Response::Ok => Ok(StatusCode::OK.into_response()),
            Response::AuthErr => Ok(StatusCode::UNAUTHORIZED.into_response()),
            Response::InternalErr => Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            Response::ExternalErr(e) => Ok((StatusCode::INTERNAL_SERVER_ERROR, e).into_response()),
            Response::UserErr(e) => Ok((StatusCode::BAD_REQUEST, e).into_response()),
            Response::Json(b) => return Ok((StatusCode::OK, b.to_vec()).into_response()),
        }
    }
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

    pub fn build(&mut self, log: Log, debug_flag: Flags) -> Handler {
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
        return Handler {
            root: t,
            log: log,
            debug_flag: debug_flag,
        };
    }
}
