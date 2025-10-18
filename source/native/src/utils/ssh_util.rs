use {
    crate::{
        interface::stored::record,
        resolving::{
            default_resolver_url_pairs,
            resolve,
        },
    },
    flowcontrol::{
        shed,
        superif,
    },
    futures::FutureExt,
    itertools::Itertools,
    loga::{
        conversion::ResultIgnore,
        ea,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    russh::{
        client::{
            AuthResult,
            Handle,
            Msg,
        },
        keys::{
            parse_public_key_base64,
            PrivateKeyWithHashAlg,
        },
        Channel,
        ChannelMsg,
        Disconnect,
    },
    russh_sftp::{
        client::SftpSession,
        protocol::{
            OpenFlags,
            StatusCode,
        },
    },
    std::{
        collections::HashMap,
        ffi::OsString,
        future::Future,
        io::{
            stderr,
            stdout,
            ErrorKind,
            Write,
        },
        net::{
            IpAddr,
            SocketAddr,
        },
        os::unix::fs::MetadataExt,
        path::{
            Path,
            PathBuf,
        },
        sync::Arc,
        time::SystemTime,
    },
    tokio::{
        fs::{
            create_dir,
            read_dir,
            remove_dir_all,
            File,
        },
        io::AsyncRead,
    },
};

#[doc(hidden)]
pub struct Handler {
    host_keys: Vec<russh::keys::PublicKey>,
}

#[async_trait::async_trait]
impl russh::client::Handler for Handler {
    type Error = loga::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        let r = shed!{
            'r _;
            for k in &self.host_keys {
                if k == server_public_key {
                    break 'r true;
                }
            }
            break 'r false;
        };
        return async move {
            return Ok(r);
        }
    }
}

pub type SshConn = Arc<Handle<Handler>>;
pub type SshSess = Channel<Msg>;

pub trait SshConnectHandler {
    #[allow(async_fn_in_trait)]
    async fn run(self, conn: SshConn) -> Result<(), loga::Error>;
}

pub async fn ssh_connect(
    log: &Log,
    user: Option<String>,
    host: String,
    port: Option<u16>,
    key: Option<PathBuf>,
    inner: impl SshConnectHandler,
) -> Result<(), loga::Error> {
    let hostkey_key = vec![record::ssh_record::KEY_SUFFIX_SSH_HOSTKEYS.to_string()];
    let (ips, mut additional_records) =
        resolve(log, &default_resolver_url_pairs(log)?, &host, &[hostkey_key.clone()])
            .await
            .context("Error resolving host")?;
    let mut host_keys = vec![];
    shed!{
        let Some(r) = additional_records.remove(&hostkey_key) else {
            log.log(loga::DEBUG, "Response missing SSH host keys record; not using for verification");
            break;
        };
        let Some(r) = r.data else {
            log.log(loga::DEBUG, "Response SSH host keys record is empty; not using for verification");
            break;
        };
        let r = match serde_json::from_value::<record::ssh_record::SshHostKeys>(r) {
            Ok(r) => r,
            Err(e) => {
                log.log_err(
                    loga::DEBUG,
                    e.context(
                        "Couldn't parse SSH host keys record into expected JSON format, not using for verification",
                    ),
                );
                break;
            },
        };
        match r {
            record::ssh_record::SshHostKeys::V1(keys) => {
                for key in keys.0 {
                    let mut parts = key.split_whitespace();
                    shed!{
                        let Some(_algo) = parts.next() else {
                            break;
                        };
                        let Some(key_key) = parts.next() else {
                            break;
                        };
                        match parse_public_key_base64(&key_key) {
                            Ok(k) => {
                                host_keys.push(k);
                            },
                            Err(e) => {
                                log.log_err(
                                    loga::DEBUG,
                                    e.context_with("Received invalid host key, skipping", ea!(key = key)),
                                );
                                break;
                            },
                        }
                    }
                }
            },
        }
        break;
    };
    if host_keys.is_empty() {
        return Err(loga::err("No host keys published for host, use normal SSH if this is intended"));
    }
    let config_port;
    let config_user;
    match russh_config::parse_home(&host) {
        Ok(c) => {
            config_port = c.port;
            config_user = Some(c.user);
        },
        Err(e) => match e {
            russh_config::Error::HostNotFound => {
                config_port = 22;
                config_user = None;
            },
            russh_config::Error::Io(x) if x.kind() == ErrorKind::NotFound => {
                config_port = 22;
                config_user = None;
            },
            _ => return Err(e.context("Error parsing ssh config")),
        },
    };
    let mut conn =
        russh::client::connect(
            Arc::new(russh::client::Config::default()),
            Iterator::chain(
                ips.ipv6s.into_iter().map(|x| IpAddr::V6(x)),
                ips.ipv4s.into_iter().map(|x| IpAddr::V4(x)),
            )
                .map(|i| SocketAddr::new(i, port.unwrap_or(config_port)))
                .collect_vec()
                .as_slice(),
            Handler { host_keys: host_keys },
        )
            .await
            .context("Error connecting to remote host")?;
    shed!{
        'authenticated _;
        let user = user.or(config_user).unwrap_or("root".to_string());
        if let Some(key) = key {
            let key =
                russh::keys::load_secret_key(
                    &key,
                    None,
                ).context_with("Error loading specified keypair", ea!(path = key.to_string_lossy()))?;
            let pubkey = key.public_key();
            log.log_with(
                loga::DEBUG,
                "Attempting auth via command line keypair",
                ea!(key = pubkey.fingerprint(russh::keys::HashAlg::Sha256)),
            );
            match conn
                .authenticate_publickey(&user, PrivateKeyWithHashAlg::new(Arc::new(key), None))
                .await
                .context("Error attempting auth method via specified key")? {
                AuthResult::Success => {
                    break 'authenticated;
                },
                AuthResult::Failure { .. } => {
                    return Err(loga::err("Key provided on command line was rejected"));
                },
            }
        }
        match russh::keys::agent::client::AgentClient::connect_env().await {
            Ok(mut agent) => {
                let identities =
                    agent.request_identities().await.context("Error requesting identities from SSH agent")?;
                for key in identities {
                    log.log_with(
                        loga::DEBUG,
                        "Attempting auth via SSH agent key",
                        ea!(key = key.fingerprint(russh::keys::HashAlg::Sha256)),
                    );
                    let res = conn.authenticate_publickey_with(&user, key, None, &mut agent).await;
                    match res.context("Error attempting auth method via SSH agent")? {
                        AuthResult::Success => { },
                        AuthResult::Failure { .. } => {
                            break 'authenticated;
                        },
                    };
                }
            },
            Err(e) => {
                log.log_err(loga::DEBUG, e.context("Error connecting to SSH agent, skipping as auth method"));
            },
        }
        if let Some(home) = dirs_next::home_dir() {
            for suffix in ["rsa", "ed25519"] {
                let key = home.join(format!(".ssh/id_{}", suffix));
                let key =
                    russh::keys::load_secret_key(
                        &key,
                        None,
                    ).context_with("Error loading discovered keypair", ea!(path = key.to_string_lossy()))?;
                let pubkey = key.public_key();
                log.log_with(
                    loga::DEBUG,
                    "Attempting auth via discovered keypair",
                    ea!(key = pubkey.fingerprint(russh::keys::HashAlg::Sha256)),
                );
                match conn
                    .authenticate_publickey(&user, PrivateKeyWithHashAlg::new(Arc::new(key), None))
                    .await
                    .context("Error attempting auth method via specified key")? {
                    AuthResult::Success => {
                        break 'authenticated;
                    },
                    AuthResult::Failure { .. } => { },
                }
            }
        }
        return Err(loga::err("Couldn't locate any authentication methods or all attempted methods were invalid"));
    }
    let conn = Arc::new(conn);
    let res = inner.run(conn.clone()).await;
    conn.disconnect(Disconnect::ByApplication, "", "English").await.log(log, loga::DEBUG, "Error disconnecting");
    return res;
}

/// Turn a list of command line arguments into a single quoted string suitable for
/// executing via ssh.
pub fn quote(command: Vec<String>) -> String {
    return command.iter().map(|x| shell_escape::escape(x.into())).join(" ");
}

pub struct RunCommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub enum CmdResult {
    Eof,
    Close,
    Failure,
    Status(u32),
    Signal(russh::Sig),
}

pub async fn run_command<
    H: russh::client::Handler,
>(
    log: &Log,
    conn: &Handle<H>,
    command: Vec<String>,
    mut handler: impl FnMut(russh::CryptoVec, Option<u32>),
) -> Result<CmdResult, loga::Error> {
    log.log_with(loga::DEBUG, "Running remote command", ea!(command = command.dbg_str()));
    let mut session =
        conn
            .channel_open_session()
            .await
            .context_with("Error opening session to run command", ea!(command = command.dbg_str()))?;
    let command = quote(command);
    session.exec(true, command.as_bytes()).await.context_with("Error running command", ea!(command = command))?;
    loop {
        match session.wait().await {
            None => {
                return Ok(CmdResult::Eof);
            },
            Some(m) => {
                match m {
                    ChannelMsg::Data { data } => {
                        handler(data, None);
                    },
                    ChannelMsg::ExtendedData { data, ext } => {
                        handler(data, Some(ext));
                    },
                    ChannelMsg::Eof => {
                        // nop
                    },
                    ChannelMsg::Close => {
                        // relevant?
                        return Ok(CmdResult::Close);
                    },
                    // supposedly server->client, but that seems wrong
                    ChannelMsg::Open { .. } |
                    ChannelMsg::RequestPty { .. } |
                    ChannelMsg::RequestShell { .. } |
                    ChannelMsg::Exec { .. } |
                    ChannelMsg::Signal { .. } |
                    ChannelMsg::RequestSubsystem { .. } |
                    ChannelMsg::RequestX11 { .. } |
                    ChannelMsg::SetEnv { .. } |
                    ChannelMsg::WindowChange { .. } |
                    ChannelMsg::AgentForward { .. } => {
                        unreachable!("got client->server message from server: {:?}", m);
                    },
                    ChannelMsg::OpenFailure(_) => {
                        unreachable!("should be handled in open_channel: {:?}", m);
                    },
                    ChannelMsg::WindowAdjusted { .. } => {
                        // nop
                    },
                    ChannelMsg::XonXoff { .. } => {
                        // nop
                    },
                    ChannelMsg::ExitStatus { exit_status } => {
                        return Ok(CmdResult::Status(exit_status));
                    },
                    ChannelMsg::ExitSignal { signal_name, core_dumped: _, error_message: _, lang_tag: _ } => {
                        return Ok(CmdResult::Signal(signal_name));
                    },
                    ChannelMsg::Success => {
                        // nop
                    },
                    ChannelMsg::Failure => {
                        // relevant?
                        return Ok(CmdResult::Failure);
                    },
                    _ => {
                        // Please, this is insane #[deny(non_exhaustive_omitted_patterns)]
                        unreachable!();
                    },
                }
            },
        }
    }
}

/// A simple method to run a command on an ssh session and return the stdout/stderr.
pub async fn run_command_capture<
    H: russh::client::Handler,
>(log: &Log, conn: &Handle<H>, command: Vec<String>) -> Result<RunCommandOutput, loga::Error> {
    let mut stdout = vec![];
    let mut stderr = vec![];
    let res = run_command(log, conn, command, |data, ext| {
        match ext {
            Some(1) => {
                stderr.extend_from_slice(&data);
            },
            Some(_) => { },
            None => {
                stdout.extend_from_slice(&data);
            },
        }
    }).await?;
    match res {
        CmdResult::Status(0) => {
            return Ok(RunCommandOutput {
                stderr: stderr,
                stdout: stdout,
            });
        },
        _ => {
            return Err(
                loga::err_with(
                    format!("Command ended with unexpected result: {:?}", res),
                    ea!(stdout = String::from_utf8_lossy(&stdout), stderr = String::from_utf8_lossy(&stderr)),
                ),
            );
        },
    }
}

/// A simple method to run a command on an ssh session. Stderr/stdout are sent to
/// the process's stderr/stdout.
pub async fn run_command_inherit<
    H: russh::client::Handler,
>(log: &Log, conn: &Handle<H>, command: Vec<String>) -> Result<(), loga::Error> {
    let mut stdout_remainder = vec![];
    let mut stderr_remainder = vec![];
    let mut stdout = stdout();
    let mut stderr = stderr();
    match run_command(log, conn, command, |data, ext| {
        let is_stdout;
        match ext {
            None => {
                is_stdout = true;
            },
            Some(1) => {
                is_stdout = false;
            },
            Some(_) => {
                return;
            },
        }
        let mut prev = None;
        for line in data.split(|x| *x == b'\n') {
            if let Some(prev1) = prev {
                if is_stdout {
                    stdout.write_all(&stdout_remainder).ignore();
                    stdout_remainder.clear();
                    stdout.write_all(prev1).ignore();
                } else {
                    stderr.write_all(&stderr_remainder).ignore();
                    stderr_remainder.clear();
                    stderr.write_all(prev1).ignore();
                }
            }
            prev = Some(line);
        }
        if let Some(prev1) = prev {
            if is_stdout {
                stdout_remainder.extend_from_slice(prev1);
            } else {
                stderr_remainder.extend_from_slice(prev1);
            }
        }
    }).await? {
        CmdResult::Status(0) => {
            return Ok(());
        },
        res => {
            return Err(loga::err(format!("Command ended with unexpected result: {:?}", res)));
        },
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum EntryType {
    File,
    Dir,
}

struct Entry {
    type_: EntryType,
    modified: Option<SystemTime>,
    size: Option<u64>,
}

trait TransferTarget {
    async fn list(&self, path: &Path) -> Result<HashMap<OsString, Entry>, loga::Error>;
    async fn remove_tree(&self, log: &Log, path: &Path) -> Result<(), loga::Error>;
    async fn create_dir(&self, log: &Log, path: &Path) -> Result<(), loga::Error>;
    async fn read(&self, path: &Path) -> Result<impl AsyncRead + Unpin, loga::Error>;
    async fn write(&self, log: &Log, path: &Path, source: impl AsyncRead + Unpin) -> Result<(), loga::Error>;
}

struct TargetRemote<'a, H: russh::client::Handler> {
    conn: &'a russh::client::Handle<H>,
    sftp: &'a SftpSession,
}

impl<'a, H: russh::client::Handler> TransferTarget for TargetRemote<'a, H> {
    async fn list(&self, path: &Path) -> Result<HashMap<OsString, Entry>, loga::Error> {
        let mut remote_entries = HashMap::new();
        for remote_entry in self
            .sftp
            .read_dir(path.to_string_lossy())
            .await
            .context_with("Error reading remote directory", ea!(path = path.to_string_lossy()))? {
            let remote_meta = remote_entry.metadata();
            remote_entries.insert(OsString::from(remote_entry.file_name()), Entry {
                type_: if remote_meta.is_regular() {
                    EntryType::File
                } else {
                    EntryType::Dir
                },
                size: remote_meta.size,
                modified: remote_meta.modified().ok(),
            });
        }
        return Ok(remote_entries);
    }

    async fn remove_tree(&self, log: &Log, path: &Path) -> Result<(), loga::Error> {
        run_command_capture(
            log,
            self.conn,
            vec!["rm".to_string(), "-r".to_string(), path.to_string_lossy().to_string()],
        ).await?;
        return Ok(());
    }

    async fn create_dir(&self, log: &Log, path: &Path) -> Result<(), loga::Error> {
        log.log_with(loga::DEBUG, "Creating remote dir", ea!(remote = path.dbg_str()));
        self
            .sftp
            .create_dir(path.to_string_lossy())
            .await
            .context_with("Error creating remote directory", ea!(remote = path.dbg_str()))?;
        return Ok(());
    }

    async fn read(&self, path: &Path) -> Result<impl AsyncRead + Unpin, loga::Error> {
        return Ok(
            self
                .sftp
                .open_with_flags(path.to_string_lossy(), OpenFlags::READ)
                .await
                .context_with("Error opening remote file to download", ea!(remote = path.to_string_lossy()))?,
        );
    }

    async fn write(&self, log: &Log, path: &Path, mut source: impl AsyncRead + Unpin) -> Result<(), loga::Error> {
        log.log_with(loga::DEBUG, "Uploading file", ea!(remote = path.dbg_str()));
        let mut dest =
            self
                .sftp
                .open_with_flags(
                    path
                        .to_str()
                        .context_with(
                            "Couldn't convert remote path to string, required by sftp subsystem",
                            ea!(remote = path.dbg_str()),
                        )?,
                    OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                )
                .await
                .unwrap();
        tokio::io::copy(&mut source, &mut dest).await.context("Error during data transfer")?;
        return Ok(());
    }
}
struct TargetLocal;

impl TransferTarget for TargetLocal {
    async fn list(&self, path: &Path) -> Result<HashMap<OsString, Entry>, loga::Error> {
        let mut out = HashMap::new();
        let mut local_entries =
            read_dir(&path).await.context_with("Error reading local directory", ea!(local = path.dbg_str()))?;
        while let Some(local_entry) =
            local_entries
                .next_entry()
                .await
                .context_with("Error reading entry in directory", ea!(local = path.dbg_str()))? {
            let local_entry_meta =
                local_entry
                    .metadata()
                    .await
                    .context_with("Error reading local metadata", ea!(local = local_entry.path().dbg_str()))?;
            out.insert(local_entry.path().into(), Entry {
                type_: if local_entry_meta.is_dir() {
                    EntryType::Dir
                } else {
                    EntryType::File
                },
                modified: local_entry_meta.modified().ok(),
                size: Some(local_entry_meta.size()),
            });
        }
        return Ok(out);
    }

    async fn remove_tree(&self, log: &Log, path: &Path) -> Result<(), loga::Error> {
        log.log_with(loga::DEBUG, "Deleting local tree", ea!(path = path.dbg_str()));
        remove_dir_all(&path).await.context_with("Failed to sync-remove file", ea!(local = path.dbg_str()))?;
        return Ok(());
    }

    async fn create_dir(&self, log: &Log, path: &Path) -> Result<(), loga::Error> {
        log.log_with(loga::DEBUG, "Creating local dir", ea!(local = path.dbg_str()));
        match create_dir(path).await {
            Ok(_) => (),
            Err(e) => {
                if e.kind() == ErrorKind::AlreadyExists {
                    // nop
                } else {
                    return Err(
                        e.context_with("Failed to create local dir for download", ea!(local = path.dbg_str())),
                    );
                }
            },
        }
        return Ok(());
    }

    async fn read(&self, path: &Path) -> Result<impl AsyncRead + Unpin, loga::Error> {
        return Ok(
            File::open(&path)
                .await
                .context_with("Error opening local file for reading", ea!(local = path.to_string_lossy()))?,
        );
    }

    async fn write(&self, log: &Log, path: &Path, mut source: impl AsyncRead + Unpin) -> Result<(), loga::Error> {
        log.log_with(loga::DEBUG, "Downloading file", ea!(local = path.dbg_str()));
        let mut dest =
            File::create(&path)
                .await
                .context_with("Error opening local file for writing", ea!(path = path.to_string_lossy()))?;
        tokio::io::copy(&mut source, &mut dest)
            .await
            .context_with("Error during data transfer", ea!(local = path.dbg_str()))?;
        return Ok(());
    }
}

async fn transfer_dir(
    log: &Log,
    source_target: &impl TransferTarget,
    dest_target: &impl TransferTarget,
    source: &Path,
    dest: &Path,
    dest_entries: &mut HashMap<OsString, Entry>,
    skip_newer: bool,
    skip_same_size: bool,
    sync: bool,
) -> Result<(), loga::Error> {
    for (source_entry_filename, source_entry) in source_target.list(source).await? {
        transfer(
            log,
            source_target,
            dest_target,
            &source.join(&source_entry_filename),
            source_entry,
            &dest.join(&source_entry_filename),
            dest_entries.remove(&source_entry_filename),
            skip_newer,
            skip_same_size,
            sync,
        )
            .boxed_local()
            .await?;
    }
    return Ok(());
}

async fn transfer_file(
    log: &Log,
    source_target: &impl TransferTarget,
    dest_target: &impl TransferTarget,
    source: &Path,
    dest: &Path,
) -> Result<(), loga::Error> {
    dest_target.write(log, dest, source_target.read(source).await?).await?;
    return Ok(());
}

async fn transfer(
    log: &Log,
    source_target: &impl TransferTarget,
    dest_target: &impl TransferTarget,
    source: &Path,
    source_entry: Entry,
    dest: &Path,
    dest_entry: Option<Entry>,
    skip_newer: bool,
    skip_same_size: bool,
    sync: bool,
) -> Result<(), loga::Error> {
    if let Some(remote_entry) = dest_entry {
        match (source_entry.type_, remote_entry.type_) {
            (EntryType::Dir, EntryType::Dir) => {
                let mut dest_entries = dest_target.list(dest).await?;
                transfer_dir(
                    log,
                    source_target,
                    dest_target,
                    source,
                    dest,
                    &mut dest_entries,
                    skip_newer,
                    skip_same_size,
                    sync,
                ).await?;
                if sync {
                    for (name, _) in dest_entries {
                        dest_target.remove_tree(log, &dest.join(name)).await?;
                    }
                }
            },
            (EntryType::File, EntryType::File) => {
                match (remote_entry.size, source_entry.size) {
                    (Some(remote_size), Some(local_size)) => {
                        if skip_same_size && remote_size == local_size {
                            return Ok(());
                        }
                    },
                    _ => { },
                }
                match (remote_entry.modified, source_entry.modified) {
                    (Some(remote_modified), Some(local_modified)) => {
                        if skip_newer && remote_modified >= local_modified {
                            return Ok(());
                        }
                    },
                    _ => { },
                }
                transfer_file(log, source_target, dest_target, source, dest).await?;
            },
            (_, _) => {
                dest_target.remove_tree(log, dest).await?;
                match source_entry.type_ {
                    EntryType::File => {
                        transfer_file(log, source_target, dest_target, source, dest).await?;
                    },
                    EntryType::Dir => {
                        dest_target.create_dir(log, dest).await?;
                        transfer_dir(
                            log,
                            source_target,
                            dest_target,
                            source,
                            dest,
                            &mut Default::default(),
                            skip_newer,
                            skip_same_size,
                            sync,
                        ).await?;
                    },
                }
                if source_entry.type_ == EntryType::Dir { } else { }
            },
        }
    } else {
        match source_entry.type_ {
            EntryType::File => {
                transfer_file(log, source_target, dest_target, source, dest).await?;
            },
            EntryType::Dir => {
                dest_target.create_dir(log, dest).await?;
                transfer_dir(
                    log,
                    source_target,
                    dest_target,
                    source,
                    dest,
                    &mut Default::default(),
                    skip_newer,
                    skip_same_size,
                    sync,
                ).await?;
            },
        }
    }
    return Ok(());
}

/// Upload a local file to a remote path. If the source is a file, it will be
/// uploaded to the exact remote path.  If the source is a directory, its contents
/// will be uploaded to the remote path, which must be an existing directory. No
/// parent directories will be created.
///
/// If `sync` and the source is a directory, remote files not present locally will
/// be deleted after other files have been uploaded.
pub async fn upload<
    H: russh::client::Handler,
>(
    log: &Log,
    conn: &russh::client::Handle<H>,
    sftp: &SftpSession,
    local: &Path,
    remote: &Path,
    skip_newer: bool,
    skip_same_size: bool,
    sync: bool,
) -> Result<(), loga::Error> {
    let local_meta =
        tokio::fs::metadata(&local)
            .await
            .context_with("Error reading local metadata", ea!(path = local.dbg_str()))?;
    let remote_meta = match sftp.metadata(remote.to_string_lossy()).await {
        Ok(meta) => Some(meta),
        Err(e) => superif!({
            let russh_sftp::client::error::Error::Status(status) = &e else {
                break 'bad;
            };
            if status.status_code != StatusCode::NoSuchFile {
                break 'bad;
            }
            None
        } 'bad {
            return Err(e.context_with("Error reading local metadata", ea!(path = remote.dbg_str())));
        }),
    };
    transfer(
        //. .
        log,
        &TargetLocal,
        &TargetRemote {
            conn: conn,
            sftp: sftp,
        },
        local,
        Entry {
            type_: if local_meta.is_dir() {
                EntryType::Dir
            } else {
                EntryType::File
            },
            modified: local_meta.modified().ok(),
            size: Some(local_meta.size()),
        },
        remote,
        match remote_meta {
            Some(m) => {
                Some(Entry {
                    type_: if m.file_type().is_dir() {
                        EntryType::Dir
                    } else {
                        EntryType::File
                    },
                    modified: m.modified().ok(),
                    size: m.size,
                })
            },
            None => None,
        },
        skip_newer,
        skip_same_size,
        sync,
    ).await?;
    return Ok(());
}

/// Download a remote file to a local path. If the source is a file, it will be
/// downloaded to the exact local path.  If the source is a directory, its contents
/// will be downloaded to the local path, which must be an existing directory. No
/// parent directories will be created.
///
/// If `sync` and the source is a directory, local files not present remotely will
/// be deleted after other files have been downloaded.
pub async fn download<
    H: russh::client::Handler,
>(
    log: &Log,
    conn: &russh::client::Handle<H>,
    sftp: &SftpSession,
    remote: &Path,
    local: &Path,
    skip_newer: bool,
    skip_same_size: bool,
    sync: bool,
) -> Result<(), loga::Error> {
    let remote_meta =
        sftp
            .metadata(remote.to_string_lossy())
            .await
            .context_with("Error reading remote metadata", ea!(path = remote.dbg_str()))?;
    let local_meta = match tokio::fs::metadata(&local).await {
        Ok(meta) => Some(meta),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                None
            },
            _ => {
                return Err(e.context_with("Error reading local metadata", ea!(path = local.dbg_str())));
            },
        },
    };
    transfer(
        //. .
        log,
        &TargetRemote {
            sftp: sftp,
            conn: conn,
        },
        &TargetLocal,
        remote,
        Entry {
            type_: if remote_meta.is_dir() {
                EntryType::Dir
            } else {
                EntryType::File
            },
            modified: remote_meta.modified().ok(),
            size: remote_meta.size,
        },
        local,
        match local_meta {
            Some(m) => Some(Entry {
                type_: if m.is_dir() {
                    EntryType::Dir
                } else {
                    EntryType::File
                },
                modified: m.modified().ok(),
                size: Some(m.size()),
            }),
            None => None,
        },
        skip_newer,
        skip_same_size,
        sync,
    ).await?;
    return Ok(());
}
