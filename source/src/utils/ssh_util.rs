use {
    crate::{
        interface::stored::record,
        resolving::{
            resolve,
            default_resolver_url_pairs,
        },
    },
    flowcontrol::{
        shed,
        superif,
    },
    futures::FutureExt,
    itertools::Itertools,
    loga::{
        ea,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    russh::{
        client::{
            Handle,
            Msg,
        },
        Channel,
        ChannelMsg,
        Disconnect,
    },
    russh_keys::parse_public_key_base64,
    russh_sftp::{
        client::SftpSession,
        protocol::OpenFlags,
    },
    std::{
        collections::{
            HashMap,
        },
        ffi::OsString,
        io::ErrorKind,
        net::{
            IpAddr,
            SocketAddr,
        },
        path::{
            Path,
            PathBuf,
        },
        sync::Arc,
        time::SystemTime,
    },
    tokio::fs::{
        create_dir,
        read_dir,
        remove_dir_all,
        File,
    },
};

#[doc(hidden)]
pub struct Handler {
    host_keys: Vec<russh_keys::key::PublicKey>,
}

#[async_trait::async_trait]
impl russh::client::Handler for Handler {
    type Error = loga::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        for k in &self.host_keys {
            if k == server_public_key {
                return Ok(true);
            }
        }
        return Ok(false);
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
                russh_keys::load_secret_key(
                    &key,
                    None,
                ).context_with("Error loading specified keypair", ea!(path = key.to_string_lossy()))?;
            let pubkey = key.clone_public_key().context("Error getting public key from keypair")?;
            log.log_with(loga::DEBUG, "Attempting auth via command line keypair", ea!(key = pubkey.fingerprint()));
            if conn
                .authenticate_publickey(&user, Arc::new(key))
                .await
                .context("Error attempting auth method via specified key")? {
                break 'authenticated;
            } else {
                return Err(loga::err("Key provided on command line was rejected"));
            }
        }
        match russh_keys::agent::client::AgentClient::connect_env().await {
            Ok(mut agent) => {
                let identities =
                    agent.request_identities().await.context("Error requesting identities from SSH agent")?;
                for key in identities {
                    log.log_with(loga::DEBUG, "Attempting auth via SSH agent key", ea!(key = key.fingerprint()));
                    let res;
                    (agent, res) = conn.authenticate_future(&user, key, agent).await;
                    if res.context("Error attempting auth method via SSH agent")? {
                        break 'authenticated;
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
                    russh_keys::load_secret_key(
                        &key,
                        None,
                    ).context_with("Error loading discovered keypair", ea!(path = key.to_string_lossy()))?;
                let pubkey = key.clone_public_key().context("Error getting public key from keypair")?;
                log.log_with(loga::DEBUG, "Attempting auth via discovered keypair", ea!(key = pubkey.fingerprint()));
                if conn
                    .authenticate_publickey(&user, Arc::new(key))
                    .await
                    .context("Error attempting auth method via specified key")? {
                    break 'authenticated;
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

/// A simple method to run a command on an ssh session.
pub async fn run_command(session: &mut Channel<Msg>, command: Vec<String>) -> Result<(), loga::Error> {
    let command = quote(command);
    session.exec(true, command.as_bytes()).await.context_with("Error running command", ea!(command = command))?;
    loop {
        match session.wait().await {
            None => {
                return Ok(());
            },
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                if exit_status != 0 {
                    return Err(loga::err_with("Command exited with non-0 exit code", ea!(command = command)));
                }
                return Ok(());
            },
            _ => { },
        }
    }
}

/// Upload a local file to a remote path. If the source is a file, it will be
/// uploaded to the exact remote path.  If the source is a directory, its contents
/// will be uploaded to the remote path, which must be an existing directory. No
/// parent directories will be created.
///
/// You need to open two sessions: one session to run commands (like `rm -f`) and
/// one to turn into an sftp session.
///
/// If `sync` and the source is a directory, remote files not present locally will
/// be deleted after other files have been uploaded.
pub async fn upload(
    session: &mut SshSess,
    sftp: &SftpSession,
    local: &Path,
    local_is_dir: bool,
    remote: &Path,
    skip_newer: bool,
    sync: bool,
) -> Result<(), loga::Error> {
    if local_is_dir {
        // Get remote state
        struct RemoteEntry {
            modified: SystemTime,
        }

        let mut remote_entries = if !sync && !skip_newer {
            HashMap::new()
        } else {
            let remote_str =
                remote
                    .to_str()
                    .context_with(
                        "Sftp requires utf-8 paths but remote path is not utf-8",
                        ea!(path = remote.dbg_str()),
                    )?;
            match sftp.read_dir(remote_str).await {
                Ok(d) => {
                    let mut remote_entries = HashMap::new();
                    for remote_entry in d {
                        remote_entries.insert(
                            OsString::from(remote_entry.file_name()),
                            RemoteEntry {
                                modified: remote_entry
                                    .metadata()
                                    .modified()
                                    .context_with(
                                        "Error reading remote file modified time",
                                        ea!(path = remote.join(remote_entry.file_name()).dbg_str()),
                                    )?,
                            },
                        );
                    }
                    remote_entries
                },
                Err(e) => superif!({
                    let russh_sftp::client::error::Error::Status(s) = &e else {
                        break 'reraise;
                    };
                    let russh_sftp::protocol::StatusCode::NoSuchFile = &s.status_code else {
                        break 'reraise;
                    };
                    sftp
                        .create_dir(remote_str)
                        .await
                        .context_with("Error creating remote directory", ea!(path = remote.dbg_str()))?;
                    HashMap::new()
                } 'reraise {
                    return Err(e.context_with("Error reading remote directory", ea!(path = remote.dbg_str())));
                }),
            }
        };

        // Upload files
        let mut local_entries =
            read_dir(&local).await.context_with("Error reading local directory", ea!(path = local.dbg_str()))?;
        while let Some(local_entry) =
            local_entries
                .next_entry()
                .await
                .context_with("Error reading entry in directory", ea!(dir = local.dbg_str()))? {
            let local_meta =
                local_entry
                    .metadata()
                    .await
                    .context_with("Error reading local metadata", ea!(path = local_entry.path().dbg_str()))?;
            let remote_entry = remote_entries.remove(&local_entry.file_name());
            if skip_newer && remote_entry.is_some() &&
                remote_entry.unwrap().modified >
                    local_meta
                        .modified()
                        .context_with(
                            "Error reading local file modified time",
                            ea!(path = local_entry.path().dbg_str()),
                        )? {
                continue;
            }
            upload(
                session,
                sftp,
                &local.join(local_entry.file_name()),
                local_entry
                    .file_type()
                    .await
                    .context_with(
                        "Error getting local directory entry type",
                        ea!(path = local_entry.path().dbg_str()),
                    )?
                    .is_dir(),
                &remote.join(local_entry.file_name()),
                skip_newer,
                sync,
            )
                .boxed_local()
                .await?;
        }

        // If syncing, delete old remote files
        if sync {
            for (name, _) in remote_entries {
                let path = remote.join(name);
                let str_path =
                    path
                        .to_str()
                        .context_with(
                            "Remote path to recursively delete is invalid utf-8, but sftp requires utf-8 paths",
                            ea!(path = path.dbg_str()),
                        )?;
                run_command(session, vec!["rm".to_string(), "-r".to_string(), str_path.to_string()]).await?;
            }
        }
    } else {
        let mut source =
            File::open(&local)
                .await
                .context_with("Error opening local file for reading", ea!(path = local.to_string_lossy()))?;
        let mut dest =
            sftp
                .open_with_flags(
                    remote
                        .to_str()
                        .context_with(
                            "Couldn't convert remote path to string, required by sftp subsystem",
                            ea!(path = remote.dbg_str()),
                        )?,
                    OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                )
                .await
                .unwrap();
        tokio::io::copy(&mut source, &mut dest).await.context("Error during data transfer")?;
    }
    return Ok(());
}

/// Download a remote file to a local path. If the source is a file, it will be
/// downloaded to the exact local path.  If the source is a directory, its contents
/// will be downloaded to the local path, which must be an existing directory. No
/// parent directories will be created.
///
/// You need to open two sessions: one session to run commands (like `rm -f`) and
/// one to turn into an sftp session.
///
/// If `sync` and the source is a directory, local files not present remotely will
/// be deleted after other files have been downloaded.
pub async fn download(
    sftp: &SftpSession,
    remote: &Path,
    remote_is_dir: bool,
    local: &Path,
    skip_newer: bool,
    sync: bool,
) -> Result<(), loga::Error> {
    let str_remote =
        remote
            .to_str()
            .context_with(
                "Couldn't convert remote path to string, required by sftp subsystem",
                ea!(path = remote.to_string_lossy()),
            )?;
    if remote_is_dir {
        struct LocalEntry {
            modified: SystemTime,
        }

        let mut local_entries = if !sync && !skip_newer {
            HashMap::new()
        } else {
            match create_dir(local).await {
                Ok(_) => (),
                Err(e) => {
                    if e.kind() == ErrorKind::AlreadyExists {
                        // nop
                    } else {
                        return Err(
                            e.context_with("Failed to create local dir for download", ea!(path = local.dbg_str())),
                        );
                    }
                },
            }
            let mut local_entries = HashMap::new();
            let mut local_entries1 =
                read_dir(local)
                    .await
                    .context_with("Error reading local dir for sync", ea!(path = local.dbg_str()))?;
            while let Some(entry) =
                local_entries1
                    .next_entry()
                    .await
                    .context_with("Error reading entry from local directory for sync", ea!(path = local.dbg_str()))? {
                let meta = entry.metadata().await.context("Error reading local file metadata")?;
                local_entries.insert(
                    entry.file_name(),
                    LocalEntry { modified: meta.modified().context("Error reading local file time")? },
                );
            }
            local_entries
        };
        for remote_entry in sftp
            .read_dir(str_remote)
            .await
            .context_with("Error reading remote directory", ea!(path = str_remote))? {
            let local_entry = local_entries.remove(&OsString::from(remote_entry.file_name()));
            let child_remote = remote.join(remote_entry.file_name());
            if skip_newer && local_entry.is_some() &&
                local_entry.unwrap().modified >
                    remote_entry
                        .metadata()
                        .modified()
                        .context_with("Error reading remote file modified time", ea!(path = child_remote.dbg_str()))? {
                continue;
            }
            download(
                sftp,
                &child_remote,
                remote_entry.file_type().is_dir(),
                &local.join(remote_entry.file_name()),
                skip_newer,
                sync,
            )
                .boxed_local()
                .await?;
        }
        if sync {
            for (name, _entry) in local_entries {
                let path = remote.join(name);
                remove_dir_all(&path).await.context_with("Failed to sync-remove file", ea!(path = path.dbg_str()))?;
            }
        }
    } else {
        let mut source =
            sftp
                .open_with_flags(str_remote, OpenFlags::READ)
                .await
                .context_with("Error opening remote file to download", ea!(path = str_remote))?;
        let mut dest =
            File::create(&local)
                .await
                .context_with("Error opening local file for writing", ea!(path = local.to_string_lossy()))?;
        tokio::io::copy(&mut source, &mut dest)
            .await
            .context_with("Error during data transfer", ea!(remote = str_remote, local = local.dbg_str()))?;
    }
    return Ok(());
}
