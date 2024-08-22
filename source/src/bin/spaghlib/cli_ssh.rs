use {
    itertools::Itertools,
    loga::{
        ea,
        ErrContext,
        Log,
        ResultContext,
    },
    path_absolutize::Absolutize,
    russh::{
        client::Msg,
        Channel,
        ChannelMsg,
        Disconnect,
        Pty,
    },
    russh_keys::{
        parse_public_key_base64,
    },
    russh_sftp::{
        client::SftpSession,
        protocol::OpenFlags,
    },
    spaghettinuum::{
        bb,
        interface::stored::record,
        resolving::{
            resolve,
            system_resolver_url_pairs,
        },
        ta_res,
    },
    std::{
        env,
        io::ErrorKind,
        net::{
            IpAddr,
            SocketAddr,
        },
        path::PathBuf,
        sync::Arc,
    },
    termion::raw::IntoRawMode,
    tokio::{
        fs::{
            create_dir_all,
            File,
        },
        io::{
            stdin,
            stdout,
            AsyncReadExt,
            AsyncWriteExt,
        },
    },
};

pub mod args {
    use {
        aargvark::{
            Aargvark,
            AargvarkFromStr,
            HelpPattern,
            HelpPatternElement,
        },
        std::path::PathBuf,
    };

    #[derive(Clone)]
    pub struct StrSocketAddr {
        pub host: String,
        pub port: Option<u16>,
    }

    impl AargvarkFromStr for StrSocketAddr {
        fn from_str(mut host: &str) -> Result<Self, String> {
            let port;
            if let Some((host1, port1)) = host.rsplit_once(":") {
                let port1 = u16::from_str(port1).map_err(|s| format!("Couldn't parse port as number: {}", s))?;
                port = Some(port1);
                host = host1;
            } else {
                port = None;
            }
            return Ok(Self {
                host: host.to_string(),
                port: port,
            });
        }

        fn build_help_pattern(_state: &mut aargvark::HelpState) -> HelpPattern {
            return HelpPattern(vec![HelpPatternElement::Type("HOST[:PORT]".to_string())]);
        }
    }

    #[derive(Clone)]
    pub struct StrUserSocketAddr {
        pub user: Option<String>,
        pub host: String,
        pub port: Option<u16>,
    }

    impl AargvarkFromStr for StrUserSocketAddr {
        fn from_str(mut host: &str) -> Result<Self, String> {
            let user;
            if let Some((user1, host1)) = host.split_once("@") {
                user = Some(user1.to_string());
                host = host1;
            } else {
                user = None;
            }
            let port;
            if let Some((host1, port1)) = host.rsplit_once(":") {
                let port1 = u16::from_str(port1).map_err(|s| format!("Couldn't parse port as number: {}", s))?;
                port = Some(port1);
                host = host1;
            } else {
                port = None;
            }
            return Ok(Self {
                user: user,
                host: host.to_string(),
                port: port,
            });
        }

        fn build_help_pattern(_state: &mut aargvark::HelpState) -> HelpPattern {
            return HelpPattern(vec![HelpPatternElement::Type("[USER@]HOST[:PORT]".to_string())]);
        }
    }

    #[derive(Aargvark)]
    pub struct SshShell {
        pub host: StrUserSocketAddr,
        /// Use a specific key file instead of whatever's automatically detected.
        pub key: Option<PathBuf>,
        pub command: Option<Vec<String>>,
    }

    #[derive(Aargvark)]
    pub struct SshDownload {
        pub host: StrUserSocketAddr,
        /// Use a specific key file instead of whatever's automatically detected.
        pub key: Option<PathBuf>,
        pub remote: PathBuf,
        pub local: PathBuf,
        pub create_dirs: Option<()>,
    }

    #[derive(Aargvark)]
    pub struct SshUpload {
        pub host: StrUserSocketAddr,
        /// Use a specific key file instead of whatever's automatically detected.
        pub key: Option<PathBuf>,
        pub local: PathBuf,
        pub remote: PathBuf,
        pub create_dirs: Option<()>,
    }

    #[derive(Aargvark)]
    pub enum Ssh {
        Shell(SshShell),
        Download(SshDownload),
        Upload(SshUpload),
    }
}

struct Handler {
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

trait SshInner {
    async fn run(self, session: Channel<Msg>) -> Result<(), loga::Error>;
}

async fn connect(
    log: &Log,
    host: args::StrUserSocketAddr,
    key: Option<PathBuf>,
    inner: impl SshInner,
) -> Result<(), loga::Error> {
    let (ips, mut additional_records) =
        resolve(log, &system_resolver_url_pairs(log)?, &host.host, &[record::ssh_record::KEY])
            .await
            .context("Error resolving host")?;
    let mut host_keys = vec![];
    bb!{
        let Some(r) = additional_records.remove(record::ssh_record::KEY) else {
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
                    bb!{
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
    match russh_config::parse_home(&host.host) {
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
                .map(|i| SocketAddr::new(i, host.port.unwrap_or(config_port)))
                .collect_vec()
                .as_slice(),
            Handler { host_keys: host_keys },
        )
            .await
            .context("Error connecting to remote host")?;
    bb!{
        'authenticated _;
        let user = host.user.or(config_user).unwrap_or("root".to_string());
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
    let res = async {
        ta_res!(());
        let session = conn.channel_open_session().await.context("Error opening command channel")?;
        inner.run(session).await?;
        return Ok(());
    }.await;
    conn.disconnect(Disconnect::ByApplication, "", "English").await.log(log, loga::DEBUG, "Error disconnecting");
    return res;
}

fn quote(command: Vec<String>) -> String {
    return command.iter().map(|x| shell_escape::escape(x.into())).join(" ");
}

pub async fn run(log: &Log, config: args::Ssh) -> Result<(), loga::Error> {
    match config {
        args::Ssh::Shell(config) => {
            struct Inner(args::SshShell);

            impl SshInner for Inner {
                async fn run(self, mut session: Channel<Msg>) -> Result<(), loga::Error> {
                    let config = self.0;
                    let _raw_term = std::io::stdout().into_raw_mode().context("Error putting terminal in raw mode")?;
                    let (w, h) = termion::terminal_size().context("Error determining terminal size")?;
                    session.request_pty(
                        false,
                        &env::var("TERM").unwrap_or("xterm".into()),
                        w as u32,
                        h as u32,
                        0,
                        0,
                        // ideally you want to pass the actual terminal modes here
                        &[(Pty::ECHO, 1), (Pty::TTY_OP_ISPEED, 14400), (Pty::TTY_OP_OSPEED, 14400)],
                    ).await.context("Error requesting remote pty")?;
                    if let Some(command) = config.command {
                        session.exec(true, quote(command).into_bytes()).await.context("Error running command")?;
                    } else {
                        session.request_shell(true).await.context("Error running command")?;
                    }
                    let mut stdin = stdin();
                    let mut stdout = stdout();
                    let mut buf = vec![
                        0;
                        1024
                    ];
                    let mut stdin_closed = false;
                    loop {
                        tokio::select!{
                            r = stdin.read(&mut buf),
                            if ! stdin_closed => {
                                match r {
                                    Ok(0) => {
                                        stdin_closed = true;
                                        session.eof().await.context("Error while closing channel due to stdin EOF")?;
                                    },
                                    Ok(n) => session
                                        .data(&buf[..n])
                                        .await
                                        .context("Error sending stdin data to remote")?,
                                    Err(e) => return Err(e.context("Error while reading stdin")),
                                };
                            },
                            Some(msg) = session.wait() => {
                                match msg {
                                    ChannelMsg::Data { ref data } => {
                                        stdout
                                            .write_all(data)
                                            .await
                                            .context("Error while writing received data to stdout")?;
                                        stdout.flush().await.context("Error while flushing stdout")?;
                                    },
                                    ChannelMsg::ExitStatus { exit_status } => {
                                        if !stdin_closed {
                                            session
                                                .eof()
                                                .await
                                                .context("Error while closing channel due to remote exit")?;
                                        }
                                        if exit_status != 0 {
                                            return Err(loga::err("Command or shell exited with non-0 exit code"));
                                        }
                                        break;
                                    },
                                    _ => { },
                                }
                            },
                        }
                    }
                    return Ok(());
                }
            }

            connect(log, config.host.clone(), config.key.clone(), Inner(config)).await?;
        },
        args::Ssh::Download(config) => {
            struct Inner(args::SshDownload);

            impl SshInner for Inner {
                async fn run(self, session: Channel<Msg>) -> Result<(), loga::Error> {
                    let config = self.0;
                    session.request_subsystem(true, "sftp").await?;
                    let local = config.local.absolutize().context("Invalid local path")?;
                    if config.create_dirs.is_some() {
                        let parent =
                            local
                                .parent()
                                .context_with(
                                    "Absolute local path has no parent",
                                    ea!(path = local.to_string_lossy()),
                                )?;
                        create_dir_all(parent)
                            .await
                            .context_with(
                                "Error ensuring parent directories for destination",
                                ea!(path = parent.to_string_lossy()),
                            )?;
                    }
                    let sftp = SftpSession::new(session.into_stream()).await.unwrap();
                    let mut source =
                        sftp
                            .open_with_flags(
                                config
                                    .remote
                                    .to_str()
                                    .context_with(
                                        "Couldn't convert remote path to string, required by sftp subsystem",
                                        ea!(path = config.remote.to_string_lossy()),
                                    )?,
                                OpenFlags::READ,
                            )
                            .await
                            .unwrap();
                    let mut dest =
                        File::create(&local)
                            .await
                            .context_with(
                                "Error opening local file for writing",
                                ea!(path = local.to_string_lossy()),
                            )?;
                    tokio::io::copy(&mut source, &mut dest).await.context("Error during data transfer")?;
                    return Ok(());
                }
            }

            connect(log, config.host.clone(), config.key.clone(), Inner(config)).await?;
        },
        args::Ssh::Upload(config) => {
            struct Inner(args::SshUpload);

            impl SshInner for Inner {
                async fn run(self, mut session: Channel<Msg>) -> Result<(), loga::Error> {
                    let config = self.0;
                    let mut source =
                        File::open(&config.local)
                            .await
                            .context_with(
                                "Error opening local file for reading",
                                ea!(path = config.local.to_string_lossy()),
                            )?;
                    session.request_subsystem(true, "sftp").await?;
                    let remote = config.remote.absolutize().context("Invalid remote path")?;
                    if config.create_dirs.is_some() {
                        let parent =
                            remote
                                .parent()
                                .context_with(
                                    "Absolute remote path has no parent",
                                    ea!(path = remote.to_string_lossy()),
                                )?;
                        let command =
                            quote(
                                vec![
                                    "mkdir".to_string(),
                                    "-p".to_string(),
                                    parent
                                        .to_str()
                                        .context_with(
                                            "Couldn't convert remote parent path to string, required by sftp subsystem",
                                            ea!(path = config.remote.to_string_lossy()),
                                        )?
                                        .to_string()
                                ],
                            );
                        session
                            .exec(true, command.as_bytes())
                            .await
                            .context_with("Error running command", ea!(command = command))?;
                        loop {
                            match session.wait().await {
                                None => {
                                    return Ok(());
                                },
                                Some(ChannelMsg::ExitStatus { exit_status }) => {
                                    if exit_status != 0 {
                                        return Err(
                                            loga::err_with(
                                                "Command exited with non-0 exit code",
                                                ea!(command = command),
                                            ),
                                        );
                                    }
                                    break;
                                },
                                _ => { },
                            }
                        }
                    }
                    let sftp = SftpSession::new(session.into_stream()).await.unwrap();
                    let mut dest =
                        sftp
                            .open_with_flags(
                                remote
                                    .to_str()
                                    .context_with(
                                        "Couldn't convert remote path to string, required by sftp subsystem",
                                        ea!(path = config.remote.to_string_lossy()),
                                    )?,
                                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                            )
                            .await
                            .unwrap();
                    tokio::io::copy(&mut source, &mut dest).await.context("Error during data transfer")?;
                    return Ok(());
                }
            }

            connect(log, config.host.clone(), config.key.clone(), Inner(config)).await?;
        },
    }
    return Ok(());
}
