use {
    aargvark::Aargvark,
    loga::{
        ea,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    path_absolutize::Absolutize,
    russh::{
        ChannelMsg,
        Pty,
    },
    russh_sftp::client::SftpSession,
    spaghettinuum::utils::ssh_util::{
        download,
        quote,
        run_command,
        ssh_connect,
        upload,
        SshConn,
        SshConnectHandler,
    },
    std::{
        env,
        path::PathBuf,
    },
    termion::raw::IntoRawMode,
    tokio::{
        fs::create_dir_all,
        io::{
            stdin,
            stdout,
            AsyncReadExt,
            AsyncWriteExt,
        },
    },
};

#[derive(Aargvark)]
pub struct SshShell {
    /// User, defaults to root.
    #[vark(flag = "-u", flag = "--user")]
    pub user: Option<String>,
    /// Host to connect to.
    pub host: String,
    /// Ssh port, defaults to 22.
    #[vark(flag = "-p", flag = "--port")]
    pub port: Option<u16>,
    /// Use a specific key file instead of whatever's automatically detected.
    #[vark(flag = "-i", flag = "--keyfile")]
    pub key: Option<PathBuf>,
    /// Run a command and exit.
    pub command: Option<Vec<String>>,
}

#[derive(Aargvark)]
pub enum Preposition {
    /// Place the file or directory as a child of the destination path, using the
    /// filename of the source path to name the destination file.
    In,
    /// Place the file or directory at the exact destination path. If a file, the
    /// destination must not exist or be a file. If a directory, the destination must
    /// not exist or be a directory, and the contents of the source will be created in
    /// the destination.
    At,
}

#[derive(Aargvark)]
pub struct SshDownload {
    // User, defaults to root.
    #[vark(flag = "-u", flag = "--user")]
    pub user: Option<String>,
    pub host: String,
    #[vark(flag = "-p", flag = "--port")]
    // Ssh port, defaults to 22.
    pub port: Option<u16>,
    /// Use a specific key file instead of whatever's automatically detected.
    #[vark(flag = "-i", flag = "--keyfile")]
    pub key: Option<PathBuf>,
    /// Absolute path to a file or directory to download.
    pub remote: PathBuf,
    pub preposition: Preposition,
    /// Path of where to place the file on the local host.
    pub local: PathBuf,
    /// Create the parent directories on the destination if they don't already exist.
    pub create_dirs: Option<()>,
    /// By default, newer files in the destination are skipped. This flag disables that
    /// behavior.
    pub no_skip_newer: Option<()>,
    /// When transfering a directory, delete files in the destination that aren't in
    /// the source so that the directory contents are equal afterwards.
    pub sync: Option<()>,
}

#[derive(Aargvark)]
pub struct SshUpload {
    // User, defaults to root.
    #[vark(flag = "-u", flag = "--user")]
    pub user: Option<String>,
    pub host: String,
    #[vark(flag = "-p", flag = "--port")]
    // Ssh port, defaults to 22.
    pub port: Option<u16>,
    /// Path to a file or directory to upload.
    pub local: PathBuf,
    pub preposition: Preposition,
    /// Absolute path of where to place the file on the remote.
    pub remote: PathBuf,
    /// Create the parent directories on the destination if they don't already exist.
    pub create_dirs: Option<()>,
    /// By default, newer files in the destination are skipped. This flag disables that
    /// behavior.
    pub no_skip_newer: Option<()>,
    /// When transfering a directory, delete files in the destination that aren't in
    /// the source so that the directory contents are equal afterwards.
    pub sync: Option<()>,
}

#[derive(Aargvark)]
#[vark(break_help)]
pub enum Command {
    Shell(SshShell),
    Download(SshDownload),
    Upload(SshUpload),
}

#[derive(Aargvark)]
pub struct Args {
    /// Use a specific key file instead of whatever's automatically detected.
    #[vark(flag = "--keyfile", flag = "-i")]
    key: Option<PathBuf>,
    command: Command,
}

pub async fn run(log: &Log, args: Args) -> Result<(), loga::Error> {
    let key = args.key;
    match args.command {
        Command::Shell(args) => {
            struct Inner(SshShell);

            impl SshConnectHandler for Inner {
                async fn run(self, conn: SshConn) -> Result<(), loga::Error> {
                    let mut session = conn.channel_open_session().await.context("Error opening command channel")?;
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

            ssh_connect(
                log,
                args.user.clone(),
                format!("{}.s", args.host),
                args.port,
                key.clone(),
                Inner(args),
            ).await?;
        },
        Command::Download(args) => {
            struct Inner(SshDownload);

            impl SshConnectHandler for Inner {
                async fn run(self, conn: SshConn) -> Result<(), loga::Error> {
                    let config = self.0;

                    // Prep (connection)
                    let sftp_session = conn.channel_open_session().await.context("Error opening sftp channel")?;
                    sftp_session.request_subsystem(true, "sftp").await?;
                    let sftp = SftpSession::new(sftp_session.into_stream()).await.unwrap();

                    // Prep (calc)
                    let local = config.local.absolutize().context("Invalid local path")?;
                    let local = match config.preposition {
                        Preposition::In => local.join(
                            config
                                .remote
                                .file_name()
                                .context("File name of remote path unknown, can't form local path (`in`)")?,
                        ),
                        Preposition::At => local.to_path_buf(),
                    };
                    let str_remote =
                        config
                            .remote
                            .to_str()
                            .context_with(
                                "Error converting remote path to utf-8, required by sftp subsystem",
                                ea!(path = config.remote.dbg_str()),
                            )?;

                    // Prep (mutation)
                    let source_meta =
                        sftp
                            .metadata(str_remote)
                            .await
                            .context_with("Error reading metadata for remote file", ea!(path = str_remote))?;
                    if config.create_dirs.is_some() {
                        let create_dirs = if source_meta.is_dir() {
                            &local
                        } else {
                            local
                                .parent()
                                .context_with(
                                    "Absolute local path has no parent",
                                    ea!(path = local.to_string_lossy()),
                                )?
                        };
                        create_dir_all(create_dirs)
                            .await
                            .context_with(
                                "Error ensuring parent directories for destination",
                                ea!(path = create_dirs.to_string_lossy()),
                            )?;
                    }

                    // Transfer
                    download(
                        &sftp,
                        &config.remote,
                        source_meta.is_dir(),
                        &local,
                        !config.no_skip_newer.is_some(),
                        config.sync.is_some(),
                    ).await?;
                    return Ok(());
                }
            }

            ssh_connect(
                log,
                args.user.clone(),
                format!("{}.s", args.host),
                args.port,
                key.clone(),
                Inner(args),
            ).await?;
        },
        Command::Upload(args) => {
            struct Inner(SshUpload);

            impl SshConnectHandler for Inner {
                async fn run(self, conn: SshConn) -> Result<(), loga::Error> {
                    let config = self.0;

                    // Prep (conn)
                    let mut session = conn.channel_open_session().await.context("Error opening command channel")?;
                    let sftp_session = conn.channel_open_session().await.context("Error opening sftp channel")?;
                    sftp_session.request_subsystem(true, "sftp").await?;
                    let sftp = SftpSession::new(sftp_session.into_stream()).await.unwrap();

                    // Prep ( calc)
                    let remote = config.remote.absolutize().context("Invalid remote path")?;
                    let remote = match config.preposition {
                        Preposition::In => remote.join(
                            PathBuf::from(
                                config
                                    .local
                                    .file_name()
                                    .context("File name of local path unknown, can't form remote path (`in`)")?,
                            ),
                        ),
                        Preposition::At => remote.to_path_buf(),
                    };

                    // Prep (mutation)
                    let source_meta =
                        tokio::fs::metadata(&config.local)
                            .await
                            .context_with(
                                "Error reading metadata for local file",
                                ea!(path = config.local.dbg_str()),
                            )?;
                    if config.create_dirs.is_some() {
                        let create_dirs = if source_meta.is_dir() {
                            &remote
                        } else {
                            remote
                                .parent()
                                .context_with(
                                    "Absolute remote path has no parent",
                                    ea!(path = remote.to_string_lossy()),
                                )?
                        };
                        run_command(
                            &mut session,
                            vec![
                                "mkdir".to_string(),
                                "-p".to_string(),
                                create_dirs
                                    .to_str()
                                    .context_with(
                                        "Couldn't convert remote parent path to string, required by sftp subsystem",
                                        ea!(path = config.remote.to_string_lossy()),
                                    )?
                                    .to_string()
                            ],
                        ).await?;
                    }

                    // Transfer
                    upload(
                        &mut session,
                        &sftp,
                        &config.local,
                        source_meta.is_dir(),
                        &remote,
                        !config.no_skip_newer.is_some(),
                        config.sync.is_some(),
                    ).await?;
                    return Ok(());
                }
            }

            ssh_connect(
                log,
                args.user.clone(),
                format!("{}.s", args.host),
                args.port,
                key.clone(),
                Inner(args),
            ).await?;
        },
    }
    return Ok(());
}
