use {
    aargvark::{
        vark,
        Aargvark,
        AargvarkFile,
    },
    flowcontrol::{
        shed,
        superif,
        ta_return,
    },
    loga::{
        ea,
        fatal,
        DebugDisplay,
        Log,
        ResultContext,
    },
    openpgp_card_rpgp::CardSlot,
    path_absolutize::Absolutize,
    pcsc::Context,
    pgp::Deserializable,
    rand::{
        prelude::SliceRandom,
        thread_rng,
    },
    serde::{
        de::DeserializeOwned,
        Deserialize,
    },
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        fs::{
            create_dir_all,
            read,
            OpenOptions,
        },
        io::{
            copy,
            Write,
        },
        os::unix::fs::OpenOptionsExt,
        path::{
            Path,
            PathBuf,
        },
        process::{
            Command,
            Stdio,
        },
        thread::sleep,
        time::Duration,
    },
};

const OUTER_UUID: &'static str = "3d02cfd4-968a-4fe4-a2a0-fe84614485f6";
const INNER_UUID: &'static str = "0afee777-4fca-45c6-9bed-64bf3091536b";

#[derive(Aargvark)]
#[vark(placeholder = "KEY-MODE")]
enum SharedImageKeyMode {
    /// The contents of a text (utf8) file are used as the password.
    File(AargvarkFile),
    /// `systemd-ask-password` will be used to query the password. The volume will be
    /// initialized/unlocked with the password.
    Password,
}

#[derive(Aargvark)]
struct SharedImageArgs {
    /// How to unlock the volume
    #[vark(flag = "--key-mode")]
    key_mode: SharedImageKeyMode,
}

#[derive(Aargvark)]
enum PinMode {
    /// Use the default PIN (`123456`)
    FactoryDefault,
    /// Use a numeric PIN entry, with a scrambled keypad prompt. Press the numpad keys
    /// that correspond positionally to the numbers displayed in the prompt.
    ///
    /// This accepts presses from the blocks (starting from the top left, left to
    /// right, top to bottom): `789456123` `uiojklm,.` or `wersdfxcv`.
    Numpad,
    /// Request an alphanumeric PIN.
    Text,
}

#[derive(Aargvark)]
#[vark(placeholder = "KEY-MODE")]
enum PrivateImageKeyMode {
    /// A GPG smartcard is used to decrypt a key file which is then used to
    /// initialize/unlock the volume. A prompt will be written to all system terminals.
    /// If your NFC reader has a light, the light will come on when it wants to unlock
    /// the key.
    #[cfg(feature = "smartcard")]
    Smartcard {
        /// How to get the PIN.
        pin: PinMode,
    },
}

#[derive(Aargvark)]
struct PrivateImageArgs {
    /// The location of the key to use to initialize/unlock the volume.
    ///
    /// The key file should be an encrypted utf-8 string. Start and end whitespace will
    /// be stripped.
    #[vark(flag = "--key")]
    key_path: PathBuf,
    /// How to unlock the key file
    #[vark(flag = "--key-mode")]
    key_mode: PrivateImageKeyMode,
    /// Additional data to decrypt. This will be written to
    /// `/run/volumesetup_decrypted`.
    decrypt: Option<PathBuf>,
}

#[derive(Aargvark)]
#[vark(break_help)]
enum EncryptionMode {
    /// Disk is unencrypted.
    None,
    /// A password is used directly to encrypt the disk
    SharedImage(SharedImageArgs),
    /// A password in an encrypted file stored in the image is used to encrypt the disk
    PrivateImage(PrivateImageArgs),
}

#[derive(Aargvark)]
struct Args {
    debug: Option<()>,
    /// Override the default UUID.
    uuid: Option<String>,
    /// How encryption should be handled.  Defaults to unencrypted.
    encryption: Option<EncryptionMode>,
    /// The mount point of the volume.  Defaults to `/mnt/persistent`.
    mountpoint: Option<PathBuf>,
    /// Ensure these directories (and parents) relative to the mountdir once it's
    /// mounted.
    create_dirs: Option<Vec<PathBuf>>,
}

fn from_utf8(data: Vec<u8>) -> Result<String, loga::Error> {
    return Ok(
        String::from_utf8(
            data,
        ).map_err(
            |e| loga::err_with(
                "Received bytes are not valid utf-8",
                ea!(bytes = String::from_utf8_lossy(&e.as_bytes())),
            ),
        )?,
    );
}

struct SimpleCommand<'a>(&'a mut Command);

impl<'a> SimpleCommand<'a> {
    fn run(&mut self) -> Result<(), loga::Error> {
        let log = Log::new().fork(ea!(command = self.0.dbg_str()));
        self.0.stdout(std::process::Stdio::piped());
        self.0.stderr(std::process::Stdio::piped());
        let o = self.0.output().stack_context(&log, "Failed to start child process")?;
        if !o.status.success() {
            return Err(
                log.err_with(
                    "Child process exited with error",
                    ea!(code = o.status.code().dbg_str(), output = o.dbg_str()),
                ),
            );
        }
        return Ok(());
    }

    fn run_stdin(&mut self, data: &[u8]) -> Result<(), loga::Error> {
        let log = Log::new().fork(ea!(command = self.0.dbg_str()));
        self.0.stdout(std::process::Stdio::piped());
        self.0.stderr(std::process::Stdio::piped());
        let mut child = self.0.stdin(Stdio::piped()).spawn().stack_context(&log, "Failed to start child process")?;
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(data).stack_context(&log, "Error writing to child process stdin")?;
        let output = child.wait_with_output().stack_context(&log, "Failed to wait for child process to exit")?;
        if !output.status.success() {
            return Err(
                log.err_with(
                    "Child process exited with error",
                    ea!(code = output.status.code().dbg_str(), output = output.dbg_str()),
                ),
            );
        }
        return Ok(());
    }

    fn run_stdout(&mut self) -> Result<Vec<u8>, loga::Error> {
        let log = Log::new().fork(ea!(command = self.0.dbg_str()));
        self.0.stdout(std::process::Stdio::piped());
        self.0.stderr(std::process::Stdio::piped());
        let child = self.0.spawn().stack_context(&log, "Failed to start child process")?;
        let output = child.wait_with_output().stack_context(&log, "Failed to wait for child process to exit")?;
        if !output.status.success() {
            return Err(
                log.err_with(
                    "Child process exited with error",
                    ea!(code = output.status.code().dbg_str(), output = output.dbg_str()),
                ),
            );
        }
        return Ok(output.stdout);
    }

    fn run_json_out<D: DeserializeOwned>(&mut self) -> Result<D, loga::Error> {
        let res = self.run_stdout()?;
        let log = Log::new().fork(ea!(command = self.0.dbg_str()));
        return Ok(
            serde_json::from_slice(
                &res,
            ).stack_context_with(&log, "Error parsing output as json", ea!(output = res.dbg_str()))?,
        );
    }
}

fn ask_password(message: &str) -> Result<String, loga::Error> {
    let raw =
        Command::new("systemd-ask-password")
            .arg("-n")
            .arg("--timeout=0")
            .arg(message)
            .simple()
            .run_stdout()
            .context("Error asking for password")?;
    return Ok(from_utf8(raw).context("Received password was invalid utf8")?.trim().to_string());
}

fn get_shared_image_key(key_mode: &SharedImageKeyMode, confirm: bool) -> Result<String, loga::Error> {
    match key_mode {
        SharedImageKeyMode::File(f) => {
            return Ok(from_utf8(f.value.clone())?);
        },
        SharedImageKeyMode::Password => {
            let mut warning = None;
            loop {
                let mut prompt = String::new();
                if let Some(warning) = warning.take() {
                    prompt.push_str(warning);
                }
                prompt.push_str("Enter the password");
                let pw1 = ask_password(&prompt)?;
                if confirm {
                    let pw2 = ask_password("Confirm your password")?;
                    if pw1 != pw2 {
                        warning = Some("Passwords didn't match, please try again.\n");
                        continue;
                    }
                }
                return Ok(pw1);
            }
        },
    }
}

fn get_private_image_key(log: &Log, key_path: &Path, key_mode: &PrivateImageKeyMode) -> Result<String, loga::Error> {
    let encrypted =
        pgp::Message::from_armor_single(
            &mut read(key_path)
                .context_with("Error reading encrypted key", ea!(path = key_path.to_string_lossy()))?
                .as_slice(),
        )
            .context("Encrypted data isn't valid ASCII Armor")?
            .0;
    match key_mode {
        #[cfg(feature = "smartcard")]
        PrivateImageKeyMode::Smartcard { pin } => {
            let mut pcsc_context =
                pcsc::Context::establish(pcsc::Scope::User).context("Error setting up PCSC context")?;
            let mut watch: Vec<pcsc::ReaderState> = vec![];
            loop {
                let pin = match &pin {
                    PinMode::FactoryDefault => "123456".to_string(),
                    PinMode::Text => ask_password("Enter your PIN")?,
                    PinMode::Numpad => {
                        let mut warning = None;
                        'retry : loop {
                            let mut prompt = String::new();
                            if let Some(warning) = warning {
                                prompt.push_str(warning);
                            }
                            prompt.push_str("Press numpad buttons matching the locations of your PIN digits\n");
                            let mut digits = (1 ..= 9).collect::<Vec<_>>();
                            digits.shuffle(&mut thread_rng());
                            let digit_lookup =
                                Iterator::zip(
                                    [
                                        ['7', 'u', 'w'],
                                        ['8', 'i', 'e'],
                                        ['9', 'o', 'r'],
                                        ['4', 'j', 's'],
                                        ['5', 'k', 'f'],
                                        ['6', 'l', 'f'],
                                        ['1', 'm', 'x'],
                                        ['2', ',', 'c'],
                                        ['3', '.', 'v'],
                                    ].into_iter(),
                                    &digits,
                                )
                                    .flat_map(|(positions, digit)| positions.map(|p| (p, digit)))
                                    .collect::<HashMap<_, _>>();
                            for row in digits.chunks(3) {
                                for digit in row {
                                    prompt.push_str(&format!(" {}", digit));
                                }
                                prompt.push('\n');
                            }
                            let pre_pin = ask_password(&prompt)?;
                            let pre_pin = pre_pin.trim();
                            let mut pin = String::new();
                            for c in pre_pin.chars() {
                                let d = match digit_lookup.get(&c) {
                                    Some(d) => **d,
                                    None => {
                                        warning = Some("There were invalid digits in the PIN. Please try again.\n");
                                        continue 'retry;
                                    },
                                };
                                pin.push_str(&d.to_string());
                            }
                            break pin;
                        }
                    },
                };
                if pin.is_empty() {
                    log.log(loga::WARN, "Got empty pin, please retry");
                    sleep(Duration::from_secs(1));
                    continue;
                }
                loop {
                    let mut reader_names = pcsc_context.list_readers_owned()?.into_iter().collect::<HashSet<_>>();
                    reader_names.insert(pcsc::PNP_NOTIFICATION().to_owned());
                    let mut i = 0;
                    loop {
                        if i >= watch.len() {
                            break;
                        }
                        if reader_names.remove(&watch[i].name().to_owned()) {
                            i += 1;
                        } else {
                            watch.remove(i);
                        }
                    }
                    for new in reader_names {
                        watch.push(pcsc::ReaderState::new(new, pcsc::State::UNKNOWN));
                    }
                    log.log(loga::INFO, "Please hold your smartcard to the reader");
                    match pcsc_context.get_status_change(Duration::from_secs(10), &mut watch) {
                        Ok(_) => { },
                        Err(pcsc::Error::Timeout) => {
                            continue;
                        },
                        Err(pcsc::Error::ServiceStopped) | Err(pcsc::Error::NoService) => {
                            // Windows will kill the SmartCard service when the last reader is disconnected
                            // Restart it and wait (sleep) for a new reader connection if that occurs
                            pcsc_context = Context::establish(pcsc::Scope::User)?;
                            continue;
                        },
                        Err(err) => return Err(err.into()),
                    };
                    for state in &mut watch {
                        'detect : loop {
                            let old_state = state.current_state();
                            let new_state = state.event_state();
                            if !new_state.contains(pcsc::State::CHANGED) {
                                break 'detect;
                            }
                            if state.name() == pcsc::PNP_NOTIFICATION() {
                                break 'detect;
                            }
                            if !old_state.contains(pcsc::State::PRESENT) && new_state.contains(pcsc::State::PRESENT) {
                                match (|| {
                                    let mut card = openpgp_card::Card::new(
                                        // Workaround pending
                                        // https://gitlab.com/openpgp-card/openpgp-card/-/merge_requests/42
                                        card_backend_pcsc::PcscBackend::card_backends(None)?
                                            .next()
                                            .context("Card missing (timing?)")?
                                            .context("Error opening card backend")?,
                                    ).context("Error opening card for card backend")?;
                                    let mut tx = card.transaction().context("Error starting card transaction")?;
                                    tx.verify_user_pin(pin.clone().into()).context("Error verifying PIN")?;
                                    let card_key =
                                        CardSlot::init_from_card(
                                            &mut tx,
                                            openpgp_card::ocard::KeyType::Decryption,
                                            &|| { },
                                        ).context("Error turning card into decryption key")?;
                                    let decrypted =
                                        match card_key
                                            .decrypt_message(&encrypted)
                                            .context("Failed to decrypt disk secret - wrong key device?")? {
                                            pgp::Message::Literal(l) => l.data().to_vec(),
                                            other => {
                                                return Err(
                                                    loga::err_with(
                                                        "Rpgp returned unrecognized payload type",
                                                        ea!(other = other.dbg_str()),
                                                    ),
                                                );
                                            },
                                        };
                                    log.log(loga::INFO, "Done reading smartcard, you may now remove it");
                                    return Ok(
                                        from_utf8(decrypted)
                                            .context("Key file contains invalid utf-8")?
                                            .trim()
                                            .to_string(),
                                    );
                                })() {
                                    Ok(key) => {
                                        return Ok(key);
                                    },
                                    Err(e) => {
                                        log.log_err(loga::WARN, e.context("Failed to get volume key, retrying"));
                                    },
                                }
                            }
                            break 'detect;
                        }
                        state.sync_current_state();
                    }
                }
            }
        },
    }
}

trait SimpleCommandExt {
    fn simple<'a>(&'a mut self) -> SimpleCommand<'a>;
}

impl SimpleCommandExt for Command {
    fn simple<'a>(&'a mut self) -> SimpleCommand<'a> {
        return SimpleCommand(self);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LsblkRoot {
    blockdevices: Vec<LsblkDevice>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LsblkDevice {
    //. /// alignment offset
    //. alignment: i64,
    //. /// * ID-LINK: the shortest udev /dev/disk/by-id link name
    //. #[serde(rename = "id-link")]
    //. id_link: Option<String>,
    //. /// udev ID (based on ID-LINK)
    //. id: Option<String>,
    //. /// filesystem size available
    //. fsavail: Option<i64>,
    //. /// mounted filesystem roots
    //. fsroots: Vec<Option<String>>,
    //. /// filesystem size
    //. fssize: Option<i64>,
    //. /// filesystem type
    //. fstype: Option<String>,
    //. /// filesystem size used
    //. fsused: Option<i64>,
    //. /// filesystem version
    //. fsver: Option<String>,
    //. /// group name
    //. group: String,
    //. /// removable or hotplug device (usb, pcmcia, ...)
    //. hotplug: bool,
    //. /// internal kernel device name.  This appears to be what is in `/dev`.
    //. kname: String,
    //. /// filesystem LABEL
    //. label: Option<String>,
    //. /// * LOG-SEC: logical sector size
    //. #[serde(rename = "log-sec")]
    //. log_sec: i64,
    //. /// * MAJ:MIN: major:minor device number
    //. #[serde(rename = "maj:min")]
    //. maj_min: String,
    //. /// * MIN-IO: minimum I/O size
    //. #[serde(rename = "min-io")]
    //. min_io: i64,
    //. /// device node permissions
    //. mode: String,
    //. /// device identifier
    //. model: Option<String>,
    //. /// device name.  This appears to be what is in `/dev/mapper`.
    //. name: String,
    //. /// * OPT-IO: optimal I/O size
    //. #[serde(rename = "opt-io")]
    //. opt_io: i64,
    //. /// user name
    //. owner: String,
    //. /// partition flags. Like `0x8000000000000000`
    //. partflags: Option<String>,
    //. /// partition LABEL
    //. partlabel: Option<String>,
    //. /// partition number as read from the partition table
    //. partn: Option<usize>,
    //. /// partition type code or UUID
    //. parttype: Option<String>,
    //. /// partition type name
    //. parttypename: Option<String>,
    //. /// partition UUID
    //. partuuid: Option<String>,
    /// path to the device node
    path: String,
    //. /// internal parent kernel device name
    //. pkname: Option<String>,
    //. /// partition table type
    //. pttype: Option<String>,
    //. /// partition table identifier (usually UUID)
    //. ptuuid: Option<String>,
    //. /// removable device
    //. rm: bool,
    //. /// read-only device
    //. ro: bool,
    //. /// disk serial number
    //. serial: Option<String>,
    /// size of the device in bytes.
    size: i64,
    //. /// partition start offset
    //. start: Option<usize>,
    //. /// state of the device
    //. state: Option<String>,
    /// de-duplicated chain of subsystems
    subsystems: String,
    //. /// where the device is mounted
    //. mountpoint: Option<String>,
    /// all locations where device is mounted
    mountpoints: Vec<Option<String>>,
    //. /// device transport type
    //. tran: Option<String>,
    /// device type
    #[serde(rename = "type")]
    type_: String,
    /// filesystem UUID. Not always a standard uuid, can be 8 characters.
    uuid: Option<String>,
    //. /// device vendor
    //. vendor: Option<String>,
    //. /// write same max bytes
    //. wsame: i64,
    //. /// unique storage identifier
    //. wwn: Option<String>,
    #[serde(default)]
    children: Vec<LsblkDevice>,
}

fn volume_setup() -> Result<(), loga::Error> {
    let args = vark::<Args>();
    let log = Log::new_root(if args.debug.is_some() {
        loga::DEBUG
    } else {
        loga::INFO
    });
    let outer_uuid = args.uuid.unwrap_or_else(|| OUTER_UUID.to_string());
    let outer_uuid_dev_path = PathBuf::from(format!("/dev/disk/by-uuid/{}", &outer_uuid));
    let inner_uuid_dev_path = PathBuf::from(format!("/dev/disk/by-uuid/{}", &INNER_UUID));
    let mount_path =
        args
            .mountpoint
            .clone()
            .unwrap_or_else(|| PathBuf::from("/mnt/persistent"))
            .absolutize()
            .context("Couldn't make mountpoint absolute")?
            .into_owned();

    // Mounting - helper methods
    let format = |dev_path: &Path, uuid: &str| -> Result<PathBuf, loga::Error> {
        log.log_with(loga::INFO, "Creating filesystem", ea!(dev = dev_path.dbg_str()));
        Command::new("mkfs.ext4")
            .arg("-F")
            .arg(dev_path)
            .arg("-U")
            .arg(uuid)
            .simple()
            .run()
            .context("Error formatting persistent volume")?;
        let fs_dev_path = PathBuf::from(format!("/dev/disk/by-uuid/{}", uuid));
        for _ in 0 .. 30 {
            if fs_dev_path.exists() {
                return Ok(fs_dev_path);
            }
            sleep(Duration::from_secs(1));
        }
        return Err(
            loga::err_with(
                "Even after formatting disk ext4, it never appeared in `by-uuid`. Try wiping the disk to remove misleading headers or doing a health check.",
                ea!(dev = dev_path.to_string_lossy(), path = fs_dev_path.to_string_lossy()),
            ),
        );
    };
    let ensure_mounted = |fs_dev_path: &Path| {
        ta_return!((), loga::Error);
        let systemd_mount_name =
            from_utf8(
                Command::new("systemd-escape")
                    .arg("--path")
                    .arg("--suffix=mount")
                    .arg(&mount_path)
                    .simple()
                    .run_stdout()
                    .context("Error determining systemd mount name")?,
            ).context("Systemd mount name via systemd-escape is not valid utf-8")?;
        let raw_active_state =
            from_utf8(
                Command::new("systemctl")
                    .arg("show")
                    .arg("--property=ActiveState")
                    .arg(&systemd_mount_name)
                    .simple()
                    .run_stdout()
                    .context("Error checking mount unit active state")?,
            ).context("Mount unit active state isn't valid utf-8")?;
        let Some((key, value)) = raw_active_state.trim().split_once("=") else {
            return Err(
                loga::err_with(
                    "Unable to parse mount unit active state",
                    ea!(unit = systemd_mount_name, raw_active_state = raw_active_state),
                ),
            );
        };
        if key != "ActiveState" {
            return Err(
                loga::err_with(
                    "Active state output has unexpected KV data",
                    ea!(unit = systemd_mount_name, raw_active_state = raw_active_state),
                ),
            );
        }
        if value != "active" {
            log.log_with(
                loga::INFO,
                "Mounting filesystem",
                ea!(dev = fs_dev_path.dbg_str(), mountpoint = mount_path.dbg_str()),
            );
            Command::new("systemd-mount")
                .arg("--options=noatime")
                .arg(fs_dev_path)
                .arg(&mount_path)
                .simple()
                .run()
                .context("Failed to mount persistent disk")?;
        }
        return Ok(());
    };
    let ensure_map_luks = |key: &str| -> Result<PathBuf, loga::Error> {
        let mapper_name = "persistent";
        let mapper_dev_path = PathBuf::from(format!("/dev/mapper/{}", mapper_name));
        if mapper_dev_path.exists() {
            return Ok(mapper_dev_path);
        }
        log.log_with(loga::INFO, "Unlocking LUKS device", ea!(dev = outer_uuid_dev_path.dbg_str()));
        Command::new("cryptsetup")
            .arg("open")
            .arg("--key-file=-")
            .arg(&outer_uuid_dev_path)
            .arg(mapper_name)
            .simple()
            .run_stdin(key.as_bytes())
            .context("Error opening existing encrypted volume")?;
        return Ok(mapper_dev_path);
    };
    let blocks =
        Command::new("lsblk")
            .arg("--bytes")
            .arg("--json")
            .arg("--output-all")
            .arg("--tree")
            .simple()
            .run_json_out::<LsblkRoot>()
            .context("Error looking up block devices for disk setup")?
            .blockdevices;

    // Ensure mount
    superif!({
        // Find existing volume, or candidate disk to format
        let mut best_candidate: Option<&LsblkDevice> = None;
        for candidate in &blocks {
            let subsystems = candidate.subsystems.split(":").collect::<HashSet<&str>>();

            // Only consider physical disks
            if candidate.type_ != "disk" || subsystems.contains("usb") {
                continue;
            }

            // Does the volume already exist?
            let uuid = candidate.uuid.as_ref().map(|u| u.as_str());
            if uuid == Some(&outer_uuid) {
                log.log_with(loga::INFO, "Found persistent disk", ea!(disk = candidate.path));
                break 'exists_outer candidate;
            }

            // Skip in-use devices
            fn in_use(candidate: &LsblkDevice) -> bool {
                if candidate.mountpoints.iter().filter(|p| p.is_some()).count() > 0 {
                    return true;
                }
                for child in &candidate.children {
                    if in_use(child) {
                        return true;
                    }
                }
                return false;
            }

            if in_use(candidate) {
                continue;
            }

            // Maybe keep as candidate
            log.log_with(
                loga::INFO,
                "UUID mismatch, remembering as candidate disk",
                ea!(disk = candidate.path, found = uuid.dbg_str(), want = outer_uuid),
            );
            shed!{
                if let Some(best) = &best_candidate {
                    if best.size >= candidate.size {
                        break;
                    }
                };
                best_candidate = Some(candidate);
            }
        }

        // Didn't find existing volume, so format the best candidate volume
        let candidate = best_candidate.context("Couldn't find persistent disk or a suitable candidate for formatting")?;
        log.log_with(
            loga::INFO,
            "Couldn't find persistent disk, formatting best attached candidate disk",
            ea!(disk = candidate.path),
        );
        let setup_encrypted = |key: &str| -> Result<(), loga::Error> {
            log.log_with(loga::INFO, "Initializing LUKS device", ea!(dev = candidate.path.dbg_str()));
            Command::new("cryptsetup")
                .arg("luksFormat")
                .arg("--type=luks2")
                .arg("--key-file=-")
                .arg(&candidate.path)
                .simple()
                .run_stdin(key.as_bytes())
                .context("Error encypting new volume on persistent disk")?;
            Command::new("cryptsetup")
                .arg("luksUUID")
                .arg("--uuid")
                .arg(&outer_uuid)
                .arg(&candidate.path)
                .simple()
                .run()
                .context("Error setting UUID on newly encrypted volume on persistent disk")?;
            shed!{
                'exists_outer1 _;
                for _ in 0 .. 30 {
                    if outer_uuid_dev_path.exists() {
                        break 'exists_outer1;
                    }
                    sleep(Duration::from_secs(1));
                }
                return Err(
                    loga::err_with(
                        "LUKS source disk with UUID never appeared",
                        ea!(path = outer_uuid_dev_path.dbg_str()),
                    ),
                );
            }
            let luks_dev_path = ensure_map_luks(&key).context("Error mapping new LUKS volume")?;
            let fs_dev_path = format(&luks_dev_path, INNER_UUID)?;
            ensure_mounted(&fs_dev_path)?;
            return Ok(());
        };
        match args.encryption.unwrap_or(EncryptionMode::None) {
            EncryptionMode::None => {
                let fs_dev_path = format(&PathBuf::from(&candidate.path), &outer_uuid)?;
                ensure_mounted(&fs_dev_path)?;
            },
            EncryptionMode::SharedImage(enc_args) => {
                let key = get_shared_image_key(&enc_args.key_mode, true)?;
                setup_encrypted(&key)?;
            },
            EncryptionMode::PrivateImage(enc_args) => {
                let key = get_private_image_key(&log, &enc_args.key_path, &enc_args.key_mode)?;
                setup_encrypted(&key)?;
            },
        }
    } candidate = 'exists_outer {
        // Found existing volume, just mount it
        let mount_encrypted = |key: &str| -> Result<(), loga::Error> {
            let luks_dev_path = ensure_map_luks(key)?;
            let fs_dev_path = shed!{
                'exists_inner1 _;
                for _ in 0 .. 30 {
                    if inner_uuid_dev_path.exists() {
                        break 'exists_inner1 inner_uuid_dev_path;
                    }
                    sleep(Duration::from_secs(1));
                }
                log.log_with(
                    loga::INFO,
                    "Filesystem with UUID never appeared; assuming formatting never completed.",
                    ea!(dev = inner_uuid_dev_path.dbg_str()),
                );
                break 'exists_inner1 format(&luks_dev_path, INNER_UUID)?;
            };
            ensure_mounted(&fs_dev_path)?;
            return Ok(());
        };
        match args.encryption.unwrap_or(EncryptionMode::None) {
            EncryptionMode::None => {
                let fs_dev_path = PathBuf::from(&candidate.path);
                ensure_mounted(&fs_dev_path)?;
            },
            EncryptionMode::SharedImage(enc_args) => {
                let key = get_shared_image_key(&enc_args.key_mode, false)?;
                mount_encrypted(&key)?;
            },
            EncryptionMode::PrivateImage(enc_args) => {
                let key = get_private_image_key(&log, &enc_args.key_path, &enc_args.key_mode)?;
                mount_encrypted(&key)?;
                if let Some(decrypt) = enc_args.decrypt {
                    let log = log.fork(ea!(path = decrypt.dbg_str()));
                    let decrypted_path = "/run/volumesetup_decrypted";
                    copy(
                        &mut match age::Decryptor::new(
                            &mut read(&decrypt)
                                .stack_context(&log, "Error reading additional file to decrypt")?
                                .as_slice(),
                        ).stack_context(&log, "Error reading additional file to decrypt")? {
                            age::Decryptor::Passphrase(d) => d,
                            _ => {
                                return Err(
                                    log.err(
                                        "Additional file to decrypt must use passphrase (symmetric) age encryption, but was asymmetric",
                                    ),
                                );
                            },
                        }
                            .decrypt(&age::secrecy::Secret::new(key.clone()), None)
                            .stack_context(&log, "Error decrypting additional file to decrypt")?,
                        &mut OpenOptions::new()
                            .mode(0o600)
                            .write(true)
                            .create(true)
                            .truncate(true)
                            .open(decrypted_path)
                            .context_with(
                                "Error opening additional file to decrypt destination path",
                                ea!(path = decrypted_path),
                            )?,
                    ).stack_context_with(&log, "Error writing file", ea!(dest_path = decrypted_path))?;
                }
            },
        }
    });

    // Ensure subdirectories in mountpoint
    for path in args.create_dirs.unwrap_or_default() {
        create_dir_all(
            &mount_path.join(&path),
        ).stack_context_with(&log, "Failed to create mount point subidr", ea!(subdir = path.to_string_lossy()))?;
    }

    // Done
    return Ok(());
}

fn main() {
    match volume_setup() {
        Ok(_) => { },
        Err(e) => {
            fatal(e);
        },
    }
}
