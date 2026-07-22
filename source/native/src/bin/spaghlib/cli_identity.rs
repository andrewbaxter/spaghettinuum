use {
    aargvark::{
        Aargvark,
        traits_impls::AargvarkJson,
    },
    loga::{
        Log,
        ResultContext,
    },
    serde_json::json,
    spaghettinuum::interface::public_key::IdentitySecret,
    spaghettinuum_native::{
        interface::config::shared::IdentitySecretArg,
        utils::identity_secret::{
            get_identity_signer,
            new_local_identity_secret,
            new_subkey,
            write_identity_secret,
        },
    },
    std::path::PathBuf,
};
#[cfg(feature = "card")]
use {
    loga::ea,
    openpgp_card_pcsc::PcscBackend,
    openpgp_card_sequoia::{
        Card,
        state::Open,
    },
    spaghettinuum_native::utils::{
        identity_secret::new_card_identity_secret,
        pgp::{
            self,
        },
    },
};

#[derive(Aargvark)]
#[vark(break_help)]
pub enum Args {
    /// List ids for usable pcsc cards (configured with curve25519/ed25519 signing keys)
    #[cfg(feature = "card")]
    ListCards,
    New(NewIdentity),
    NewSubkey(NewSubkey),
    Show(AargvarkJson<IdentitySecret>),
}

#[derive(Aargvark)]
pub struct NewIdentity {
    pub mode: NewIdentityMode,
    pub out: PathBuf,
}

#[derive(Aargvark)]
pub enum NewIdentityMode {
    #[cfg(feature = "card")]
    Card(String),
    Local,
}

/// A subkey allows you to use a less secure temporary key in place of your root
/// key. Additionally, because secret keys can only be safely used so many times,
/// you can instead rotate subkeys to limit root key wear (primarily for
/// high-traffic hosts).
#[derive(Aargvark)]
pub struct NewSubkey {
    /// The expiration limits when new announcements can be generated. Existing
    /// announcements with expired keys will not become unusable (unless a new
    /// announcement is made).
    pub expires: Option<u64>,
    /// Write the subkey to this path.
    pub out: PathBuf,
    /// Generate the subkey from this key.
    pub parent: IdentitySecretArg,
}

pub async fn run(log: &Log, config: Args) -> Result<(), loga::Error> {
    match config {
        Args::New(args) => {
            match args.mode {
                NewIdentityMode::Local => {
                    let secret = new_local_identity_secret();
                    write_identity_secret(&args.out, &secret)
                        .await
                        .stack_context(&log, "Error creating local identity")?;
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "id": secret.public_key().unwrap().to_string()
                    })).unwrap());
                },
                #[cfg(feature = "card")]
                NewIdentityMode::Card(card_args) => {
                    let secret =
                        new_card_identity_secret(
                            card_args,
                        ).stack_context(&log, "Error creating card identity secret")?;
                    write_identity_secret(&args.out, &secret)
                        .await
                        .stack_context(&log, "Error writing identity secret")?;
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "id": secret.public_key().unwrap().to_string()
                    })).unwrap());
                },
            }
        },
        Args::Show(p) => {
            println!("{}", serde_json::to_string_pretty(&json!({
                "id": p.value.public_key().map(|k| k.to_string())
            })).unwrap());
        },
        Args::NewSubkey(args) => {
            let signer = get_identity_signer(args.parent).await.stack_context(&log, "Error opening parent signer")?;
            let child =
                new_subkey(
                    &mut *signer.lock().unwrap(),
                    args.expires,
                ).stack_context(&log, "Error signing new subkey chain link")?;
            write_identity_secret(&args.out, &child).await.stack_context(&log, "Error writing subkey secret")?;
            println!("{}", serde_json::to_string_pretty(&json!({
                "id": child.public_key().unwrap().to_string()
            })).unwrap());
        },
        #[cfg(feature = "card")]
        Args::ListCards => {
            let mut out = vec![];
            for card in PcscBackend::cards(None).stack_context(log, "Failed to list smart cards")? {
                let mut card: Card<Open> = card.into();
                let mut transaction = card.transaction().stack_context(log, "Error starting transaction with card")?;
                let card_id =
                    transaction.application_identifier().stack_context(log, "Error getting gpg id of card")?.ident();
                let identity = match pgp::card_to_ident(&mut transaction) {
                    Ok(i) => match i {
                        Some(i) => i,
                        None => {
                            continue;
                        },
                    },
                    Err(e) => {
                        log.log_err(
                            loga::WARN,
                            e.context_with("Error getting identity of card", ea!(card = card_id)),
                        );
                        continue;
                    },
                };
                out.push(json!({
                    "pcsc_id": card_id,
                    "id": identity.to_string(),
                }));
            }
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        },
    }
    return Ok(());
}
