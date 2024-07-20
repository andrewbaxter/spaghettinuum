use {
    loga::{
        ea,
        Log,
        ResultContext,
    },
    serde_json::json,
    spaghettinuum::{
        interface::config::identity::{
            LocalIdentitySecret,
        },
        utils::local_identity::write_identity_secret,
    },
};
#[cfg(feature = "card")]
use {
    spaghettinuum::{
        utils::{
            pgp::{
                self,
            },
        },
    },
    openpgp_card_pcsc::PcscBackend,
    openpgp_card_sequoia::{
        state::Open,
        Card,
    },
};

pub mod args {
    use {
        aargvark::{
            Aargvark,
            AargvarkJson,
        },
        spaghettinuum::interface::config::identity::LocalIdentitySecret,
        std::path::PathBuf,
    };

    #[derive(Aargvark)]
    pub struct NewLocalIdentity {
        /// Store the new id and secret in a file at this path
        pub path: PathBuf,
    }

    #[derive(Aargvark)]
    pub enum Identity {
        /// Create a new local (file) identity
        NewLocal(NewLocalIdentity),
        /// Show the id for a local identity
        ShowLocal(AargvarkJson<LocalIdentitySecret>),
        /// List ids for usable pcsc cards (configured with curve25519/ed25519 signing keys)
        #[cfg(feature = "card")]
        ListCards,
    }
}

pub async fn run(log: &Log, config: args::Identity) -> Result<(), loga::Error> {
    match config {
        args::Identity::NewLocal(args) => {
            let (ident, secret) = LocalIdentitySecret::new();
            write_identity_secret(&args.path, &secret).await.stack_context(&log, "Error creating local identity")?;
            println!("{}", serde_json::to_string_pretty(&json!({
                "id": ident.to_string()
            })).unwrap());
        },
        args::Identity::ShowLocal(p) => {
            let secret = p.value;
            let identity = secret.identity();
            println!("{}", serde_json::to_string_pretty(&json!({
                "id": identity.to_string()
            })).unwrap());
        },
        #[cfg(feature = "card")]
        args::Identity::ListCards => {
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
