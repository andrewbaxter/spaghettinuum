use {
    super::fs_util::{
        write,
    },
    crate::interface::config::identity::IdentitySecretLocal,
    loga::ResultContext,
    std::path::Path,
};

pub async fn write_identity_secret(path: &Path, identity: &IdentitySecretLocal) -> Result<(), loga::Error> {
    write(path, serde_json::to_string_pretty(identity).unwrap().as_bytes())
        .await
        .context("Failed to write identity secret to file")?;
    return Ok(());
}
