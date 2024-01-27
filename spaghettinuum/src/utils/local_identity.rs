use std::path::Path;
use loga::{
    ea,
    ResultContext,
};
use tokio::fs;
use crate::interface::config::identity::BackedIdentityLocal;

pub async fn write_identity(path: &Path, identity: &BackedIdentityLocal) -> Result<(), loga::Error> {
    fs::write(path, &serde_json::to_string_pretty(identity).unwrap())
        .await
        .context_with("Failed to write identity secret to file", ea!(path = path.to_string_lossy()))?;
    return Ok(());
}
