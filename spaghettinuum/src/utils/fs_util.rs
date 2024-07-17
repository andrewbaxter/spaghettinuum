use {
    loga::{
        ea,
        ResultContext,
    },
    std::path::Path,
};

pub async fn write(path: impl AsRef<Path>, data: &[u8]) -> Result<(), loga::Error> {
    tokio::fs::write(path.as_ref(), data)
        .await
        .context_with("Error writing file", ea!(path = path.as_ref().to_string_lossy()))?;
    return Ok(());
}

pub async fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, loga::Error> {
    return Ok(
        tokio::fs::read(path.as_ref())
            .await
            .context_with("Error reading file", ea!(path = path.as_ref().to_string_lossy()))?,
    );
}

pub async fn maybe_read(path: impl AsRef<Path>) -> Result<Option<Vec<u8>>, loga::Error> {
    match tokio::fs::read(path.as_ref()).await {
        Ok(r) => return Ok(Some(r)),
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => {
                return Ok(None);
            },
            _ => {
                return Err(e.into());
            },
        },
    }
}
