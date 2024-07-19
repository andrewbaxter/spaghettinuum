use {
    loga::{
        ea,
        ResultContext,
    },
    std::{
        env,
        path::{
            Path,
            PathBuf,
        },
    },
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

const APP_DIRNAME: &'static str = "spaghettinuum";

pub fn config_path() -> PathBuf {
    const CONFIG_FILENAME: &'static str = "config.json";
    if let Some(d) = env::var_os("APP_CONFIG_DIRECTORY") {
        return PathBuf::from(d).join(CONFIG_FILENAME);
    } else if let Some(d) = env::var_os("CONFIG_DIRECTORY") {
        return PathBuf::from(d).join(APP_DIRNAME).join(CONFIG_FILENAME);
    } else {
        return PathBuf::from("/etc").join(APP_DIRNAME).join(CONFIG_FILENAME);
    }
}

pub fn data_dir() -> PathBuf {
    if let Some(d) = env::var_os("APP_DATA_DIRECTORY") {
        return PathBuf::from(d);
    } else if let Some(d) = env::var_os("DATA_DIRECTORY") {
        return PathBuf::from(d).join(APP_DIRNAME);
    } else {
        return PathBuf::from("/var/lib").join(APP_DIRNAME);
    }
}

pub fn cache_dir() -> PathBuf {
    if let Some(d) = env::var_os("APP_CACHE_DIRECTORY") {
        return PathBuf::from(d);
    } else if let Some(d) = env::var_os("CACHE_DIRECTORY") {
        return PathBuf::from(d).join(APP_DIRNAME);
    } else {
        return PathBuf::from("/var/cache").join(APP_DIRNAME);
    }
}
