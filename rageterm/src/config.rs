use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn config_dir() -> io::Result<PathBuf> {
    if let Ok(dir) = std::env::var("RAGEWARDEN_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = dirs::home_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine home directory",
        )
    })?;
    Ok(home.join(".config").join("ragewarden"))
}

pub fn identity_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join("identity.age"))
}

pub fn store_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join("store.json"))
}

pub fn vault_cache_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join("vault.json"))
}

pub fn recovery_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join("recovery.age"))
}

pub fn identities_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join("identities.json"))
}

pub fn ensure_config_dir() -> io::Result<PathBuf> {
    let dir = config_dir()?;
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    set_mode(&dir, 0o700)?;
    Ok(dir)
}

pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("write")
    ));
    fs::write(&tmp, contents)?;
    set_mode(&tmp, 0o600)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}
