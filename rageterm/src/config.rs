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
    restrict_dir(&dir)?;
    Ok(dir)
}

/// Write a secret-bearing file so it is never readable by anyone else, not
/// even for a moment: the temp file is created 0600 (never with the umask),
/// flushed to disk, renamed into place, and the directory entry synced.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    if config_dir().map(|d| d == parent).unwrap_or(false) {
        ensure_config_dir()?;
    }
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("write"),
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);
    let mut f = create_private(&tmp)?;
    f.write_all(contents)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    sync_dir(parent);
    Ok(())
}

#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<fs::File> {
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    restrict_to_current_user(path)?;
    Ok(f)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

#[cfg(unix)]
fn restrict_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn restrict_dir(dir: &Path) -> io::Result<()> {
    restrict_to_current_user(dir)
}

/// Windows: drop inherited ACEs and grant the current user full control only.
#[cfg(not(unix))]
fn restrict_to_current_user(path: &Path) -> io::Result<()> {
    let user = std::env::var("USERNAME").map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "USERNAME is not set; cannot set the ACL",
        )
    })?;
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{user}:F"))
        .stdout(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "icacls could not restrict {} to {user}",
            path.display()
        )))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_private_file_is_0600_and_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.age");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, b"secret").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn the_temp_file_is_never_created_with_the_umask() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("t");
        let f = create_private(&tmp).unwrap();
        assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
}
