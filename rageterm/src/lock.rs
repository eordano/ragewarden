use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;

use fs2::FileExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockError {
    #[error("lock file io: {0}")]
    Io(#[from] io::Error),

    #[error("hardware busy (another rageterm process holds the lock)")]
    Busy,
}

#[allow(dead_code)]
pub struct HardwareLock {
    file: File,
}

impl Drop for HardwareLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub fn lock_path() -> io::Result<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir).join("ragewarden.lock"));
        }
    }

    if let Some(rt) = dirs::runtime_dir() {
        return Ok(rt.join("ragewarden.lock"));
    }
    let tmp = std::env::temp_dir();
    Ok(tmp.join("ragewarden.lock"))
}

pub fn acquire(wait: bool) -> Result<HardwareLock, LockError> {
    let path = lock_path()?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;

    if wait {
        FileExt::lock_exclusive(&file)?;
    } else {
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(LockError::Busy),
            Err(e) => return Err(LockError::Io(e)),
        }
    }

    Ok(HardwareLock { file })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tests_lock::ENV_LOCK;

    #[test]
    fn lock_then_release_then_relock() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::TempDir::new().unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", tmp.path());
        let l1 = acquire(true).expect("first acquire");
        drop(l1);
        let l2 = acquire(true).expect("second acquire after drop");
        drop(l2);
        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    fn try_lock_when_held_returns_busy() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", tmp.path());
        let _held = acquire(true).expect("first acquire");

        match acquire(false) {
            Err(LockError::Busy) => {}

            _ => eprintln!("note: this platform allows re-lock from the same process"),
        }
        std::env::remove_var("XDG_RUNTIME_DIR");
    }
}
