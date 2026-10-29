use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use fs2::FileExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockError {
    #[error("lock file io: {0}")]
    Io(#[from] io::Error),

    #[error("hardware busy (another rageterm process holds the lock)")]
    Busy,
}

/// One process-wide holder of the advisory lock, re-entrant so an enrollment
/// that already holds it can still reach the device boundary, which takes it too.
struct Held {
    file: File,
    depth: usize,
}

static HELD: Mutex<Option<Held>> = Mutex::new(None);
static WAIT: AtomicBool = AtomicBool::new(true);

/// `--no-wait`: fail with `Busy` instead of blocking when another process holds
/// the device.
pub fn set_wait(wait: bool) {
    WAIT.store(wait, Ordering::SeqCst);
}

pub struct HardwareLock {
    _private: (),
}

impl Drop for HardwareLock {
    fn drop(&mut self) {
        let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = held.as_mut() {
            h.depth -= 1;
            if h.depth == 0 {
                let _ = FileExt::unlock(&h.file);
                *held = None;
            }
        }
    }
}

/// Taken by every function that talks to a PC/SC card or a FIDO2 HID device,
/// for the length of that conversation. Honours `set_wait`.
pub fn device_session() -> Result<HardwareLock, LockError> {
    acquire(WAIT.load(Ordering::SeqCst))
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
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(h) = held.as_mut() {
        h.depth += 1;
        return Ok(HardwareLock { _private: () });
    }
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

    *held = Some(Held { file, depth: 1 });
    Ok(HardwareLock { _private: () })
}

#[cfg(test)]
pub(crate) fn held_depth() -> usize {
    HELD.lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map_or(0, |h| h.depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tests_lock::ENV_LOCK;

    #[test]
    fn lock_then_release_then_relock() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::TempDir::new().unwrap();
        crate::tests_lock::set_var("XDG_RUNTIME_DIR", tmp.path());
        let l1 = acquire(true).expect("first acquire");
        drop(l1);
        let l2 = acquire(true).expect("second acquire after drop");
        drop(l2);
        crate::tests_lock::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    fn the_device_boundary_lock_nests_inside_an_enrollment_lock() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        crate::tests_lock::set_var("XDG_RUNTIME_DIR", tmp.path());
        let outer = acquire(true).expect("enrollment lock");
        set_wait(false);
        let inner = device_session().expect("re-entrant device lock must not report Busy");
        assert_eq!(held_depth(), 2);
        drop(inner);
        assert_eq!(held_depth(), 1);
        drop(outer);
        assert_eq!(held_depth(), 0);
        set_wait(true);
        crate::tests_lock::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    fn another_open_file_description_is_refused_while_held() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        crate::tests_lock::set_var("XDG_RUNTIME_DIR", tmp.path());
        let _held = acquire(true).expect("first acquire");
        let other = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path().unwrap())
            .unwrap();
        assert!(FileExt::try_lock_exclusive(&other).is_err());
        crate::tests_lock::remove_var("XDG_RUNTIME_DIR");
    }
}
