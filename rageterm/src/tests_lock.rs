use std::ffi::OsStr;
use std::sync::Mutex;

pub static ENV_LOCK: Mutex<()> = Mutex::new(());

pub fn set_var(key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) {
    // SAFETY: the tests edit the environment only while they hold ENV_LOCK.
    unsafe { std::env::set_var(key, value) }
}

pub fn remove_var(key: impl AsRef<OsStr>) {
    // SAFETY: as in set_var.
    unsafe { std::env::remove_var(key) }
}
