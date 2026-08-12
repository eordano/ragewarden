use std::sync::Mutex;

pub static ENV_LOCK: Mutex<()> = Mutex::new(());
