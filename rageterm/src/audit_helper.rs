use std::path::PathBuf;
use std::sync::Mutex;

use ragewarden_core::audit::{AuditEvent, AuditKind, AuditLog, AuditResult};

use crate::config;

/// The log of the config directory it was opened in; reopened if that
/// directory changes (tests switch it, a real run never does).
static LOG: Mutex<Option<(PathBuf, Option<AuditLog>)>> = Mutex::new(None);

fn with_log<R>(f: impl FnOnce(&AuditLog) -> R) -> Option<R> {
    let dir = config::ensure_config_dir().ok()?;
    let mut guard = LOG.lock().unwrap_or_else(|e| e.into_inner());
    if guard.as_ref().is_none_or(|(open_in, _)| *open_in != dir) {
        let log = match AuditLog::open(&dir) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("rageterm: audit log unavailable ({e}); continuing without it");
                None
            }
        };
        *guard = Some((dir, log));
    }
    guard.as_ref().and_then(|(_, log)| log.as_ref()).map(f)
}

pub fn record(event: AuditEvent) {
    if let Some(Err(e)) = with_log(|l| l.record(&event)) {
        eprintln!("rageterm: failed to write audit event ({e}); continuing");
    }
}

pub fn record_kind(kind: AuditKind) {
    record(AuditEvent::now(kind));
}

pub fn record_target(kind: AuditKind, target: impl Into<String>) {
    record(AuditEvent::now(kind).with_target(target));
}

pub fn record_with(kind: AuditKind, target: impl Into<String>, detail: impl Into<String>) {
    record(
        AuditEvent::now(kind)
            .with_target(target)
            .with_detail(detail),
    );
}

pub fn record_detail(kind: AuditKind, detail: impl Into<String>) {
    record(AuditEvent::now(kind).with_detail(detail));
}

/// Whether a failed action was refused by the user (or a gate) rather than
/// broken.
pub trait Declinable {
    fn declined(&self) -> bool;
}

impl Declinable for crate::commands::CmdError {
    fn declined(&self) -> bool {
        matches!(self, crate::commands::CmdError::Cancelled)
    }
}

impl Declinable for ragewarden_core::sync::SyncError {
    fn declined(&self) -> bool {
        false
    }
}

pub fn result_of<T, E: Declinable>(result: &Result<T, E>) -> AuditResult {
    match result {
        Ok(_) => AuditResult::Ok,
        Err(e) if e.declined() => AuditResult::Declined,
        Err(_) => AuditResult::Failed,
    }
}

/// Record what actually happened to one use of a credential: delivered to
/// `destination`, or refused/failed and why. Written after the fact, so the log
/// never claims a delivery that did not occur.
pub fn record_result<T, E: std::fmt::Display + Declinable>(
    kind: AuditKind,
    target: &str,
    destination: Option<&str>,
    result: &Result<T, E>,
) {
    let mut event = AuditEvent::now(kind)
        .with_target(target.to_string())
        .with_result(result_of(result));
    match (result, destination) {
        (Ok(_), Some(d)) => event = event.with_detail(d.to_string()),
        (Ok(_), None) => {}
        (Err(e), Some(d)) => event = event.with_detail(format!("{d}: {e}")),
        (Err(e), None) => event = event.with_detail(e.to_string()),
    }
    record(event);
}

pub fn outcome<T, E: std::fmt::Display + Declinable>(
    kind: AuditKind,
    target: &str,
    destination: Option<String>,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let r = f();
    record_result(kind, target, destination.as_deref(), &r);
    r
}

/// The newest `limit` events, plus how many lines were unreadable.
pub fn tail(limit: usize) -> Result<ragewarden_core::audit::AuditTail, String> {
    with_log(|l| l.tail(limit).map_err(|e| e.to_string()))
        .unwrap_or_else(|| Err("the audit log is unavailable".to_string()))
}
