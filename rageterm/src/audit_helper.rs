use std::sync::OnceLock;

use ragewarden_core::audit::{AuditEvent, AuditKind, AuditLog};

use crate::config;

static LOG: OnceLock<Option<AuditLog>> = OnceLock::new();

fn log() -> Option<&'static AuditLog> {
    LOG.get_or_init(|| match config::ensure_config_dir().and_then(|dir| {
        AuditLog::open(&dir).map_err(std::io::Error::other)
    }) {
        Ok(l) => Some(l),
        Err(e) => {
            eprintln!("rageterm: audit log unavailable ({e}); continuing without it");
            None
        }
    })
    .as_ref()
}

pub fn record(event: AuditEvent) {
    if let Some(l) = log() {
        if let Err(e) = l.record(&event) {
            eprintln!("rageterm: failed to write audit event ({e}); continuing");
        }
    }
}

pub fn record_kind(kind: AuditKind) {
    record(AuditEvent::now(kind));
}

pub fn record_target(kind: AuditKind, target: impl Into<String>) {
    record(AuditEvent::now(kind).with_target(target));
}

pub fn record_with(kind: AuditKind, target: impl Into<String>, detail: impl Into<String>) {
    record(AuditEvent::now(kind).with_target(target).with_detail(detail));
}

pub fn record_detail(kind: AuditKind, detail: impl Into<String>) {
    record(AuditEvent::now(kind).with_detail(detail));
}
