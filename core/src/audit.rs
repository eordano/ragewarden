//! Local-only, append-only JSONL audit log of user-initiated tap actions.
//! Strictly local -- never sync it. See `docs/ragewarden/core.md`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const AUDIT_LOG_FILENAME: &str = "audit.jsonl";

pub const AUDIT_LOG_ROTATED_FILENAME: &str = "audit.jsonl.1";

/// Soft cap: past this size [`AuditLog::record`] rotates before writing.
pub const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

/// Variant names are stable on the wire. Consumers MUST match with a `_` arm;
/// treat as `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditKind {
    Reveal,
    Copy,
    Autofill,
    Set,
    Update,
    Rotate,
    Delete,
    EnrollIdentity,
    RemoveRecipient,
    Login,
    Logout,
    Sync,
}

/// `target` is a free-form caller-meaningful id (cipher id, recipient id,
/// host...); `detail` an optional human-readable note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub recorded_at: DateTime<Utc>,

    pub kind: AuditKind,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AuditEvent {
    pub fn now(kind: AuditKind) -> Self {
        Self {
            recorded_at: Utc::now(),
            kind,
            target: None,
            detail: None,
        }
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit io: {0}")]
    Io(#[from] io::Error),

    #[error("audit json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Share one instance per state directory; internally `Mutex<File>`, so the
/// public API is `Send + Sync`.
pub struct AuditLog {
    dir: PathBuf,
    path: PathBuf,
    rotated_path: PathBuf,
    max_bytes: u64,
    inner: Mutex<File>,
}

impl AuditLog {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, AuditError> {
        Self::open_with_cap(dir, MAX_LOG_BYTES)
    }

    /// Test hook: overrides the rotation cap. Production callers use
    /// [`open`](Self::open).
    pub fn open_with_cap(dir: impl AsRef<Path>, max_bytes: u64) -> Result<Self, AuditError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let path = dir.join(AUDIT_LOG_FILENAME);
        let rotated_path = dir.join(AUDIT_LOG_ROTATED_FILENAME);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        Ok(Self {
            dir,
            path,
            rotated_path,
            max_bytes,
            inner: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn rotated_path(&self) -> &Path {
        &self.rotated_path
    }

    /// Appends one JSONL line, rotating first if over the size cap.
    pub fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut line = serde_json::to_string(event)?;
        line.push('\n');

        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let size = guard.metadata().map(|m| m.len()).unwrap_or(0);
        if size >= self.max_bytes {
            let _ = fs::remove_file(&self.rotated_path);
            fs::rename(&self.path, &self.rotated_path)?;
            let fresh = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&self.path)?;
            *guard = fresh;
        }

        guard.write_all(line.as_bytes())?;
        let _ = guard.sync_data();
        Ok(())
    }

    /// Most recent `limit` events from the active log, newest-first. Reads in
    /// tail-first chunks; unparseable lines are skipped silently.
    pub fn tail(&self, limit: usize) -> Result<Vec<AuditEvent>, AuditError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut reader = File::open(&self.path)?;
        let len = reader.metadata()?.len();
        drop(guard);

        if len == 0 {
            return Ok(Vec::new());
        }

        const CHUNK: usize = 8 * 1024;
        let mut carry: Vec<u8> = Vec::new();
        let mut events: Vec<AuditEvent> = Vec::with_capacity(limit.min(1024));
        let mut pos: u64 = len;

        while pos > 0 && events.len() < limit {
            let read_size = std::cmp::min(CHUNK as u64, pos);
            pos -= read_size;
            reader.seek(SeekFrom::Start(pos))?;
            let mut buf = vec![0u8; read_size as usize];
            reader.read_exact(&mut buf)?;
            buf.extend_from_slice(&carry);
            carry.clear();

            let mut end = buf.len();
            if end > 0 && buf[end - 1] == b'\n' {
                end -= 1;
            }

            while events.len() < limit {
                match buf[..end].iter().rposition(|&b| b == b'\n') {
                    Some(idx) => {
                        let line_start = idx + 1;
                        if let Ok(line) = std::str::from_utf8(&buf[line_start..end]) {
                            if let Ok(ev) = serde_json::from_str::<AuditEvent>(line) {
                                events.push(ev);
                            }
                        }
                        end = idx;
                    }
                    None => {
                        if pos == 0 {
                            if let Ok(line) = std::str::from_utf8(&buf[..end]) {
                                if let Ok(ev) = serde_json::from_str::<AuditEvent>(line) {
                                    events.push(ev);
                                }
                            }
                        } else {
                            carry = buf[..end].to_vec();
                        }
                        break;
                    }
                }
            }
        }

        Ok(events)
    }

    /// Truncates the active log and removes the rotated file.
    pub fn clear(&self) -> Result<(), AuditError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.set_len(0)?;
        guard.seek(SeekFrom::Start(0))?;
        let _ = guard.sync_all();
        if self.rotated_path.exists() {
            fs::remove_file(&self.rotated_path)?;
        }
        Ok(())
    }

    pub fn state_dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            p.push(format!(
                "ragewarden-audit-{tag}-{}-{}",
                std::process::id(),
                nanos
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn round_trip_events() {
        let tmp = TmpDir::new("roundtrip");
        let log = AuditLog::open(tmp.path()).unwrap();
        log.record(&AuditEvent::now(AuditKind::Login)).unwrap();
        log.record(
            &AuditEvent::now(AuditKind::Reveal)
                .with_target("cipher-1")
                .with_detail("eye tap"),
        )
        .unwrap();
        log.record(&AuditEvent::now(AuditKind::Logout)).unwrap();

        let got = log.tail(10).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].kind, AuditKind::Logout);
        assert_eq!(got[1].kind, AuditKind::Reveal);
        assert_eq!(got[1].target.as_deref(), Some("cipher-1"));
        assert_eq!(got[1].detail.as_deref(), Some("eye tap"));
        assert_eq!(got[2].kind, AuditKind::Login);
    }

    #[test]
    fn tail_returns_newest_first_with_limit() {
        let tmp = TmpDir::new("tail-limit");
        let log = AuditLog::open(tmp.path()).unwrap();
        for i in 0..50 {
            log.record(
                &AuditEvent::now(AuditKind::Sync).with_detail(format!("step-{i}")),
            )
            .unwrap();
        }
        let got = log.tail(5).unwrap();
        assert_eq!(got.len(), 5);
        assert_eq!(got[0].detail.as_deref(), Some("step-49"));
        assert_eq!(got[4].detail.as_deref(), Some("step-45"));
    }

    #[test]
    fn tail_with_zero_limit_returns_empty() {
        let tmp = TmpDir::new("tail-zero");
        let log = AuditLog::open(tmp.path()).unwrap();
        log.record(&AuditEvent::now(AuditKind::Sync)).unwrap();
        assert!(log.tail(0).unwrap().is_empty());
    }

    #[test]
    fn tail_on_empty_log_returns_empty() {
        let tmp = TmpDir::new("tail-empty");
        let log = AuditLog::open(tmp.path()).unwrap();
        assert!(log.tail(10).unwrap().is_empty());
    }

    #[test]
    fn clear_truncates_active_and_removes_rotated() {
        let tmp = TmpDir::new("clear");
        let log = AuditLog::open_with_cap(tmp.path(), 256).unwrap();
        for i in 0..40 {
            log.record(
                &AuditEvent::now(AuditKind::Copy).with_detail(format!("payload-{i:03}")),
            )
            .unwrap();
        }
        assert!(log.rotated_path().exists(), "rotation should have occurred");
        log.clear().unwrap();
        assert_eq!(log.path().metadata().unwrap().len(), 0);
        assert!(!log.rotated_path().exists());
        assert!(log.tail(10).unwrap().is_empty());
    }

    #[test]
    fn rotation_kicks_in_past_cap_and_keeps_one_prior() {
        let tmp = TmpDir::new("rotate");
        let log = AuditLog::open_with_cap(tmp.path(), 512).unwrap();
        for i in 0..50 {
            log.record(
                &AuditEvent::now(AuditKind::Update).with_detail(format!("entry-{i}")),
            )
            .unwrap();
        }
        assert!(log.rotated_path().exists());
        let active_size = log.path().metadata().unwrap().len();
        assert!(
            active_size < 512 * 4,
            "active log should be small after rotation, got {active_size}"
        );
        let mut prior_files = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("audit.jsonl."))
            .collect::<Vec<_>>();
        prior_files.sort();
        assert_eq!(prior_files, vec![AUDIT_LOG_ROTATED_FILENAME.to_string()]);
    }

    #[test]
    fn record_is_send_sync_and_thread_safe() {
        let tmp = TmpDir::new("threads");
        let log = Arc::new(AuditLog::open(tmp.path()).unwrap());
        let mut handles = Vec::new();
        for t in 0..8 {
            let log = Arc::clone(&log);
            handles.push(thread::spawn(move || {
                for i in 0..25 {
                    log.record(
                        &AuditEvent::now(AuditKind::Autofill)
                            .with_target(format!("t{t}"))
                            .with_detail(format!("i{i}")),
                    )
                    .unwrap();
                    thread::sleep(Duration::from_micros(50));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let all = log.tail(usize::MAX).unwrap();
        assert_eq!(all.len(), 8 * 25);
    }

    #[test]
    fn audit_event_serde_roundtrip_skips_none_fields() {
        let ev = AuditEvent::now(AuditKind::EnrollIdentity);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("target"));
        assert!(!json.contains("detail"));
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn tail_skips_corrupt_lines() {
        let tmp = TmpDir::new("corrupt");
        let log = AuditLog::open(tmp.path()).unwrap();
        log.record(&AuditEvent::now(AuditKind::Login)).unwrap();
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(log.path())
                .unwrap();
            f.write_all(b"this is not json\n").unwrap();
        }
        log.record(&AuditEvent::now(AuditKind::Logout)).unwrap();
        let got = log.tail(10).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].kind, AuditKind::Logout);
        assert_eq!(got[1].kind, AuditKind::Login);
    }
}
