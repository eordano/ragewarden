use std::fs;
use std::io;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ragewarden_core::sync::{Server, Session};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session io: {0}")]
    Io(#[from] io::Error),

    #[error("session parse: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("session base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("session version {0} not supported (expected 1)")]
    UnsupportedVersion(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSession {
    version: u32,
    server: Server,
    email: String,
    user_id: String,
    access_token: ragewarden_core::BearerToken,
    refresh_token: ragewarden_core::RefreshToken,

    user_enc_key_b64: String,

    user_mac_key_b64: String,
    kdf_iterations: u32,
    #[serde(default)]
    device_id: String,
}

pub struct OpenSession {
    pub server: Server,

    pub session: Session,
}

pub fn session_path() -> io::Result<PathBuf> {
    Ok(config::config_dir()?.join("session.json"))
}

pub fn save(server: &Server, session: &Session) -> Result<(), SessionError> {
    let stored = StoredSession {
        version: 1,
        server: server.clone(),
        email: session.email.clone(),
        user_id: session.user_id.clone(),
        access_token: session.access_token.clone(),
        refresh_token: session.refresh_token.clone(),
        user_enc_key_b64: B64.encode(&session.user_enc_key),
        user_mac_key_b64: B64.encode(&session.user_mac_key),
        kdf_iterations: session.kdf_iterations,
        device_id: session.device_id.clone(),
    };
    let path = session_path()?;
    config::ensure_config_dir()?;
    let json = serde_json::to_vec_pretty(&stored)?;
    config::write_private(&path, &json)?;
    Ok(())
}

pub fn load() -> Result<Option<OpenSession>, SessionError> {
    let path = session_path()?;
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let stored: StoredSession = serde_json::from_slice(&bytes)?;
    if stored.version != 1 {
        return Err(SessionError::UnsupportedVersion(stored.version));
    }
    let user_enc_key = B64.decode(&stored.user_enc_key_b64)?;
    let user_mac_key = B64.decode(&stored.user_mac_key_b64)?;
    let session = Session {
        access_token: stored.access_token,
        refresh_token: stored.refresh_token,
        user_id: stored.user_id,
        email: stored.email,
        // `Session` now holds `VaultKey` (a zeroizing newtype in core). The
        // conversion moves the decoded `Vec` in rather than copying it, so the
        // only allocation these bytes ever lived in is the one that gets wiped.
        user_enc_key: user_enc_key.into(),
        user_mac_key: user_mac_key.into(),
        kdf_iterations: stored.kdf_iterations,
        device_id: stored.device_id,
    };
    Ok(Some(OpenSession {
        server: stored.server,
        session,
    }))
}

pub fn clear() -> Result<(), SessionError> {
    let session = session_path()?;
    let vault = config::vault_cache_path()?;
    for p in [session, vault] {
        if let Err(e) = fs::remove_file(&p) {
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
    }
    Ok(())
}

