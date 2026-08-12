use std::fs;
use std::io;
use std::path::PathBuf;

use ragewarden_core::sync::{Cipher, Folder, Organization, Vault};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config;

#[derive(Debug, Error)]
pub enum VaultCacheError {
    #[error("vault cache io: {0}")]
    Io(#[from] io::Error),

    #[error("vault cache parse: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("vault cache version {0} not supported (expected 1)")]
    UnsupportedVersion(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredVault {
    version: u32,
    ciphers: Vec<Cipher>,
    folders: Vec<Folder>,
    organizations: Vec<Organization>,

    synced_at: String,
}

pub fn path() -> io::Result<PathBuf> {
    config::vault_cache_path()
}

pub fn save(vault: &Vault) -> Result<(), VaultCacheError> {
    let stored = StoredVault {
        version: 1,
        ciphers: vault.ciphers.clone(),
        folders: vault.folders.clone(),
        organizations: vault.organizations.clone(),
        synced_at: chrono::Utc::now().to_rfc3339(),
    };
    let path = path()?;
    config::ensure_config_dir()?;
    let json = serde_json::to_vec_pretty(&stored)?;
    config::write_private(&path, &json)?;
    Ok(())
}

pub fn load() -> Result<Option<Vault>, VaultCacheError> {
    let path = path()?;
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let stored: StoredVault = serde_json::from_slice(&bytes)?;
    if stored.version != 1 {
        return Err(VaultCacheError::UnsupportedVersion(stored.version));
    }
    Ok(Some(Vault {
        ciphers: stored.ciphers,
        folders: stored.folders,
        organizations: stored.organizations,
    }))
}

pub fn last_synced_at() -> Option<chrono::DateTime<chrono::Utc>> {
    let bytes = fs::read(path().ok()?).ok()?;
    let stored: StoredVault = serde_json::from_slice(&bytes).ok()?;
    chrono::DateTime::parse_from_rfc3339(&stored.synced_at)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}
