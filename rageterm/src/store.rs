use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub rage_blob: String,

    pub created: DateTime<Utc>,

    pub modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub version: u32,

    pub items: BTreeMap<String, Item>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            items: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store io: {0}")]
    Io(#[from] io::Error),

    #[error("store parse: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("store version {0} not supported (expected 1)")]
    UnsupportedVersion(u32),
}

impl Store {
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        match fs::read(path) {
            Ok(bytes) => {
                let store: Store = serde_json::from_slice(&bytes)?;
                if store.version != 1 {
                    return Err(StoreError::UnsupportedVersion(store.version));
                }
                Ok(store)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        let json = serde_json::to_vec_pretty(self)?;
        config::write_private(path, &json)?;
        Ok(())
    }

    pub fn upsert(&mut self, name: &str, rage_blob: String, now: DateTime<Utc>) {
        if let Some(existing) = self.items.get_mut(name) {
            existing.rage_blob = rage_blob;
            existing.modified = now;
        } else {
            self.items.insert(
                name.to_string(),
                Item {
                    rage_blob,
                    created: now,
                    modified: now,
                },
            );
        }
    }

    pub fn get(&self, name: &str) -> Option<&Item> {
        self.items.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn round_trip_via_disk() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("store.json");

        let mut s = Store::default();
        let now = Utc::now();
        s.upsert("github", "BLOB-A".to_string(), now);
        s.upsert("gitlab", "BLOB-B".to_string(), now);
        s.save(&path).unwrap();

        let loaded = Store::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.items.len(), 2);
        assert_eq!(loaded.get("github").unwrap().rage_blob, "BLOB-A");
        assert_eq!(loaded.get("gitlab").unwrap().rage_blob, "BLOB-B");
    }

    #[test]
    fn missing_file_yields_empty_store() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("does-not-exist.json");
        let s = Store::load(&path).unwrap();
        assert_eq!(s.version, 1);
        assert!(s.items.is_empty());
    }

    #[test]
    fn upsert_preserves_created_timestamp() {
        let mut s = Store::default();
        let t1 = DateTime::parse_from_rfc3339("2026-05-03T20:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let t2 = DateTime::parse_from_rfc3339("2026-05-03T21:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        s.upsert("a", "B1".into(), t1);
        s.upsert("a", "B2".into(), t2);
        let it = s.get("a").unwrap();
        assert_eq!(it.created, t1);
        assert_eq!(it.modified, t2);
        assert_eq!(it.rage_blob, "B2");
    }
}
