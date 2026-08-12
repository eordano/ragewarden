use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config;

#[derive(Debug, Error)]
pub enum IdentitiesError {
    #[error("identities io: {0}")]
    Io(#[from] io::Error),

    #[error("identities parse: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("identities version {0} not supported (expected 1)")]
    UnsupportedVersion(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledIdentity {
    pub id: String,

    pub kind: IdentityKind,

    pub label: String,

    pub created: DateTime<Utc>,

    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum IdentityKind {
    YubiKeyPiv {
        public_key_hex: String,

        serial: u32,

        slot: u8,

        /// Set when the enrollment used the software stand-in instead of a
        /// card. Defaults to false so pre-existing `identities.json` files
        /// (which could only have been written by a mock-capable build) load,
        /// and `commands::build_identity_list` treats an unmarked hardware
        /// entry as real -- a real build then fails closed at the reader
        /// instead of quietly decrypting from a file.
        #[serde(default)]
        mock: bool,
    },

    Fido2HmacSecret {
        credential_id_b64: String,

        salt_hex: String,

        rp_id: String,

        #[serde(default)]
        mock: bool,
    },

    OsKeyring {
        public_key_hex: String,

        armored_pubkey: ragewarden_core::ArmoredAgeRecipient,

        keyring_service: String,

        keyring_user: String,
    },

    PaperRecovery {
        armored_pubkey: ragewarden_core::ArmoredAgeRecipient,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    version: u32,
    items: BTreeMap<String, EnrolledIdentity>,
}

impl Default for Stored {
    fn default() -> Self {
        Self {
            version: 1,
            items: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Identities {
    pub items: BTreeMap<String, EnrolledIdentity>,
}

impl Identities {
    pub fn load() -> Result<Self, IdentitiesError> {
        let path = config::identities_path()?;
        Self::load_from(&path)
    }

    pub fn load_from(path: &Path) -> Result<Self, IdentitiesError> {
        match fs::read(path) {
            Ok(bytes) => {
                let stored: Stored = serde_json::from_slice(&bytes)?;
                if stored.version != 1 {
                    return Err(IdentitiesError::UnsupportedVersion(stored.version));
                }
                Ok(Self {
                    items: stored.items,
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<(), IdentitiesError> {
        let path = config::identities_path()?;
        config::ensure_config_dir()?;
        let stored = Stored {
            version: 1,
            items: self.items.clone(),
        };
        let json = serde_json::to_vec_pretty(&stored)?;
        config::write_private(&path, &json)?;
        Ok(())
    }

    pub fn insert(&mut self, identity: EnrolledIdentity) {
        self.items.insert(identity.id.clone(), identity);
    }

    pub fn remove(&mut self, id: &str) -> Option<EnrolledIdentity> {
        self.items.remove(id)
    }

    #[allow(dead_code)]
    pub fn get(&self, id: &str) -> Option<&EnrolledIdentity> {
        self.items.get(id)
    }

    /// Was this FIDO2 credential enrolled with the software stand-in?
    /// Encryption to a FIDO2 recipient needs the same PRF the decrypter will
    /// see, and the `Recipient` on the wire carries no mock flag, so the answer
    /// has to come from the local enrollment record.
    pub fn is_mock_fido_credential(&self, credential_id: &[u8]) -> bool {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
        self.items.values().any(|e| match &e.kind {
            IdentityKind::Fido2HmacSecret {
                credential_id_b64,
                mock,
                ..
            } => {
                *mock
                    && B64URL
                        .decode(credential_id_b64.as_bytes())
                        .map(|id| id == credential_id)
                        .unwrap_or(false)
            }
            _ => false,
        })
    }

    pub fn iter_chronological(&self) -> impl Iterator<Item = &EnrolledIdentity> {
        let mut v: Vec<&EnrolledIdentity> = self.items.values().collect();
        v.sort_by_key(|e| e.created);
        v.into_iter()
    }
}

pub fn fresh_id() -> String {
    uuid_v4_string()
}

fn uuid_v4_string() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);

    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn save_then_load_round_trips_an_entry() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("identities.json");
        let mut ids = Identities::default();
        ids.insert(EnrolledIdentity {
            id: "abc".into(),
            kind: IdentityKind::PaperRecovery {
                armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted(
                    "age1xxxxxx".into(),
                ),
            },
            label: "paper".into(),
            created: Utc::now(),
            last_used: None,
        });

        let stored = Stored {
            version: 1,
            items: ids.items.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&stored).unwrap();
        crate::config::write_private(&path, &bytes).unwrap();
        let loaded = Identities::load_from(&path).unwrap();
        assert_eq!(loaded.items.len(), 1);
        assert!(matches!(
            loaded.get("abc").unwrap().kind,
            IdentityKind::PaperRecovery { .. }
        ));
    }

    #[test]
    fn fresh_id_is_uuidv4_shaped() {
        let id = fresh_id();
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[2].chars().next().unwrap(), '4');
    }
}
