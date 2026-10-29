//! Bitwarden master-key derivation parameters: PBKDF2-SHA256 and Argon2id.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::bitwarden::{KDF_ARGON2ID, KDF_ITERATIONS_DEFAULT, KDF_PBKDF2, derive_master_key};

/// The 2013-era Bitwarden default; the lowest PBKDF2 count any real account
/// can carry, and only accepted from a server with the user's consent.
pub const KDF_ITERATIONS_LEGACY_MIN: u32 = 5_000;

pub const KDF_ITERATIONS_MAX: u32 = 2_000_000;

pub const ARGON2_ITERATIONS_MIN: u32 = 2;
pub const ARGON2_ITERATIONS_MAX: u32 = 10;
pub const ARGON2_ITERATIONS_DEFAULT: u32 = 3;

pub const ARGON2_MEMORY_MIB_MIN: u32 = 16;
pub const ARGON2_MEMORY_MIB_MAX: u32 = 1024;
pub const ARGON2_MEMORY_MIB_DEFAULT: u32 = 64;

pub const ARGON2_PARALLELISM_MIN: u32 = 1;
pub const ARGON2_PARALLELISM_MAX: u32 = 16;
pub const ARGON2_PARALLELISM_DEFAULT: u32 = 4;

/// How an account's master key is derived, as prelogin reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub kdf: u32,

    pub iterations: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::pbkdf2(KDF_ITERATIONS_DEFAULT)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KdfError {
    #[error("KDF type {0} is neither PBKDF2-SHA256 (0) nor Argon2id (1)")]
    UnsupportedType(u32),

    #[error("Argon2id needs memory and parallelism parameters")]
    MissingArgon2Params,

    #[error("argon2: {0}")]
    Argon2(String),
}

impl KdfParams {
    pub fn pbkdf2(iterations: u32) -> Self {
        Self {
            kdf: KDF_PBKDF2,
            iterations,
            memory_mib: None,
            parallelism: None,
        }
    }

    pub fn argon2id(iterations: u32, memory_mib: u32, parallelism: u32) -> Self {
        Self {
            kdf: KDF_ARGON2ID,
            iterations,
            memory_mib: Some(memory_mib),
            parallelism: Some(parallelism),
        }
    }

    pub fn argon2id_default() -> Self {
        Self::argon2id(
            ARGON2_ITERATIONS_DEFAULT,
            ARGON2_MEMORY_MIB_DEFAULT,
            ARGON2_PARALLELISM_DEFAULT,
        )
    }

    /// From the four loose values a stored session or a server response
    /// carries; an absent type means PBKDF2, the only kind older sessions had.
    pub fn from_parts(
        kdf: Option<u32>,
        iterations: u32,
        memory_mib: Option<u32>,
        parallelism: Option<u32>,
    ) -> Self {
        match kdf.unwrap_or(KDF_PBKDF2) {
            KDF_PBKDF2 => Self::pbkdf2(iterations),
            other => Self {
                kdf: other,
                iterations,
                memory_mib,
                parallelism,
            },
        }
    }

    pub fn is_argon2id(&self) -> bool {
        self.kdf == KDF_ARGON2ID
    }

    /// True when `self` is cheaper to brute-force than `pinned` in a way the
    /// account's owner would not have chosen: fewer PBKDF2 iterations, fewer
    /// Argon2id passes or less memory, or a move from Argon2id to PBKDF2.
    pub fn weaker_than(&self, pinned: &KdfParams) -> bool {
        match (pinned.is_argon2id(), self.is_argon2id()) {
            (false, false) => self.iterations < pinned.iterations,
            (true, false) => true,
            (false, true) => false,
            (true, true) => {
                self.iterations < pinned.iterations
                    || self.memory_mib.unwrap_or(0) < pinned.memory_mib.unwrap_or(0)
            }
        }
    }

    /// Below what this client would choose for a new account.
    pub fn below_recommended(&self) -> bool {
        if self.is_argon2id() {
            self.iterations < ARGON2_ITERATIONS_DEFAULT
                || self.memory_mib.unwrap_or(0) < ARGON2_MEMORY_MIB_DEFAULT
        } else {
            self.iterations < KDF_ITERATIONS_DEFAULT
        }
    }

    pub fn describe(&self) -> String {
        if self.is_argon2id() {
            format!(
                "Argon2id t={} m={}MiB p={}",
                self.iterations,
                self.memory_mib.unwrap_or(0),
                self.parallelism.unwrap_or(0)
            )
        } else {
            format!("PBKDF2-SHA256 {} iterations", self.iterations)
        }
    }

    /// The 32-byte Bitwarden master key. Argon2id hashes SHA-256 of the
    /// lowercased email as its salt, as the Bitwarden clients do.
    pub fn derive_master_key(
        &self,
        password: &str,
        email: &str,
    ) -> Result<Zeroizing<[u8; 32]>, KdfError> {
        let email = email.trim().to_lowercase();
        match self.kdf {
            KDF_PBKDF2 => Ok(derive_master_key(password, &email, self.iterations)),
            KDF_ARGON2ID => {
                let (Some(memory_mib), Some(parallelism)) = (self.memory_mib, self.parallelism)
                else {
                    return Err(KdfError::MissingArgon2Params);
                };
                let salt = Sha256::digest(email.as_bytes());
                let params = argon2::Params::new(
                    memory_mib.saturating_mul(1024),
                    self.iterations,
                    parallelism,
                    Some(32),
                )
                .map_err(|e| KdfError::Argon2(e.to_string()))?;
                let argon = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    params,
                );
                let mut out = Zeroizing::new([0u8; 32]);
                argon
                    .hash_password_into(password.as_bytes(), salt.as_slice(), out.as_mut())
                    .map_err(|e| KdfError::Argon2(e.to_string()))?;
                Ok(out)
            }
            other => Err(KdfError::UnsupportedType(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_the_existing_derivation() {
        let p = KdfParams::pbkdf2(5_000);
        assert_eq!(
            *p.derive_master_key("pw", "A@Example.com").unwrap(),
            *derive_master_key("pw", "a@example.com", 5_000)
        );
    }

    #[test]
    fn argon2id_matches_libargon2_over_the_sha256_of_the_email() {
        // Reference computed with argon2-cffi 25.1.0 (libargon2):
        // hash_secret_raw(b"67t9b5g67$%Dh89n", sha256(b"test_key").digest(),
        //   time_cost=4, memory_cost=32*1024, parallelism=2, hash_len=32, type=ID)
        let p = KdfParams::argon2id(4, 32, 2);
        let got = p.derive_master_key("67t9b5g67$%Dh89n", "test_key").unwrap();
        assert_eq!(hex(&*got), ARGON2_REFERENCE);
    }

    const ARGON2_REFERENCE: &str =
        "cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn argon2id_without_memory_or_parallelism_is_refused() {
        let p = KdfParams::from_parts(Some(KDF_ARGON2ID), 3, None, Some(4));
        assert_eq!(
            p.derive_master_key("pw", "e").unwrap_err(),
            KdfError::MissingArgon2Params
        );
    }

    #[test]
    fn downgrade_ordering() {
        let pin = KdfParams::pbkdf2(600_000);
        assert!(KdfParams::pbkdf2(100_000).weaker_than(&pin));
        assert!(!KdfParams::pbkdf2(600_000).weaker_than(&pin));
        assert!(!KdfParams::argon2id_default().weaker_than(&pin));
        let pin = KdfParams::argon2id_default();
        assert!(KdfParams::pbkdf2(2_000_000).weaker_than(&pin));
        assert!(KdfParams::argon2id(3, 32, 4).weaker_than(&pin));
        assert!(KdfParams::argon2id(2, 64, 4).weaker_than(&pin));
        assert!(!KdfParams::argon2id(3, 64, 1).weaker_than(&pin));
    }

    #[test]
    fn a_stored_session_without_a_type_is_pbkdf2() {
        assert_eq!(
            KdfParams::from_parts(None, 100_000, Some(64), Some(4)),
            KdfParams::pbkdf2(100_000)
        );
    }
}
