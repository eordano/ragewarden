//! FIDO2 `hmac-secret` identity.
//!
//! Same shape as `piv.rs`: a `Fido2Device` trait is the boundary, the real
//! implementation lives in `fido_ctap.rs` and is the only device-blocked code,
//! and the software stand-in is compiled out of any build that is not a test or
//! an explicit `--features mock-hardware` build.
//!
//! The credential is created with the `hmac-secret` extension at enrollment.
//! Every later use is a `getAssertion` with that extension and the stanza's
//! salt; the authenticator returns HMAC-SHA256(CredRandom, salt) only after a
//! user-presence check, which is the tap.

use ragewarden_core::stanza_format::{
    self, decrypt_fido2_hmac_with_prf, fido2_hmac_credential_id, fido2_hmac_salt,
};
use ragewarden_core::{FileKey, Identity, IdentityError, Stanza};
use thiserror::Error;

pub const FIDO2_RP_ID: &str = "ragewarden";

#[derive(Debug, Error)]
pub enum FidoError {
    #[error(
        "no FIDO2 authenticator found. Plug in the security key and try again \
         (a use needs the same key that was enrolled)."
    )]
    NoDevice,

    #[error("more than one FIDO2 authenticator is plugged in; leave exactly one connected")]
    AmbiguousDevice,

    #[error(
        "this authenticator does not support the `hmac-secret` extension, so it cannot \
         wrap secrets. A YubiKey 5, SoloKey or Nitrokey 3 does."
    )]
    NoHmacSecret,

    #[error("the authenticator requires its PIN for this operation")]
    PinRequired,

    #[error("wrong FIDO2 PIN")]
    PinInvalid,

    #[error("FIDO2 PIN is blocked; reset the authenticator to clear it")]
    PinBlocked,

    #[error("no terminal available to read the FIDO2 PIN on")]
    NoPinPrompt,

    #[error(
        "the authenticator did not report a user-presence touch -- the ceremony timed out \
         or was declined"
    )]
    TouchNotRegistered,

    #[error(
        "the enrolled credential is not on this authenticator (no assertion for the \
         stored credential id)"
    )]
    UnknownCredential,

    #[error(
        "the authenticator returned an assertion without an hmac-secret output; the \
         credential was probably created without the extension"
    )]
    NoPrfOutput,

    #[error("fido: {0}")]
    Hardware(String),

    #[error("stanza: {0}")]
    Stanza(#[from] stanza_format::StanzaFormatError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(not(any(test, feature = "mock-hardware")))]
    #[error(
        "this identity was enrolled with the software stand-in \
         (RAGEWARDEN_MOCK_HARDWARE=1) and this build has no mock support. Re-enroll \
         against a real authenticator with `rageterm enroll-fido2`."
    )]
    MockIdentityOnRealBuild,

    #[cfg(any(test, feature = "mock-hardware"))]
    #[error("mock hardware: {0}")]
    Mock(String),
}

#[derive(Debug, Clone)]
pub struct EnrolledFido {
    pub credential_id: Vec<u8>,
    pub salt: [u8; 32],
    pub rp_id: String,
    /// True only for the software stand-in.
    pub mock: bool,
}

/// The device boundary. `fido_ctap::CtapDevice` is the only real implementation.
pub trait Fido2Device {
    /// Create a credential carrying the `hmac-secret` extension. Returns the
    /// credential id.
    fn make_hmac_credential(&mut self, rp_id: &str) -> Result<Vec<u8>, FidoError>;

    /// One `getAssertion` with the hmac-secret extension. Blocks on the touch.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Result<[u8; 32], FidoError>;

    fn describe(&self) -> String;
}

pub fn real_enroll(rp_id: &str) -> Result<EnrolledFido, FidoError> {
    use rand::Rng;

    let mut device = crate::fido_ctap::open_single_authenticator()?;
    let credential_id = device.make_hmac_credential(rp_id)?;

    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);

    // Immediately exercise the extension. An authenticator that silently drops
    // hmac-secret would otherwise become a recipient nothing can decrypt.
    let probe = device.hmac_secret(rp_id, &credential_id, &salt)?;
    if probe == [0u8; 32] {
        return Err(FidoError::NoPrfOutput);
    }

    Ok(EnrolledFido {
        credential_id,
        salt,
        rp_id: rp_id.to_string(),
        mock: false,
    })
}

fn real_prf(credential_id: &[u8], salt: &[u8; 32], rp_id: &str) -> Result<[u8; 32], FidoError> {
    let mut device = crate::fido_ctap::open_single_authenticator()?;
    device.hmac_secret(rp_id, credential_id, salt)
}

pub struct FidoIdentity {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub label: String,
    /// Recorded at enrollment, never read from the environment.
    pub mock: bool,
}

impl Identity for FidoIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if stanza.tag != stanza_format::TAG_FIDO2_HMAC {
            return Ok(None);
        }
        let stanza_credid =
            fido2_hmac_credential_id(stanza).map_err(|e| IdentityError::Crypto(e.to_string()))?;
        if stanza_credid != self.credential_id {
            return Ok(None);
        }
        let salt = fido2_hmac_salt(stanza).map_err(|e| IdentityError::Crypto(e.to_string()))?;

        let prf = derive_prf(&self.credential_id, &salt, &self.rp_id, self.mock)
            .map_err(|e| IdentityError::Hardware(e.to_string()))?;

        let fk = decrypt_fido2_hmac_with_prf(stanza, &prf)
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        Ok(Some(fk))
    }

    fn display(&self) -> &str {
        &self.label
    }
}

/// Encryption to a FIDO2 recipient needs the same PRF value the decrypter will
/// see, so `set` / `rotate` also require a tap. `mock` comes from the enrolled
/// identity record, not from the environment.
pub fn derive_prf_for_encrypt(
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    mock: bool,
) -> Result<[u8; 32], FidoError> {
    derive_prf(credential_id, salt, rp_id, mock)
}

fn derive_prf(
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    mock: bool,
) -> Result<[u8; 32], FidoError> {
    if mock {
        mock_prf_dispatch(credential_id, salt)
    } else {
        real_prf(credential_id, salt, rp_id)
    }
}

// ---------------------------------------------------------------------------
// Software stand-in -- compiled out of every non-test, non-`mock-hardware` build
// ---------------------------------------------------------------------------

#[cfg(not(any(test, feature = "mock-hardware")))]
fn mock_prf_dispatch(_credential_id: &[u8], _salt: &[u8; 32]) -> Result<[u8; 32], FidoError> {
    Err(FidoError::MockIdentityOnRealBuild)
}

#[cfg(any(test, feature = "mock-hardware"))]
fn mock_prf_dispatch(credential_id: &[u8], salt: &[u8; 32]) -> Result<[u8; 32], FidoError> {
    use crate::hw;
    if !hw::mock_enabled() {
        return Err(FidoError::Mock(format!(
            "identity is a software stand-in but {} is not set to 1; refusing to derive \
             a PRF without either a device or an explicit mock opt-in",
            hw::MOCK_ENV
        )));
    }
    hw::warn_banner_once();
    mock::prf(credential_id, salt)
}

#[cfg(any(test, feature = "mock-hardware"))]
pub fn mock_enroll(rp_id: &str) -> Result<EnrolledFido, FidoError> {
    crate::hw::warn_banner_once();
    mock::enroll(rp_id)
}

#[cfg(any(test, feature = "mock-hardware"))]
mod mock {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use rand::Rng;
    use sha2::Sha256;
    use std::path::PathBuf;

    type HmacSha256 = Hmac<Sha256>;

    pub fn enroll(rp_id: &str) -> Result<EnrolledFido, FidoError> {
        let mut credential_id = [0u8; 16];
        let mut salt = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        rand::rng().fill_bytes(&mut credential_id);
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut hmac_key);
        write_key(&credential_id, &hmac_key)?;
        Ok(EnrolledFido {
            credential_id: credential_id.to_vec(),
            salt,
            rp_id: rp_id.to_string(),
            mock: true,
        })
    }

    pub fn prf(credential_id: &[u8], salt: &[u8; 32]) -> Result<[u8; 32], FidoError> {
        let key = read_key(credential_id)?;
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(salt);
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn key_path(credential_id: &[u8]) -> std::io::Result<PathBuf> {
        let hex: String = hex::encode(credential_id);
        Ok(crate::config::config_dir()?.join(format!("mock-fido-{hex}.bin")))
    }

    fn write_key(credential_id: &[u8], key: &[u8; 32]) -> Result<(), FidoError> {
        let path = key_path(credential_id)?;
        crate::config::ensure_config_dir()?;
        crate::config::write_private(&path, key)?;
        Ok(())
    }

    fn read_key(credential_id: &[u8]) -> Result<[u8; 32], FidoError> {
        let path = key_path(credential_id)?;
        let bytes = std::fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(FidoError::Mock(format!(
                "mock fido key at {} is {} bytes",
                path.display(),
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw;
    use crate::tests_lock::ENV_LOCK;

    #[test]
    fn mock_identity_round_trip_is_labelled_as_mock() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::TempDir::new().unwrap();
        std::env::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        std::env::set_var(hw::MOCK_ENV, "1");
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                std::env::remove_var(hw::MOCK_ENV);
                std::env::remove_var("RAGEWARDEN_CONFIG_DIR");
            }
        }
        let _cleanup = Cleanup;

        let enrolled = mock_enroll("ragewarden").expect("mock enroll");
        assert!(enrolled.mock);
        let mut file_key = [0u8; 16];
        for (i, b) in file_key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11);
        }

        let prf = derive_prf_for_encrypt(
            &enrolled.credential_id,
            &enrolled.salt,
            &enrolled.rp_id,
            true,
        )
        .expect("mock prf");
        let stanza = ragewarden_core::stanza_format::encrypt_fido2_hmac_with_prf(
            &file_key,
            &enrolled.credential_id,
            &enrolled.salt,
            &enrolled.rp_id,
            &prf,
        );

        let id = FidoIdentity {
            credential_id: enrolled.credential_id.clone(),
            rp_id: enrolled.rp_id.clone(),
            label: hw::mock_label("mock-fido"),
            mock: true,
        };
        assert!(hw::is_mock_label(id.display()));
        let recovered = id.try_unwrap_stanza(&stanza).unwrap().expect("matches");
        assert_eq!(&*recovered, &file_key);
    }

    #[test]
    fn a_mock_identity_refuses_to_derive_a_prf_without_the_opt_in() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        std::env::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        std::env::set_var(hw::MOCK_ENV, "1");
        let enrolled = mock_enroll("ragewarden").expect("mock enroll");
        std::env::remove_var(hw::MOCK_ENV);

        let err = derive_prf_for_encrypt(
            &enrolled.credential_id,
            &enrolled.salt,
            &enrolled.rp_id,
            true,
        )
        .unwrap_err();
        std::env::remove_var("RAGEWARDEN_CONFIG_DIR");
        assert!(err.to_string().contains("refusing to derive"));
    }
}
