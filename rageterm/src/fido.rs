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

    #[error(
        "the authenticator needs its FIDO2 PIN, but there is no terminal and no `pinentry` \
         program on PATH to ask for it"
    )]
    NoPinPrompt,

    #[error("FIDO2 PIN entry: {0}")]
    Pin(String),

    #[error("{0}")]
    Busy(String),

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
    /// The seed this credential's items are bound to (see `IdentityKind`).
    pub uv: Option<bool>,
    /// The credential's ES256 public key (uncompressed SEC1), which signs the
    /// native host's unwrap proofs; `None` for a credential of another algorithm.
    pub public_key: Option<[u8; 65]>,
}

/// What `makeCredential` returned: the credential id and, for ES256, its
/// public key as an uncompressed SEC1 point.
pub struct NewCredential {
    pub id: Vec<u8>,
    pub public_key: Option<[u8; 65]>,
}

/// One assertion's signed part: authenticatorData and the DER signature over
/// `authenticatorData || SHA-256(client data)`.
#[derive(Debug, Clone, Default)]
pub struct AssertionSignature {
    pub authenticator_data: Vec<u8>,
    pub signature_der: Vec<u8>,
}

/// One hmac-secret assertion: the PRF plus the authenticatorData flags that
/// prove (UP) a touch happened and (UV) the user was verified, and the
/// assertion's signature.
#[derive(Clone)]
pub struct HmacAssertion {
    pub prf: [u8; 32],
    pub user_present: bool,
    pub user_verified: bool,
    pub signed: AssertionSignature,
}

static LAST_ASSERTION_FLAGS: std::sync::Mutex<Option<(bool, bool)>> = std::sync::Mutex::new(None);

/// Forget the flags of the previous assertion; call before an unwrap whose
/// evidence matters (the native host).
pub fn reset_observed_flags() {
    *LAST_ASSERTION_FLAGS
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
}

/// `(user_present, user_verified)` of the last real assertion in this process.
pub fn take_observed_flags() -> Option<(bool, bool)> {
    LAST_ASSERTION_FLAGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
}

fn observe(a: &HmacAssertion) -> Result<[u8; 32], FidoError> {
    *LAST_ASSERTION_FLAGS
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some((a.user_present, a.user_verified));
    if !a.user_present {
        return Err(FidoError::TouchNotRegistered);
    }
    Ok(a.prf)
}

/// The device boundary. `fido_ctap::CtapDevice` is the only real implementation.
pub trait Fido2Device {
    /// Create a credential carrying the `hmac-secret` extension.
    fn make_hmac_credential(&mut self, rp_id: &str) -> Result<NewCredential, FidoError>;

    /// One `getAssertion` with the hmac-secret extension. Blocks on the touch.
    /// `uv` selects the seed (see `IdentityKind::Fido2HmacSecret::uv`).
    /// `client_data` is what the assertion signs (as SHA-256 of it, the
    /// clientDataHash); `None` is a fresh random challenge.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        uv: Option<bool>,
        client_data: Option<&[u8]>,
    ) -> Result<HmacAssertion, FidoError>;

    /// A plain assertion over `client_data`, with a touch or (`user_presence:
    /// false`) silently where the authenticator allows it.
    fn sign_assertion(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        client_data: &[u8],
        user_presence: bool,
    ) -> Result<AssertionSignature, FidoError>;

    /// Whether this authenticator verifies users (PIN or built-in UV) today.
    fn verifies_users(&mut self) -> Result<bool, FidoError>;

    fn describe(&self) -> String;
}

pub fn real_enroll(rp_id: &str) -> Result<EnrolledFido, FidoError> {
    use rand::Rng;

    let _device = crate::lock::device_session().map_err(|e| FidoError::Busy(e.to_string()))?;
    let mut device = crate::fido_ctap::open_single_authenticator()?;
    let credential = device.make_hmac_credential(rp_id)?;

    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);

    let uv = Some(device.verifies_users()?);
    let probe = observe(&device.hmac_secret(rp_id, &credential.id, &salt, uv, None)?)?;
    if probe == [0u8; 32] {
        return Err(FidoError::NoPrfOutput);
    }

    Ok(EnrolledFido {
        credential_id: credential.id,
        salt,
        rp_id: rp_id.to_string(),
        mock: false,
        uv,
        public_key: credential.public_key,
    })
}

fn real_assertion(
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    uv: Option<bool>,
    client_data: Option<&[u8]>,
) -> Result<HmacAssertion, FidoError> {
    let _device = crate::lock::device_session().map_err(|e| FidoError::Busy(e.to_string()))?;
    let mut device = crate::fido_ctap::open_single_authenticator()?;
    device.hmac_secret(rp_id, credential_id, salt, uv, client_data)
}

pub struct FidoIdentity {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub label: String,
    /// Recorded at enrollment, never read from the environment.
    pub mock: bool,
    /// Recorded at enrollment: which hmac-secret seed to ask for.
    pub uv: Option<bool>,
    /// The credential's public key, when enrollment (or `attest-fido2`)
    /// recorded it: a native-host unwrap then returns a signed proof.
    pub public_key: Option<[u8; 65]>,
}

impl FidoIdentity {
    /// Whether this stanza is addressed to this credential, without touching the key.
    pub fn names(&self, stanza: &Stanza) -> Result<bool, IdentityError> {
        if stanza.tag != stanza_format::TAG_FIDO2_HMAC {
            return Ok(false);
        }
        let stanza_credid =
            fido2_hmac_credential_id(stanza).map_err(|e| IdentityError::Crypto(e.to_string()))?;
        Ok(stanza_credid == self.credential_id)
    }
}

impl Identity for FidoIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if !self.names(stanza)? {
            return Ok(None);
        }
        let salt = fido2_hmac_salt(stanza).map_err(|e| IdentityError::Crypto(e.to_string()))?;
        let message = crate::native_proof::pending_message();
        let assertion = assertion(
            &self.credential_id,
            &salt,
            &self.rp_id,
            self.mock,
            self.uv,
            message.as_deref(),
        )
        .map_err(|e| IdentityError::Hardware(e.to_string()))?;
        let prf = observe(&assertion).map_err(|e| IdentityError::Hardware(e.to_string()))?;
        if let (Some(_), Some(public_key)) = (&message, self.public_key) {
            if let Ok(signature) =
                crate::native_proof::raw_signature(&assertion.signed.signature_der)
            {
                crate::native_proof::record(crate::native_proof::DeviceSignature::Fido2 {
                    authenticator_data: assertion.signed.authenticator_data.clone(),
                    signature,
                    public_key,
                });
            }
        }

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
    uv: Option<bool>,
) -> Result<[u8; 32], FidoError> {
    derive_prf(credential_id, salt, rp_id, mock, uv)
}

fn derive_prf(
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    mock: bool,
    uv: Option<bool>,
) -> Result<[u8; 32], FidoError> {
    observe(&assertion(credential_id, salt, rp_id, mock, uv, None)?)
}

fn assertion(
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    mock: bool,
    uv: Option<bool>,
    client_data: Option<&[u8]>,
) -> Result<HmacAssertion, FidoError> {
    if mock {
        mock_assertion_dispatch(credential_id, salt, rp_id, client_data)
    } else {
        real_assertion(credential_id, salt, rp_id, uv, client_data)
    }
}

/// The public keys that could have made `signed` over `client_data`: ECDSA
/// recovery gives two candidates per signature.
fn recovery_candidates(
    signed: &AssertionSignature,
    client_data: &[u8],
) -> Result<Vec<[u8; 65]>, FidoError> {
    use p256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use p256::elliptic_curve::sec1::ToSec1Point;
    let signature = Signature::from_der(&signed.signature_der)
        .map_err(|e| FidoError::Hardware(format!("assertion signature is not DER: {e}")))?;
    let message = [
        signed.authenticator_data.as_slice(),
        &crate::native_proof::digest(client_data),
    ]
    .concat();
    Ok([false, true]
        .into_iter()
        .filter_map(|odd| {
            VerifyingKey::recover_from_msg(&message, &signature, RecoveryId::new(odd, false)).ok()
        })
        .filter_map(|k| {
            k.as_affine()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()
                .ok()
        })
        .collect())
}

/// The credential's public key, recovered from two of its assertion
/// signatures: one with a touch, the second silent where the authenticator
/// allows it (else a second touch). For a credential enrolled before rageterm
/// stored the key, so its native-host unwraps can be attested.
pub fn recover_public_key(
    credential_id: &[u8],
    rp_id: &str,
    mock: bool,
) -> Result<[u8; 65], FidoError> {
    use rand::Rng;
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    rand::rng().fill_bytes(&mut first);
    rand::rng().fill_bytes(&mut second);
    let sign = |data: &[u8], up: bool| -> Result<AssertionSignature, FidoError> {
        if mock {
            mock_sign_dispatch(credential_id, rp_id, data, up)
        } else {
            let _device =
                crate::lock::device_session().map_err(|e| FidoError::Busy(e.to_string()))?;
            let mut device = crate::fido_ctap::open_single_authenticator()?;
            device.sign_assertion(rp_id, credential_id, data, up)
        }
    };
    let touched = sign(&first, true)?;
    if touched
        .authenticator_data
        .get(32)
        .is_none_or(|f| f & 0x01 == 0)
    {
        return Err(FidoError::TouchNotRegistered);
    }
    let silent = sign(&second, false).or_else(|_| {
        crate::ceremony::announce_step(
            "this authenticator signs only with a touch; touch it once more to finish",
        );
        sign(&second, true)
    })?;
    let a = recovery_candidates(&touched, &first)?;
    let b = recovery_candidates(&silent, &second)?;
    let common: Vec<[u8; 65]> = a.into_iter().filter(|k| b.contains(k)).collect();
    match common.as_slice() {
        [key] => Ok(*key),
        _ => Err(FidoError::Hardware(
            "the two assertions do not agree on one public key; is this the enrolled \
             credential, and an ES256 one?"
                .into(),
        )),
    }
}

#[cfg(not(any(test, feature = "mock-hardware")))]
fn mock_assertion_dispatch(
    _credential_id: &[u8],
    _salt: &[u8; 32],
    _rp_id: &str,
    _client_data: Option<&[u8]>,
) -> Result<HmacAssertion, FidoError> {
    Err(FidoError::MockIdentityOnRealBuild)
}

#[cfg(not(any(test, feature = "mock-hardware")))]
fn mock_sign_dispatch(
    _credential_id: &[u8],
    _rp_id: &str,
    _client_data: &[u8],
    _user_presence: bool,
) -> Result<AssertionSignature, FidoError> {
    Err(FidoError::MockIdentityOnRealBuild)
}

#[cfg(any(test, feature = "mock-hardware"))]
fn mock_opt_in() -> Result<(), FidoError> {
    use crate::hw;
    if !hw::mock_enabled() {
        return Err(FidoError::Mock(format!(
            "identity is a software stand-in but {} is not set to 1; refusing to derive \
             a PRF without either a device or an explicit mock opt-in",
            hw::MOCK_ENV
        )));
    }
    hw::warn_banner_once();
    Ok(())
}

#[cfg(any(test, feature = "mock-hardware"))]
fn mock_assertion_dispatch(
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    client_data: Option<&[u8]>,
) -> Result<HmacAssertion, FidoError> {
    mock_opt_in()?;
    let random = rand::random::<[u8; 32]>();
    Ok(HmacAssertion {
        prf: mock::prf(credential_id, salt)?,
        user_present: true,
        user_verified: false,
        signed: mock::sign(credential_id, rp_id, client_data.unwrap_or(&random), true)?,
    })
}

#[cfg(any(test, feature = "mock-hardware"))]
fn mock_sign_dispatch(
    credential_id: &[u8],
    rp_id: &str,
    client_data: &[u8],
    user_presence: bool,
) -> Result<AssertionSignature, FidoError> {
    mock_opt_in()?;
    mock::sign(credential_id, rp_id, client_data, user_presence)
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
        use p256::elliptic_curve::Generate;
        use p256::elliptic_curve::sec1::ToSec1Point;
        let mut credential_id = [0u8; 16];
        let mut salt = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        rand::rng().fill_bytes(&mut credential_id);
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut hmac_key);
        write_key(&credential_id, &hmac_key)?;
        let signing = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let path = signing_key_path(&credential_id)?;
        crate::config::write_private(&path, &signing.to_bytes())?;
        let public_key = signing
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .ok();
        Ok(EnrolledFido {
            credential_id: credential_id.to_vec(),
            salt,
            rp_id: rp_id.to_string(),
            mock: true,
            uv: Some(false),
            public_key,
        })
    }

    /// An assertion as an authenticator makes it: authenticatorData is
    /// SHA-256(rp id) || flags || a zero counter, signed together with
    /// SHA-256(client data).
    pub fn sign(
        credential_id: &[u8],
        rp_id: &str,
        client_data: &[u8],
        user_presence: bool,
    ) -> Result<AssertionSignature, FidoError> {
        use p256::ecdsa::signature::Signer;
        use sha2::Digest;
        let bytes = std::fs::read(signing_key_path(credential_id)?)?;
        let key = p256::ecdsa::SigningKey::from_slice(&bytes)
            .map_err(|_| FidoError::Mock("mock FIDO2 signing key is malformed".into()))?;
        let mut authenticator_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        authenticator_data.push(if user_presence { 0x01 } else { 0x00 });
        authenticator_data.extend_from_slice(&[0, 0, 0, 0]);
        let signed = [
            authenticator_data.as_slice(),
            &crate::native_proof::digest(client_data),
        ]
        .concat();
        let signature: p256::ecdsa::Signature = key.sign(&signed);
        Ok(AssertionSignature {
            authenticator_data,
            signature_der: signature.to_der().as_bytes().to_vec(),
        })
    }

    fn signing_key_path(credential_id: &[u8]) -> std::io::Result<PathBuf> {
        Ok(crate::config::config_dir()?
            .join(format!("mock-fido-{}.p256", hex::encode(credential_id))))
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
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        crate::tests_lock::set_var(hw::MOCK_ENV, "1");
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                crate::tests_lock::remove_var(hw::MOCK_ENV);
                crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
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
            enrolled.uv,
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
            uv: enrolled.uv,
            public_key: enrolled.public_key,
        };
        assert!(hw::is_mock_label(id.display()));
        let recovered = id.try_unwrap_stanza(&stanza).unwrap().expect("matches");
        assert_eq!(&*recovered, &file_key);
    }

    #[test]
    fn a_mock_identity_refuses_to_derive_a_prf_without_the_opt_in() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        crate::tests_lock::set_var(hw::MOCK_ENV, "1");
        let enrolled = mock_enroll("ragewarden").expect("mock enroll");
        crate::tests_lock::remove_var(hw::MOCK_ENV);

        let err = derive_prf_for_encrypt(
            &enrolled.credential_id,
            &enrolled.salt,
            &enrolled.rp_id,
            true,
            enrolled.uv,
        )
        .unwrap_err();
        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
        assert!(err.to_string().contains("refusing to derive"));
    }
}
