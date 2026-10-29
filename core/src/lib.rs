#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

use std::collections::HashSet;
use std::io::{Read, Write};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age_core_compat::{age_filekey_from_bytes, age_stanza_to_ours, our_stanza_to_age};
use thiserror::Error;
use zeroize::Zeroizing;

pub mod armored;
pub mod audit;
pub mod bech32;
#[cfg(feature = "bitwarden")]
pub mod bitwarden;
pub mod generator;
#[cfg(feature = "history")]
pub mod history;
#[cfg(feature = "reqwest-client")]
pub mod http_reqwest;
pub mod identity;
#[cfg(feature = "bitwarden")]
pub mod kdf;
#[cfg(feature = "policy")]
pub mod policy;
pub mod protected;
pub mod recipient;
pub mod recovery;
#[cfg(feature = "registry")]
pub mod registry;
pub mod stanza;
pub mod stanza_format;
#[cfg(feature = "sync")]
pub mod sync;
#[cfg(feature = "bitwarden")]
pub mod tokens;
pub mod totp;
#[cfg(feature = "bitwarden")]
pub mod type2;

#[cfg(all(test, feature = "bitwarden"))]
mod tests;

pub use armored::{ArmoredAgeRecipient, ArmoredAgeSecret, ArmoredKeyError};
pub use identity::{FileKey, Identity, IdentityError};
pub use recipient::Recipient;
pub use stanza::Stanza;
#[cfg(feature = "bitwarden")]
pub use tokens::{BearerToken, RefreshToken};
#[cfg(feature = "bitwarden")]
pub use type2::Type2EncString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgeBlob(pub Vec<u8>);

impl AgeBlob {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_str(&self) -> Result<&str, AgeBlobUtf8Error> {
        std::str::from_utf8(&self.0).map_err(|e| AgeBlobUtf8Error {
            valid_up_to: e.valid_up_to(),
        })
    }

    pub fn to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "age blob is not valid UTF-8 (first bad byte at offset {valid_up_to}); ASCII-armored age output always is, so this blob is not armored age output"
)]
pub struct AgeBlobUtf8Error {
    pub valid_up_to: usize,
}

pub type Plaintext = Zeroizing<Vec<u8>>;

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("no recipients provided")]
    NoRecipients,

    #[error(
        "recipient `{0}` needs PRF output supplied via encrypt_with_prf; not available at encrypt time"
    )]
    NeedsPrfOutput(&'static str),

    #[error("recipient: {0}")]
    Recipient(String),

    #[error("age: {0}")]
    Age(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("no supplied identity matched any stanza in the header")]
    NoMatchingIdentity,

    #[error("identity: {0}")]
    Identity(#[from] IdentityError),

    #[error("age: {0}")]
    Age(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl DecryptError {
    /// Stable machine-readable code for this failure, for boundaries (WASM,
    /// native messaging) whose callers must branch on the cause without
    /// string-matching the human message.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoMatchingIdentity => "no_matching_identity",
            Self::Identity(_) => "identity_failed",
            Self::Age(_) => "age_error",
            Self::Io(_) => "io_error",
        }
    }
}

pub fn encrypt(plaintext: &[u8], recipients: &[Recipient]) -> Result<AgeBlob, EncryptError> {
    encrypt_with_prf(plaintext, recipients, &[])
}

pub type PrfTable<'a> = &'a [PrfEntry<'a>];

/// One authenticator evaluation for `encrypt_with_prf`: the PRF output the
/// credential `credential_id` under `rp_id` returned for `salt`. The salt is
/// what the stanza carries, so drawing a fresh one per secret
/// ([`prf_requests_for`]) makes every secret need its own evaluation -- one
/// captured output opens one secret, not the vault.
///
/// An empty `credential_id` names the recipient whose enrolment salt equals
/// `salt`: the per-recipient form every client wrote before, still accepted
/// (and still siphonable) until that client evaluates fresh salts.
#[derive(Debug, Clone, Copy)]
pub struct PrfEntry<'a> {
    pub rp_id: &'a str,

    pub credential_id: &'a [u8],

    pub salt: &'a [u8; 32],

    pub prf_output: &'a [u8; 32],
}

/// What a client must have each PRF authenticator evaluate before one
/// `encrypt_with_prf` call: one fresh CSPRNG salt per PRF recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfRequest {
    pub rp_id: String,

    pub credential_id: Vec<u8>,

    pub salt: [u8; 32],
}

pub fn prf_requests_for(recipients: &[Recipient]) -> Vec<PrfRequest> {
    use rand_core::Rng;
    recipients
        .iter()
        .filter_map(|r| match r {
            Recipient::Fido2HmacSecret {
                credential_id,
                rp_id,
                ..
            }
            | Recipient::PasskeyPrf {
                credential_id,
                rp_id,
                ..
            } => {
                let mut salt = [0u8; 32];
                rand::rng().fill_bytes(&mut salt);
                Some(PrfRequest {
                    rp_id: rp_id.clone(),
                    credential_id: credential_id.clone(),
                    salt,
                })
            }
            _ => None,
        })
        .collect()
}

pub fn encrypt_with_prf(
    plaintext: &[u8],
    recipients: &[Recipient],
    prf_table: PrfTable<'_>,
) -> Result<AgeBlob, EncryptError> {
    if recipients.is_empty() {
        return Err(EncryptError::NoRecipients);
    }

    let mut age_recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();
    let mut hardware_recipients: Vec<HardwareRecipient<'_>> = Vec::new();
    for r in recipients {
        match r {
            Recipient::X25519 { public_key } => {
                let armored = encode_x25519_recipient(public_key);
                let parsed: age::x25519::Recipient = armored
                    .parse()
                    .map_err(|e: &str| EncryptError::Recipient(e.to_string()))?;
                age_recipients.push(Box::new(parsed));
            }
            Recipient::SoftwarePassphrase { armored_pubkey } => {
                let parsed: age::x25519::Recipient = armored_pubkey
                    .as_str()
                    .parse()
                    .map_err(|e: &str| EncryptError::Recipient(e.to_string()))?;
                age_recipients.push(Box::new(parsed));
            }
            Recipient::YubiKeyPiv {
                public_key,
                stanza_version,
                ..
            } => {
                hardware_recipients.push(HardwareRecipient::PivX25519 {
                    pubkey: *public_key,
                    version: stanza_version_of(*stanza_version)?,
                });
            }
            Recipient::YubiKeyPivP256 { public_key, .. } => {
                if !stanza_format::is_valid_p256_sec1_compressed(public_key) {
                    return Err(EncryptError::Recipient(
                        "YubiKeyPivP256 pubkey must be a 33-byte SEC1-compressed P-256 point"
                            .to_string(),
                    ));
                }
                hardware_recipients.push(HardwareRecipient::PivP256 { pubkey: public_key });
            }
            Recipient::AndroidKeystore {
                public_key,
                key_handle,
                stanza_version,
            } => {
                if public_key.len() != 33 {
                    return Err(EncryptError::Recipient(format!(
                        "AndroidKeystore pubkey must be 33 SEC1-compressed bytes, got {}",
                        public_key.len()
                    )));
                }
                if !stanza_format::is_valid_p256_sec1_compressed(public_key) {
                    return Err(EncryptError::Recipient(
                        "AndroidKeystore pubkey is 33 bytes but not a valid SEC1-compressed \
                         P-256 point"
                            .to_string(),
                    ));
                }
                hardware_recipients.push(HardwareRecipient::Keystore {
                    pubkey: public_key,
                    key_handle,
                    version: stanza_version_of(*stanza_version)?,
                });
            }
            Recipient::Fido2HmacSecret {
                credential_id,
                salt,
                rp_id,
            } => {
                let (salt, prf) = lookup_prf(prf_table, rp_id, credential_id, salt)
                    .ok_or(EncryptError::NeedsPrfOutput(stanza_format::TAG_FIDO2_HMAC))?;
                hardware_recipients.push(HardwareRecipient::Fido2 {
                    credential_id,
                    salt,
                    rp_id,
                    prf_output: prf,
                });
            }
            Recipient::PasskeyPrf {
                credential_id,
                salt,
                rp_id,
                ..
            } => {
                let (salt, prf) = lookup_prf(prf_table, rp_id, credential_id, salt).ok_or(
                    EncryptError::NeedsPrfOutput(stanza_format::TAG_WEBAUTHN_PRF_V1),
                )?;
                hardware_recipients.push(HardwareRecipient::WebauthnPrf {
                    credential_id,
                    salt,
                    rp_id,
                    prf_output: prf,
                });
            }
        }
    }

    let adapters: Vec<HardwareAdapter<'_>> = hardware_recipients
        .into_iter()
        .map(HardwareAdapter)
        .collect();

    let mut all_refs: Vec<&dyn age::Recipient> = Vec::new();
    for r in &age_recipients {
        all_refs.push(r.as_ref() as &dyn age::Recipient);
    }
    for a in &adapters {
        all_refs.push(a as &dyn age::Recipient);
    }

    let encryptor = age::Encryptor::with_recipients(all_refs.into_iter())
        .map_err(|e| EncryptError::Age(format!("{e}")))?;

    let mut output = Vec::new();
    {
        let armor = ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)
            .map_err(EncryptError::Io)?;
        let mut writer = encryptor
            .wrap_output(armor)
            .map_err(|e| EncryptError::Age(format!("{e}")))?;
        writer.write_all(plaintext)?;
        writer
            .finish()
            .map_err(|e| EncryptError::Age(format!("{e}")))?
            .finish()
            .map_err(EncryptError::Io)?;
    }
    Ok(AgeBlob(output))
}

fn stanza_version_of(v: u8) -> Result<stanza_format::EcdhStanzaVersion, EncryptError> {
    stanza_format::EcdhStanzaVersion::from_wire(v)
        .map_err(|e| EncryptError::Recipient(e.to_string()))
}

fn lookup_prf<'a>(
    table: PrfTable<'a>,
    rp_id: &str,
    credential_id: &[u8],
    enrolment_salt: &[u8; 32],
) -> Option<(&'a [u8; 32], &'a [u8; 32])> {
    use subtle::ConstantTimeEq;
    table.iter().find_map(|e| {
        let rp_match: bool = e.rp_id.as_bytes().ct_eq(rp_id.as_bytes()).into();
        let names_this_recipient = if e.credential_id.is_empty() {
            bool::from(e.salt.ct_eq(enrolment_salt))
        } else {
            e.credential_id == credential_id
        };
        (rp_match && names_this_recipient).then_some((e.salt, e.prf_output))
    })
}

pub fn decrypt(
    blob: &AgeBlob,
    identities: &[Box<dyn Identity>],
) -> Result<Plaintext, DecryptError> {
    let armored = ArmoredReader::new(blob.as_bytes());
    let decryptor = age::Decryptor::new(armored).map_err(|e| DecryptError::Age(format!("{e}")))?;

    let failures = std::cell::RefCell::new(Vec::new());
    let mut adapters: Vec<IdentityAdapter<'_>> = Vec::new();
    for id in identities {
        adapters.push(IdentityAdapter {
            identity: id.as_ref(),
            failures: &failures,
        });
    }

    let mut id_refs: Vec<&dyn age::Identity> = Vec::new();
    for id in identities {
        if let Some(sw) = id.as_ref().as_software_age_identity() {
            id_refs.push(sw as &dyn age::Identity);
        }
    }
    for a in &adapters {
        id_refs.push(a as &dyn age::Identity);
    }

    if id_refs.is_empty() {
        return Err(DecryptError::NoMatchingIdentity);
    }

    let result = decryptor.decrypt(id_refs.into_iter());
    let failure = most_telling_failure(std::mem::take(&mut *failures.borrow_mut()));
    let mut reader = match result {
        Ok(reader) => reader,
        Err(age::DecryptError::NoMatchingKeys) => {
            return Err(failure.map_or(DecryptError::NoMatchingIdentity, DecryptError::Identity));
        }
        Err(other) => {
            return Err(failure.map_or_else(
                || DecryptError::Age(format!("{other}")),
                DecryptError::Identity,
            ));
        }
    };
    let mut buf = Zeroizing::new(Vec::with_capacity(blob.as_bytes().len()));
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

/// The failure to report when no identity produced the file key: a refusal
/// by the user or the device outranks a device that was absent or broken,
/// which outranks a stanza that did not parse.
fn most_telling_failure(failures: Vec<IdentityError>) -> Option<IdentityError> {
    fn rank(e: &IdentityError) -> u8 {
        match e {
            IdentityError::Cancelled => 0,
            IdentityError::Auth(_) => 1,
            IdentityError::Hardware(_) => 2,
            IdentityError::Io(_) => 3,
            IdentityError::Crypto(_) => 4,
        }
    }
    failures.into_iter().min_by_key(rank)
}

/// Parse an armored age blob far enough to record every recipient stanza in
/// its header, without unwrapping any of them. Cheap (header only, no payload
/// key derivation, no hardware) -- this is the primitive behind "is this item
/// even openable here?" checks done at snapshot time.
pub fn parse_header_stanzas(blob: &AgeBlob) -> Result<Vec<Stanza>, DecryptError> {
    #[derive(Default)]
    struct StanzaRecorder {
        inner: std::cell::RefCell<Vec<Stanza>>,
    }

    impl age::Identity for StanzaRecorder {
        fn unwrap_stanza(
            &self,
            stanza: &age_core_compat::AgeStanza,
        ) -> Option<Result<age_core_compat::AgeFileKey, age::DecryptError>> {
            self.inner
                .borrow_mut()
                .push(age_core_compat::age_stanza_to_ours(stanza));
            None
        }
    }

    let mut armored = ArmoredReader::new(blob.as_bytes());
    let mut buf = Vec::new();
    armored.read_to_end(&mut buf)?;

    let decryptor =
        age::Decryptor::new(buf.as_slice()).map_err(|e| DecryptError::Age(format!("{e}")))?;
    let recorder = StanzaRecorder::default();
    let _ = decryptor.decrypt(std::iter::once(&recorder as &dyn age::Identity));
    Ok(recorder.inner.into_inner())
}

/// How many PRF stanzas in `blob`'s header use the pre-`wrap_salt` format,
/// whose body key every secret wrapped to that authenticator shares. Header
/// only: no unwrap, no hardware. Any such secret should be rotated; [`rewrap`]
/// writes the current format.
pub fn legacy_prf_wraps(blob: &AgeBlob) -> Result<usize, DecryptError> {
    Ok(parse_header_stanzas(blob)?
        .iter()
        .filter(|s| stanza_format::is_legacy_prf_wrap(s))
        .count())
}

#[derive(Debug, Error)]
pub enum RewrapError {
    #[error("decrypt: {0}")]
    Decrypt(#[from] DecryptError),

    #[error("encrypt: {0}")]
    Encrypt(#[from] EncryptError),
}

/// Opens `blob` with `identities` and wraps the same plaintext to
/// `recipients` in the current stanza formats. The plaintext never leaves
/// zeroizing memory.
pub fn rewrap(
    blob: &AgeBlob,
    identities: &[Box<dyn Identity>],
    recipients: &[Recipient],
    prf_table: PrfTable<'_>,
) -> Result<AgeBlob, RewrapError> {
    let plaintext = decrypt(blob, identities)?;
    Ok(encrypt_with_prf(&plaintext, recipients, prf_table)?)
}

struct IdentityAdapter<'a> {
    identity: &'a dyn Identity,
    failures: &'a std::cell::RefCell<Vec<IdentityError>>,
}

/// An identity's failure on one stanza does not end the search: the next
/// stanza or identity may still produce the file key, which is the
/// multi-recipient fall-through. The failure is kept so that, when nothing
/// matches, the caller gets it instead of `NoMatchingIdentity` -- an absent
/// or refusing device must never read as "no device was named", which is
/// what lets a caller offer the software key. A cancellation is the user
/// saying no to this decryption, so it ends the search at once.
impl<'a> age::Identity for IdentityAdapter<'a> {
    fn unwrap_stanza(
        &self,
        stanza: &age_core_compat::AgeStanza,
    ) -> Option<Result<age_core_compat::AgeFileKey, age::DecryptError>> {
        let our_stanza = age_stanza_to_ours(stanza);
        match self.identity.try_unwrap_stanza(&our_stanza) {
            Ok(Some(file_key)) => Some(Ok(age_filekey_from_bytes(*file_key))),
            Ok(None) => None,
            Err(IdentityError::Cancelled) => {
                self.failures.borrow_mut().push(IdentityError::Cancelled);
                Some(Err(age::DecryptError::Io(std::io::Error::other(
                    "cancelled by user",
                ))))
            }
            Err(e) => {
                self.failures.borrow_mut().push(e);
                None
            }
        }
    }
}

enum HardwareRecipient<'a> {
    PivX25519 {
        pubkey: [u8; 32],
        version: stanza_format::EcdhStanzaVersion,
    },
    PivP256 {
        pubkey: &'a [u8],
    },
    Keystore {
        pubkey: &'a [u8],
        key_handle: &'a str,
        version: stanza_format::EcdhStanzaVersion,
    },
    Fido2 {
        credential_id: &'a [u8],
        salt: &'a [u8; 32],
        rp_id: &'a str,
        prf_output: &'a [u8; 32],
    },
    WebauthnPrf {
        credential_id: &'a [u8],
        salt: &'a [u8; 32],
        rp_id: &'a str,
        prf_output: &'a [u8; 32],
    },
}

struct HardwareAdapter<'a>(HardwareRecipient<'a>);

fn invalid_input(e: stanza_format::StanzaFormatError) -> age::EncryptError {
    age::EncryptError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        e.to_string(),
    ))
}

impl<'a> age::Recipient for HardwareAdapter<'a> {
    fn wrap_file_key(
        &self,
        file_key: &age_core_compat::AgeFileKey,
    ) -> Result<(Vec<age_core_compat::AgeStanza>, HashSet<String>), age::EncryptError> {
        let fk_bytes = age_core_compat::age_filekey_to_bytes(file_key);
        let stanza = match &self.0 {
            HardwareRecipient::PivX25519 { pubkey, version } => {
                stanza_format::encrypt_piv_x25519_stanza(&fk_bytes, pubkey, *version)
            }
            HardwareRecipient::PivP256 { pubkey } => {
                stanza_format::encrypt_piv_ec_p256_stanza(&fk_bytes, pubkey)
                    .map_err(invalid_input)?
            }
            HardwareRecipient::Keystore {
                pubkey,
                key_handle,
                version,
            } => stanza_format::encrypt_ragedroid_keystore_stanza(
                &fk_bytes, pubkey, key_handle, *version,
            )
            .map_err(invalid_input)?,
            HardwareRecipient::Fido2 {
                credential_id,
                salt,
                rp_id,
                prf_output,
            } => stanza_format::encrypt_fido2_hmac_with_prf(
                &fk_bytes,
                credential_id,
                salt,
                rp_id,
                prf_output,
            ),
            HardwareRecipient::WebauthnPrf {
                credential_id,
                salt,
                rp_id,
                prf_output,
            } => stanza_format::encrypt_webauthn_prf_with_prf(
                &fk_bytes,
                credential_id,
                salt,
                rp_id,
                prf_output,
            ),
        };
        Ok((vec![our_stanza_to_age(&stanza)], HashSet::new()))
    }
}

mod age_core_compat {
    use crate::stanza::Stanza as OurStanza;

    pub type AgeStanza = age_core::format::Stanza;

    pub type AgeFileKey = age_core::format::FileKey;

    pub fn age_stanza_to_ours(s: &AgeStanza) -> OurStanza {
        OurStanza {
            tag: s.tag.clone(),
            args: s.args.clone(),
            body: s.body.clone(),
        }
    }

    pub fn our_stanza_to_age(s: &OurStanza) -> AgeStanza {
        AgeStanza {
            tag: s.tag.clone(),
            args: s.args.clone(),
            body: s.body.clone(),
        }
    }

    pub fn age_filekey_from_bytes(bytes: [u8; 16]) -> AgeFileKey {
        AgeFileKey::new(Box::new(bytes))
    }

    pub fn age_filekey_to_bytes(fk: &AgeFileKey) -> [u8; 16] {
        use age_core::secrecy::ExposeSecret;
        *fk.expose_secret()
    }
}

fn encode_x25519_recipient(pubkey: &[u8; 32]) -> String {
    bech32::encode_age_x25519(pubkey)
}

pub fn no_hardware_identities() -> Vec<Box<dyn Identity>> {
    Vec::new()
}

pub fn software_passphrase_identity(
    armored_secret: &ArmoredAgeSecret,
) -> Result<SoftwareIdentity, DecryptError> {
    let parsed: age::x25519::Identity = armored_secret
        .expose_secret()
        .parse()
        .map_err(|e: &str| DecryptError::Age(e.to_string()))?;
    Ok(SoftwareIdentity { inner: parsed })
}

pub struct SoftwareIdentity {
    inner: age::x25519::Identity,
}

impl Identity for SoftwareIdentity {
    fn try_unwrap_stanza(&self, _stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        Ok(None)
    }

    fn display(&self) -> &str {
        "software age identity"
    }

    fn as_software_age_identity(&self) -> Option<&age::x25519::Identity> {
        Some(&self.inner)
    }
}
