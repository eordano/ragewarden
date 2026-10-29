use base64::{
    Engine,
    engine::general_purpose::{STANDARD_NO_PAD as B64, URL_SAFE_NO_PAD as B64URL},
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, AeadInOut, KeyInit},
};
use hkdf::Hkdf;
use p256::{
    PublicKey as P256PublicKey, SecretKey as P256SecretKey, elliptic_curve::Generate,
    elliptic_curve::sec1::ToSec1Point,
};
use rand_core::Rng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::identity::FileKey;
use crate::stanza::Stanza;

const BASE32_CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub const TAG_X25519: &str = "X25519";

pub const TAG_SCRYPT: &str = "scrypt";

/// Shared by two wire formats, told apart by argument shape: this crate's
/// original X25519 PIV stanza (`[ephemeral_pub, recipient_tag]`, 43 + 6 base64
/// characters; read-only now, see [`PivStanzaKind::X25519V1`]) and
/// `age-plugin-yubikey`'s genuine P-256 stanza (`[recipient_tag,
/// ephemeral_pub]`, 6 + 44 characters; [`PivStanzaKind::P256`]).
pub const TAG_PIV_P256: &str = "piv-p256";

pub const TAG_PIV_X25519_V2: &str = "piv-x25519-v2";

pub const TAG_FIDO2_HMAC: &str = "fido2-hmac";

pub const TAG_WEBAUTHN_PRF_V1: &str = "webauthn-prf-v1";

pub const TAG_RAGEDROID_KEYSTORE_V1: &str = "ragedroid-keystore-v1";

pub const TAG_RAGEDROID_KEYSTORE_V2: &str = "ragedroid-keystore-v2";

/// Every tag a ragewarden client can name a recipient by, for header
/// inspection (`stanza_descriptor`-style code in the frontends).
pub const RECIPIENT_TAGS: &[&str] = &[
    TAG_X25519,
    TAG_SCRYPT,
    TAG_PIV_P256,
    TAG_PIV_X25519_V2,
    TAG_FIDO2_HMAC,
    TAG_WEBAUTHN_PRF_V1,
    TAG_RAGEDROID_KEYSTORE_V1,
    TAG_RAGEDROID_KEYSTORE_V2,
];

const HKDF_INFO_PIV_X25519_V1: &[u8] = TAG_PIV_P256.as_bytes();
const HKDF_INFO_PIV_X25519_V2: &[u8] = TAG_PIV_X25519_V2.as_bytes();
const HKDF_INFO_PIV_P256: &[u8] = TAG_PIV_P256.as_bytes();
const HKDF_INFO_FIDO2_HMAC: &[u8] = TAG_FIDO2_HMAC.as_bytes();
const HKDF_INFO_WEBAUTHN_PRF: &[u8] = TAG_WEBAUTHN_PRF_V1.as_bytes();
const HKDF_INFO_RAGEDROID_KEYSTORE_V1: &[u8] = TAG_RAGEDROID_KEYSTORE_V1.as_bytes();
const HKDF_INFO_RAGEDROID_KEYSTORE_V2: &[u8] = TAG_RAGEDROID_KEYSTORE_V2.as_bytes();

const AD_PIV_X25519_V1: &[u8] = TAG_PIV_P256.as_bytes();
const AD_PIV_X25519_V2: &[u8] = TAG_PIV_X25519_V2.as_bytes();
/// `age-plugin-yubikey` seals with age's `aead_encrypt`: no associated data.
const AD_PIV_P256: &[u8] = b"";
const AD_FIDO2_HMAC: &[u8] = TAG_FIDO2_HMAC.as_bytes();
const AD_WEBAUTHN_PRF: &[u8] = TAG_WEBAUTHN_PRF_V1.as_bytes();
const AD_RAGEDROID_KEYSTORE_V1: &[u8] = TAG_RAGEDROID_KEYSTORE_V1.as_bytes();
const AD_RAGEDROID_KEYSTORE_V2: &[u8] = TAG_RAGEDROID_KEYSTORE_V2.as_bytes();

/// Which body-key derivation a writer uses for the ECDH stanzas. `V1` salts
/// HKDF with the ephemeral public key only (the original `piv-p256` X25519
/// and `ragedroid-keystore-v1` formats, still read everywhere); `V2` salts it
/// with `ephemeral_pub || recipient_pub`, binding the key to the recipient the
/// way age's own X25519 stanza does. Writers emit V2 only to a recipient whose
/// registry entry says its readers understand it (`stanzaVersion: 2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhStanzaVersion {
    V1,
    V2,
}

impl EcdhStanzaVersion {
    pub fn from_wire(v: u8) -> Result<Self, StanzaFormatError> {
        match v {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            other => Err(StanzaFormatError::Shape(format!(
                "unknown stanza version {other}"
            ))),
        }
    }
}

pub const WRAP_SALT_LEN: usize = 32;

const PRF_ARGS_LEGACY: usize = 3;
const PRF_ARGS_CURRENT: usize = 4;

#[derive(Debug, Error)]
pub enum StanzaFormatError {
    #[error("stanza shape: {0}")]
    Shape(String),

    #[error("base64: {0}")]
    Base64(String),

    #[error("aead decrypt failed (wrong key or tampered)")]
    AeadFailed,

    #[error("body length: expected {expected}, got {got}")]
    BodyLength { expected: usize, got: usize },
}

/// The three PIV stanza shapes this crate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivStanzaKind {
    /// `-> piv-p256 <x25519_ephemeral_pub> <recipient_tag>`, HKDF salt =
    /// ephemeral pub, info and associated data `piv-p256`. Written before the
    /// v2 formats; read only.
    X25519V1,
    /// `-> piv-x25519-v2 <x25519_ephemeral_pub> <recipient_tag>`, HKDF salt =
    /// ephemeral pub || recipient pub.
    X25519V2,
    /// `age-plugin-yubikey`'s `-> piv-p256 <recipient_tag>
    /// <p256_ephemeral_pub_compressed>`, HKDF salt = ephemeral pub ||
    /// recipient pub, no associated data.
    P256,
}

const B64_LEN_4: usize = 6;
const B64_LEN_32: usize = 43;
const B64_LEN_33: usize = 44;

/// Classifies a PIV stanza by tag and argument shape, or `None` when it is
/// not one this crate reads (another tag, or a `piv-p256` shape neither
/// format produces).
pub fn piv_stanza_kind(stanza: &Stanza) -> Option<PivStanzaKind> {
    let lens: Vec<usize> = stanza.args.iter().map(String::len).collect();
    match (stanza.tag.as_str(), lens.as_slice()) {
        (TAG_PIV_X25519_V2, [B64_LEN_32, B64_LEN_4]) => Some(PivStanzaKind::X25519V2),
        (TAG_PIV_P256, [B64_LEN_32, B64_LEN_4]) => Some(PivStanzaKind::X25519V1),
        (TAG_PIV_P256, [B64_LEN_4, B64_LEN_33]) => Some(PivStanzaKind::P256),
        _ => None,
    }
}

/// The first four bytes of SHA-256 over the recipient's public key bytes (raw
/// 32-byte X25519, or 33-byte compressed SEC1 P-256, matching
/// `age-plugin-yubikey`) -- a matching hint, not a key.
pub fn piv_recipient_tag(recipient_pubkey: &[u8]) -> [u8; 4] {
    use sha2::Digest;
    let h = Sha256::digest(recipient_pubkey);
    let mut out = [0u8; 4];
    out.copy_from_slice(&h[..4]);
    out
}

pub fn encrypt_piv_x25519_stanza(
    file_key: &[u8; 16],
    recipient_pubkey: &[u8; 32],
    version: EcdhStanzaVersion,
) -> Stanza {
    let mut eph_seed = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(eph_seed.as_mut());
    piv_x25519_stanza_from(file_key, recipient_pubkey, version, &eph_seed)
}

fn piv_x25519_stanza_from(
    file_key: &[u8; 16],
    recipient_pubkey: &[u8; 32],
    version: EcdhStanzaVersion,
    eph_seed: &[u8; 32],
) -> Stanza {
    let eph_secret = X25519Secret::from(*eph_seed);
    let eph_public = X25519Public::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&X25519Public::from(*recipient_pubkey));

    let (tag, body) = match version {
        EcdhStanzaVersion::V1 => {
            let body_key = hkdf_extract_expand(
                Some(eph_public.as_bytes().as_slice()),
                HKDF_INFO_PIV_X25519_V1,
                shared.as_bytes(),
            );
            (
                TAG_PIV_P256,
                aead_encrypt_filekey(&body_key, AD_PIV_X25519_V1, file_key),
            )
        }
        EcdhStanzaVersion::V2 => {
            let salt = concat_salt(eph_public.as_bytes(), recipient_pubkey);
            let body_key =
                hkdf_extract_expand(Some(&salt), HKDF_INFO_PIV_X25519_V2, shared.as_bytes());
            (
                TAG_PIV_X25519_V2,
                aead_encrypt_filekey(&body_key, AD_PIV_X25519_V2, file_key),
            )
        }
    };

    Stanza {
        tag: tag.to_string(),
        args: vec![
            B64.encode(eph_public.as_bytes()),
            B64.encode(piv_recipient_tag(recipient_pubkey)),
        ],
        body,
    }
}

/// The ephemeral X25519 public key of a `piv-p256` (v1) or `piv-x25519-v2`
/// stanza: what the card's GENERAL AUTHENTICATE needs.
pub fn piv_x25519_ephemeral_pub(stanza: &Stanza) -> Result<[u8; 32], StanzaFormatError> {
    expect_piv_kind(stanza, &[PivStanzaKind::X25519V1, PivStanzaKind::X25519V2])?;
    decode_fixed::<32>(&stanza.args[0], "ephemeral pub")
}

pub fn piv_x25519_recipient_tag(stanza: &Stanza) -> Result<[u8; 4], StanzaFormatError> {
    expect_piv_kind(stanza, &[PivStanzaKind::X25519V1, PivStanzaKind::X25519V2])?;
    decode_fixed::<4>(&stanza.args[1], "recipient tag")
}

/// Unwraps a `piv-p256` (v1) or `piv-x25519-v2` stanza given the ECDH share
/// the card computed and the slot's own public key, which v2 binds into its
/// HKDF salt: a v1 stanza ignores it and a v2 stanza without it is refused.
pub fn decrypt_piv_x25519_with_ecdh_share(
    stanza: &Stanza,
    ecdh_share: &[u8; 32],
    recipient_pubkey: Option<&[u8; 32]>,
) -> Result<FileKey, StanzaFormatError> {
    let kind = expect_piv_kind(stanza, &[PivStanzaKind::X25519V1, PivStanzaKind::X25519V2])?;
    let eph_pub = decode_fixed::<32>(&stanza.args[0], "ephemeral pub")?;
    match kind {
        PivStanzaKind::X25519V1 => {
            let body_key = hkdf_extract_expand(Some(&eph_pub), HKDF_INFO_PIV_X25519_V1, ecdh_share);
            aead_decrypt_filekey(&body_key, AD_PIV_X25519_V1, &stanza.body)
        }
        _ => {
            let recipient_pubkey = recipient_pubkey.ok_or_else(|| {
                StanzaFormatError::Shape(
                    "piv-x25519-v2 needs the slot public key to derive its body key".into(),
                )
            })?;
            let salt = concat_salt(&eph_pub, recipient_pubkey);
            let body_key = hkdf_extract_expand(Some(&salt), HKDF_INFO_PIV_X25519_V2, ecdh_share);
            aead_decrypt_filekey(&body_key, AD_PIV_X25519_V2, &stanza.body)
        }
    }
}

/// Wraps a file key to a P-256 PIV slot in `age-plugin-yubikey`'s
/// `piv-p256` format, byte-compatible with that plugin in both directions.
pub fn encrypt_piv_ec_p256_stanza(
    file_key: &[u8; 16],
    recipient_pubkey_sec1_compressed: &[u8],
) -> Result<Stanza, StanzaFormatError> {
    let eph = P256SecretKey::generate_from_rng(&mut rand::rng());
    piv_ec_p256_stanza_from(file_key, recipient_pubkey_sec1_compressed, &eph)
}

fn piv_ec_p256_stanza_from(
    file_key: &[u8; 16],
    recipient_pubkey_sec1_compressed: &[u8],
    eph: &P256SecretKey,
) -> Result<Stanza, StanzaFormatError> {
    let recipient_pk = p256_compressed_point(recipient_pubkey_sec1_compressed, "PIV P-256 pubkey")?;
    let eph_point = eph.public_key().to_sec1_point(true);
    let shared = p256_diffie_hellman(eph, &recipient_pk);
    let salt = concat_salt(eph_point.as_bytes(), recipient_pubkey_sec1_compressed);
    let body_key = hkdf_extract_expand(
        Some(&salt),
        HKDF_INFO_PIV_P256,
        shared.raw_secret_bytes().as_slice(),
    );
    Ok(Stanza {
        tag: TAG_PIV_P256.to_string(),
        args: vec![
            B64.encode(piv_recipient_tag(recipient_pubkey_sec1_compressed)),
            B64.encode(eph_point.as_bytes()),
        ],
        body: aead_encrypt_filekey(&body_key, AD_PIV_P256, file_key),
    })
}

/// The compressed SEC1 ephemeral point of an `age-plugin-yubikey` stanza,
/// validated as a point on the curve.
pub fn piv_ec_p256_ephemeral_pub(stanza: &Stanza) -> Result<[u8; 33], StanzaFormatError> {
    expect_piv_kind(stanza, &[PivStanzaKind::P256])?;
    let bytes = decode_fixed::<33>(&stanza.args[1], "ephemeral pub")?;
    p256_compressed_point(&bytes, "ephemeral pub")?;
    Ok(bytes)
}

pub fn piv_ec_p256_recipient_tag(stanza: &Stanza) -> Result<[u8; 4], StanzaFormatError> {
    expect_piv_kind(stanza, &[PivStanzaKind::P256])?;
    decode_fixed::<4>(&stanza.args[0], "recipient tag")
}

/// Unwraps an `age-plugin-yubikey` stanza given the P-256 ECDH share (the
/// x-coordinate the card returns) and the slot's compressed public key.
pub fn decrypt_piv_ec_p256_with_ecdh_share(
    stanza: &Stanza,
    ecdh_share: &[u8; 32],
    recipient_pubkey_sec1_compressed: &[u8],
) -> Result<FileKey, StanzaFormatError> {
    let eph = piv_ec_p256_ephemeral_pub(stanza)?;
    let salt = concat_salt(&eph, recipient_pubkey_sec1_compressed);
    let body_key = hkdf_extract_expand(Some(&salt), HKDF_INFO_PIV_P256, ecdh_share);
    aead_decrypt_filekey(&body_key, AD_PIV_P256, &stanza.body)
}

fn expect_piv_kind(
    stanza: &Stanza,
    allowed: &[PivStanzaKind],
) -> Result<PivStanzaKind, StanzaFormatError> {
    match piv_stanza_kind(stanza) {
        Some(k) if allowed.contains(&k) => Ok(k),
        Some(k) => Err(StanzaFormatError::Shape(format!(
            "{} stanza is {k:?}, expected one of {allowed:?}",
            stanza.tag
        ))),
        None => Err(StanzaFormatError::Shape(format!(
            "not a PIV stanza this crate reads: tag {} with {} args",
            stanza.tag,
            stanza.args.len()
        ))),
    }
}

fn decode_fixed<const N: usize>(arg: &str, what: &str) -> Result<[u8; N], StanzaFormatError> {
    let bytes = B64
        .decode(arg.as_bytes())
        .map_err(|e| StanzaFormatError::Base64(format!("{what}: {e}")))?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        StanzaFormatError::Shape(format!("{what} must be {N} bytes, got {}", b.len()))
    })
}

fn p256_compressed_point(bytes: &[u8], what: &str) -> Result<P256PublicKey, StanzaFormatError> {
    if !is_valid_p256_sec1_compressed(bytes) {
        return Err(StanzaFormatError::Shape(format!(
            "{what} must be a 33-byte SEC1-compressed P-256 point"
        )));
    }
    P256PublicKey::from_sec1_bytes(bytes)
        .map_err(|_| StanzaFormatError::Shape(format!("{what} is not on the curve")))
}

fn concat_salt(ephemeral: &[u8], recipient: &[u8]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(ephemeral.len() + recipient.len());
    salt.extend_from_slice(ephemeral);
    salt.extend_from_slice(recipient);
    salt
}

pub fn encrypt_fido2_hmac_with_prf(
    file_key: &[u8; 16],
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    prf_output: &[u8; 32],
) -> Stanza {
    fido2_hmac_stanza_from(
        file_key,
        credential_id,
        salt,
        rp_id,
        prf_output,
        &fresh_wrap_salt(),
    )
}

fn fido2_hmac_stanza_from(
    file_key: &[u8; 16],
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    prf_output: &[u8; 32],
    wrap_salt: &[u8; WRAP_SALT_LEN],
) -> Stanza {
    let body_key = prf_body_key(salt, Some(wrap_salt), HKDF_INFO_FIDO2_HMAC, prf_output);
    let body = aead_encrypt_filekey(&body_key, AD_FIDO2_HMAC, file_key);

    Stanza {
        tag: TAG_FIDO2_HMAC.to_string(),
        args: vec![
            B64URL.encode(credential_id),
            B64.encode(salt),
            rp_id.to_string(),
            B64.encode(wrap_salt),
        ],
        body,
    }
}

pub fn decrypt_fido2_hmac_with_prf(
    stanza: &Stanza,
    prf_output: &[u8; 32],
) -> Result<FileKey, StanzaFormatError> {
    let salt = fido2_hmac_salt(stanza)?;
    let wrap_salt = fido2_hmac_wrap_salt(stanza)?;
    let body_key = prf_body_key(&salt, wrap_salt.as_ref(), HKDF_INFO_FIDO2_HMAC, prf_output);
    aead_decrypt_filekey(&body_key, AD_FIDO2_HMAC, &stanza.body)
}

pub fn fido2_hmac_credential_id(stanza: &Stanza) -> Result<Vec<u8>, StanzaFormatError> {
    if stanza.tag != TAG_FIDO2_HMAC {
        return Err(StanzaFormatError::Shape(format!(
            "expected tag fido2-hmac, got {}",
            stanza.tag
        )));
    }
    check_prf_stanza_arity(stanza, TAG_FIDO2_HMAC)?;
    B64URL
        .decode(stanza.args[0].as_bytes())
        .map_err(|e| StanzaFormatError::Base64(format!("credential id: {e}")))
}

pub fn fido2_hmac_salt(stanza: &Stanza) -> Result<[u8; 32], StanzaFormatError> {
    check_prf_stanza_arity(stanza, TAG_FIDO2_HMAC)?;
    decode_salt_arg(&stanza.args[1], "salt")
}

pub fn fido2_hmac_rp_id(stanza: &Stanza) -> Result<&str, StanzaFormatError> {
    check_prf_stanza_arity(stanza, TAG_FIDO2_HMAC)?;
    Ok(stanza.args[2].as_str())
}

pub fn fido2_hmac_wrap_salt(stanza: &Stanza) -> Result<Option<[u8; 32]>, StanzaFormatError> {
    let n = check_prf_stanza_arity(stanza, TAG_FIDO2_HMAC)?;
    if n == PRF_ARGS_LEGACY {
        return Ok(None);
    }
    decode_wrap_salt_arg(&stanza.args[3]).map(Some)
}

pub fn fido2_hmac_is_legacy_wrap(stanza: &Stanza) -> Result<bool, StanzaFormatError> {
    Ok(check_prf_stanza_arity(stanza, TAG_FIDO2_HMAC)? == PRF_ARGS_LEGACY)
}

pub fn encrypt_webauthn_prf_with_prf(
    file_key: &[u8; 16],
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    prf_output: &[u8; 32],
) -> Stanza {
    webauthn_prf_stanza_from(
        file_key,
        credential_id,
        salt,
        rp_id,
        prf_output,
        &fresh_wrap_salt(),
    )
}

fn webauthn_prf_stanza_from(
    file_key: &[u8; 16],
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    prf_output: &[u8; 32],
    wrap_salt: &[u8; WRAP_SALT_LEN],
) -> Stanza {
    let body_key = prf_body_key(salt, Some(wrap_salt), HKDF_INFO_WEBAUTHN_PRF, prf_output);
    let body = aead_encrypt_filekey(&body_key, AD_WEBAUTHN_PRF, file_key);

    Stanza {
        tag: TAG_WEBAUTHN_PRF_V1.to_string(),
        args: vec![
            B64URL.encode(credential_id),
            rp_id.to_string(),
            B64.encode(salt),
            B64.encode(wrap_salt),
        ],
        body,
    }
}

pub fn decrypt_webauthn_prf_with_prf(
    stanza: &Stanza,
    prf_output: &[u8; 32],
) -> Result<FileKey, StanzaFormatError> {
    let salt = webauthn_prf_salt(stanza)?;
    let wrap_salt = webauthn_prf_wrap_salt(stanza)?;
    let body_key = prf_body_key(
        &salt,
        wrap_salt.as_ref(),
        HKDF_INFO_WEBAUTHN_PRF,
        prf_output,
    );
    aead_decrypt_filekey(&body_key, AD_WEBAUTHN_PRF, &stanza.body)
}

pub fn webauthn_prf_credential_id(stanza: &Stanza) -> Result<Vec<u8>, StanzaFormatError> {
    if stanza.tag != TAG_WEBAUTHN_PRF_V1 {
        return Err(StanzaFormatError::Shape(format!(
            "expected tag webauthn-prf-v1, got {}",
            stanza.tag
        )));
    }
    check_prf_stanza_arity(stanza, TAG_WEBAUTHN_PRF_V1)?;
    B64URL
        .decode(stanza.args[0].as_bytes())
        .map_err(|e| StanzaFormatError::Base64(format!("credential id: {e}")))
}

pub fn webauthn_prf_rp_id(stanza: &Stanza) -> Result<&str, StanzaFormatError> {
    check_prf_stanza_arity(stanza, TAG_WEBAUTHN_PRF_V1)?;
    Ok(stanza.args[1].as_str())
}

pub fn webauthn_prf_salt(stanza: &Stanza) -> Result<[u8; 32], StanzaFormatError> {
    check_prf_stanza_arity(stanza, TAG_WEBAUTHN_PRF_V1)?;
    decode_salt_arg(&stanza.args[2], "salt")
}

pub fn webauthn_prf_wrap_salt(stanza: &Stanza) -> Result<Option<[u8; 32]>, StanzaFormatError> {
    let n = check_prf_stanza_arity(stanza, TAG_WEBAUTHN_PRF_V1)?;
    if n == PRF_ARGS_LEGACY {
        return Ok(None);
    }
    decode_wrap_salt_arg(&stanza.args[3]).map(Some)
}

pub fn webauthn_prf_is_legacy_wrap(stanza: &Stanza) -> Result<bool, StanzaFormatError> {
    Ok(check_prf_stanza_arity(stanza, TAG_WEBAUTHN_PRF_V1)? == PRF_ARGS_LEGACY)
}

/// Whether `stanza` is a pre-`wrap_salt` (three-argument) PRF stanza.
pub fn is_legacy_prf_wrap(stanza: &Stanza) -> bool {
    match stanza.tag.as_str() {
        TAG_WEBAUTHN_PRF_V1 => webauthn_prf_is_legacy_wrap(stanza).unwrap_or(false),
        TAG_FIDO2_HMAC => fido2_hmac_is_legacy_wrap(stanza).unwrap_or(false),
        _ => false,
    }
}

/// A 33-byte SEC1 point with the compressed tag (`0x02`/`0x03`) that lies on
/// P-256. `from_sec1_bytes` alone also accepts the 33-byte compact encoding
/// (`0x05`), which is not what any writer here or in `age-plugin-yubikey`
/// produces.
pub fn is_valid_p256_sec1_compressed(bytes: &[u8]) -> bool {
    bytes.len() == 33
        && matches!(bytes[0], 0x02 | 0x03)
        && P256PublicKey::from_sec1_bytes(bytes).is_ok()
}

pub fn encrypt_ragedroid_keystore_stanza(
    file_key: &[u8; 16],
    keystore_pubkey_sec1_compressed: &[u8],
    key_handle: &str,
    version: EcdhStanzaVersion,
) -> Result<Stanza, StanzaFormatError> {
    if keystore_pubkey_sec1_compressed.len() != 33 {
        return Err(StanzaFormatError::Shape(format!(
            "keystore pubkey must be 33 SEC1-compressed bytes, got {}",
            keystore_pubkey_sec1_compressed.len()
        )));
    }
    let recipient_pk =
        P256PublicKey::from_sec1_bytes(keystore_pubkey_sec1_compressed).map_err(|_| {
            StanzaFormatError::Shape(
                "keystore pubkey is not a valid SEC1-compressed P-256 point".to_string(),
            )
        })?;

    let eph = P256SecretKey::generate_from_rng(&mut rand::rng());
    Ok(ragedroid_keystore_stanza_from(
        file_key,
        keystore_pubkey_sec1_compressed,
        &recipient_pk,
        key_handle,
        version,
        &eph,
    ))
}

fn ragedroid_keystore_stanza_from(
    file_key: &[u8; 16],
    keystore_pubkey_sec1_compressed: &[u8],
    recipient_pk: &P256PublicKey,
    key_handle: &str,
    version: EcdhStanzaVersion,
    eph: &P256SecretKey,
) -> Stanza {
    let eph_public_point = eph.public_key().to_sec1_point(true);
    let eph_pub_bytes = eph_public_point.as_bytes();
    debug_assert_eq!(eph_pub_bytes.len(), 33, "p256 SEC1-compressed is 33 bytes");

    let shared = p256_diffie_hellman(eph, recipient_pk);
    let shared_bytes = shared.raw_secret_bytes();

    let (tag, body) = match version {
        EcdhStanzaVersion::V1 => {
            let body_key = hkdf_extract_expand(
                Some(eph_pub_bytes),
                HKDF_INFO_RAGEDROID_KEYSTORE_V1,
                shared_bytes.as_slice(),
            );
            (
                TAG_RAGEDROID_KEYSTORE_V1,
                aead_encrypt_filekey(&body_key, AD_RAGEDROID_KEYSTORE_V1, file_key),
            )
        }
        EcdhStanzaVersion::V2 => {
            let salt = concat_salt(eph_pub_bytes, keystore_pubkey_sec1_compressed);
            let body_key = hkdf_extract_expand(
                Some(&salt),
                HKDF_INFO_RAGEDROID_KEYSTORE_V2,
                shared_bytes.as_slice(),
            );
            (
                TAG_RAGEDROID_KEYSTORE_V2,
                aead_encrypt_filekey(&body_key, AD_RAGEDROID_KEYSTORE_V2, file_key),
            )
        }
    };

    Stanza {
        tag: tag.to_string(),
        args: vec![
            base32_encode(key_handle.as_bytes()),
            B64.encode(eph_pub_bytes),
        ],
        body,
    }
}

fn p256_diffie_hellman(eph: &P256SecretKey, peer: &P256PublicKey) -> p256::ecdh::SharedSecret {
    p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), peer.as_affine())
}

/// Unwraps a `ragedroid-keystore-v1` or `-v2` stanza given the P-256 ECDH
/// share the Keystore computed. `keystore_pubkey` is the device key's own
/// compressed public key, bound into the v2 HKDF salt; a v1 stanza ignores it,
/// and a v2 stanza without it is refused.
pub fn decrypt_ragedroid_keystore_with_ecdh_share(
    stanza: &Stanza,
    ecdh_share: &[u8; 32],
    keystore_pubkey_sec1_compressed: Option<&[u8]>,
) -> Result<FileKey, StanzaFormatError> {
    let eph_pub = ragedroid_keystore_ephemeral_pub(stanza)?;
    if stanza.tag == TAG_RAGEDROID_KEYSTORE_V1 {
        let body_key =
            hkdf_extract_expand(Some(&eph_pub), HKDF_INFO_RAGEDROID_KEYSTORE_V1, ecdh_share);
        return aead_decrypt_filekey(&body_key, AD_RAGEDROID_KEYSTORE_V1, &stanza.body);
    }
    let recipient = keystore_pubkey_sec1_compressed.ok_or_else(|| {
        StanzaFormatError::Shape(
            "ragedroid-keystore-v2 needs the keystore public key to derive its body key".into(),
        )
    })?;
    let salt = concat_salt(&eph_pub, recipient);
    let body_key = hkdf_extract_expand(Some(&salt), HKDF_INFO_RAGEDROID_KEYSTORE_V2, ecdh_share);
    aead_decrypt_filekey(&body_key, AD_RAGEDROID_KEYSTORE_V2, &stanza.body)
}

fn check_ragedroid_keystore_shape(stanza: &Stanza) -> Result<(), StanzaFormatError> {
    if stanza.tag != TAG_RAGEDROID_KEYSTORE_V1 && stanza.tag != TAG_RAGEDROID_KEYSTORE_V2 {
        return Err(StanzaFormatError::Shape(format!(
            "expected tag ragedroid-keystore-v1 or -v2, got {}",
            stanza.tag
        )));
    }
    if stanza.args.len() != 2 {
        return Err(StanzaFormatError::Shape(format!(
            "{} stanza must have 2 args, got {}",
            stanza.tag,
            stanza.args.len()
        )));
    }
    Ok(())
}

pub fn ragedroid_keystore_key_handle(stanza: &Stanza) -> Result<String, StanzaFormatError> {
    check_ragedroid_keystore_shape(stanza)?;
    let bytes = base32_decode(&stanza.args[0])
        .map_err(|e| StanzaFormatError::Base64(format!("key handle base32: {e}")))?;
    String::from_utf8(bytes).map_err(|e| StanzaFormatError::Shape(format!("key handle utf8: {e}")))
}

pub fn ragedroid_keystore_ephemeral_pub(stanza: &Stanza) -> Result<Vec<u8>, StanzaFormatError> {
    check_ragedroid_keystore_shape(stanza)?;
    let bytes = B64
        .decode(stanza.args[1].as_bytes())
        .map_err(|e| StanzaFormatError::Base64(format!("ephemeral pub: {e}")))?;
    if bytes.len() != 33 {
        return Err(StanzaFormatError::Shape(format!(
            "ephemeral pub must be 33 SEC1-compressed bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn check_prf_stanza_arity(stanza: &Stanza, tag: &str) -> Result<usize, StanzaFormatError> {
    let n = stanza.args.len();
    if n != PRF_ARGS_LEGACY && n != PRF_ARGS_CURRENT {
        return Err(StanzaFormatError::Shape(format!(
            "{tag} stanza must have {PRF_ARGS_CURRENT} args \
             (or {PRF_ARGS_LEGACY} for the pre-wrap-salt format), got {n}"
        )));
    }
    Ok(n)
}

fn decode_salt_arg(arg: &str, what: &str) -> Result<[u8; 32], StanzaFormatError> {
    let bytes = B64
        .decode(arg.as_bytes())
        .map_err(|e| StanzaFormatError::Base64(format!("{what}: {e}")))?;
    if bytes.len() != WRAP_SALT_LEN {
        return Err(StanzaFormatError::Shape(format!(
            "{what} must be {WRAP_SALT_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// HMAC zero-pads a 32-byte key to its 64-byte block, so `prf_salt || 0^32`
/// is the same HKDF-extract key as the legacy `prf_salt` alone: an all-zero
/// wrap salt would silently select the shared legacy body key. No honest
/// writer draws one from the CSPRNG, so it is refused.
fn decode_wrap_salt_arg(arg: &str) -> Result<[u8; 32], StanzaFormatError> {
    use subtle::ConstantTimeEq;
    let wrap = decode_salt_arg(arg, "wrap salt")?;
    if bool::from(wrap.ct_eq(&[0u8; WRAP_SALT_LEN])) {
        return Err(StanzaFormatError::Shape(
            "wrap salt is all zeros, which would select the legacy shared body key".into(),
        ));
    }
    Ok(wrap)
}

fn fresh_wrap_salt() -> [u8; WRAP_SALT_LEN] {
    let mut out = [0u8; WRAP_SALT_LEN];
    rand::rng().fill_bytes(&mut out);
    out
}

fn prf_body_key(
    prf_salt: &[u8; 32],
    wrap_salt: Option<&[u8; WRAP_SALT_LEN]>,
    info: &[u8],
    prf_output: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    match wrap_salt {
        Some(wrap) => {
            let mut salt = [0u8; 32 + WRAP_SALT_LEN];
            salt[..32].copy_from_slice(prf_salt);
            salt[32..].copy_from_slice(wrap);
            hkdf_extract_expand(Some(&salt), info, prf_output)
        }
        None => hkdf_extract_expand(Some(prf_salt), info, prf_output),
    }
}

fn hkdf_extract_expand(salt: Option<&[u8]>, info: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut())
        .expect("32 bytes is well within HKDF expand bounds");
    out
}

fn aead_encrypt_filekey(key: &[u8; 32], ad: &[u8], file_key: &[u8; 16]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = [0u8; 12];
    cipher
        .encrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: file_key,
                aad: ad,
            },
        )
        .expect("encrypt of 16 bytes always succeeds")
}

fn aead_decrypt_filekey(
    key: &[u8; 32],
    ad: &[u8],
    body: &[u8],
) -> Result<FileKey, StanzaFormatError> {
    if body.len() != 32 {
        return Err(StanzaFormatError::BodyLength {
            expected: 32,
            got: body.len(),
        });
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = [0u8; 12];
    let (ct, tag) = body.split_at(16);
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(ct);
    let tag = chacha20poly1305::Tag::try_from(tag).map_err(|_| StanzaFormatError::AeadFailed)?;
    cipher
        .decrypt_inout_detached(&nonce.into(), ad, out.as_mut_slice().into(), &tag)
        .map_err(|_| StanzaFormatError::AeadFailed)?;
    Ok(out)
}

fn base32_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in input {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_CHARSET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_CHARSET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((input.len() * 5).div_ceil(8));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in input.bytes() {
        let v = match BASE32_CHARSET.iter().position(|&x| x == c) {
            Some(p) => p as u32,
            None => return Err(format!("invalid base32 char: {c:?}")),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_file_key() -> [u8; 16] {
        let mut k = [0u8; 16];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn x25519_keypair_from_seed(seed: u8) -> ([u8; 32], [u8; 32]) {
        let mut s = [0u8; 32];
        s[0] = seed;
        let secret = X25519Secret::from(s);
        let public = X25519Public::from(&secret);
        (s, *public.as_bytes())
    }

    fn x25519_share(seed: [u8; 32], stanza: &Stanza) -> [u8; 32] {
        let eph = piv_x25519_ephemeral_pub(stanza).unwrap();
        *X25519Secret::from(seed)
            .diffie_hellman(&X25519Public::from(eph))
            .as_bytes()
    }

    #[test]
    fn piv_x25519_round_trip_both_versions() {
        let file_key = fixed_file_key();
        let (seed, recipient_pub) = x25519_keypair_from_seed(7);
        for (version, tag, kind) in [
            (EcdhStanzaVersion::V1, TAG_PIV_P256, PivStanzaKind::X25519V1),
            (
                EcdhStanzaVersion::V2,
                TAG_PIV_X25519_V2,
                PivStanzaKind::X25519V2,
            ),
        ] {
            let stanza = encrypt_piv_x25519_stanza(&file_key, &recipient_pub, version);
            assert_eq!(stanza.tag, tag);
            assert_eq!(piv_stanza_kind(&stanza), Some(kind));
            assert_eq!(
                piv_x25519_recipient_tag(&stanza).unwrap(),
                piv_recipient_tag(&recipient_pub)
            );
            let share = x25519_share(seed, &stanza);
            let recovered =
                decrypt_piv_x25519_with_ecdh_share(&stanza, &share, Some(&recipient_pub)).unwrap();
            assert_eq!(&*recovered, &file_key);
        }
    }

    #[test]
    fn piv_x25519_v2_binds_the_recipient_public_key_and_v1_did_not() {
        let file_key = fixed_file_key();
        let (seed, recipient_pub) = x25519_keypair_from_seed(7);
        let (_, other_pub) = x25519_keypair_from_seed(8);

        let v2 = encrypt_piv_x25519_stanza(&file_key, &recipient_pub, EcdhStanzaVersion::V2);
        let share = x25519_share(seed, &v2);
        assert!(matches!(
            decrypt_piv_x25519_with_ecdh_share(&v2, &share, Some(&other_pub)).unwrap_err(),
            StanzaFormatError::AeadFailed
        ));

        let v1 = encrypt_piv_x25519_stanza(&file_key, &recipient_pub, EcdhStanzaVersion::V1);
        let share = x25519_share(seed, &v1);
        assert_eq!(
            &*decrypt_piv_x25519_with_ecdh_share(&v1, &share, Some(&other_pub)).unwrap(),
            &file_key,
            "v1 never bound the recipient key; that is what v2 fixes",
        );
    }

    #[test]
    fn piv_x25519_wrong_share_fails() {
        let file_key = fixed_file_key();
        let (_, recipient_pub) = x25519_keypair_from_seed(7);
        for version in [EcdhStanzaVersion::V1, EcdhStanzaVersion::V2] {
            let stanza = encrypt_piv_x25519_stanza(&file_key, &recipient_pub, version);
            let err =
                decrypt_piv_x25519_with_ecdh_share(&stanza, &[0xff; 32], Some(&recipient_pub))
                    .unwrap_err();
            assert!(matches!(err, StanzaFormatError::AeadFailed));
        }
    }

    fn p256_keypair() -> (p256::SecretKey, Vec<u8>) {
        let sk = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let pk = sk.public_key().to_sec1_point(true).as_bytes().to_vec();
        (sk, pk)
    }

    fn p256_share(sk: &p256::SecretKey, peer_compressed: &[u8]) -> [u8; 32] {
        let peer = P256PublicKey::from_sec1_bytes(peer_compressed).unwrap();
        let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
        shared.raw_secret_bytes().as_slice().try_into().unwrap()
    }

    /// `age-plugin-yubikey` 0.5.1 `RecipientLine::wrap_file_key`
    /// (src/format.rs), restated with age-core's own primitives so the check
    /// does not lean on this module's helpers.
    fn upstream_wrap(file_key: &[u8; 16], recipient_compressed: &[u8]) -> Stanza {
        use p256::elliptic_curve::Generate;
        let recipient = P256PublicKey::from_sec1_bytes(recipient_compressed).unwrap();
        let esk = p256::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
        let epk = esk.public_key().to_sec1_point(true);
        let shared = esk.diffie_hellman(&recipient);
        let mut salt = vec![];
        salt.extend_from_slice(epk.as_bytes());
        salt.extend_from_slice(recipient_compressed);
        let enc_key = age_core::primitives::hkdf(&salt, b"piv-p256", shared.raw_secret_bytes());
        use sha2::Digest;
        let tag = &Sha256::digest(recipient_compressed)[..4];
        Stanza {
            tag: "piv-p256".into(),
            args: vec![B64.encode(tag), B64.encode(epk.as_bytes())],
            body: age_core::primitives::aead_encrypt(&enc_key, file_key),
        }
    }

    fn upstream_unwrap(
        stanza: &Stanza,
        sk: &p256::SecretKey,
        recipient_compressed: &[u8],
    ) -> Vec<u8> {
        let epk = B64.decode(&stanza.args[1]).unwrap();
        let shared = p256_share(sk, &epk);
        let mut salt = epk.clone();
        salt.extend_from_slice(recipient_compressed);
        let enc_key = age_core::primitives::hkdf(&salt, b"piv-p256", &shared);
        age_core::primitives::aead_decrypt(&enc_key, 16, &stanza.body).unwrap()
    }

    #[test]
    fn piv_p256_reads_what_age_plugin_yubikey_writes() {
        let file_key = fixed_file_key();
        let (sk, pk) = p256_keypair();
        let stanza = upstream_wrap(&file_key, &pk);
        assert_eq!(piv_stanza_kind(&stanza), Some(PivStanzaKind::P256));
        assert_eq!(
            piv_ec_p256_recipient_tag(&stanza).unwrap(),
            piv_recipient_tag(&pk)
        );
        let share = p256_share(&sk, &piv_ec_p256_ephemeral_pub(&stanza).unwrap());
        let recovered = decrypt_piv_ec_p256_with_ecdh_share(&stanza, &share, &pk).unwrap();
        assert_eq!(&*recovered, &file_key);
    }

    #[test]
    fn age_plugin_yubikey_reads_what_piv_p256_writes() {
        let file_key = fixed_file_key();
        let (sk, pk) = p256_keypair();
        let stanza = encrypt_piv_ec_p256_stanza(&file_key, &pk).unwrap();
        assert_eq!(stanza.tag, "piv-p256");
        assert_eq!(stanza.args[0].len(), 6);
        assert_eq!(stanza.args[1].len(), 44);
        assert_eq!(upstream_unwrap(&stanza, &sk, &pk), file_key);
    }

    #[test]
    fn the_two_piv_p256_shapes_never_cross() {
        let file_key = fixed_file_key();
        let (_, x_pub) = x25519_keypair_from_seed(3);
        let (_, p_pub) = p256_keypair();
        let legacy = encrypt_piv_x25519_stanza(&file_key, &x_pub, EcdhStanzaVersion::V1);
        let upstream = encrypt_piv_ec_p256_stanza(&file_key, &p_pub).unwrap();
        assert_eq!(legacy.tag, upstream.tag);
        assert_eq!(piv_stanza_kind(&legacy), Some(PivStanzaKind::X25519V1));
        assert_eq!(piv_stanza_kind(&upstream), Some(PivStanzaKind::P256));
        assert!(piv_x25519_ephemeral_pub(&upstream).is_err());
        assert!(piv_ec_p256_ephemeral_pub(&legacy).is_err());
        let odd = Stanza {
            tag: TAG_PIV_P256.into(),
            args: vec!["AAAA".into()],
            body: vec![0; 32],
        };
        assert_eq!(piv_stanza_kind(&odd), None);
    }

    #[test]
    fn piv_p256_rejects_an_off_curve_ephemeral_point() {
        let file_key = fixed_file_key();
        let (_, pk) = p256_keypair();
        let mut stanza = encrypt_piv_ec_p256_stanza(&file_key, &pk).unwrap();
        let mut epk = B64.decode(&stanza.args[1]).unwrap();
        epk[0] = 0x05;
        stanza.args[1] = B64.encode(&epk);
        assert!(piv_ec_p256_ephemeral_pub(&stanza).is_err());
        let mut off_curve = [0x01u8; 33];
        off_curve[0] = 0x02;
        assert!(encrypt_piv_ec_p256_stanza(&file_key, &off_curve).is_err());
    }

    #[test]
    fn fido2_hmac_round_trip() {
        let file_key = fixed_file_key();
        let credential_id = b"\x01\x02\x03\x04";
        let salt = [0xab; 32];
        let prf = [0x42; 32];
        let stanza =
            encrypt_fido2_hmac_with_prf(&file_key, credential_id, &salt, "ragewarden", &prf);
        assert_eq!(stanza.tag, "fido2-hmac");
        assert_eq!(stanza.args.len(), PRF_ARGS_CURRENT);

        let recovered = decrypt_fido2_hmac_with_prf(&stanza, &prf).unwrap();
        assert_eq!(&*recovered, &file_key);
    }

    #[test]
    fn fido2_hmac_arg_extraction() {
        let file_key = fixed_file_key();
        let credential_id = b"cred-id-abc";
        let salt = [0xab; 32];
        let stanza =
            encrypt_fido2_hmac_with_prf(&file_key, credential_id, &salt, "ragewarden", &[0x42; 32]);
        assert_eq!(fido2_hmac_credential_id(&stanza).unwrap(), credential_id);
        assert_eq!(fido2_hmac_salt(&stanza).unwrap(), salt);
        assert_eq!(fido2_hmac_rp_id(&stanza).unwrap(), "ragewarden");
    }

    #[test]
    fn fido2_hmac_wrong_prf_fails() {
        let file_key = fixed_file_key();
        let stanza =
            encrypt_fido2_hmac_with_prf(&file_key, b"cred", &[0xab; 32], "ragewarden", &[0x42; 32]);
        let err = decrypt_fido2_hmac_with_prf(&stanza, &[0xff; 32]).unwrap_err();
        assert!(matches!(err, StanzaFormatError::AeadFailed));
    }

    #[test]
    fn webauthn_prf_round_trip() {
        let file_key = fixed_file_key();
        let credential_id = b"webauthn-cred";
        let salt = [0xcd; 32];
        let prf = [0x77; 32];
        let stanza =
            encrypt_webauthn_prf_with_prf(&file_key, credential_id, &salt, "ragewarden", &prf);
        assert_eq!(stanza.tag, "webauthn-prf-v1");
        assert_eq!(stanza.args.len(), PRF_ARGS_CURRENT);

        assert_eq!(webauthn_prf_credential_id(&stanza).unwrap(), credential_id);
        assert_eq!(webauthn_prf_rp_id(&stanza).unwrap(), "ragewarden");
        assert_eq!(webauthn_prf_salt(&stanza).unwrap(), salt);

        let recovered = decrypt_webauthn_prf_with_prf(&stanza, &prf).unwrap();
        assert_eq!(&*recovered, &file_key);
    }

    #[test]
    fn webauthn_prf_does_not_decrypt_with_fido2_hmac_key() {
        let file_key = fixed_file_key();
        let prf = [0x55; 32];
        let salt = [0x11; 32];
        let cred = b"x";
        let s_fido = encrypt_fido2_hmac_with_prf(&file_key, cred, &salt, "rp", &prf);
        let s_prf = encrypt_webauthn_prf_with_prf(&file_key, cred, &salt, "rp", &prf);
        assert!(
            decrypt_webauthn_prf_with_prf(
                &Stanza {
                    tag: "webauthn-prf-v1".into(),
                    ..s_fido.clone()
                },
                &prf,
            )
            .is_err()
        );
        assert!(
            decrypt_fido2_hmac_with_prf(
                &Stanza {
                    tag: "fido2-hmac".into(),
                    ..s_prf.clone()
                },
                &prf,
            )
            .is_err()
        );
    }

    #[test]
    fn ragedroid_keystore_round_trip_both_versions() {
        let file_key = fixed_file_key();
        let (sk, pk) = p256_keypair();
        let key_handle = "alias-12345";
        for (version, tag) in [
            (EcdhStanzaVersion::V1, "ragedroid-keystore-v1"),
            (EcdhStanzaVersion::V2, "ragedroid-keystore-v2"),
        ] {
            let stanza =
                encrypt_ragedroid_keystore_stanza(&file_key, &pk, key_handle, version).unwrap();
            assert_eq!(stanza.tag, tag);
            assert_eq!(stanza.args.len(), 2);
            assert_eq!(ragedroid_keystore_key_handle(&stanza).unwrap(), key_handle);
            let share = p256_share(&sk, &ragedroid_keystore_ephemeral_pub(&stanza).unwrap());
            let recovered =
                decrypt_ragedroid_keystore_with_ecdh_share(&stanza, &share, Some(&pk)).unwrap();
            assert_eq!(&*recovered, &file_key);
        }
    }

    #[test]
    fn ragedroid_keystore_v2_binds_the_recipient_public_key() {
        let file_key = fixed_file_key();
        let (sk, pk) = p256_keypair();
        let (_, other) = p256_keypair();
        let v2 =
            encrypt_ragedroid_keystore_stanza(&file_key, &pk, "k", EcdhStanzaVersion::V2).unwrap();
        let share = p256_share(&sk, &ragedroid_keystore_ephemeral_pub(&v2).unwrap());
        assert!(matches!(
            decrypt_ragedroid_keystore_with_ecdh_share(&v2, &share, Some(&other)).unwrap_err(),
            StanzaFormatError::AeadFailed
        ));
        assert!(matches!(
            decrypt_ragedroid_keystore_with_ecdh_share(&v2, &share, None).unwrap_err(),
            StanzaFormatError::Shape(_)
        ));

        let v1 =
            encrypt_ragedroid_keystore_stanza(&file_key, &pk, "k", EcdhStanzaVersion::V1).unwrap();
        let share = p256_share(&sk, &ragedroid_keystore_ephemeral_pub(&v1).unwrap());
        assert_eq!(
            &*decrypt_ragedroid_keystore_with_ecdh_share(&v1, &share, None).unwrap(),
            &file_key
        );
    }

    #[test]
    fn ragedroid_keystore_wrong_share_fails() {
        let file_key = fixed_file_key();
        let (_, pk) = p256_keypair();
        for version in [EcdhStanzaVersion::V1, EcdhStanzaVersion::V2] {
            let stanza =
                encrypt_ragedroid_keystore_stanza(&file_key, &pk, "alias", version).unwrap();
            let err = decrypt_ragedroid_keystore_with_ecdh_share(&stanza, &[0xee; 32], Some(&pk))
                .unwrap_err();
            assert!(matches!(err, StanzaFormatError::AeadFailed));
        }
    }

    #[test]
    fn webauthn_prf_kat_body_bytes() {
        let file_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let salt = [0xab; 32];
        let prf = [0x42; 32];

        let body_key = hkdf_extract_expand(Some(&salt), HKDF_INFO_WEBAUTHN_PRF, &prf);
        let body = aead_encrypt_filekey(&body_key, AD_WEBAUTHN_PRF, &file_key);

        let body2 = aead_encrypt_filekey(&body_key, AD_WEBAUTHN_PRF, &file_key);
        assert_eq!(body, body2);
        assert_eq!(body.len(), 32, "ChaCha20-Poly1305(16-byte pt) = 32 bytes");

        let stanza = Stanza {
            tag: TAG_WEBAUTHN_PRF_V1.to_string(),
            args: vec![
                B64URL.encode(b"cred"),
                "ragewarden".into(),
                B64.encode(salt),
            ],
            body,
        };
        let recovered = decrypt_webauthn_prf_with_prf(&stanza, &prf).unwrap();
        assert_eq!(&*recovered, &file_key);
    }

    #[test]
    fn ragedroid_keystore_kat_body_bytes() {
        use p256::SecretKey as P256Secret;
        let file_key = fixed_file_key();
        let pub_point = P256Secret::generate_from_rng(&mut rand::rng())
            .public_key()
            .to_sec1_point(true);
        let stanza = encrypt_ragedroid_keystore_stanza(
            &file_key,
            pub_point.as_bytes(),
            "k",
            EcdhStanzaVersion::V2,
        )
        .unwrap();
        assert_eq!(stanza.body.len(), 32);
    }

    fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
    }

    fn legacy_webauthn_prf_stanza(
        file_key: &[u8; 16],
        credential_id: &[u8],
        salt: &[u8; 32],
        rp_id: &str,
        prf_output: &[u8; 32],
    ) -> Stanza {
        let body_key = prf_body_key(salt, None, HKDF_INFO_WEBAUTHN_PRF, prf_output);
        Stanza {
            tag: TAG_WEBAUTHN_PRF_V1.to_string(),
            args: vec![
                B64URL.encode(credential_id),
                rp_id.to_string(),
                B64.encode(salt),
            ],
            body: aead_encrypt_filekey(&body_key, AD_WEBAUTHN_PRF, file_key),
        }
    }

    fn legacy_fido2_hmac_stanza(
        file_key: &[u8; 16],
        credential_id: &[u8],
        salt: &[u8; 32],
        rp_id: &str,
        prf_output: &[u8; 32],
    ) -> Stanza {
        let body_key = prf_body_key(salt, None, HKDF_INFO_FIDO2_HMAC, prf_output);
        Stanza {
            tag: TAG_FIDO2_HMAC.to_string(),
            args: vec![
                B64URL.encode(credential_id),
                B64.encode(salt),
                rp_id.to_string(),
            ],
            body: aead_encrypt_filekey(&body_key, AD_FIDO2_HMAC, file_key),
        }
    }

    const FK_A: [u8; 16] = [0x11; 16];
    const FK_B: [u8; 16] = [0x22; 16];

    #[test]
    fn legacy_wrap_is_the_bug_this_module_fixes() {
        let salt = [0xab; 32];
        let prf = [0x42; 32];
        let s1 = legacy_webauthn_prf_stanza(&FK_A, b"cred", &salt, "rp", &prf);
        let s2 = legacy_webauthn_prf_stanza(&FK_B, b"cred", &salt, "rp", &prf);
        assert_eq!(
            xor(&s1.body[..16], &s2.body[..16]),
            xor(&FK_A, &FK_B),
            "the pre-wrap-salt derivation reused key+nonce; this test pins the old \
             behaviour so the fix below is demonstrably a fix, not a no-op",
        );
    }

    #[test]
    fn webauthn_prf_two_secrets_to_one_recipient_do_not_reuse_keystream() {
        let salt = [0xab; 32];
        let prf = [0x42; 32];
        let s1 = encrypt_webauthn_prf_with_prf(&FK_A, b"cred", &salt, "rp", &prf);
        let s2 = encrypt_webauthn_prf_with_prf(&FK_B, b"cred", &salt, "rp", &prf);

        assert_ne!(
            webauthn_prf_wrap_salt(&s1).unwrap(),
            webauthn_prf_wrap_salt(&s2).unwrap(),
            "wrap salt must be freshly drawn per stanza",
        );
        assert_ne!(
            xor(&s1.body[..16], &s2.body[..16]),
            xor(&FK_A, &FK_B),
            "xor(body1,body2) == xor(fk1,fk2) means one ChaCha20 keystream wrapped both",
        );
        assert_ne!(&s1.body[16..], &s2.body[16..], "Poly1305 tags collided");

        assert_eq!(&*decrypt_webauthn_prf_with_prf(&s1, &prf).unwrap(), &FK_A);
        assert_eq!(&*decrypt_webauthn_prf_with_prf(&s2, &prf).unwrap(), &FK_B);
    }

    #[test]
    fn fido2_hmac_two_secrets_to_one_recipient_do_not_reuse_keystream() {
        let salt = [0xcd; 32];
        let prf = [0x77; 32];
        let s1 = encrypt_fido2_hmac_with_prf(&FK_A, b"cred", &salt, "rp", &prf);
        let s2 = encrypt_fido2_hmac_with_prf(&FK_B, b"cred", &salt, "rp", &prf);

        assert_ne!(
            fido2_hmac_wrap_salt(&s1).unwrap(),
            fido2_hmac_wrap_salt(&s2).unwrap(),
        );
        assert_ne!(
            xor(&s1.body[..16], &s2.body[..16]),
            xor(&FK_A, &FK_B),
            "xor(body1,body2) == xor(fk1,fk2) means one ChaCha20 keystream wrapped both",
        );
        assert_ne!(&s1.body[16..], &s2.body[16..], "Poly1305 tags collided");

        assert_eq!(&*decrypt_fido2_hmac_with_prf(&s1, &prf).unwrap(), &FK_A);
        assert_eq!(&*decrypt_fido2_hmac_with_prf(&s2, &prf).unwrap(), &FK_B);
    }

    #[test]
    fn same_file_key_twice_to_one_recipient_yields_different_bodies() {
        let salt = [0x01; 32];
        let prf = [0x02; 32];
        let a = encrypt_webauthn_prf_with_prf(&FK_A, b"c", &salt, "rp", &prf);
        let b = encrypt_webauthn_prf_with_prf(&FK_A, b"c", &salt, "rp", &prf);
        assert_ne!(a.body, b.body);
        let c = encrypt_fido2_hmac_with_prf(&FK_A, b"c", &salt, "rp", &prf);
        let d = encrypt_fido2_hmac_with_prf(&FK_A, b"c", &salt, "rp", &prf);
        assert_ne!(c.body, d.body);
    }

    #[test]
    fn piv_p256_two_secrets_to_one_recipient_do_not_reuse_keystream() {
        let (_, recipient_pub) = x25519_keypair_from_seed(9);
        for version in [EcdhStanzaVersion::V1, EcdhStanzaVersion::V2] {
            let s1 = encrypt_piv_x25519_stanza(&FK_A, &recipient_pub, version);
            let s2 = encrypt_piv_x25519_stanza(&FK_B, &recipient_pub, version);
            assert_ne!(
                piv_x25519_ephemeral_pub(&s1).unwrap(),
                piv_x25519_ephemeral_pub(&s2).unwrap(),
                "ephemeral key must be fresh per encryption",
            );
            assert_ne!(xor(&s1.body[..16], &s2.body[..16]), xor(&FK_A, &FK_B));
        }
        let (_, p_pub) = p256_keypair();
        let s1 = encrypt_piv_ec_p256_stanza(&FK_A, &p_pub).unwrap();
        let s2 = encrypt_piv_ec_p256_stanza(&FK_B, &p_pub).unwrap();
        assert_ne!(s1.args[1], s2.args[1]);
        assert_ne!(xor(&s1.body[..16], &s2.body[..16]), xor(&FK_A, &FK_B));
    }

    #[test]
    fn ragedroid_keystore_two_secrets_to_one_recipient_do_not_reuse_keystream() {
        let (_, pk) = p256_keypair();
        for version in [EcdhStanzaVersion::V1, EcdhStanzaVersion::V2] {
            let s1 = encrypt_ragedroid_keystore_stanza(&FK_A, &pk, "k", version).unwrap();
            let s2 = encrypt_ragedroid_keystore_stanza(&FK_B, &pk, "k", version).unwrap();
            assert_ne!(
                ragedroid_keystore_ephemeral_pub(&s1).unwrap(),
                ragedroid_keystore_ephemeral_pub(&s2).unwrap(),
                "ephemeral key must be fresh per encryption",
            );
            assert_ne!(xor(&s1.body[..16], &s2.body[..16]), xor(&FK_A, &FK_B));
        }
    }

    #[test]
    fn legacy_three_arg_stanzas_still_decrypt() {
        let salt = [0x33; 32];
        let prf = [0x44; 32];

        let legacy_prf = legacy_webauthn_prf_stanza(&FK_A, b"cred", &salt, "rp", &prf);
        assert_eq!(legacy_prf.args.len(), PRF_ARGS_LEGACY);
        assert!(webauthn_prf_is_legacy_wrap(&legacy_prf).unwrap());
        assert_eq!(webauthn_prf_wrap_salt(&legacy_prf).unwrap(), None);
        assert_eq!(webauthn_prf_salt(&legacy_prf).unwrap(), salt);
        assert_eq!(webauthn_prf_rp_id(&legacy_prf).unwrap(), "rp");
        assert_eq!(
            webauthn_prf_credential_id(&legacy_prf).unwrap(),
            b"cred".to_vec()
        );
        assert_eq!(
            &*decrypt_webauthn_prf_with_prf(&legacy_prf, &prf).unwrap(),
            &FK_A
        );

        let legacy_fido = legacy_fido2_hmac_stanza(&FK_B, b"cred", &salt, "rp", &prf);
        assert_eq!(legacy_fido.args.len(), PRF_ARGS_LEGACY);
        assert!(fido2_hmac_is_legacy_wrap(&legacy_fido).unwrap());
        assert_eq!(fido2_hmac_wrap_salt(&legacy_fido).unwrap(), None);
        assert_eq!(fido2_hmac_salt(&legacy_fido).unwrap(), salt);
        assert_eq!(fido2_hmac_rp_id(&legacy_fido).unwrap(), "rp");
        assert_eq!(
            &*decrypt_fido2_hmac_with_prf(&legacy_fido, &prf).unwrap(),
            &FK_B
        );
    }

    #[test]
    fn freshly_written_stanzas_are_not_legacy() {
        let salt = [0x55; 32];
        let prf = [0x66; 32];
        let a = encrypt_webauthn_prf_with_prf(&FK_A, b"c", &salt, "rp", &prf);
        let b = encrypt_fido2_hmac_with_prf(&FK_A, b"c", &salt, "rp", &prf);
        assert!(!webauthn_prf_is_legacy_wrap(&a).unwrap());
        assert!(!fido2_hmac_is_legacy_wrap(&b).unwrap());
        assert!(webauthn_prf_wrap_salt(&a).unwrap().is_some());
        assert!(fido2_hmac_wrap_salt(&b).unwrap().is_some());
    }

    #[test]
    fn stripping_the_wrap_salt_does_not_fall_back_to_the_legacy_key() {
        let salt = [0x99; 32];
        let prf = [0x88; 32];
        let current = encrypt_webauthn_prf_with_prf(&FK_A, b"c", &salt, "rp", &prf);
        let wrap = webauthn_prf_wrap_salt(&current).unwrap().unwrap();
        let downgraded = Stanza {
            args: current.args[..PRF_ARGS_LEGACY].to_vec(),
            ..current.clone()
        };
        assert!(
            decrypt_webauthn_prf_with_prf(&downgraded, &prf).is_err(),
            "stripping the wrap salt must not silently fall back to the legacy key",
        );
        assert_eq!(
            &*decrypt_webauthn_prf_with_prf(&current, &prf).unwrap(),
            &FK_A
        );
        assert_eq!(webauthn_prf_wrap_salt(&current).unwrap().unwrap(), wrap);
    }

    #[test]
    fn an_all_zero_wrap_salt_is_refused_because_it_is_the_legacy_key() {
        let salt = [0x99; 32];
        let prf = [0x88; 32];
        assert_eq!(
            *prf_body_key(
                &salt,
                Some(&[0u8; WRAP_SALT_LEN]),
                HKDF_INFO_WEBAUTHN_PRF,
                &prf
            ),
            *prf_body_key(&salt, None, HKDF_INFO_WEBAUTHN_PRF, &prf),
            "the zero wrap salt collides with the legacy derivation",
        );

        let legacy = legacy_webauthn_prf_stanza(&FK_A, b"c", &salt, "rp", &prf);
        let mut zero = legacy.clone();
        zero.args.push(B64.encode([0u8; WRAP_SALT_LEN]));
        assert!(webauthn_prf_wrap_salt(&zero).is_err());
        assert!(decrypt_webauthn_prf_with_prf(&zero, &prf).is_err());

        let legacy_fido = legacy_fido2_hmac_stanza(&FK_B, b"c", &salt, "rp", &prf);
        let mut zero_fido = legacy_fido.clone();
        zero_fido.args.push(B64.encode([0u8; WRAP_SALT_LEN]));
        assert!(fido2_hmac_wrap_salt(&zero_fido).is_err());
        assert!(decrypt_fido2_hmac_with_prf(&zero_fido, &prf).is_err());
    }

    #[test]
    fn wrong_arity_prf_stanzas_are_rejected() {
        let s = Stanza {
            tag: TAG_WEBAUTHN_PRF_V1.into(),
            args: vec!["a".into(), "b".into()],
            body: vec![0u8; 32],
        };
        assert!(matches!(
            webauthn_prf_salt(&s).unwrap_err(),
            StanzaFormatError::Shape(_)
        ));
        let s5 = Stanza {
            args: vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
            ..s
        };
        assert!(matches!(
            webauthn_prf_salt(&s5).unwrap_err(),
            StanzaFormatError::Shape(_)
        ));
    }

    fn stanza_json(s: &Stanza) -> serde_json::Value {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        serde_json::json!({"tag": s.tag, "args": s.args, "body_hex": hex(&s.body)})
    }

    /// Byte-exact answers for every stanza writer from fixed keys, ephemerals
    /// and salts, pinned in `tests/vectors/stanza_kat_v2.json` (with the
    /// inputs, so another language can reproduce them). A change to any
    /// derivation, argument order or encoding fails here instead of on a
    /// user's device. `RAGEWARDEN_BLESS_VECTORS=1` rewrites the file.
    #[test]
    fn stanza_writers_match_the_pinned_known_answers() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let fk = [0x0fu8; 16];
        let x_secret = [0x42u8; 32];
        let x_pub = *X25519Public::from(&X25519Secret::from(x_secret)).as_bytes();
        let x_eph = [0x17u8; 32];
        let p_secret = P256SecretKey::from_slice(&[0x21u8; 32]).unwrap();
        let p_pub = p_secret
            .public_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();
        let p_eph_bytes = [0x35u8; 32];
        let p_eph = P256SecretKey::from_slice(&p_eph_bytes).unwrap();
        let cred = b"kat-credential";
        let prf_salt = [0x51u8; 32];
        let prf_output = [0x63u8; 32];
        let wrap_salt = [0x74u8; 32];
        let recipient_pk = P256PublicKey::from_sec1_bytes(&p_pub).unwrap();

        let stanzas = [
            (
                "piv_x25519_v1",
                piv_x25519_stanza_from(&fk, &x_pub, EcdhStanzaVersion::V1, &x_eph),
            ),
            (
                "piv_x25519_v2",
                piv_x25519_stanza_from(&fk, &x_pub, EcdhStanzaVersion::V2, &x_eph),
            ),
            (
                "piv_p256",
                piv_ec_p256_stanza_from(&fk, &p_pub, &p_eph).unwrap(),
            ),
            (
                "ragedroid_keystore_v1",
                ragedroid_keystore_stanza_from(
                    &fk,
                    &p_pub,
                    &recipient_pk,
                    "kat-alias",
                    EcdhStanzaVersion::V1,
                    &p_eph,
                ),
            ),
            (
                "ragedroid_keystore_v2",
                ragedroid_keystore_stanza_from(
                    &fk,
                    &p_pub,
                    &recipient_pk,
                    "kat-alias",
                    EcdhStanzaVersion::V2,
                    &p_eph,
                ),
            ),
            (
                "webauthn_prf_v1",
                webauthn_prf_stanza_from(
                    &fk,
                    cred,
                    &prf_salt,
                    "kat.example",
                    &prf_output,
                    &wrap_salt,
                ),
            ),
            (
                "fido2_hmac",
                fido2_hmac_stanza_from(
                    &fk,
                    cred,
                    &prf_salt,
                    "kat.example",
                    &prf_output,
                    &wrap_salt,
                ),
            ),
        ];

        let x_share = |s: &Stanza| -> [u8; 32] {
            *X25519Secret::from(x_secret)
                .diffie_hellman(&X25519Public::from(piv_x25519_ephemeral_pub(s).unwrap()))
                .as_bytes()
        };
        for (name, s) in &stanzas {
            let recovered = match *name {
                "piv_x25519_v1" | "piv_x25519_v2" => {
                    decrypt_piv_x25519_with_ecdh_share(s, &x_share(s), Some(&x_pub))
                }
                "piv_p256" => decrypt_piv_ec_p256_with_ecdh_share(
                    s,
                    &p256_share(&p_secret, &piv_ec_p256_ephemeral_pub(s).unwrap()),
                    &p_pub,
                ),
                "webauthn_prf_v1" => decrypt_webauthn_prf_with_prf(s, &prf_output),
                "fido2_hmac" => decrypt_fido2_hmac_with_prf(s, &prf_output),
                _ => decrypt_ragedroid_keystore_with_ecdh_share(
                    s,
                    &p256_share(&p_secret, &ragedroid_keystore_ephemeral_pub(s).unwrap()),
                    Some(&p_pub),
                ),
            };
            assert_eq!(*recovered.unwrap(), fk, "{name} does not round-trip");
        }

        let mut doc = serde_json::json!({
            "comment": "Known answers for core::stanza_format writers. Inputs are fixed; outputs must match byte for byte. Regenerate only with RAGEWARDEN_BLESS_VECTORS=1 after a deliberate format change.",
            "inputs": {
                "file_key_hex": hex(&fk),
                "x25519_recipient_secret_hex": hex(&x_secret),
                "x25519_recipient_pub_hex": hex(&x_pub),
                "x25519_ephemeral_secret_hex": hex(&x_eph),
                "p256_recipient_secret_hex": hex(&[0x21u8; 32]),
                "p256_recipient_pub_hex": hex(&p_pub),
                "p256_ephemeral_secret_hex": hex(&p_eph_bytes),
                "keystore_key_handle": "kat-alias",
                "prf_credential_id_hex": hex(cred),
                "prf_rp_id": "kat.example",
                "prf_salt_hex": hex(&prf_salt),
                "prf_output_hex": hex(&prf_output),
                "wrap_salt_hex": hex(&wrap_salt),
            },
        });
        for (name, s) in &stanzas {
            doc[*name] = stanza_json(s);
        }
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/stanza_kat_v2.json"
        );
        if std::env::var("RAGEWARDEN_BLESS_VECTORS").as_deref() == Ok("1") {
            std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        }
        let pinned: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).unwrap();
        assert_eq!(
            doc, pinned,
            "a stanza writer's output drifted from the pinned answers"
        );
    }

    #[test]
    fn base32_round_trip_known_vector() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
    }
}
