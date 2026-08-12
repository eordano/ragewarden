use base64::{
    engine::general_purpose::{STANDARD_NO_PAD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret as P256EphemeralSecret, elliptic_curve::sec1::ToSec1Point,
    PublicKey as P256PublicKey,
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

pub const TAG_PIV_P256: &str = "piv-p256";

pub const TAG_FIDO2_HMAC: &str = "fido2-hmac";

pub const TAG_WEBAUTHN_PRF_V1: &str = "webauthn-prf-v1";

pub const TAG_RAGEDROID_KEYSTORE_V1: &str = "ragedroid-keystore-v1";

const HKDF_INFO_PIV_P256: &[u8] = TAG_PIV_P256.as_bytes();
const HKDF_INFO_FIDO2_HMAC: &[u8] = TAG_FIDO2_HMAC.as_bytes();
const HKDF_INFO_WEBAUTHN_PRF: &[u8] = TAG_WEBAUTHN_PRF_V1.as_bytes();
const HKDF_INFO_RAGEDROID_KEYSTORE: &[u8] = TAG_RAGEDROID_KEYSTORE_V1.as_bytes();

const AD_PIV_P256: &[u8] = TAG_PIV_P256.as_bytes();
const AD_FIDO2_HMAC: &[u8] = TAG_FIDO2_HMAC.as_bytes();
const AD_WEBAUTHN_PRF: &[u8] = TAG_WEBAUTHN_PRF_V1.as_bytes();
const AD_RAGEDROID_KEYSTORE: &[u8] = TAG_RAGEDROID_KEYSTORE_V1.as_bytes();

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

pub fn encrypt_piv_p256_stanza(file_key: &[u8; 16], recipient_pubkey: &[u8; 32]) -> Stanza {
    let mut eph_seed = [0u8; 32];
    rand::rng().fill_bytes(&mut eph_seed);
    let eph_secret = X25519Secret::from(eph_seed);
    let eph_public = X25519Public::from(&eph_secret);

    let recipient_pk = X25519Public::from(*recipient_pubkey);
    let shared = eph_secret.diffie_hellman(&recipient_pk);

    let body_key = hkdf_extract_expand(
        Some(eph_public.as_bytes().as_slice()),
        HKDF_INFO_PIV_P256,
        shared.as_bytes(),
    );
    let body = aead_encrypt_filekey(&body_key, AD_PIV_P256, file_key);

    Stanza {
        tag: TAG_PIV_P256.to_string(),
        args: vec![
            B64.encode(eph_public.as_bytes()),
            B64.encode(piv_recipient_tag(recipient_pubkey)),
        ],
        body,
    }
}

pub fn decrypt_piv_p256_with_ecdh_share(
    stanza: &Stanza,
    ecdh_share: &[u8; 32],
) -> Result<FileKey, StanzaFormatError> {
    let eph_pub = piv_p256_ephemeral_pub(stanza)?;
    let body_key = hkdf_extract_expand(Some(&eph_pub), HKDF_INFO_PIV_P256, ecdh_share);
    aead_decrypt_filekey(&body_key, AD_PIV_P256, &stanza.body)
}

pub fn piv_recipient_tag(recipient_pubkey: &[u8; 32]) -> [u8; 4] {
    use sha2::Digest;
    let h = Sha256::digest(recipient_pubkey);
    let mut out = [0u8; 4];
    out.copy_from_slice(&h[..4]);
    out
}

pub fn piv_p256_ephemeral_pub(stanza: &Stanza) -> Result<[u8; 32], StanzaFormatError> {
    if stanza.tag != TAG_PIV_P256 {
        return Err(StanzaFormatError::Shape(format!(
            "expected tag piv-p256, got {}",
            stanza.tag
        )));
    }
    if stanza.args.len() != 2 {
        return Err(StanzaFormatError::Shape(format!(
            "piv-p256 stanza must have 2 args, got {}",
            stanza.args.len()
        )));
    }
    let bytes = B64
        .decode(stanza.args[0].as_bytes())
        .map_err(|e| StanzaFormatError::Base64(format!("ephemeral pub: {e}")))?;
    if bytes.len() != 32 {
        return Err(StanzaFormatError::Shape(format!(
            "ephemeral pub must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn piv_p256_recipient_tag(stanza: &Stanza) -> Result<[u8; 4], StanzaFormatError> {
    if stanza.args.len() != 2 {
        return Err(StanzaFormatError::Shape(format!(
            "piv-p256 stanza must have 2 args, got {}",
            stanza.args.len()
        )));
    }
    let bytes = B64
        .decode(stanza.args[1].as_bytes())
        .map_err(|e| StanzaFormatError::Base64(format!("recipient tag: {e}")))?;
    if bytes.len() != 4 {
        return Err(StanzaFormatError::Shape(format!(
            "recipient tag must be 4 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn encrypt_fido2_hmac_with_prf(
    file_key: &[u8; 16],
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    prf_output: &[u8; 32],
) -> Stanza {
    let wrap_salt = fresh_wrap_salt();
    let body_key = prf_body_key(salt, Some(&wrap_salt), HKDF_INFO_FIDO2_HMAC, prf_output);
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
    let body_key = prf_body_key(
        &salt,
        wrap_salt.as_ref(),
        HKDF_INFO_FIDO2_HMAC,
        prf_output,
    );
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
    decode_salt_arg(&stanza.args[3], "wrap salt").map(Some)
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
    let wrap_salt = fresh_wrap_salt();
    let body_key = prf_body_key(salt, Some(&wrap_salt), HKDF_INFO_WEBAUTHN_PRF, prf_output);
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
    decode_salt_arg(&stanza.args[3], "wrap salt").map(Some)
}

pub fn webauthn_prf_is_legacy_wrap(stanza: &Stanza) -> Result<bool, StanzaFormatError> {
    Ok(check_prf_stanza_arity(stanza, TAG_WEBAUTHN_PRF_V1)? == PRF_ARGS_LEGACY)
}

pub fn is_valid_p256_sec1_compressed(bytes: &[u8]) -> bool {
    bytes.len() == 33 && P256PublicKey::from_sec1_bytes(bytes).is_ok()
}

pub fn encrypt_ragedroid_keystore_stanza(
    file_key: &[u8; 16],
    keystore_pubkey_sec1_compressed: &[u8],
    key_handle: &str,
) -> Result<Stanza, StanzaFormatError> {
    if keystore_pubkey_sec1_compressed.len() != 33 {
        return Err(StanzaFormatError::Shape(format!(
            "keystore pubkey must be 33 SEC1-compressed bytes, got {}",
            keystore_pubkey_sec1_compressed.len()
        )));
    }
    let recipient_pk = P256PublicKey::from_sec1_bytes(keystore_pubkey_sec1_compressed)
        .map_err(|_| {
            StanzaFormatError::Shape(
                "keystore pubkey is not a valid SEC1-compressed P-256 point".to_string(),
            )
        })?;

    let eph_secret = P256EphemeralSecret::random(&mut rand::rng());
    let eph_public_point = eph_secret.public_key().to_sec1_point(true);
    let eph_pub_bytes = eph_public_point.as_bytes();
    debug_assert_eq!(eph_pub_bytes.len(), 33, "p256 SEC1-compressed is 33 bytes");

    let shared = eph_secret.diffie_hellman(&recipient_pk);
    let shared_bytes = shared.raw_secret_bytes();

    let body_key = hkdf_extract_expand(
        Some(eph_pub_bytes),
        HKDF_INFO_RAGEDROID_KEYSTORE,
        shared_bytes.as_slice(),
    );
    let body = aead_encrypt_filekey(&body_key, AD_RAGEDROID_KEYSTORE, file_key);

    Ok(Stanza {
        tag: TAG_RAGEDROID_KEYSTORE_V1.to_string(),
        args: vec![
            base32_encode(key_handle.as_bytes()),
            B64.encode(eph_pub_bytes),
        ],
        body,
    })
}

pub fn decrypt_ragedroid_keystore_with_ecdh_share(
    stanza: &Stanza,
    ecdh_share: &[u8; 32],
) -> Result<FileKey, StanzaFormatError> {
    let eph_pub = ragedroid_keystore_ephemeral_pub(stanza)?;
    let body_key = hkdf_extract_expand(Some(&eph_pub), HKDF_INFO_RAGEDROID_KEYSTORE, ecdh_share);
    aead_decrypt_filekey(&body_key, AD_RAGEDROID_KEYSTORE, &stanza.body)
}

pub fn ragedroid_keystore_key_handle(stanza: &Stanza) -> Result<String, StanzaFormatError> {
    if stanza.tag != TAG_RAGEDROID_KEYSTORE_V1 {
        return Err(StanzaFormatError::Shape(format!(
            "expected tag ragedroid-keystore-v1, got {}",
            stanza.tag
        )));
    }
    if stanza.args.len() != 2 {
        return Err(StanzaFormatError::Shape(format!(
            "ragedroid-keystore-v1 stanza must have 2 args, got {}",
            stanza.args.len()
        )));
    }
    let bytes = base32_decode(&stanza.args[0])
        .map_err(|e| StanzaFormatError::Base64(format!("key handle base32: {e}")))?;
    String::from_utf8(bytes).map_err(|e| StanzaFormatError::Shape(format!("key handle utf8: {e}")))
}

pub fn ragedroid_keystore_ephemeral_pub(stanza: &Stanza) -> Result<Vec<u8>, StanzaFormatError> {
    if stanza.args.len() != 2 {
        return Err(StanzaFormatError::Shape(format!(
            "ragedroid-keystore-v1 stanza must have 2 args, got {}",
            stanza.args.len()
        )));
    }
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
    let pt = cipher
        .decrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload { msg: body, aad: ad },
        )
        .map_err(|_| StanzaFormatError::AeadFailed)?;
    if pt.len() != 16 {
        return Err(StanzaFormatError::BodyLength {
            expected: 16,
            got: pt.len(),
        });
    }
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&pt);
    Ok(out)
}

fn base32_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 8 + 4) / 5);
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
    let mut out = Vec::with_capacity((input.len() * 5 + 7) / 8);
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

    #[test]
    fn piv_p256_round_trip() {
        let file_key = fixed_file_key();
        let (recipient_seed, recipient_pub) = x25519_keypair_from_seed(7);
        let recipient_secret = X25519Secret::from(recipient_seed);

        let stanza = encrypt_piv_p256_stanza(&file_key, &recipient_pub);
        assert_eq!(stanza.tag, "piv-p256");
        assert_eq!(stanza.args.len(), 2);

        let eph_pub = piv_p256_ephemeral_pub(&stanza).unwrap();
        let share = recipient_secret.diffie_hellman(&X25519Public::from(eph_pub));
        let recovered = decrypt_piv_p256_with_ecdh_share(&stanza, share.as_bytes()).unwrap();
        assert_eq!(&*recovered, &file_key);
    }

    #[test]
    fn piv_p256_recipient_tag_matches_encoded_arg() {
        let (_, recipient_pub) = x25519_keypair_from_seed(11);
        let file_key = fixed_file_key();
        let stanza = encrypt_piv_p256_stanza(&file_key, &recipient_pub);
        let tag_arg = piv_p256_recipient_tag(&stanza).unwrap();
        let expected = piv_recipient_tag(&recipient_pub);
        assert_eq!(tag_arg, expected);
    }

    #[test]
    fn piv_p256_wrong_share_fails() {
        let file_key = fixed_file_key();
        let (_, recipient_pub) = x25519_keypair_from_seed(7);
        let stanza = encrypt_piv_p256_stanza(&file_key, &recipient_pub);
        let bogus = [0xffu8; 32];
        let err = decrypt_piv_p256_with_ecdh_share(&stanza, &bogus).unwrap_err();
        assert!(matches!(err, StanzaFormatError::AeadFailed));
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
        assert!(decrypt_webauthn_prf_with_prf(
            &Stanza {
                tag: "webauthn-prf-v1".into(),
                ..s_fido.clone()
            },
            &prf,
        )
        .is_err());
        assert!(decrypt_fido2_hmac_with_prf(
            &Stanza {
                tag: "fido2-hmac".into(),
                ..s_prf.clone()
            },
            &prf,
        )
        .is_err());
    }

    #[test]
    fn ragedroid_keystore_round_trip() {
        use p256::{ecdh::diffie_hellman, SecretKey as P256Secret};
        let file_key = fixed_file_key();
        let recipient_secret = P256Secret::random(&mut rand::rng());
        let recipient_pub_point = recipient_secret.public_key().to_sec1_point(true);
        let recipient_pub = recipient_pub_point.as_bytes();
        assert_eq!(recipient_pub.len(), 33);
        let key_handle = "alias-12345";

        let stanza =
            encrypt_ragedroid_keystore_stanza(&file_key, recipient_pub, key_handle).unwrap();
        assert_eq!(stanza.tag, "ragedroid-keystore-v1");
        assert_eq!(stanza.args.len(), 2);
        assert_eq!(ragedroid_keystore_key_handle(&stanza).unwrap(), key_handle);

        let eph_pub_bytes = ragedroid_keystore_ephemeral_pub(&stanza).unwrap();
        let eph_pub = P256PublicKey::from_sec1_bytes(&eph_pub_bytes).unwrap();
        let share = diffie_hellman(recipient_secret.to_nonzero_scalar(), eph_pub.as_affine());
        let share_bytes = share.raw_secret_bytes();
        let mut share_arr = [0u8; 32];
        share_arr.copy_from_slice(&share_bytes);
        let recovered = decrypt_ragedroid_keystore_with_ecdh_share(&stanza, &share_arr).unwrap();
        assert_eq!(&*recovered, &file_key);
    }

    #[test]
    fn ragedroid_keystore_wrong_share_fails() {
        use p256::SecretKey as P256Secret;
        let file_key = fixed_file_key();
        let recipient_pub_point = P256Secret::random(&mut rand::rng())
            .public_key()
            .to_sec1_point(true);
        let stanza = encrypt_ragedroid_keystore_stanza(
            &file_key,
            recipient_pub_point.as_bytes(),
            "alias",
        )
        .unwrap();
        let err = decrypt_ragedroid_keystore_with_ecdh_share(&stanza, &[0xee; 32]).unwrap_err();
        assert!(matches!(err, StanzaFormatError::AeadFailed));
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
        let pub_point = P256Secret::random(&mut rand::rng())
            .public_key()
            .to_sec1_point(true);
        let stanza = encrypt_ragedroid_keystore_stanza(&file_key, pub_point.as_bytes(), "k").unwrap();
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

        assert_eq!(
            &*decrypt_webauthn_prf_with_prf(&s1, &prf).unwrap(),
            &FK_A
        );
        assert_eq!(
            &*decrypt_webauthn_prf_with_prf(&s2, &prf).unwrap(),
            &FK_B
        );
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

        assert_eq!(
            &*decrypt_fido2_hmac_with_prf(&s1, &prf).unwrap(),
            &FK_A
        );
        assert_eq!(
            &*decrypt_fido2_hmac_with_prf(&s2, &prf).unwrap(),
            &FK_B
        );
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
        let s1 = encrypt_piv_p256_stanza(&FK_A, &recipient_pub);
        let s2 = encrypt_piv_p256_stanza(&FK_B, &recipient_pub);
        assert_ne!(
            piv_p256_ephemeral_pub(&s1).unwrap(),
            piv_p256_ephemeral_pub(&s2).unwrap(),
            "ephemeral key must be fresh per encryption",
        );
        assert_ne!(xor(&s1.body[..16], &s2.body[..16]), xor(&FK_A, &FK_B));
    }

    #[test]
    fn ragedroid_keystore_two_secrets_to_one_recipient_do_not_reuse_keystream() {
        use p256::SecretKey as P256Secret;
        let pub_point = P256Secret::random(&mut rand::rng())
            .public_key()
            .to_sec1_point(true);
        let s1 = encrypt_ragedroid_keystore_stanza(&FK_A, pub_point.as_bytes(), "k").unwrap();
        let s2 = encrypt_ragedroid_keystore_stanza(&FK_B, pub_point.as_bytes(), "k").unwrap();
        assert_ne!(
            ragedroid_keystore_ephemeral_pub(&s1).unwrap(),
            ragedroid_keystore_ephemeral_pub(&s2).unwrap(),
            "ephemeral key must be fresh per encryption",
        );
        assert_ne!(xor(&s1.body[..16], &s2.body[..16]), xor(&FK_A, &FK_B));
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
    fn legacy_and_current_derivations_are_domain_separated() {
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

    #[test]
    fn base32_round_trip_known_vector() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
    }
}
