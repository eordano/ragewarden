use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand_core::Rng;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

pub const KDF_PBKDF2: u32 = 0;

pub const KDF_ARGON2ID: u32 = 1;

pub const KDF_ITERATIONS_DEFAULT: u32 = 600_000;

/// Hard floor for a *server-supplied* PBKDF2-SHA256 iteration count.
///
/// 100_000 is the Bitwarden client default that shipped from 2018 until the
/// 2023 bump to 600_000, so it is the lowest count a legitimately-provisioned
/// account is likely to still carry. Anything below it (notably the 5_000 of
/// the 2013-era default) is refused outright: at 5_000 iterations a stolen
/// master-password hash is roughly 120x cheaper to crack than at the current
/// default, and the remedy -- raising the count server-side -- is available to
/// the user without this client.
///
/// A floor alone does not close the downgrade attack. A hostile server can
/// still answer prelogin with 100_000 for an account that really uses 600_000
/// and stay above the floor. The only mechanism that catches that is pinning
/// the count observed on a previous login; see
/// [`crate::sync::check_kdf_not_downgraded`].
pub const KDF_ITERATIONS_MIN: u32 = 100_000;

/// Floor for a count *this client chooses* when creating an account.
///
/// Nothing legacy can exist at registration time, so there is no reason to
/// accept less than the current OWASP / Bitwarden recommendation.
pub const KDF_ITERATIONS_MIN_NEW_ACCOUNT: u32 = KDF_ITERATIONS_DEFAULT;

pub fn kdf_type_name(kdf: u32) -> &'static str {
    match kdf {
        KDF_PBKDF2 => "PBKDF2-SHA256",
        KDF_ARGON2ID => "Argon2id",
        _ => "unknown",
    }
}

#[derive(Debug, Error)]
pub enum Type2Error {
    #[error("malformed Type-2 string")]
    Malformed,

    #[error("MAC verification failed")]
    MacFailed,

    #[error("decryption failed: {0}")]
    Decrypt(String),

    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub fn derive_master_key(password: &str, email: &str, iterations: u32) -> Zeroizing<[u8; 32]> {
    let salt = email.to_lowercase();
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt.as_bytes(),
        iterations,
        out.as_mut(),
    );
    out
}

pub fn master_password_hash(master_key: &[u8; 32], password: &str) -> String {
    let mut hash = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, &mut hash);
    B64.encode(hash)
}

pub fn stretch_master_key(master_key: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hkdf = Hkdf::<Sha256>::from_prk(master_key).expect("master key is exactly 32 bytes");
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"enc", enc.as_mut())
        .expect("32 bytes is well within HKDF expand limits");
    hkdf.expand(b"mac", mac.as_mut())
        .expect("32 bytes is well within HKDF expand limits");
    (enc, mac)
}

pub fn encrypt_type2(plaintext: &[u8], enc_key: &[u8; 32], mac_key: &[u8; 32]) -> String {
    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    let cipher = Aes256CbcEnc::new(enc_key.into(), (&iv).into());
    let ct = cipher.encrypt_padded_vec::<Pkcs7>(plaintext);

    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&iv);
    mac.update(&ct);
    let mac_bytes = mac.finalize().into_bytes();

    format!(
        "2.{}|{}|{}",
        B64.encode(iv),
        B64.encode(&ct),
        B64.encode(mac_bytes)
    )
}

#[derive(Debug)]
pub struct UserKey {
    pub enc_key: Zeroizing<[u8; 32]>,

    pub mac_key: Zeroizing<[u8; 32]>,

    pub protected: String,
}

pub fn make_user_key(master_key: &[u8; 32]) -> UserKey {
    let mut raw = Zeroizing::new([0u8; 64]);
    rand::rng().fill_bytes(raw.as_mut());

    let (stretch_enc, stretch_mac) = stretch_master_key(master_key);
    let protected = encrypt_type2(raw.as_ref(), &stretch_enc, &stretch_mac);

    let mut enc_key = Zeroizing::new([0u8; 32]);
    let mut mac_key = Zeroizing::new([0u8; 32]);
    enc_key.copy_from_slice(&raw[..32]);
    mac_key.copy_from_slice(&raw[32..]);
    UserKey {
        enc_key,
        mac_key,
        protected,
    }
}

#[derive(Debug)]
pub struct RegistrationKeys {
    pub public_key_b64: String,

    pub encrypted_private_key: String,
}

pub fn make_rsa_keypair_for_registration(
    user_enc_key: &[u8; 32],
    user_mac_key: &[u8; 32],
) -> Result<RegistrationKeys, RsaError> {
    let mut rng = rand_core06::OsRng;
    let private =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|e| RsaError::Generate(e.to_string()))?;
    let public = private.to_public_key();

    let spki = public
        .to_public_key_der()
        .map_err(|e| RsaError::Encode(format!("public spki: {e}")))?;
    let pkcs8 = private
        .to_pkcs8_der()
        .map_err(|e| RsaError::Encode(format!("private pkcs8: {e}")))?;

    let public_key_b64 = B64.encode(spki.as_bytes());
    let encrypted_private_key = encrypt_type2(pkcs8.as_bytes(), user_enc_key, user_mac_key);
    Ok(RegistrationKeys {
        public_key_b64,
        encrypted_private_key,
    })
}

#[derive(Debug, Error)]
pub enum RsaError {
    #[error("rsa keypair generate: {0}")]
    Generate(String),

    #[error("rsa encode: {0}")]
    Encode(String),
}

pub fn decrypt_type2(
    s: &str,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<Vec<u8>, Type2Error> {
    let body = s.strip_prefix("2.").ok_or(Type2Error::Malformed)?;
    let mut parts = body.split('|');
    let iv_b64 = parts.next().ok_or(Type2Error::Malformed)?;
    let ct_b64 = parts.next().ok_or(Type2Error::Malformed)?;
    let mac_b64 = parts.next().ok_or(Type2Error::Malformed)?;
    if parts.next().is_some() {
        return Err(Type2Error::Malformed);
    }

    let iv = B64.decode(iv_b64)?;
    let ct = B64.decode(ct_b64)?;
    let mac_provided = B64.decode(mac_b64)?;

    if iv.len() != 16 {
        return Err(Type2Error::Malformed);
    }
    if mac_provided.len() != 32 {
        return Err(Type2Error::Malformed);
    }

    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&iv);
    mac.update(&ct);
    let mac_expected = mac.finalize().into_bytes();
    if mac_expected.as_slice().ct_eq(&mac_provided).unwrap_u8() != 1 {
        return Err(Type2Error::MacFailed);
    }

    let iv_arr: [u8; 16] = iv.as_slice().try_into().expect("iv length checked above");
    let cipher = Aes256CbcDec::new(enc_key.into(), (&iv_arr).into());
    cipher
        .decrypt_padded_vec::<Pkcs7>(&ct)
        .map_err(|e| Type2Error::Decrypt(format!("{e}")))
}
