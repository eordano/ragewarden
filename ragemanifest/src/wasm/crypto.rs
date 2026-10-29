use super::{js_err, js_object};

use ragewarden_core::{
    AgeBlob, Identity, Recipient, decrypt as core_decrypt, encrypt as core_encrypt,
    software_passphrase_identity,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = wasm_software_keygen)]
pub fn wasm_software_keygen() -> Result<JsValue, JsValue> {
    identity_js(&age::x25519::Identity::generate())
}

fn identity_js(identity: &age::x25519::Identity) -> Result<JsValue, JsValue> {
    use secrecy::ExposeSecret;
    let secret_armored: String = identity.to_string().expose_secret().to_owned();
    let public_armored = identity.to_public().to_string();
    let public_key = decode_age_pubkey_bech32(&public_armored)
        .map_err(|e| js_err(format!("decode pubkey: {e}")))?;

    js_object(&[
        (
            "secret",
            js_sys::Uint8Array::from(secret_armored.as_bytes()).into(),
        ),
        (
            "public_key",
            js_sys::Uint8Array::from(&public_key[..]).into(),
        ),
        ("armored_pubkey", JsValue::from_str(&public_armored)),
        ("armored_secret", JsValue::from_str(&secret_armored)),
    ])
}

#[wasm_bindgen(js_name = wasm_generate_recovery_phrase)]
pub fn wasm_generate_recovery_phrase() -> Result<JsValue, JsValue> {
    let generated = ragewarden_core::recovery::generate()
        .map_err(|e| js_err(format!("recovery::generate: {e}")))?;
    let phrase = generated.mnemonic.to_string();
    let armored_pubkey: String = generated.armored_pubkey.into_inner();
    let armored_secret: String = generated.armored_secret.expose_secret().to_string();
    let public_key = decode_age_pubkey_bech32(&armored_pubkey)
        .map_err(|e| js_err(format!("decode pubkey: {e}")))?;

    js_object(&[
        ("phrase", JsValue::from_str(&phrase)),
        ("armored_pubkey", JsValue::from_str(&armored_pubkey)),
        ("armored_secret", JsValue::from_str(&armored_secret)),
        (
            "public_key",
            js_sys::Uint8Array::from(&public_key[..]).into(),
        ),
        (
            "secret",
            js_sys::Uint8Array::from(armored_secret.as_bytes()).into(),
        ),
    ])
}

#[wasm_bindgen(js_name = wasm_recovery_identity_from_phrase)]
pub fn wasm_recovery_identity_from_phrase(phrase: &str) -> Result<JsValue, JsValue> {
    let identity = ragewarden_core::recovery::from_phrase(phrase)
        .map_err(|e| js_err(format!("recovery from phrase: {e}")))?;
    identity_js(&identity)
}

#[wasm_bindgen(js_name = wasm_encrypt)]
pub fn wasm_encrypt(plaintext: &[u8], recipient_pubkey: &[u8]) -> Result<Vec<u8>, JsValue> {
    if recipient_pubkey.len() != 32 {
        return Err(js_err(format!(
            "recipient pubkey must be 32 bytes, got {}",
            recipient_pubkey.len()
        )));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(recipient_pubkey);

    let recipient = Recipient::X25519 { public_key: pk };
    let blob = core_encrypt(plaintext, &[recipient]).map_err(js_err)?;
    Ok(blob.0)
}

#[wasm_bindgen(js_name = wasm_decrypt_with_software)]
pub fn wasm_decrypt_with_software(blob: &[u8], armored_secret: &str) -> Result<Vec<u8>, JsValue> {
    let secret = ragewarden_core::ArmoredAgeSecret::from_trusted(armored_secret.to_string());
    let identity = software_passphrase_identity(&secret).map_err(js_err)?;
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(identity)];
    let blob = AgeBlob::from_bytes(blob.to_vec());
    let plaintext = core_decrypt(&blob, &identities).map_err(js_err)?;
    Ok(plaintext.to_vec())
}

fn decode_age_pubkey_bech32(s: &str) -> Result<[u8; 32], String> {
    ragewarden_core::bech32::decode_age_x25519(s)
        .ok_or_else(|| format!("malformed age recipient: {s}"))
}

/// `core::generator::password`: the shared generator, so the popup draws
/// from the same alphabets and the same unbiased sampler as the other clients.
#[wasm_bindgen(js_name = wasm_generate_password)]
pub fn wasm_generate_password(
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, JsValue> {
    let policy = ragewarden_core::generator::PasswordPolicy {
        length,
        lowercase,
        uppercase,
        digits,
        symbols,
    };
    ragewarden_core::generator::password(&policy)
        .map(|p| p.to_string())
        .map_err(|e| js_err(format!("generate: {e}")))
}

#[wasm_bindgen(js_name = wasm_generate_passphrase)]
pub fn wasm_generate_passphrase(words: usize, separator: &str) -> Result<String, JsValue> {
    ragewarden_core::generator::passphrase(words, separator)
        .map(|p| p.to_string())
        .map_err(|e| js_err(format!("generate: {e}")))
}

#[wasm_bindgen(js_name = wasm_totp_generate)]
pub fn wasm_totp_generate(input: &str) -> Result<JsValue, JsValue> {
    let cfg = if input.starts_with("otpauth://") {
        ragewarden_core::totp::TotpConfig::from_otpauth_uri(input)
    } else {
        ragewarden_core::totp::TotpConfig::from_base32_secret(input)
    }
    .map_err(|e| js_err(format!("totp: {e}")))?;
    let now_ms = js_sys::Date::now();
    if !now_ms.is_finite() || now_ms < 0.0 {
        return Err(js_err("totp: Date.now() returned non-finite value"));
    }
    let unix_ts = (now_ms / 1000.0) as u64;
    let code = ragewarden_core::totp::generate_at(&cfg, unix_ts)
        .map_err(|e| js_err(format!("totp: {e}")))?;
    js_object(&[
        ("code", JsValue::from_str(&code.code)),
        (
            "seconds_remaining",
            JsValue::from_f64(code.seconds_remaining as f64),
        ),
        ("period", JsValue::from_f64(code.period as f64)),
    ])
}
