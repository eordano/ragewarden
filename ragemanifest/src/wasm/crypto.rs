use super::js_err;

use ragewarden_core::{
    decrypt as core_decrypt, encrypt as core_encrypt, software_passphrase_identity,
    stanza_format::{decrypt_webauthn_prf_with_prf, webauthn_prf_credential_id, TAG_WEBAUTHN_PRF_V1},
    AgeBlob, FileKey, Identity, IdentityError, Recipient, Stanza,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, JsFuture};

#[wasm_bindgen(js_name = wasm_software_keygen)]
pub fn wasm_software_keygen() -> Result<JsValue, JsValue> {
    use secrecy::ExposeSecret;
    let identity = age::x25519::Identity::generate();
    let secret_armored: String = identity.to_string().expose_secret().to_owned();
    let public_armored = identity.to_public().to_string();
    let public_key = decode_age_pubkey_bech32(&public_armored)
        .map_err(|e| js_err(format!("decode pubkey: {e}")))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("secret"),
        &js_sys::Uint8Array::from(secret_armored.as_bytes()).into(),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("public_key"),
        &js_sys::Uint8Array::from(&public_key[..]).into(),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("armored_pubkey"),
        &JsValue::from_str(&public_armored),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("armored_secret"),
        &JsValue::from_str(&secret_armored),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    Ok(obj.into())
}

#[wasm_bindgen(js_name = wasm_generate_recovery_phrase)]
pub fn wasm_generate_recovery_phrase() -> Result<JsValue, JsValue> {
    use secrecy::ExposeSecret;
    let gen = ragewarden_core::recovery::generate()
        .map_err(|e| js_err(format!("recovery::generate: {e}")))?;
    let phrase = gen.mnemonic.to_string();
    let armored_pubkey: String = gen.armored_pubkey.into_inner();
    let armored_secret: String = gen.armored_secret.expose_secret().to_string();
    let public_key = decode_age_pubkey_bech32(&armored_pubkey)
        .map_err(|e| js_err(format!("decode pubkey: {e}")))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from_str("phrase"), &JsValue::from_str(&phrase))
        .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("armored_pubkey"),
        &JsValue::from_str(&armored_pubkey),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("armored_secret"),
        &JsValue::from_str(&armored_secret),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("public_key"),
        &js_sys::Uint8Array::from(&public_key[..]).into(),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("secret"),
        &js_sys::Uint8Array::from(armored_secret.as_bytes()).into(),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    Ok(obj.into())
}

#[wasm_bindgen(js_name = wasm_recovery_identity_from_phrase)]
pub fn wasm_recovery_identity_from_phrase(phrase: &str) -> Result<JsValue, JsValue> {
    use secrecy::ExposeSecret;
    let identity = ragewarden_core::recovery::from_phrase(phrase)
        .map_err(|e| js_err(format!("recovery from phrase: {e}")))?;
    let secret_armored: String = identity.to_string().expose_secret().to_owned();
    let public_armored = identity.to_public().to_string();
    let public_key = decode_age_pubkey_bech32(&public_armored)
        .map_err(|e| js_err(format!("decode pubkey: {e}")))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("secret"),
        &js_sys::Uint8Array::from(secret_armored.as_bytes()).into(),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("public_key"),
        &js_sys::Uint8Array::from(&public_key[..]).into(),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("armored_pubkey"),
        &JsValue::from_str(&public_armored),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("armored_secret"),
        &JsValue::from_str(&secret_armored),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    Ok(obj.into())
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

#[wasm_bindgen(js_name = wasm_decrypt_with_passkey)]
pub fn wasm_decrypt_with_passkey(
    blob: js_sys::Uint8Array,
    credential_id: js_sys::Uint8Array,
    salt: js_sys::Uint8Array,
    prf_callback: js_sys::Function,
) -> js_sys::Promise {
    let blob_bytes = blob.to_vec();
    let credential_id_bytes = credential_id.to_vec();
    let salt_vec = salt.to_vec();

    future_to_promise(async move {
        if salt_vec.len() != 32 {
            return Err(js_err(format!(
                "salt must be 32 bytes, got {}",
                salt_vec.len()
            )));
        }
        let mut salt_arr = [0u8; 32];
        salt_arr.copy_from_slice(&salt_vec);

        let salt_js = js_sys::Uint8Array::from(&salt_arr[..]);
        let this = JsValue::NULL;
        let cb_result = prf_callback
            .call1(&this, &salt_js)
            .map_err(|e| js_err(format!("prf callback threw: {e:?}")))?;
        let prf_value = JsFuture::from(js_sys::Promise::resolve(&cb_result))
            .await
            .map_err(|e| js_err(format!("prf callback rejected: {e:?}")))?;
        let prf_array = js_sys::Uint8Array::new(&prf_value);
        if prf_array.length() != 32 {
            return Err(js_err(format!(
                "prf callback must return 32 bytes, got {}",
                prf_array.length()
            )));
        }
        let mut prf_output = [0u8; 32];
        prf_array.copy_to(&mut prf_output);

        let identity = PasskeyPrfIdentity {
            credential_id: credential_id_bytes,
            prf_output,
        };
        let identities: Vec<Box<dyn Identity>> = vec![Box::new(identity)];
        let blob = AgeBlob::from_bytes(blob_bytes);
        let plaintext = core_decrypt(&blob, &identities).map_err(js_err)?;
        Ok(js_sys::Uint8Array::from(plaintext.as_slice()).into())
    })
}

struct PasskeyPrfIdentity {
    credential_id: Vec<u8>,
    prf_output: [u8; 32],
}

impl Identity for PasskeyPrfIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if stanza.tag != TAG_WEBAUTHN_PRF_V1 {
            return Ok(None);
        }
        let stanza_cred = match webauthn_prf_credential_id(stanza) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };
        if stanza_cred != self.credential_id {
            return Ok(None);
        }
        let key = decrypt_webauthn_prf_with_prf(stanza, &self.prf_output)
            .map_err(|e| IdentityError::Crypto(format!("webauthn-prf-v1: {e}")))?;
        Ok(Some(key))
    }

    fn display(&self) -> &str {
        "passkey-prf"
    }
}

fn decode_age_pubkey_bech32(s: &str) -> Result<[u8; 32], String> {
    ragewarden_core::bech32::decode_age_x25519(s)
        .ok_or_else(|| format!("malformed age recipient: {s}"))
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
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("code"),
        &JsValue::from_str(&code.code),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("seconds_remaining"),
        &JsValue::from_f64(code.seconds_remaining as f64),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("period"),
        &JsValue::from_f64(code.period as f64),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    Ok(obj.into())
}
