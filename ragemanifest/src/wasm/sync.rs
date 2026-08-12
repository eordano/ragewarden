use super::http::JsHttpClient;
use super::session::{jsvalue_to_session, session_to_jsvalue};
use super::{js_err, js_err_with_code};

use crate::reveal::decrypt_non_rage_field;
use crate::snapshot::{
    assess_rage_header, build_snapshot_with_identities, is_internal_cipher_name, DisplayCipher,
    LocalIdentityInventory, VaultSnapshot,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ragewarden_core::policy as core_policy;
use ragewarden_core::registry::{
    self as core_registry, kinds as registry_kinds, WireDocument as RegistryDocument,
    WireEntry as RegistryEntry, MARKER_NAME as REGISTRY_MARKER_NAME,
};
use ragewarden_core::sync::{
    self, build_meta_cipher, build_rage_cipher, cipher_name,
    create_cipher as core_create_cipher, decrypt_string, extract_rage_blob, fetch_vault,
    login_with_device, refresh_session, register, update_cipher as core_update_cipher, Cipher,
    CipherIn, CipherLogin, Server, Session, SyncError,
};
use ragewarden_core::{
    decrypt as core_decrypt, encrypt as core_encrypt,
    stanza_format::{
        decrypt_webauthn_prf_with_prf, webauthn_prf_credential_id, TAG_FIDO2_HMAC, TAG_PIV_P256,
        TAG_WEBAUTHN_PRF_V1,
    },
    AgeBlob, FileKey, Identity, IdentityError, Recipient, Stanza,
};
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen(js_name = wasm_register)]
pub async fn wasm_register(
    server_url: String,
    email: String,
    name: String,
    master_password: String,
    kdf_iterations: u32,
) -> Result<JsValue, JsValue> {
    let server = Server::self_hosted(&server_url);
    server
        .require_secure()
        .map_err(|e| js_err(format!("insecure server: {e}")))?;

    let client = JsHttpClient::new();
    let out = register(
        &client,
        &server,
        &email,
        &master_password,
        &name,
        kdf_iterations,
    )
    .await
    .map_err(|e| js_err(format!("register: {e}")))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("email"),
        &JsValue::from_str(&out.email),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("kdf_iterations"),
        &JsValue::from_f64(out.kdf_iterations as f64),
    )
    .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    Ok(obj.into())
}

#[wasm_bindgen(js_name = wasm_login)]
pub async fn wasm_login(
    server_url: String,
    email: String,
    master_password: String,
    device_name: String,
    device_id: String,
) -> Result<JsValue, JsValue> {
    let server = Server::self_hosted(&server_url);
    server
        .require_secure()
        .map_err(|e| js_err(format!("insecure server: {e}")))?;

    let client = JsHttpClient::new();
    let session = login_with_device(
        &client,
        &server,
        &email,
        &master_password,
        &device_name,
        &device_id,
    )
    .await
    .map_err(|e| js_err(format!("login: {e}")))?;

    session_to_jsvalue(&server, &session)
}

/*
 * Legacy entry point: no identity inventory, so every rage item is reported
 * `decryptable: false` (fail closed). UI code that gates on decryptability
 * must call wasm_fetch_vault_with_identities instead.
 */
#[wasm_bindgen(js_name = wasm_fetch_vault)]
pub async fn wasm_fetch_vault(session_value: JsValue) -> Result<JsValue, JsValue> {
    fetch_vault_snapshot(session_value, LocalIdentityInventory::default()).await
}

/*
 * Snapshot with per-item decryptability. `local_identities_value` is a plain
 * object naming what THIS profile holds:
 *
 *   {
 *     software_armored_pubkeys:   ["age1..."],       // software identity present
 *     passkey_credential_ids_b64: ["<b64>", ...],    // webauthn-prf-v1
 *     fido2_credential_ids_b64:   ["<b64>", ...],    // fido2-hmac via native host
 *     piv_pubkeys_hex:            ["<64 hex>", ...], // piv-p256 via native host
 *     keystore_handles:           ["...", ...],      // ragedroid-keystore-v1
 *   }
 *
 * Every field is optional; null/undefined means "nothing available here".
 * The check is header-stanza matching only -- nothing is decrypted and no
 * hardware is tapped.
 */
#[wasm_bindgen(js_name = wasm_fetch_vault_with_identities)]
pub async fn wasm_fetch_vault_with_identities(
    session_value: JsValue,
    local_identities_value: JsValue,
) -> Result<JsValue, JsValue> {
    let inventory = parse_local_identities(&local_identities_value)?;
    fetch_vault_snapshot(session_value, inventory).await
}

async fn fetch_vault_snapshot(
    session_value: JsValue,
    inventory: LocalIdentityInventory,
) -> Result<JsValue, JsValue> {
    let (server, mut session) = jsvalue_to_session(&session_value)?;
    let client = JsHttpClient::new();

    // Access tokens expire while a persisted session lives on. On a 401,
    // refresh once with the stored refresh token and retry rather than making
    // the user re-enter their master password. If the refresh itself fails
    // (refresh token also expired/revoked), surface the original error so the
    // UI falls back to a full login.
    let mut refreshed = false;
    let vault = match fetch_vault(&client, &server, &session).await {
        Ok(v) => v,
        Err(SyncError::Server { status: 401, .. }) => {
            refresh_session(&client, &server, &mut session)
                .await
                .map_err(|e| js_err(format!("session expired, refresh failed: {e}")))?;
            refreshed = true;
            fetch_vault(&client, &server, &session)
                .await
                .map_err(|e| js_err(format!("fetch_vault after refresh: {e}")))?
        }
        Err(e) => return Err(js_err(format!("fetch_vault: {e}"))),
    };

    let snap = build_snapshot_with_identities(&session, &vault, &inventory);
    let value = snapshot_to_jsvalue(&snap)?;
    // If we minted a new access token, hand the updated session back so the
    // caller can persist it; otherwise the next fetch would 401 again.
    if refreshed {
        if let Ok(sess_value) = session_to_jsvalue(&server, &session) {
            let _ = js_sys::Reflect::set(
                &value,
                &JsValue::from_str("refreshed_session"),
                &sess_value,
            );
        }
    }
    Ok(value)
}

fn parse_local_identities(value: &JsValue) -> Result<LocalIdentityInventory, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(LocalIdentityInventory::default());
    }
    let s: String = js_sys::JSON::stringify(value)
        .map_err(|e| js_err(format!("stringify local identities: {e:?}")))?
        .into();
    serde_json::from_str(&s).map_err(|e| js_err(format!("parse local identities: {e}")))
}

#[wasm_bindgen(js_name = wasm_decrypt_cipher_field)]
pub async fn wasm_decrypt_cipher_field(
    session_value: JsValue,
    cipher_value: JsValue,
    field_name: String,
    prf_callback: Option<js_sys::Function>,
) -> Result<Vec<u8>, JsValue> {
    wasm_decrypt_cipher_field_with_secrets(
        session_value,
        cipher_value,
        field_name,
        prf_callback,
        JsValue::UNDEFINED,
    )
    .await
}

#[wasm_bindgen(js_name = wasm_decrypt_cipher_field_with_secrets)]
pub async fn wasm_decrypt_cipher_field_with_secrets(
    session_value: JsValue,
    cipher_value: JsValue,
    field_name: String,
    prf_callback: Option<js_sys::Function>,
    armored_secrets: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let (_server, session) = jsvalue_to_session(&session_value)?;
    let cipher = jsvalue_to_cipher(&cipher_value)?;

    let secrets: Vec<String> = if armored_secrets.is_undefined() || armored_secrets.is_null() {
        Vec::new()
    } else {
        let arr = js_sys::Array::from(&armored_secrets);
        arr.iter()
            .filter_map(|v| v.as_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    if let Some(blob) = extract_rage_blob(&session, &cipher)
        .map_err(|e| js_err(format!("extract rage blob: {e}")))?
    {
        let plaintext =
            decrypt_rage_blob(blob.into_bytes(), prf_callback.as_ref(), &secrets).await?;
        let _ = field_name;
        return Ok(plaintext);
    }

    let bytes = decrypt_non_rage_field(&session, &cipher, &field_name)
        .map_err(|e| js_err_with_code(e.code(), format!("decrypt: {e}")))?;
    Ok(bytes)
}

/*
 * The file-key seam: decrypt a rage-protected field with a file key the caller
 * obtained from somewhere this side cannot reach -- today, `rageterm` over native
 * messaging, which owns the PIV / FIDO2 devices the browser cannot talk to.
 *
 * `native_callback(stanzas)` is handed only the stanzas this side cannot open
 * itself, each as `{ index, tag, args, body }` with `body` base64 -- the exact
 * shape `rageterm`'s `WireStanza` deserialises, so a caller can forward one
 * straight down the `native.unwrap` path in ext/background.js without reshaping
 * it. It must resolve to `{ fileKeyB64, receipt }`, and may additionally name
 * which stanza it opened as `stanzaIndex` and/or `stanza`.
 *
 * Two refusals live here, and neither of them is the ceremony check:
 *
 *   - the returned key must actually open this blob. A key that does not is a
 *     plain error (age verifies the header MAC before any payload key is
 *     derived), never a panic and never an empty plaintext.
 *   - a `stanzaIndex` / `stanza` naming something outside the set handed to the
 *     callback is refused, and the identity built from the key answers *only*
 *     the stanzas that were handed out. This mirrors invoke_prf_callback_multi,
 *     which refuses a credentialId outside the pairs it supplied.
 *
 * The `receipt` is opaque here. Rust does not and cannot judge whether a
 * physical touch happened -- glue/hardware-tap.js decides that, and it must be
 * the last thing to read the receipt. So this function releasing a plaintext is
 * NOT an assertion that a device was tapped; it asserts only that the key it was
 * handed opens the item.
 *
 * Returns the plaintext as a `Uint8Array`, the same shape
 * wasm_decrypt_cipher_field returns, so a caller can decode and zero it exactly
 * as before. The receipt it handed back is re-attached untouched as a `receipt`
 * property on that array rather than being swallowed here: whatever gates on it
 * should be able to reach it from the value this call produced, not only from
 * the closure that minted it.
 */
#[wasm_bindgen(js_name = wasm_decrypt_cipher_field_with_native)]
pub async fn wasm_decrypt_cipher_field_with_native(
    session_value: JsValue,
    cipher_value: JsValue,
    field_name: String,
    native_callback: js_sys::Function,
) -> Result<JsValue, JsValue> {
    let (_server, session) = jsvalue_to_session(&session_value)?;
    let cipher = jsvalue_to_cipher(&cipher_value)?;
    let _ = field_name;

    let blob = extract_rage_blob(&session, &cipher)
        .map_err(|e| js_err(format!("extract rage blob: {e}")))?
        .ok_or_else(|| {
            js_err(
                "this item is not rage-protected, so it holds no stanza a native host could \
                 unwrap. Refusing: a caller that reached for the hardware path must not be \
                 handed a plaintext that never needed one. Use wasm_decrypt_cipher_field.",
            )
        })?;
    let blob = AgeBlob::from_bytes(blob.into_bytes());

    let offered = native_unwrappable_stanzas(blob.as_bytes())?;
    if offered.is_empty() {
        return Err(js_err(format!(
            "this item carries no stanza a native host can unwrap (looked for `{TAG_PIV_P256}` \
             and `{TAG_FIDO2_HMAC}`). Refusing to ask for a touch that could not open it.",
        )));
    }

    let answer = invoke_native_callback(&native_callback, &offered).await?;

    let identities: Vec<Box<dyn Identity>> = vec![Box::new(SuppliedFileKeyIdentity {
        offered,
        file_key: answer.file_key,
    })];
    let plaintext = core_decrypt(&blob, &identities).map_err(|e| {
        js_err_with_code(
            e.code(),
            format!(
                "the file key returned by the native callback does not open this item ({e}). \
                 Refusing to return a plaintext that key did not produce.",
            ),
        )
    })?;

    let out = js_sys::Uint8Array::from(&plaintext[..]);
    js_sys::Reflect::set(&out, &JsValue::from_str("receipt"), &answer.receipt)
        .map_err(|e| js_err(format!("reflect receipt: {e:?}")))?;
    Ok(out.into())
}

#[wasm_bindgen(js_name = wasm_create_cipher)]
pub async fn wasm_create_cipher(
    session_value: JsValue,
    plaintext_field_map: JsValue,
    recipients_value: JsValue,
) -> Result<JsValue, JsValue> {
    create_cipher_inner(session_value, plaintext_field_map, recipients_value, JsValue::NULL).await
}

#[wasm_bindgen(js_name = wasm_create_cipher_with_prf)]
pub async fn wasm_create_cipher_with_prf(
    session_value: JsValue,
    plaintext_field_map: JsValue,
    recipients_value: JsValue,
    prf_table_value: JsValue,
) -> Result<JsValue, JsValue> {
    create_cipher_inner(session_value, plaintext_field_map, recipients_value, prf_table_value).await
}

async fn create_cipher_inner(
    session_value: JsValue,
    plaintext_field_map: JsValue,
    recipients_value: JsValue,
    prf_table_value: JsValue,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let fields = parse_field_map(&plaintext_field_map)?;
    let recipients = parse_recipients(&recipients_value)?;
    let prf_entries = parse_prf_table(&prf_table_value)?;

    let primary_name = fields
        .iter()
        .find(|(k, _)| k == "name")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "Untitled".to_string());

    let secret_value = fields
        .iter()
        .find(|(k, _)| k == "rage")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| js_err("plaintext_field_map.rage is required"))?;

    let blob = if prf_entries.is_empty() {
        core_encrypt(secret_value.as_bytes(), &recipients)
            .map_err(|e| js_err(format!("encrypt: {e}")))?
    } else {
        let table: Vec<ragewarden_core::PrfEntry<'_>> = prf_entries
            .iter()
            .map(|e| ragewarden_core::PrfEntry {
                rp_id: &e.rp_id,
                salt: &e.salt,
                prf_output: &e.prf_output,
            })
            .collect();
        ragewarden_core::encrypt_with_prf(secret_value.as_bytes(), &recipients, &table)
            .map_err(|e| js_err(format!("encrypt: {e}")))?
    };
    let armored = String::from_utf8(blob.0).map_err(|e| js_err(format!("blob not utf-8: {e}")))?;

    let mut cipher_in = build_rage_cipher(&session, &primary_name, &armored)
        .map_err(|e| js_err(format!("build_rage_cipher: {e}")))?;
    augment_with_login(&mut cipher_in, &fields, &session)?;

    let client = JsHttpClient::new();
    let saved = core_create_cipher(&client, &server, &session, &cipher_in)
        .await
        .map_err(|e| js_err(format!("create_cipher: {e}")))?;

    cipher_to_jsvalue(&session, &saved)
}

#[wasm_bindgen(js_name = wasm_update_cipher)]
pub async fn wasm_update_cipher(
    session_value: JsValue,
    cipher_id: String,
    plaintext_field_map: JsValue,
    recipients_value: JsValue,
) -> Result<JsValue, JsValue> {
    update_cipher_inner(
        session_value,
        cipher_id,
        plaintext_field_map,
        recipients_value,
        JsValue::NULL,
    )
    .await
}

#[wasm_bindgen(js_name = wasm_update_cipher_with_prf)]
pub async fn wasm_update_cipher_with_prf(
    session_value: JsValue,
    cipher_id: String,
    plaintext_field_map: JsValue,
    recipients_value: JsValue,
    prf_table_value: JsValue,
) -> Result<JsValue, JsValue> {
    update_cipher_inner(
        session_value,
        cipher_id,
        plaintext_field_map,
        recipients_value,
        prf_table_value,
    )
    .await
}

async fn update_cipher_inner(
    session_value: JsValue,
    cipher_id: String,
    plaintext_field_map: JsValue,
    recipients_value: JsValue,
    prf_table_value: JsValue,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    if cipher_id.is_empty() {
        return Err(js_err("cipher_id required"));
    }
    let fields = parse_field_map(&plaintext_field_map)?;
    let recipients = parse_recipients(&recipients_value)?;
    let prf_entries = parse_prf_table(&prf_table_value)?;

    let primary_name = fields
        .iter()
        .find(|(k, _)| k == "name")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "Untitled".to_string());

    let secret_value = fields
        .iter()
        .find(|(k, _)| k == "rage")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| js_err("plaintext_field_map.rage is required"))?;

    let blob = if prf_entries.is_empty() {
        core_encrypt(secret_value.as_bytes(), &recipients)
            .map_err(|e| js_err(format!("encrypt: {e}")))?
    } else {
        let table: Vec<ragewarden_core::PrfEntry<'_>> = prf_entries
            .iter()
            .map(|e| ragewarden_core::PrfEntry {
                rp_id: &e.rp_id,
                salt: &e.salt,
                prf_output: &e.prf_output,
            })
            .collect();
        ragewarden_core::encrypt_with_prf(secret_value.as_bytes(), &recipients, &table)
            .map_err(|e| js_err(format!("encrypt: {e}")))?
    };
    let armored = String::from_utf8(blob.0).map_err(|e| js_err(format!("blob not utf-8: {e}")))?;

    let mut cipher_in = build_rage_cipher(&session, &primary_name, &armored)
        .map_err(|e| js_err(format!("build_rage_cipher: {e}")))?;
    augment_with_login(&mut cipher_in, &fields, &session)?;

    let client = JsHttpClient::new();
    let saved = sync::update_cipher(&client, &server, &session, &cipher_id, &cipher_in)
        .await
        .map_err(|e| js_err(format!("update_cipher: {e}")))?;

    cipher_to_jsvalue(&session, &saved)
}

#[wasm_bindgen(js_name = wasm_delete_cipher)]
pub async fn wasm_delete_cipher(
    session_value: JsValue,
    cipher_id: String,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    if cipher_id.is_empty() {
        return Err(js_err("cipher_id required"));
    }
    let client = JsHttpClient::new();
    sync::delete_cipher(&client, &server, &session, &cipher_id)
        .await
        .map_err(|e| js_err(format!("delete_cipher: {e}")))?;
    Ok(JsValue::from_str(&cipher_id))
}

#[wasm_bindgen(js_name = wasm_create_folder)]
pub async fn wasm_create_folder(
    session_value: JsValue,
    name: String,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let client = JsHttpClient::new();
    let f = sync::create_folder(&client, &server, &session, &name)
        .await
        .map_err(|e| js_err(format!("create_folder: {e}")))?;
    let s = serde_json::to_string(&f).map_err(|e| js_err(format!("serialize folder: {e}")))?;
    js_sys::JSON::parse(&s).map_err(|e| js_err(format!("re-parse folder: {e:?}")))
}

#[wasm_bindgen(js_name = wasm_update_folder)]
pub async fn wasm_update_folder(
    session_value: JsValue,
    folder_id: String,
    name: String,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let client = JsHttpClient::new();
    let f = sync::update_folder(&client, &server, &session, &folder_id, &name)
        .await
        .map_err(|e| js_err(format!("update_folder: {e}")))?;
    let s = serde_json::to_string(&f).map_err(|e| js_err(format!("serialize folder: {e}")))?;
    js_sys::JSON::parse(&s).map_err(|e| js_err(format!("re-parse folder: {e:?}")))
}

#[wasm_bindgen(js_name = wasm_delete_folder)]
pub async fn wasm_delete_folder(
    session_value: JsValue,
    folder_id: String,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let client = JsHttpClient::new();
    sync::delete_folder(&client, &server, &session, &folder_id)
        .await
        .map_err(|e| js_err(format!("delete_folder: {e}")))?;
    Ok(JsValue::from_str(&folder_id))
}

struct OwnedPrfEntry {
    rp_id: String,
    salt: [u8; 32],
    prf_output: [u8; 32],
}

fn parse_prf_table(value: &JsValue) -> Result<Vec<OwnedPrfEntry>, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(Vec::new());
    }
    let s: String = js_sys::JSON::stringify(value)
        .map_err(|e| js_err(format!("stringify prf table: {e:?}")))?
        .into();
    #[derive(Deserialize)]
    struct WireEntry {
        rp_id: String,
        salt_b64: String,
        prf_output_b64: String,
    }
    let wire: Vec<WireEntry> =
        serde_json::from_str(&s).map_err(|e| js_err(format!("parse prf table: {e}")))?;
    let mut out = Vec::with_capacity(wire.len());
    for w in wire {
        let salt_v = B64
            .decode(w.salt_b64.as_bytes())
            .map_err(|e| js_err(format!("salt_b64: {e}")))?;
        if salt_v.len() != 32 {
            return Err(js_err(format!("salt_b64 must be 32 bytes, got {}", salt_v.len())));
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_v);

        let prf_v = B64
            .decode(w.prf_output_b64.as_bytes())
            .map_err(|e| js_err(format!("prf_output_b64: {e}")))?;
        if prf_v.len() != 32 {
            return Err(js_err(format!(
                "prf_output_b64 must be 32 bytes, got {}",
                prf_v.len()
            )));
        }
        let mut prf_output = [0u8; 32];
        prf_output.copy_from_slice(&prf_v);

        out.push(OwnedPrfEntry {
            rp_id: w.rp_id,
            salt,
            prf_output,
        });
    }
    Ok(out)
}

fn snapshot_to_jsvalue(s: &VaultSnapshot) -> Result<JsValue, JsValue> {
    let s = serde_json::to_string(s).map_err(|e| js_err(format!("serialize snapshot: {e}")))?;
    js_sys::JSON::parse(&s).map_err(|e| js_err(format!("JSON.parse: {e:?}")))
}

fn jsvalue_to_cipher(v: &JsValue) -> Result<Cipher, JsValue> {
    let s: String = js_sys::JSON::stringify(v)
        .map_err(|e| js_err(format!("JSON.stringify cipher: {e:?}")))?
        .into();
    let display: DisplayCipher =
        serde_json::from_str(&s).map_err(|e| js_err(format!("parse cipher: {e}")))?;
    Ok(display.raw)
}

fn cipher_to_jsvalue(session: &Session, cipher: &Cipher) -> Result<JsValue, JsValue> {
    let id = cipher.id.clone().unwrap_or_default();
    let name = cipher_name(session, cipher).unwrap_or_else(|_| "(undecryptable)".into());
    let rage_blob = extract_rage_blob(session, cipher).ok().flatten();
    let rage = rage_blob.is_some();
    /*
     * This is a save echo, not a snapshot: no identity inventory is in scope
     * here, so decryptability is assessed against an empty one (fail closed;
     * always false for rage items). recipient_count and internal are real.
     * The authoritative flags come from wasm_fetch_vault_with_identities.
     */
    let (decryptable, recipient_count) = match &rage_blob {
        Some(armored) => {
            let a = assess_rage_header(armored, &LocalIdentityInventory::default());
            (a.decryptable, a.recipient_count)
        }
        None => (true, 0),
    };
    let kind = match cipher.cipher_type {
        1 => "login",
        2 => "note",
        3 => "card",
        4 => "identity",
        _ => "other",
    };
    let internal = is_internal_cipher_name(&name);
    let display = DisplayCipher {
        id,
        name,
        username: None,
        site: None,
        kind: kind.into(),
        rage,
        decryptable,
        recipient_count,
        internal,
        favorite: cipher.favorite,
        folder_id: cipher.folder_id.clone(),
        raw: cipher.clone(),
    };
    let s = serde_json::to_string(&display).map_err(|e| js_err(format!("serialize: {e}")))?;
    js_sys::JSON::parse(&s).map_err(|e| js_err(format!("JSON.parse: {e:?}")))
}

async fn decrypt_rage_blob(
    blob: Vec<u8>,
    prf_callback: Option<&js_sys::Function>,
    armored_secrets: &[String],
) -> Result<Vec<u8>, JsValue> {
    let blob = AgeBlob::from_bytes(blob);

    let prf_pairs = collect_webauthn_prf_pairs(blob.as_bytes())?;

    let mut identities: Vec<Box<dyn Identity>> = Vec::new();
    if !prf_pairs.is_empty() {
        match prf_callback {
            Some(callback) => {
                let chosen = invoke_prf_callback_multi(callback, &prf_pairs).await?;
                identities.push(Box::new(SpecificPasskeyPrfIdentity {
                    credential_id: chosen.credential_id,
                    prf_output: chosen.prf_output,
                }));
            }
            None if armored_secrets.is_empty() => {
                return Err(js_err_with_code(
                    "tap_unavailable",
                    "this item is protected by a hardware passkey (webauthn-prf-v1) but the \
                     caller supplied no PRF callback, so no tap can be performed in this \
                     context. Refusing to decrypt.",
                ));
            }
            None => {}
        }
    }

    for armored in armored_secrets {
        let trusted = ragewarden_core::ArmoredAgeSecret::from_trusted(armored.clone());
        match ragewarden_core::software_passphrase_identity(&trusted) {
            Ok(id) => identities.push(Box::new(id)),
            Err(e) => return Err(js_err(format!("software identity: {e}"))),
        }
    }

    if identities.is_empty() {
        return Err(js_err_with_code(
            "no_identity_available",
            "no identity available for this item: no hardware tap was performed and no \
             software or recovery secret was supplied. Ragewarden does not release a secret \
             without a deliberate physical action.",
        ));
    }

    /*
     * NoMatchingIdentity is the "wrapped to N recipients, none on this
     * device" case. The snapshot's `decryptable: false` should keep the UI
     * from ever reaching this point; when it is reached anyway (stale
     * snapshot, X25519 stanza wrapped to some other software key), the code
     * lets JS render its own explanation instead of the raw core message.
     */
    let plaintext = core_decrypt(&blob, &identities).map_err(|e| match e {
        ragewarden_core::DecryptError::NoMatchingIdentity => js_err_with_code(
            e.code(),
            "none of this device's identities can open this item; it is wrapped only to \
             keys held elsewhere. Open it on a device that holds one of its keys, or \
             re-wrap it from there.",
        ),
        other => js_err_with_code(other.code(), format!("rage decrypt: {other}")),
    })?;
    Ok(plaintext.to_vec())
}

struct ChosenPrf {
    credential_id: Vec<u8>,
    prf_output: [u8; 32],
}

async fn invoke_prf_callback_multi(
    callback: &js_sys::Function,
    pairs: &[(Vec<u8>, [u8; 32])],
) -> Result<ChosenPrf, JsValue> {
    let arr = js_sys::Array::new();
    for (cred, salt) in pairs {
        let entry = js_sys::Object::new();
        js_sys::Reflect::set(
            &entry,
            &JsValue::from_str("credentialId"),
            &js_sys::Uint8Array::from(cred.as_slice()).into(),
        )
        .map_err(|e| js_err(format!("reflect credentialId: {e:?}")))?;
        js_sys::Reflect::set(
            &entry,
            &JsValue::from_str("salt"),
            &js_sys::Uint8Array::from(&salt[..]).into(),
        )
        .map_err(|e| js_err(format!("reflect salt: {e:?}")))?;
        arr.push(&entry);
    }
    let this = JsValue::NULL;
    let cb_result = callback
        .call1(&this, &arr)
        .map_err(|e| js_err(format!("prf callback threw: {e:?}")))?;
    let resolved = JsFuture::from(js_sys::Promise::resolve(&cb_result))
        .await
        .map_err(|e| js_err(format!("prf callback rejected: {e:?}")))?;

    let cred_val = js_sys::Reflect::get(&resolved, &JsValue::from_str("credentialId"))
        .map_err(|e| js_err(format!("reflect credentialId out: {e:?}")))?;
    let prf_val = js_sys::Reflect::get(&resolved, &JsValue::from_str("prfOutput"))
        .map_err(|e| js_err(format!("reflect prfOutput out: {e:?}")))?;
    if cred_val.is_undefined() || prf_val.is_undefined() {
        return Err(js_err(
            "prf callback must return { credentialId, prfOutput }",
        ));
    }
    let credential_id = js_sys::Uint8Array::new(&cred_val).to_vec();
    let prf_array = js_sys::Uint8Array::new(&prf_val);
    if prf_array.length() != 32 {
        return Err(js_err(format!(
            "prfOutput must be 32 bytes, got {}",
            prf_array.length()
        )));
    }
    let mut prf_output = [0u8; 32];
    prf_array.copy_to(&mut prf_output);
    if !pairs.iter().any(|(c, _)| c == &credential_id) {
        return Err(js_err(
            "prf callback returned credentialId not in the supplied set",
        ));
    }
    Ok(ChosenPrf {
        credential_id,
        prf_output,
    })
}

struct SpecificPasskeyPrfIdentity {
    credential_id: Vec<u8>,
    prf_output: [u8; 32],
}

impl Identity for SpecificPasskeyPrfIdentity {
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
        match decrypt_webauthn_prf_with_prf(stanza, &self.prf_output) {
            Ok(key) => Ok(Some(key)),
            Err(e) => Err(IdentityError::Crypto(format!("webauthn-prf-v1: {e}"))),
        }
    }

    fn display(&self) -> &str {
        "passkey-prf"
    }
}

/*
 * The stanza set this side cannot open on its own.
 *
 * Deliberately an allow-list of the two device-backed tags rageterm will serve
 * without RAGEWARDEN_NATIVE_HOST_ALLOW_SOFTWARE=1 (it mirrors `tag_is_hardware_gated`
 * minus `webauthn-prf-v1`, which the browser opens itself with a real assertion).
 * A deny-list would quietly ship every future tag -- including software ones --
 * off to a host process; a new hardware tag not being offered here is a missing
 * feature, which is the direction this should fail in.
 */
fn native_unwrappable_stanzas(blob: &[u8]) -> Result<Vec<Stanza>, JsValue> {
    let recorded = collect_stanzas(blob)?;
    Ok(recorded
        .into_iter()
        .filter(|s| s.tag == TAG_PIV_P256 || s.tag == TAG_FIDO2_HMAC)
        .collect())
}

struct NativeAnswer {
    file_key: FileKey,
    receipt: JsValue,
}

async fn invoke_native_callback(
    callback: &js_sys::Function,
    offered: &[Stanza],
) -> Result<NativeAnswer, JsValue> {
    let arr = js_sys::Array::new();
    for (i, stanza) in offered.iter().enumerate() {
        let entry = js_sys::Object::new();
        set_str(&entry, "tag", &stanza.tag)?;
        set_str(&entry, "body", &B64.encode(&stanza.body))?;
        let args = js_sys::Array::new();
        for a in &stanza.args {
            args.push(&JsValue::from_str(a));
        }
        js_sys::Reflect::set(&entry, &JsValue::from_str("args"), &args.into())
            .map_err(|e| js_err(format!("reflect args: {e:?}")))?;
        js_sys::Reflect::set(
            &entry,
            &JsValue::from_str("index"),
            &JsValue::from_f64(i as f64),
        )
        .map_err(|e| js_err(format!("reflect index: {e:?}")))?;
        arr.push(&entry);
    }

    let this = JsValue::NULL;
    let cb_result = callback
        .call1(&this, &arr)
        .map_err(|e| js_err(format!("native callback threw: {e:?}")))?;
    let resolved = JsFuture::from(js_sys::Promise::resolve(&cb_result))
        .await
        .map_err(|e| js_err(format!("native callback rejected: {e:?}")))?;
    if !resolved.is_object() {
        return Err(js_err(
            "native callback must resolve to an object { fileKeyB64, receipt }",
        ));
    }

    let key_val = js_sys::Reflect::get(&resolved, &JsValue::from_str("fileKeyB64"))
        .map_err(|e| js_err(format!("reflect fileKeyB64: {e:?}")))?;
    let receipt = js_sys::Reflect::get(&resolved, &JsValue::from_str("receipt"))
        .map_err(|e| js_err(format!("reflect receipt: {e:?}")))?;
    let key_b64 = key_val.as_string().ok_or_else(|| {
        js_err("native callback must return { fileKeyB64, receipt }: fileKeyB64 is not a string")
    })?;
    /*
     * Rust cannot read the receipt, but it can insist one exists: a callback
     * that returns key material with nothing attached leaves the JS gate with
     * nothing to refuse, and "no receipt" would silently become "no ceremony".
     */
    if receipt.is_undefined() || receipt.is_null() {
        return Err(js_err(
            "native callback returned a file key with no receipt. The receipt is not read \
             here -- it is what the caller's own tap gate reads -- but a key handed over with \
             no evidence at all attached cannot be gated on anything, so it is refused.",
        ));
    }

    check_stanza_reference(&resolved, offered)?;

    let raw = zeroize::Zeroizing::new(
        B64.decode(key_b64.trim())
            .map_err(|e| js_err(format!("fileKeyB64 is not valid base64: {e}")))?,
    );
    let file_key: [u8; 16] = raw.as_slice().try_into().map_err(|_| {
        js_err(format!(
            "fileKeyB64 must decode to a 16-byte age file key, got {} bytes",
            raw.len()
        ))
    })?;

    Ok(NativeAnswer {
        file_key: zeroize::Zeroizing::new(file_key),
        receipt,
    })
}

/*
 * Refuse an answer that names a stanza we never handed out.
 *
 * Same posture as invoke_prf_callback_multi's credentialId membership check.
 * Naming the stanza is optional -- the load-bearing check is that the key opens
 * the blob -- but if the callback does name one, it must be one of ours.
 */
fn check_stanza_reference(resolved: &JsValue, offered: &[Stanza]) -> Result<(), JsValue> {
    let idx_val = js_sys::Reflect::get(resolved, &JsValue::from_str("stanzaIndex"))
        .map_err(|e| js_err(format!("reflect stanzaIndex: {e:?}")))?;
    let mut index: Option<usize> = None;
    if !idx_val.is_undefined() && !idx_val.is_null() {
        let n = idx_val
            .as_f64()
            .ok_or_else(|| js_err("native callback returned a non-numeric stanzaIndex"))?;
        if n.fract() != 0.0 || n < 0.0 || n >= offered.len() as f64 {
            return Err(js_err(
                "native callback returned a stanzaIndex outside the set of stanzas it was \
                 handed",
            ));
        }
        index = Some(n as usize);
    }

    let stanza_val = js_sys::Reflect::get(resolved, &JsValue::from_str("stanza"))
        .map_err(|e| js_err(format!("reflect stanza: {e:?}")))?;
    if stanza_val.is_undefined() || stanza_val.is_null() {
        return Ok(());
    }
    let echoed = parse_wire_stanza(&stanza_val)?;
    match index {
        Some(i) if offered[i] != echoed => Err(js_err(
            "native callback returned a stanza that disagrees with the stanzaIndex it also \
             returned",
        )),
        _ if !offered.iter().any(|s| *s == echoed) => Err(js_err(
            "native callback returned a stanza that was not in the set it was handed",
        )),
        _ => Ok(()),
    }
}

fn parse_wire_stanza(value: &JsValue) -> Result<Stanza, JsValue> {
    if !value.is_object() {
        return Err(js_err("stanza must be an object { tag, args, body }"));
    }
    let tag = js_sys::Reflect::get(value, &JsValue::from_str("tag"))
        .map_err(|e| js_err(format!("reflect stanza.tag: {e:?}")))?
        .as_string()
        .ok_or_else(|| js_err("stanza.tag must be a string"))?;
    let body_b64 = js_sys::Reflect::get(value, &JsValue::from_str("body"))
        .map_err(|e| js_err(format!("reflect stanza.body: {e:?}")))?
        .as_string()
        .ok_or_else(|| js_err("stanza.body must be a base64 string"))?;
    let body = B64
        .decode(body_b64.trim())
        .map_err(|e| js_err(format!("stanza.body is not valid base64: {e}")))?;
    let args_val = js_sys::Reflect::get(value, &JsValue::from_str("args"))
        .map_err(|e| js_err(format!("reflect stanza.args: {e:?}")))?;
    let mut args = Vec::new();
    if !args_val.is_undefined() && !args_val.is_null() {
        for a in js_sys::Array::from(&args_val).iter() {
            args.push(
                a.as_string()
                    .ok_or_else(|| js_err("stanza.args must be strings"))?,
            );
        }
    }
    Ok(Stanza { tag, args, body })
}

fn set_str(obj: &js_sys::Object, key: &str, value: &str) -> Result<(), JsValue> {
    js_sys::Reflect::set(obj, &JsValue::from_str(key), &JsValue::from_str(value))
        .map(|_| ())
        .map_err(|e| js_err(format!("reflect {key}: {e:?}")))
}

/*
 * An identity that answers with a file key someone else produced.
 *
 * It offers the key only for stanzas that were handed to the callback, so a
 * key obtained for one item cannot be spent against a stanza this call never
 * exposed. The key itself is still checked by age: `v1_payload_key` verifies
 * the header MAC before deriving a payload key, so a wrong key ends the
 * decrypt with an error rather than a bogus plaintext.
 */
struct SuppliedFileKeyIdentity {
    offered: Vec<Stanza>,
    file_key: FileKey,
}

impl Identity for SuppliedFileKeyIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if !self.offered.iter().any(|s| s == stanza) {
            return Ok(None);
        }
        Ok(Some(self.file_key.clone()))
    }

    fn display(&self) -> &str {
        "native-host-supplied-file-key"
    }
}

fn collect_stanzas(blob: &[u8]) -> Result<Vec<Stanza>, JsValue> {
    ragewarden_core::parse_header_stanzas(&AgeBlob::from_bytes(blob.to_vec()))
        .map_err(|e| js_err_with_code(e.code(), format!("parse header: {e}")))
}

fn collect_webauthn_prf_pairs(blob: &[u8]) -> Result<Vec<(Vec<u8>, [u8; 32])>, JsValue> {
    let recorded = collect_stanzas(blob)?;
    let mut out = Vec::new();
    for s in &recorded {
        if s.tag != TAG_WEBAUTHN_PRF_V1 {
            continue;
        }
        let cred = ragewarden_core::stanza_format::webauthn_prf_credential_id(s)
            .map_err(|e| js_err(format!("webauthn-prf credential_id: {e}")))?;
        let salt = ragewarden_core::stanza_format::webauthn_prf_salt(s)
            .map_err(|e| js_err(format!("webauthn-prf salt: {e}")))?;
        out.push((cred, salt));
    }
    Ok(out)
}

fn parse_field_map(value: &JsValue) -> Result<Vec<(String, String)>, JsValue> {
    let s: String = js_sys::JSON::stringify(value)
        .map_err(|e| js_err(format!("stringify fields: {e:?}")))?
        .into();
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&s).map_err(|e| js_err(format!("parse fields: {e}")))?;
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let v = v
            .as_str()
            .ok_or_else(|| js_err(format!("field `{k}` not a string")))?
            .to_string();
        out.push((k, v));
    }
    Ok(out)
}

fn parse_recipients(value: &JsValue) -> Result<Vec<Recipient>, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Err(js_err("recipients required"));
    }
    let s: String = js_sys::JSON::stringify(value)
        .map_err(|e| js_err(format!("stringify recipients: {e:?}")))?
        .into();

    // Canonical form: exactly what `ragewarden_core::policy` emits and what
    // `wasm_select_encrypt_recipients` hands back, tagged with `type`. This is
    // the only form the vault glue produces; the `kind`-tagged form below is
    // the pre-policy shape kept for callers that still build recipients by
    // hand (enrollment flows, tests).
    if let Ok(canonical) = serde_json::from_str::<Vec<Recipient>>(&s) {
        if canonical.is_empty() {
            return Err(js_err("recipients list empty"));
        }
        return Ok(canonical);
    }

    #[derive(Deserialize)]
    struct Wire {
        kind: String,
        #[serde(default)]
        armored_pubkey: Option<String>,
        #[serde(default)]
        public_key_b64: Option<String>,
        #[serde(default)]
        credential_id_b64: Option<String>,
        #[serde(default)]
        salt_b64: Option<String>,
        #[serde(default)]
        rp_id: Option<String>,
        #[serde(default)]
        label: Option<String>,
    }
    let wire: Vec<Wire> =
        serde_json::from_str(&s).map_err(|e| js_err(format!("parse recipients: {e}")))?;
    let mut out = Vec::with_capacity(wire.len());
    for r in wire {
        match r.kind.as_str() {
            "software" => {
                let armored = r
                    .armored_pubkey
                    .ok_or_else(|| js_err("software recipient needs armored_pubkey"))?;
                out.push(Recipient::SoftwarePassphrase {
                    armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted(armored),
                });
            }
            "x25519" => {
                let pk_b64 = r
                    .public_key_b64
                    .ok_or_else(|| js_err("x25519 recipient needs public_key_b64"))?;
                let pk = B64
                    .decode(pk_b64.as_bytes())
                    .map_err(|e| js_err(format!("public_key_b64: {e}")))?;
                let pk: [u8; 32] = pk.try_into().map_err(|v: Vec<u8>| {
                    js_err(format!("x25519 pubkey wrong length: {}", v.len()))
                })?;
                out.push(Recipient::X25519 { public_key: pk });
            }
            "passkey_prf" => {
                let cred_b64 = r
                    .credential_id_b64
                    .ok_or_else(|| js_err("passkey_prf recipient needs credential_id_b64"))?;
                let salt_b64 = r
                    .salt_b64
                    .ok_or_else(|| js_err("passkey_prf recipient needs salt_b64"))?;
                let rp_id = r
                    .rp_id
                    .ok_or_else(|| js_err("passkey_prf recipient needs rp_id"))?;
                let label = r.label.unwrap_or_else(|| "passkey".to_string());
                let credential_id = B64
                    .decode(cred_b64.as_bytes())
                    .map_err(|e| js_err(format!("credential_id_b64: {e}")))?;
                let salt_vec = B64
                    .decode(salt_b64.as_bytes())
                    .map_err(|e| js_err(format!("salt_b64: {e}")))?;
                if salt_vec.len() != 32 {
                    return Err(js_err(format!(
                        "salt_b64 must be 32 bytes, got {}",
                        salt_vec.len()
                    )));
                }
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&salt_vec);
                out.push(Recipient::PasskeyPrf {
                    credential_id,
                    salt,
                    rp_id,
                    label,
                });
            }
            other => return Err(js_err(format!("unsupported recipient kind: {other}"))),
        }
    }
    if out.is_empty() {
        return Err(js_err("recipients list empty"));
    }
    Ok(out)
}

fn augment_with_login(
    cipher: &mut CipherIn,
    fields: &[(String, String)],
    session: &Session,
) -> Result<(), JsValue> {
    let username = fields
        .iter()
        .find(|(k, _)| k == "username")
        .map(|(_, v)| v.clone());
    let site = fields
        .iter()
        .find(|(k, _)| k == "site")
        .map(|(_, v)| v.clone());
    let force_login = fields
        .iter()
        .any(|(k, v)| k == "cipher_type" && v.eq_ignore_ascii_case("login"));

    if username.is_none() && site.is_none() && !force_login {
        return Ok(());
    }

    cipher.cipher_type = 1;
    cipher.secure_note = None;
    let enc_username = match username {
        Some(u) => Some(
            sync::encrypt_string(session, &u)
                .map_err(|e| js_err(format!("encrypt username: {e}")))?,
        ),
        None => None,
    };
    let uris = match site {
        Some(s) => {
            let enc = sync::encrypt_string(session, &s)
                .map_err(|e| js_err(format!("encrypt uri: {e}")))?;
            Some(vec![sync::CipherUri {
                uri: enc,
                match_type: None,
            }])
        }
        None => None,
    };
    cipher.login = Some(CipherLogin {
        username: enc_username,
        password: None,
        totp: None,
        uris,
    });
    Ok(())
}

#[wasm_bindgen(js_name = wasm_publish_recipient_to_registry)]
pub async fn wasm_publish_recipient_to_registry(
    session_value: JsValue,
    entry_value: JsValue,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;

    let entry_json: String = js_sys::JSON::stringify(&entry_value)
        .map_err(|e| js_err(format!("stringify registry entry: {e:?}")))?
        .into();
    let entry: RegistryEntry = serde_json::from_str(&entry_json)
        .map_err(|e| js_err(format!("parse registry entry: {e}")))?;
    if entry.id.is_empty() {
        return Err(js_err("registry entry id is required"));
    }

    let client = JsHttpClient::new();
    let vault = fetch_vault(&client, &server, &session)
        .await
        .map_err(|e| js_err(format!("fetch_vault: {e}")))?;

    let mut doc = core_registry::extract_document(&session, &vault)
        .map_err(|e| js_err(format!("read registry: {e}")))?
        .unwrap_or_default();

    if let Some(existing) = doc.entries.iter().find(|e| e.id == entry.id) {
        if *existing == entry {
            return Ok(JsValue::NULL);
        }
    }
    doc.entries.retain(|e| e.id != entry.id);
    doc.entries.push(entry);

    let payload =
        serde_json::to_string(&doc).map_err(|e| js_err(format!("serialize registry: {e}")))?;
    let cipher_in = build_meta_cipher(&session, REGISTRY_MARKER_NAME, &payload)
        .map_err(|e| js_err(format!("build_meta_cipher: {e}")))?;

    let saved = match core_registry::marker_cipher_id(&session, &vault) {
        Some(id) => core_update_cipher(&client, &server, &session, id, &cipher_in)
            .await
            .map_err(|e| js_err(format!("update_cipher: {e}")))?,
        None => core_create_cipher(&client, &server, &session, &cipher_in)
            .await
            .map_err(|e| js_err(format!("create_cipher: {e}")))?,
    };

    Ok(JsValue::from_str(saved.id.as_deref().unwrap_or("")))
}

#[wasm_bindgen(js_name = wasm_unpublish_from_registry)]
pub async fn wasm_unpublish_from_registry(
    session_value: JsValue,
    entry_id: String,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    if entry_id.is_empty() {
        return Err(js_err("entry_id required"));
    }

    let client = JsHttpClient::new();
    let vault = fetch_vault(&client, &server, &session)
        .await
        .map_err(|e| js_err(format!("fetch_vault: {e}")))?;

    let Some(mut doc) = core_registry::extract_document(&session, &vault)
        .map_err(|e| js_err(format!("read registry: {e}")))?
    else {
        return Ok(JsValue::NULL);
    };

    let before = doc.entries.len();
    doc.entries.retain(|e| e.id != entry_id);
    if doc.entries.len() == before {
        return Ok(JsValue::NULL);
    }

    let payload =
        serde_json::to_string(&doc).map_err(|e| js_err(format!("serialize registry: {e}")))?;
    let cipher_in = build_meta_cipher(&session, REGISTRY_MARKER_NAME, &payload)
        .map_err(|e| js_err(format!("build_meta_cipher: {e}")))?;

    let Some(marker_id) = core_registry::marker_cipher_id(&session, &vault) else {
        return Ok(JsValue::NULL);
    };
    let saved = core_update_cipher(&client, &server, &session, marker_id, &cipher_in)
        .await
        .map_err(|e| js_err(format!("update_cipher: {e}")))?;
    Ok(JsValue::from_str(saved.id.as_deref().unwrap_or("")))
}

#[wasm_bindgen(js_name = wasm_fetch_registry)]
pub async fn wasm_fetch_registry(session_value: JsValue) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let client = JsHttpClient::new();
    let vault = fetch_vault(&client, &server, &session)
        .await
        .map_err(|e| js_err(format!("fetch_vault: {e}")))?;
    let doc = core_registry::extract_document(&session, &vault)
        .map_err(|e| js_err(format!("read registry: {e}")))?;
    match doc {
        Some(d) => {
            let s =
                serde_json::to_string(&d).map_err(|e| js_err(format!("serialize doc: {e}")))?;
            js_sys::JSON::parse(&s)
                .map_err(|e| js_err(format!("re-parse to JsValue: {e:?}")))
        }
        None => Ok(JsValue::NULL),
    }
}

/// The canonical recipient-selection policy, reached from JavaScript.
///
/// `ext/glue/vault.js` used to reimplement this in JS and kept only `Software`
/// and `Recovery` entries, so anything written in the browser was
/// cryptographically unopenable by a YubiKey or an Android StrongBox key --
/// silently, with the save reporting success. The browser now runs the same
/// `ragewarden_core::policy::select_for_encrypt` that rageterm and ragedroid
/// run.
///
/// `local_prf_entry_ids` is the one sanctioned per-client divergence: registry
/// ids of PRF authenticators this browser profile can actually evaluate during
/// a wrap. Pass `null` for "none reachable". Entries that need an authenticator
/// this client cannot reach come back under `skipped` with the reason
/// `no_local_authenticator` so the caller can warn instead of losing coverage
/// quietly.
///
/// Returns `{ recipients: [...], skipped: [...] }`; `recipients` is directly
/// accepted by `wasm_create_cipher` / `wasm_update_cipher`.
#[wasm_bindgen(js_name = wasm_select_encrypt_recipients)]
pub async fn wasm_select_encrypt_recipients(
    session_value: JsValue,
    local_prf_entry_ids: JsValue,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let client = JsHttpClient::new();
    let vault = fetch_vault(&client, &server, &session)
        .await
        .map_err(|e| js_err(format!("fetch_vault: {e}")))?;
    let entries = core_registry::extract_document(&session, &vault)
        .map_err(|e| js_err(format!("read registry: {e}")))?
        .map(|d| d.entries)
        .unwrap_or_default();

    let local_auth = if local_prf_entry_ids.is_null() || local_prf_entry_ids.is_undefined() {
        core_policy::LocalAuthenticators::none()
    } else {
        core_policy::LocalAuthenticators::from_ids(parse_string_array(&local_prf_entry_ids)?)
    };

    let selection = core_policy::select_for_encrypt(&entries, &[], &local_auth);
    let s = serde_json::to_string(&selection)
        .map_err(|e| js_err(format!("serialize selection: {e}")))?;
    js_sys::JSON::parse(&s).map_err(|e| js_err(format!("re-parse selection: {e:?}")))
}

#[allow(dead_code)]
fn _registry_re_exports() {
    let _: Option<&str> = Some(registry_kinds::FIDO2);
    let _: RegistryDocument = RegistryDocument::default();
}

const HISTORY_MARKER_PREFIX: &str = "__ragewarden_history_v1__";
const HISTORY_CAP: usize = 32;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct HistoryEntry {
    #[serde(rename = "recordedAt")]
    recorded_at: i64,
    #[serde(rename = "cipherId")]
    cipher_id: String,
    #[serde(rename = "priorPayload")]
    prior_payload: String,
    #[serde(rename = "recipientsSummary")]
    recipients_summary: Vec<String>,
}

fn history_marker_name(cipher_id: &str) -> String {
    format!("{HISTORY_MARKER_PREFIX}:{cipher_id}")
}

fn find_history_cipher(
    session: &Session,
    vault: &ragewarden_core::sync::Vault,
    marker: &str,
) -> Option<Cipher> {
    for c in &vault.ciphers {
        if let Ok(name) = cipher_name(session, c) {
            if name == marker {
                return Some(c.clone());
            }
        }
    }
    None
}

#[wasm_bindgen(js_name = wasm_record_history_revision)]
pub async fn wasm_record_history_revision(
    session_value: JsValue,
    cipher_id: String,
    prior_payload_armored: String,
    recipients_summary: JsValue,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let summary = parse_string_array(&recipients_summary)?;

    let client = JsHttpClient::new();
    let vault = fetch_vault(&client, &server, &session)
        .await
        .map_err(|e| js_err(format!("fetch_vault: {e}")))?;

    let marker = history_marker_name(&cipher_id);
    let mut entries: Vec<HistoryEntry> = match find_history_cipher(&session, &vault, &marker) {
        Some(ref c) => {
            match decrypt_history_payload(&session, c) {
                Ok(list) => list,
                Err(_) => Vec::new(),
            }
        }
        None => Vec::new(),
    };

    let now_ms = (js_sys::Date::now() as i64).max(0);
    let entry = HistoryEntry {
        recorded_at: now_ms,
        cipher_id: cipher_id.clone(),
        prior_payload: prior_payload_armored,
        recipients_summary: summary,
    };
    entries.insert(0, entry);
    if entries.len() > HISTORY_CAP {
        entries.truncate(HISTORY_CAP);
    }

    let payload = serde_json::to_string(&entries)
        .map_err(|e| js_err(format!("serialize history: {e}")))?;
    let cipher_in = build_meta_cipher(&session, &marker, &payload)
        .map_err(|e| js_err(format!("build_meta_cipher: {e}")))?;

    let saved = match find_history_cipher(&session, &vault, &marker)
        .and_then(|c| c.id.clone())
    {
        Some(id) => core_update_cipher(&client, &server, &session, &id, &cipher_in)
            .await
            .map_err(|e| js_err(format!("update history: {e}")))?,
        None => core_create_cipher(&client, &server, &session, &cipher_in)
            .await
            .map_err(|e| js_err(format!("create history: {e}")))?,
    };
    Ok(JsValue::from_str(saved.id.as_deref().unwrap_or("")))
}

#[wasm_bindgen(js_name = wasm_load_history)]
pub async fn wasm_load_history(
    session_value: JsValue,
    cipher_id: String,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let client = JsHttpClient::new();
    let vault = fetch_vault(&client, &server, &session)
        .await
        .map_err(|e| js_err(format!("fetch_vault: {e}")))?;
    let marker = history_marker_name(&cipher_id);
    let Some(c) = find_history_cipher(&session, &vault, &marker) else {
        return Ok(JsValue::from_str("[]"));
    };
    let entries = decrypt_history_payload(&session, &c).unwrap_or_default();
    let s = serde_json::to_string(&entries)
        .map_err(|e| js_err(format!("serialize history: {e}")))?;
    Ok(JsValue::from_str(&s))
}

fn decrypt_history_payload(
    session: &Session,
    cipher: &Cipher,
) -> Result<Vec<HistoryEntry>, String> {
    let notes = cipher
        .notes
        .as_ref()
        .ok_or_else(|| "history cipher has no notes".to_string())?;
    let plaintext =
        decrypt_string(session, notes).map_err(|e| format!("decrypt history notes: {e}"))?;
    serde_json::from_str(&plaintext).map_err(|e| format!("parse history payload: {e}"))
}

fn parse_string_array(value: &JsValue) -> Result<Vec<String>, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(Vec::new());
    }
    let s: String = js_sys::JSON::stringify(value)
        .map_err(|e| js_err(format!("stringify summary: {e:?}")))?
        .into();
    serde_json::from_str(&s).map_err(|e| js_err(format!("parse summary: {e}")))
}
