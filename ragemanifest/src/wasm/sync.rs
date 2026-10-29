use super::http::JsHttpClient;
use super::session::{jsvalue_to_session, session_to_jsvalue, update_handle};
use super::{js_err, js_err_with_code, js_object};

use crate::decide::{self, PrfPair};
use crate::prf_identity::{
    SoftwareFirst, SpecificPasskeyPrfIdentity, decrypt_software_first, summarize_stanzas,
};
use crate::reveal::{
    decrypt_non_rage_field, protected_field, rage_protects_field, single_secret_overwrite_refusal,
};
use crate::snapshot::{
    DisplayCipher, LocalIdentityInventory, VaultSnapshot, assess_rage_header,
    build_snapshot_with_identities, is_internal_cipher_name,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ragewarden_core::kdf::KdfParams;
use ragewarden_core::registry::{
    self as core_registry, MARKER_NAME as REGISTRY_MARKER_NAME, WireDocument as RegistryDocument,
    WireEntry as RegistryEntry, kinds as registry_kinds,
};
use ragewarden_core::sync::{
    self, Cipher, LoginOptions, Server, Session, SyncError, build_meta_cipher, cipher_name,
    create_cipher as core_create_cipher, extract_rage_blob, fetch_vault, login_with_options,
    refresh_session, register, update_cipher as core_update_cipher, upgrade_kdf,
};
use ragewarden_core::{
    AgeBlob, FileKey, Identity, IdentityError, Recipient, Stanza, decrypt as core_decrypt,
    encrypt as core_encrypt,
    stanza_format::{TAG_FIDO2_HMAC, TAG_PIV_P256, TAG_PIV_X25519_V2},
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

    js_object(&[
        ("email", JsValue::from_str(&out.email)),
        (
            "kdf_iterations",
            JsValue::from_f64(out.kdf.iterations as f64),
        ),
    ])
}

/// `kdf_pin` is the account's KdfParams from its last successful login on this
/// profile (or null); a server offering weaker ones is refused before the
/// password is hashed. A PBKDF2 count below the minimum fails with code
/// `legacy_kdf_needs_consent` unless `allow_legacy_kdf`; follow such a login
/// with wasm_upgrade_kdf.
#[wasm_bindgen(js_name = wasm_login)]
pub async fn wasm_login(
    server_url: String,
    email: String,
    master_password: String,
    device_name: String,
    device_id: String,
    kdf_pin: JsValue,
    allow_legacy_kdf: bool,
) -> Result<JsValue, JsValue> {
    let server = Server::self_hosted(&server_url);
    server
        .require_secure()
        .map_err(|e| js_err(format!("insecure server: {e}")))?;
    let opts = LoginOptions {
        device_id: Some(device_id),
        kdf_pin: parse_kdf(&kdf_pin)?,
        allow_legacy_kdf,
    };
    let client = JsHttpClient::new();
    let session = login_with_options(
        &client,
        &server,
        &email,
        &master_password,
        &device_name,
        &opts,
    )
    .await
    .map_err(login_err)?;

    session_to_jsvalue(&server, &session)
}

/// Re-derive the account's master key with `new_kdf` (null = the default for new
/// accounts) and return the fresh session the server issues afterwards.
#[wasm_bindgen(js_name = wasm_upgrade_kdf)]
pub async fn wasm_upgrade_kdf(
    session_value: JsValue,
    master_password: String,
    device_name: String,
    new_kdf: JsValue,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let new = parse_kdf(&new_kdf)?.unwrap_or_default();
    let client = JsHttpClient::new();
    let upgraded = upgrade_kdf(
        &client,
        &server,
        &session,
        &master_password,
        &device_name,
        new,
    )
    .await
    .map_err(|e| js_err(format!("upgrade kdf: {e}")))?;
    session_to_jsvalue(&server, &upgraded)
}

fn parse_kdf(value: &JsValue) -> Result<Option<KdfParams>, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    let s: String = js_sys::JSON::stringify(value)
        .map_err(|e| js_err(format!("stringify kdf: {e:?}")))?
        .into();
    serde_json::from_str(&s)
        .map(Some)
        .map_err(|e| js_err(format!("parse kdf: {e}")))
}

fn login_err(e: SyncError) -> JsValue {
    match &e {
        SyncError::LegacyKdfNeedsConsent { got, min } => {
            let err = js_err_with_code("legacy_kdf_needs_consent", format!("login: {e}"));
            let _ = js_sys::Reflect::set(&err, &"got".into(), &JsValue::from(*got));
            let _ = js_sys::Reflect::set(&err, &"min".into(), &JsValue::from(*min));
            err
        }
        SyncError::KdfDowngraded { .. } => {
            js_err_with_code("kdf_downgraded", format!("login: {e}"))
        }
        _ => js_err(format!("login: {e}")),
    }
}

#[wasm_bindgen(js_name = wasm_fetch_vault)]
pub async fn wasm_fetch_vault(session_value: JsValue) -> Result<JsValue, JsValue> {
    fetch_vault_snapshot(session_value, LocalIdentityInventory::default()).await
}

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
    if refreshed {
        if update_handle(&session_value, &server, &session) {
            let _ = js_sys::Reflect::set(&value, &JsValue::from_str("refreshed"), &JsValue::TRUE);
        } else if let Ok(sess_value) = session_to_jsvalue(&server, &session) {
            let _ =
                js_sys::Reflect::set(&value, &JsValue::from_str("refreshed_session"), &sess_value);
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

    let protected = rage_protects_field(&session, &cipher, &field_name)
        .map_err(|e| js_err_with_code(e.code(), format!("{e}")))?;
    if protected {
        if let Some(blob) = extract_rage_blob(&session, &cipher)
            .map_err(|e| js_err(format!("extract rage blob: {e}")))?
        {
            let payload = zeroize::Zeroizing::new(
                decrypt_rage_blob(blob.into_bytes(), prf_callback.as_ref(), &secrets).await?,
            );
            let value = protected_field(&cipher, &payload, &field_name)
                .map_err(|e| js_err_with_code(e.code(), format!("{e}")))?;
            return Ok(value.to_vec());
        }
    }

    let bytes = decrypt_non_rage_field(&session, &cipher, &field_name)
        .map_err(|e| js_err_with_code(e.code(), format!("decrypt: {e}")))?;
    Ok(bytes.to_vec())
}

#[wasm_bindgen(js_name = wasm_decrypt_cipher_field_with_native)]
pub async fn wasm_decrypt_cipher_field_with_native(
    session_value: JsValue,
    cipher_value: JsValue,
    field_name: String,
    native_callback: js_sys::Function,
) -> Result<JsValue, JsValue> {
    let (_server, session) = jsvalue_to_session(&session_value)?;
    let cipher = jsvalue_to_cipher(&cipher_value)?;
    let protected = rage_protects_field(&session, &cipher, &field_name)
        .map_err(|e| js_err_with_code(e.code(), format!("{e}")))?;
    if !protected {
        return Err(js_err_with_code(
            "missing_field",
            format!(
                "`{field_name}` is not sealed in this item's rage blob, so no native host \
                 unwrap applies to it. Refusing to ask for a touch that could not reveal it.",
            ),
        ));
    }

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
            "this item carries no stanza a native host can unwrap (looked for \
             `{TAG_PIV_X25519_V2}`, `{TAG_PIV_P256}` and `{TAG_FIDO2_HMAC}`). Refusing to ask for \
             a touch that could not open it.",
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

    let value = protected_field(&cipher, &plaintext, &field_name)
        .map_err(|e| js_err_with_code(e.code(), format!("{e}")))?;
    let out = js_sys::Uint8Array::from(&value[..]);
    js_sys::Reflect::set(&out, &JsValue::from_str("receipt"), &answer.receipt)
        .map_err(|e| js_err(format!("reflect receipt: {e:?}")))?;
    Ok(out.into())
}

#[wasm_bindgen(js_name = wasm_rage_stanza_summary)]
pub fn wasm_rage_stanza_summary(
    session_value: JsValue,
    cipher_value: JsValue,
    field_name: String,
) -> Result<JsValue, JsValue> {
    let (_server, session) = jsvalue_to_session(&session_value)?;
    let cipher = jsvalue_to_cipher(&cipher_value)?;
    let protected = rage_protects_field(&session, &cipher, &field_name)
        .map_err(|e| js_err_with_code(e.code(), format!("{e}")))?;
    let blob = if protected {
        extract_rage_blob(&session, &cipher)
            .map_err(|e| js_err(format!("extract rage blob: {e}")))?
    } else {
        None
    };
    let (rage, summary) = match blob {
        Some(armored) => (
            true,
            summarize_stanzas(&collect_stanzas(armored.as_bytes())?),
        ),
        None => (false, Default::default()),
    };
    let summary = serde_json::to_value(&summary).map_err(|e| js_err(format!("summary: {e}")))?;
    let mut map = match summary {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    map.insert("rage".into(), serde_json::Value::Bool(rage));
    js_sys::JSON::parse(&serde_json::Value::Object(map).to_string())
        .map_err(|e| js_err(format!("JSON.parse: {e:?}")))
}

#[wasm_bindgen(js_name = wasm_create_cipher)]
pub async fn wasm_create_cipher(
    session_value: JsValue,
    plaintext_field_map: JsValue,
    recipients_value: JsValue,
) -> Result<JsValue, JsValue> {
    create_cipher_inner(
        session_value,
        plaintext_field_map,
        recipients_value,
        JsValue::NULL,
    )
    .await
}

#[wasm_bindgen(js_name = wasm_create_cipher_with_prf)]
pub async fn wasm_create_cipher_with_prf(
    session_value: JsValue,
    plaintext_field_map: JsValue,
    recipients_value: JsValue,
    prf_table_value: JsValue,
) -> Result<JsValue, JsValue> {
    create_cipher_inner(
        session_value,
        plaintext_field_map,
        recipients_value,
        prf_table_value,
    )
    .await
}

fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn seal_secret(
    fields: &[(String, String)],
    recipients: &[Recipient],
    prf_entries: &[OwnedPrfEntry],
) -> Result<String, JsValue> {
    let secret_value =
        field(fields, "rage").ok_or_else(|| js_err("plaintext_field_map.rage is required"))?;
    encrypt_payload(secret_value.as_bytes(), recipients, prf_entries)
}

fn encrypt_payload(
    payload: &[u8],
    recipients: &[Recipient],
    prf_entries: &[OwnedPrfEntry],
) -> Result<String, JsValue> {
    let blob = if prf_entries.is_empty() {
        core_encrypt(payload, recipients).map_err(|e| js_err(format!("encrypt: {e}")))?
    } else {
        let table: Vec<ragewarden_core::PrfEntry<'_>> = prf_entries
            .iter()
            .map(|e| ragewarden_core::PrfEntry {
                rp_id: &e.rp_id,
                credential_id: &e.credential_id,
                salt: &e.salt,
                prf_output: &e.prf_output,
            })
            .collect();
        ragewarden_core::encrypt_with_prf(payload, recipients, &table)
            .map_err(|e| js_err(format!("encrypt: {e}")))?
    };
    String::from_utf8(blob.0).map_err(|e| js_err(format!("blob not utf-8: {e}")))
}

fn draft_from_fields(fields: &[(String, String)]) -> sync::CipherDraft {
    let username = field(fields, "username").map(String::from);
    let site = field(fields, "site").map(String::from);
    let login = username.is_some()
        || site.is_some()
        || field(fields, "cipher_type").is_some_and(|t| t.eq_ignore_ascii_case("login"));
    sync::CipherDraft {
        login,
        name: field(fields, "name").unwrap_or("Untitled").to_string(),
        notes: field(fields, "notes").map(String::from),
        username,
        uris: site.into_iter().collect(),
        totp: field(fields, "totp").map(String::from),
        ..sync::CipherDraft::default()
    }
}

fn edit_from_fields(fields: &[(String, String)]) -> sync::CipherEdit {
    sync::CipherEdit {
        name: field(fields, "name").map(String::from),
        notes: field(fields, "notes").map(String::from),
        username: field(fields, "username").map(String::from),
        uris: field(fields, "site").map(|s| vec![s.to_string()]),
        totp: field(fields, "totp").map(String::from),
        ..sync::CipherEdit::default()
    }
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

    let armored = seal_secret(&fields, &recipients, &prf_entries)?;
    let cipher_in = sync::build_cipher(&session, &draft_from_fields(&fields), Some(&armored))
        .map_err(|e| js_err(format!("build_cipher: {e}")))?;

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

    let client = JsHttpClient::new();
    let existing = sync::get_cipher(&client, &server, &session, &cipher_id)
        .await
        .map_err(|e| js_err(format!("get_cipher: {e}")))?;
    let protected = sync::protected_field_names(&session, &existing)
        .map_err(|e| js_err(format!("protected fields: {e}")))?;
    let replacement = field(&fields, "rage").unwrap_or_default().as_bytes();
    if let Some(why) =
        single_secret_overwrite_refusal(existing.cipher_type, &protected, replacement)
    {
        return Err(js_err_with_code("multi_field", why));
    }
    record_prior(&client, &server, &session, &cipher_id, false).await?;
    let armored = seal_secret(&fields, &recipients, &prf_entries)?;
    let cipher_in = sync::edit_preserving(
        &session,
        &existing,
        Some(&armored),
        &edit_from_fields(&fields),
    )
    .map_err(|e| js_err(format!("edit: {e}")))?;
    let saved = core_update_cipher(&client, &server, &session, &cipher_id, &cipher_in)
        .await
        .map_err(|e| js_err(format!("update_cipher: {e}")))?;

    cipher_to_jsvalue(&session, &saved)
}

fn parse_json<T: serde::de::DeserializeOwned>(value: &JsValue, what: &str) -> Result<T, JsValue> {
    let s: String = js_sys::JSON::stringify(value)
        .map_err(|e| js_err(format!("stringify {what}: {e:?}")))?
        .into();
    serde_json::from_str(&s).map_err(|e| js_err(format!("parse {what}: {e}")))
}

/// Creates (`cipher_id` null) or updates any item -- login, note, card,
/// identity, SSH key -- with several protected fields at once.
///
/// `item` is a core `CipherDraft` for a create and a `CipherEdit` for an
/// update (camelCase; card/identity/sshKey blocks map Bitwarden field names
/// to plaintext). `protected_fields` maps the names of the fields to seal to
/// their values (`null` keeps the item's current blob on an update, and makes
/// an unprotected item on a create); they are sealed into one rage blob -- v1
/// for the primary field alone, a v2 field map otherwise -- and left out of
/// the Type-2 layer. An update merges against the server's current copy.
#[wasm_bindgen(js_name = wasm_save_item)]
pub async fn wasm_save_item(
    session_value: JsValue,
    cipher_id: Option<String>,
    item: JsValue,
    protected_fields: JsValue,
    recipients_value: JsValue,
    prf_table_value: JsValue,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    let secrets: Option<std::collections::BTreeMap<String, String>> =
        if protected_fields.is_null() || protected_fields.is_undefined() {
            None
        } else {
            Some(parse_json(&protected_fields, "protected fields")?)
        };
    let seal = |cipher_type: u8| -> Result<Option<(String, Vec<String>)>, JsValue> {
        let Some(secrets) = &secrets else {
            return Ok(None);
        };
        let recipients = parse_recipients(&recipients_value)?;
        let prf_entries = parse_prf_table(&prf_table_value)?;
        let fields = secrets
            .iter()
            .map(|(k, v)| (k.clone(), zeroize::Zeroizing::new(v.as_bytes().to_vec())))
            .collect();
        let payload = ragewarden_core::protected::seal(cipher_type, &fields)
            .map_err(|e| js_err(format!("seal: {e}")))?;
        let armored = encrypt_payload(&payload, &recipients, &prf_entries)?;
        Ok(Some((armored, secrets.keys().cloned().collect())))
    };

    let client = JsHttpClient::new();
    let saved = match cipher_id.filter(|id| !id.is_empty()) {
        None => {
            let mut draft: sync::CipherDraft = parse_json(&item, "item")?;
            let sealed = seal(draft.cipher_type())?;
            if let Some((_, names)) = &sealed {
                draft.protected_fields = names.clone();
            }
            let cipher_in =
                sync::build_cipher(&session, &draft, sealed.as_ref().map(|(a, _)| a.as_str()))
                    .map_err(|e| js_err(format!("build_cipher: {e}")))?;
            core_create_cipher(&client, &server, &session, &cipher_in)
                .await
                .map_err(|e| js_err(format!("create_cipher: {e}")))?
        }
        Some(id) => {
            let mut edit: sync::CipherEdit = parse_json(&item, "item")?;
            let existing = sync::get_cipher(&client, &server, &session, &id)
                .await
                .map_err(|e| js_err(format!("get_cipher: {e}")))?;
            let cipher_type = sync::edit_preserving(&session, &existing, None, &edit)
                .map_err(|e| js_err(format!("edit: {e}")))?
                .cipher_type;
            let sealed = seal(cipher_type)?;
            if let Some((_, names)) = &sealed {
                edit.protected_fields = Some(names.clone());
                record_prior(&client, &server, &session, &id, false).await?;
            }
            let cipher_in = sync::edit_preserving(
                &session,
                &existing,
                sealed.as_ref().map(|(a, _)| a.as_str()),
                &edit,
            )
            .map_err(|e| js_err(format!("edit: {e}")))?;
            core_update_cipher(&client, &server, &session, &id, &cipher_in)
                .await
                .map_err(|e| js_err(format!("update_cipher: {e}")))?
        }
    };
    cipher_to_jsvalue(&session, &saved)
}

/// The protected fields in `payload` -- what a `*` read of `cipher` returned --
/// by name, so an editor can change some of them and seal all of them again.
#[wasm_bindgen(js_name = wasm_open_payload)]
pub fn wasm_open_payload(cipher_value: JsValue, payload: String) -> Result<JsValue, JsValue> {
    let cipher = jsvalue_to_cipher(&cipher_value)?;
    let opened = ragewarden_core::protected::open(cipher.cipher_type, payload.as_bytes())
        .map_err(|e| js_err(format!("open payload: {e}")))?;
    let map = js_sys::Object::new();
    for (name, value) in opened.iter() {
        let text = std::str::from_utf8(value)
            .map_err(|_| js_err(format!("protected field `{name}` is not text")))?;
        js_sys::Reflect::set(&map, &JsValue::from_str(name), &JsValue::from_str(text))
            .map_err(|e| js_err(format!("reflect: {e:?}")))?;
    }
    Ok(map.into())
}

/// The fields `cipher`'s rage blob holds, read with no tap.
#[wasm_bindgen(js_name = wasm_protected_field_names)]
pub fn wasm_protected_field_names(
    session_value: JsValue,
    cipher_value: JsValue,
) -> Result<JsValue, JsValue> {
    let (_server, session) = jsvalue_to_session(&session_value)?;
    let cipher = jsvalue_to_cipher(&cipher_value)?;
    let names = sync::protected_field_names(&session, &cipher)
        .map_err(|e| js_err(format!("protected fields: {e}")))?;
    let s = serde_json::to_string(&names).map_err(|e| js_err(format!("serialize: {e}")))?;
    js_sys::JSON::parse(&s).map_err(|e| js_err(format!("JSON.parse: {e:?}")))
}

/// Moves an item to `folder_id` (`null` clears it) without re-encrypting
/// anything: no tap is needed and no field can be lost.
#[wasm_bindgen(js_name = wasm_set_folder)]
pub async fn wasm_set_folder(
    session_value: JsValue,
    cipher_id: String,
    folder_id: Option<String>,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    if cipher_id.is_empty() {
        return Err(js_err("cipher_id required"));
    }
    let client = JsHttpClient::new();
    let saved = sync::set_folder_on(&client, &server, &session, &cipher_id, folder_id.as_deref())
        .await
        .map_err(|e| js_err(format!("set_folder: {e}")))?;
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
    record_prior(&client, &server, &session, &cipher_id, true).await?;
    sync::delete_cipher(&client, &server, &session, &cipher_id)
        .await
        .map_err(|e| js_err(format!("delete_cipher: {e}")))?;
    Ok(JsValue::from_str(&cipher_id))
}

/// Field edits that leave the secret alone: name, username, site, notes,
/// folder. Nothing is re-wrapped, so no tap and no history revision.
#[wasm_bindgen(js_name = wasm_edit_cipher)]
pub async fn wasm_edit_cipher(
    session_value: JsValue,
    cipher_id: String,
    changed_fields: JsValue,
) -> Result<JsValue, JsValue> {
    let (server, session) = jsvalue_to_session(&session_value)?;
    if cipher_id.is_empty() {
        return Err(js_err("cipher_id required"));
    }
    let fields = parse_field_map(&changed_fields)?;
    let client = JsHttpClient::new();
    let saved = sync::update_preserving(
        &client,
        &server,
        &session,
        &cipher_id,
        None,
        &edit_from_fields(&fields),
    )
    .await
    .map_err(|e| js_err(format!("update_preserving: {e}")))?;
    cipher_to_jsvalue(&session, &saved)
}

/// Before a write replaces an item's rage payload (or deletes the item), keep
/// the payload in the account's history document as a revision (or a
/// deletion). Items without a rage payload have nothing to keep.
async fn record_prior(
    client: &JsHttpClient,
    server: &Server,
    session: &Session,
    cipher_id: &str,
    deleted: bool,
) -> Result<(), JsValue> {
    let vault = fetch_vault(client, server, session)
        .await
        .map_err(|e| js_err(format!("fetch_vault: {e}")))?;
    let Some(existing) = vault
        .ciphers
        .iter()
        .find(|c| c.id.as_deref() == Some(cipher_id))
    else {
        return Ok(());
    };
    let Some(prior) =
        extract_rage_blob(session, existing).map_err(|e| js_err(format!("history: {e}")))?
    else {
        return Ok(());
    };
    let now = (js_sys::Date::now() as i64).max(0);
    let entry = if deleted {
        ragewarden_core::history::HistoryEntry::deletion(cipher_id, prior, Vec::new(), now)
    } else {
        ragewarden_core::history::HistoryEntry::revision(cipher_id, prior, Vec::new(), now)
    };
    ragewarden_core::history::record_revision(client, server, session, &vault, None, entry)
        .await
        .map_err(|e| js_err(format!("record history: {e}")))?;
    Ok(())
}

#[wasm_bindgen(js_name = wasm_create_folder)]
pub async fn wasm_create_folder(session_value: JsValue, name: String) -> Result<JsValue, JsValue> {
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
    credential_id: Vec<u8>,
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
        #[serde(default)]
        credential_id_b64: Option<String>,
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
            return Err(js_err(format!(
                "salt_b64 must be 32 bytes, got {}",
                salt_v.len()
            )));
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

        let credential_id = match &w.credential_id_b64 {
            None => Vec::new(),
            Some(c) => B64
                .decode(c.as_bytes())
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(c.as_bytes()))
                .map_err(|e| js_err(format!("credential_id_b64: {e}")))?,
        };
        out.push(OwnedPrfEntry {
            rp_id: w.rp_id,
            credential_id,
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
    let (decryptable, recipient_count, legacy_wrap) = match &rage_blob {
        Some(armored) => {
            let a = assess_rage_header(armored, &LocalIdentityInventory::default());
            (a.decryptable, a.recipient_count, a.legacy_prf_wraps > 0)
        }
        None => (true, 0, false),
    };
    let kind = match cipher.cipher_type {
        1 => "login",
        2 => "note",
        3 => "card",
        4 => "identity",
        5 => "ssh_key",
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
        legacy_wrap,
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

    let mut software: Vec<Box<dyn Identity>> = Vec::new();
    for armored in armored_secrets {
        let trusted = ragewarden_core::ArmoredAgeSecret::from_trusted(armored.clone());
        match ragewarden_core::software_passphrase_identity(&trusted) {
            Ok(id) => software.push(Box::new(id)),
            Err(e) => return Err(js_err(format!("software identity: {e}"))),
        }
    }

    let no_match = |e: ragewarden_core::DecryptError| match e {
        ragewarden_core::DecryptError::NoMatchingIdentity => js_err_with_code(
            e.code(),
            "none of this device's identities can open this item; it is wrapped only to \
             keys held elsewhere. Open it on a device that holds one of its keys, or \
             re-wrap it from there.",
        ),
        other => js_err_with_code(other.code(), format!("rage decrypt: {other}")),
    };

    match decrypt_software_first(
        &blob,
        &software,
        !prf_pairs.is_empty(),
        prf_callback.is_some(),
    ) {
        SoftwareFirst::Opened(pt) => Ok(pt.to_vec()),
        SoftwareFirst::Failed(e) => Err(no_match(e)),
        SoftwareFirst::TapUnavailable => Err(js_err_with_code(
            "tap_unavailable",
            "this item is protected by a hardware passkey (webauthn-prf-v1) but the \
             caller supplied no PRF callback, so no tap can be performed in this \
             context. Refusing to decrypt.",
        )),
        SoftwareFirst::NoIdentity => Err(js_err_with_code(
            "no_identity_available",
            "no identity available for this item: no hardware tap was performed and no \
             software or recovery secret was supplied. Ragewarden does not release a secret \
             without a deliberate physical action.",
        )),
        SoftwareFirst::AskPrf => {
            let callback = prf_callback.ok_or_else(|| js_err("internal: PRF callback vanished"))?;
            let chosen = invoke_prf_callback_multi(callback, &prf_pairs).await?;
            let identities: Vec<Box<dyn Identity>> = vec![Box::new(SpecificPasskeyPrfIdentity {
                credential_id: chosen.credential_id,
                prf_output: chosen.prf_output,
            })];
            let pt = core_decrypt(&blob, &identities).map_err(no_match)?;
            Ok(pt.to_vec())
        }
    }
}

struct ChosenPrf {
    credential_id: Vec<u8>,
    prf_output: [u8; 32],
}

async fn invoke_prf_callback_multi(
    callback: &js_sys::Function,
    pairs: &[PrfPair],
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

fn native_unwrappable_stanzas(blob: &[u8]) -> Result<Vec<Stanza>, JsValue> {
    Ok(decide::native_unwrappable(collect_stanzas(blob)?))
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

fn check_stanza_reference(resolved: &JsValue, offered: &[Stanza]) -> Result<(), JsValue> {
    let idx_val = js_sys::Reflect::get(resolved, &JsValue::from_str("stanzaIndex"))
        .map_err(|e| js_err(format!("reflect stanzaIndex: {e:?}")))?;
    let index = if idx_val.is_undefined() || idx_val.is_null() {
        None
    } else {
        Some(
            idx_val
                .as_f64()
                .ok_or_else(|| js_err("native callback returned a non-numeric stanzaIndex"))?,
        )
    };
    let stanza_val = js_sys::Reflect::get(resolved, &JsValue::from_str("stanza"))
        .map_err(|e| js_err(format!("reflect stanza: {e:?}")))?;
    let echoed = if stanza_val.is_undefined() || stanza_val.is_null() {
        None
    } else {
        Some(parse_wire_stanza(&stanza_val)?)
    };
    decide::check_stanza_reference(index, echoed.as_ref(), offered).map_err(js_err)
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

fn collect_webauthn_prf_pairs(blob: &[u8]) -> Result<Vec<PrfPair>, JsValue> {
    decide::webauthn_prf_pairs(&collect_stanzas(blob)?).map_err(js_err)
}

fn json_of(value: &JsValue, what: &str) -> Result<String, JsValue> {
    Ok(js_sys::JSON::stringify(value)
        .map_err(|e| js_err(format!("stringify {what}: {e:?}")))?
        .into())
}

fn parse_field_map(value: &JsValue) -> Result<Vec<(String, String)>, JsValue> {
    decide::parse_field_map(&json_of(value, "fields")?).map_err(js_err)
}

fn parse_recipients(value: &JsValue) -> Result<Vec<Recipient>, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Err(js_err("recipients required"));
    }
    decide::parse_recipients(&json_of(value, "recipients")?).map_err(js_err)
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
            let s = serde_json::to_string(&d).map_err(|e| js_err(format!("serialize doc: {e}")))?;
            js_sys::JSON::parse(&s).map_err(|e| js_err(format!("re-parse to JsValue: {e:?}")))
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
    let local = if local_prf_entry_ids.is_null() || local_prf_entry_ids.is_undefined() {
        None
    } else {
        Some(parse_string_array(&local_prf_entry_ids)?)
    };
    let selection = crate::recipient_select::select_encrypt_recipients(&session, &vault, local)
        .map_err(|e| js_err(format!("read registry: {e}")))?;
    let s = serde_json::to_string(&selection)
        .map_err(|e| js_err(format!("serialize selection: {e}")))?;
    js_sys::JSON::parse(&s).map_err(|e| js_err(format!("re-parse selection: {e:?}")))
}

#[allow(dead_code)]
fn _registry_re_exports() {
    let _: Option<&str> = Some(registry_kinds::FIDO2);
    let _: RegistryDocument = RegistryDocument::default();
}

/// Records the revision an update is about to replace in the account's one
/// history document (core::history), folding in this browser's older per-item
/// documents on the way.
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
    let entry = ragewarden_core::history::HistoryEntry::revision(
        cipher_id,
        prior_payload_armored,
        summary,
        (js_sys::Date::now() as i64).max(0),
    );
    let saved =
        ragewarden_core::history::record_revision(&client, &server, &session, &vault, None, entry)
            .await
            .map_err(|e| js_err(format!("record history: {e}")))?;
    Ok(JsValue::from_str(saved.id.as_deref().unwrap_or("")))
}

/// One item's revisions, newest first, as a JSON array.
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
    let entries = ragewarden_core::history::load_history(&session, &vault, &cipher_id)
        .map_err(|e| js_err(format!("load history: {e}")))?;
    let s =
        serde_json::to_string(&entries).map_err(|e| js_err(format!("serialize history: {e}")))?;
    Ok(JsValue::from_str(&s))
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
