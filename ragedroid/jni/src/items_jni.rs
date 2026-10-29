use std::collections::BTreeMap;

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jbyteArray;
use jni::{Env, EnvUnowned};
use ragewarden_core::history::{self, HistoryEntry};
use ragewarden_core::protected;
use ragewarden_core::sync::{self as core_sync, Cipher, Session};
use zeroize::Zeroizing;

use crate::error::guarded;
use crate::http::{run_async, shared_client};
use crate::{jbyte_array_to_vec, json_out, parse_session_blob, throw_runtime, vec_to_jbyte_array};

/// The plaintext a rage blob seals for `fields_json` (an object of field name
/// to string value) on an item of `cipher_type`: v1 for the primary field
/// alone, the v2 field map otherwise.
pub fn seal_fields(cipher_type: u8, fields_json: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let fields: BTreeMap<String, String> =
        serde_json::from_slice(fields_json).map_err(|e| format!("parse fields: {e}"))?;
    let fields = fields
        .into_iter()
        .map(|(k, v)| (k, Zeroizing::new(v.into_bytes())))
        .collect();
    protected::seal(cipher_type, &fields).map_err(|e| e.to_string())
}

fn cipher_type(t: jni::sys::jint) -> Result<u8, String> {
    u8::try_from(t).map_err(|_| format!("cipher type {t} out of range"))
}

fn session_and_cipher(
    env: &mut Env<'_>,
    session_blob: &JByteArray<'_>,
    cipher_json: &JString<'_>,
) -> Option<(core_sync::Server, Session, Cipher)> {
    let (server, session) = parse_session_blob(env, session_blob)?;
    let parsed = cipher_json
        .try_to_string(env)
        .map_err(|e| e.to_string())
        .and_then(|s: String| serde_json::from_str::<Cipher>(&s).map_err(|e| e.to_string()));
    match parsed {
        Ok(c) => Some((server, session, c)),
        Err(e) => {
            throw_runtime(env, format!("parse cipher: {e}"));
            None
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_sealProtectedFields<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    cipher_type_arg: jni::sys::jint,
    fields_json: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(bytes) = jbyte_array_to_vec(env, &fields_json) else {
            return std::ptr::null_mut();
        };
        let sealed = cipher_type(cipher_type_arg).and_then(|t| seal_fields(t, &bytes));
        match sealed {
            Ok(p) => vec_to_jbyte_array(env, &p),
            Err(e) => throw_runtime(env, format!("seal: {e}")),
        }
    })
}

/// One field of a decrypted rage payload; an empty `field` is the item's
/// primary field.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_protectedField<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    cipher_type_arg: jni::sys::jint,
    plaintext: JByteArray<'local>,
    field: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(bytes) = jbyte_array_to_vec(env, &plaintext) else {
            return std::ptr::null_mut();
        };
        let bytes = Zeroizing::new(bytes);
        let picked = field
            .try_to_string(env)
            .map_err(|e| e.to_string())
            .and_then(|f: String| {
                let t = cipher_type(cipher_type_arg)?;
                protected::field(t, &bytes, &f).map_err(|e| e.to_string())
            });
        match picked {
            Ok(v) => vec_to_jbyte_array(env, &v),
            Err(e) => throw_runtime(env, format!("protected field: {e}")),
        }
    })
}

/// JSON array of the fields `cipherJson`'s rage blob holds (empty for an
/// unprotected item), read from the Type-2 layer with no tap.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_protectedFieldNames<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_json: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((_, session, cipher)) = session_and_cipher(env, &session_blob, &cipher_json)
        else {
            return std::ptr::null_mut();
        };
        match core_sync::protected_field_names(&session, &cipher) {
            Ok(names) => json_out(env, &names, "field names"),
            Err(e) => throw_runtime(env, format!("protected_field_names: {e}")),
        }
    })
}

/// An unprotected field's plaintext (login, notes, card/identity/SSH key
/// block or custom field); null when the item has no such field.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_outerField<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_json: JString<'local>,
    field: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((_, session, cipher)) = session_and_cipher(env, &session_blob, &cipher_json)
        else {
            return std::ptr::null_mut();
        };
        let name: String = match field.try_to_string(env) {
            Ok(s) => s,
            Err(e) => return throw_runtime(env, format!("get_string(field): {e}")),
        };
        match core_sync::outer_field(&session, &cipher, &name) {
            Ok(Some(v)) => vec_to_jbyte_array(env, Zeroizing::new(v.into_bytes()).as_slice()),
            Ok(None) => std::ptr::null_mut(),
            Err(e) => throw_runtime(env, format!("outer_field: {e}")),
        }
    })
}

/// Appends a revision (or, with `deleted`, an item's last value before its
/// deletion) to the account's history document and returns the saved history
/// cipher. `recipientsSummaryJson` is a JSON array of display labels.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_historyRecord<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_id: JString<'local>,
    prior_payload_armored: JString<'local>,
    recipients_summary_json: JByteArray<'local>,
    deleted: jni::sys::jboolean,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let Some(summary_bytes) = jbyte_array_to_vec(env, &recipients_summary_json) else {
            return std::ptr::null_mut();
        };
        let args = (|| -> Result<(String, String, Vec<String>), String> {
            let id: String = cipher_id.try_to_string(env).map_err(|e| e.to_string())?;
            let prior: String = prior_payload_armored
                .try_to_string(env)
                .map_err(|e| e.to_string())?;
            let summary = if summary_bytes.is_empty() {
                Vec::new()
            } else {
                serde_json::from_slice(&summary_bytes).map_err(|e| e.to_string())?
            };
            Ok((id, prior, summary))
        })();
        let (id, prior, summary) = match args {
            Ok(a) => a,
            Err(e) => return throw_runtime(env, format!("history args: {e}")),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let entry = if deleted {
            HistoryEntry::deletion(id, prior, summary, now)
        } else {
            HistoryEntry::revision(id, prior, summary, now)
        };
        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => return throw_runtime(env, format!("http client: {e}")),
        };
        let res = run_async(async {
            let vault = core_sync::fetch_vault(&client, &server, &session)
                .await
                .map_err(|e| e.to_string())?;
            history::record_revision(&client, &server, &session, &vault, None, entry)
                .await
                .map_err(|e| e.to_string())
        });
        match res {
            Ok(saved) => json_out(env, &saved, "history cipher"),
            Err(e) => throw_runtime(env, format!("record history: {e}")),
        }
    })
}

/// JSON array of one item's history entries, newest first.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_historyLoad<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_id: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let id: String = match cipher_id.try_to_string(env) {
            Ok(s) => s,
            Err(e) => return throw_runtime(env, format!("get_string(cipherId): {e}")),
        };
        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => return throw_runtime(env, format!("http client: {e}")),
        };
        let res = run_async(async {
            let vault = core_sync::fetch_vault(&client, &server, &session)
                .await
                .map_err(|e| e.to_string())?;
            history::load_history(&session, &vault, &id).map_err(|e| e.to_string())
        });
        match res {
            Ok(entries) => json_out(env, &entries, "history"),
            Err(e) => throw_runtime(env, format!("load history: {e}")),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealing_picks_v1_for_the_primary_field_and_v2_otherwise() {
        let v1 = seal_fields(1, br#"{"password":"hunter2"}"#).unwrap();
        assert_eq!(&v1[..], b"hunter2");
        let v2 = seal_fields(3, br#"{"number":"4111","code":"123"}"#).unwrap();
        assert!(v2.starts_with(protected::V2_MAGIC));
        assert_eq!(&protected::field(3, &v2, "code").unwrap()[..], b"123");
        assert!(seal_fields(1, b"{}").is_err());
        assert!(seal_fields(1, br#"{"password":1}"#).is_err());
    }
}
