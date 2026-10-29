#![allow(unsafe_code)]
#![warn(rust_2018_idioms)]

use std::str::FromStr;

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as B64};
use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString};
use jni::strings::JNIString;
use jni::sys::{jbyteArray, jobject};
use jni::{Env, EnvUnowned, jni_str};

use ragewarden_core::stanza_format::{
    PivStanzaKind, TAG_FIDO2_HMAC, TAG_PIV_P256, TAG_PIV_X25519_V2, TAG_RAGEDROID_KEYSTORE_V1,
    TAG_RAGEDROID_KEYSTORE_V2, TAG_SCRYPT, TAG_WEBAUTHN_PRF_V1, TAG_X25519, piv_stanza_kind,
};
use ragewarden_core::sync::{
    self as core_sync, CipherIn, Server, Session, build_meta_cipher, build_rage_cipher,
    build_rage_cipher_in_folder, create_cipher, extract_rage_blob, fetch_vault, register,
    update_cipher,
};
use ragewarden_core::{AgeBlob, Identity, PrfEntry, Recipient, decrypt, encrypt, encrypt_with_prf};

mod error;
mod http;
mod items_jni;
mod jni_identity;
mod lock_jni;
mod sync_jni;

use error::{ExKind, guarded, throw_kind};
use http::{run_async, shared_client};
use jni_identity::JniIdentity;
use sync_jni::{
    CardDto, IdentityDto, RegisterResultDto, SessionDto, SshDto, VaultDto, VaultItemDto,
};

macro_rules! or_throw {
    ($env:expr, $res:expr, $ctx:literal) => {
        match $res {
            Ok(v) => v,
            Err(e) => return throw_runtime($env, format!(concat!($ctx, ": {}"), e)),
        }
    };
}

fn json_out<T: serde::Serialize>(env: &mut Env<'_>, v: &T, what: &str) -> jbyteArray {
    match serde_json::to_vec(v) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode {what}: {e}")),
    }
}

fn throw_runtime(env: &mut Env<'_>, msg: impl std::fmt::Display) -> jbyteArray {
    let _ = env.throw_new(
        jni_str!("java/lang/RuntimeException"),
        JNIString::from(msg.to_string()),
    );
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_initTls<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    #[cfg_attr(not(target_os = "android"), allow(unused_variables))] context: JObject<'local>,
) {
    #[cfg(target_os = "android")]
    guarded(env, |env| {
        if let Err(e) = rustls_platform_verifier::android::init_with_env(env, context) {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("rustls-platform-verifier init failed: {e:?}")),
            );
        }
    });
    #[cfg(not(target_os = "android"))]
    {
        let _ = (env, context);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(
    _vm: *mut std::ffi::c_void,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".into());
        let msg = if cfg!(debug_assertions) {
            format!("PANIC at {} :: {}", loc, info)
        } else {
            format!("PANIC at {}", loc)
        };
        eprintln!("[ragedroid-jni] {}", msg);
        #[cfg(target_os = "android")]
        // SAFETY: liblog's __android_log_write reads two NUL-terminated strings, both
        // owned here for the duration of the call.
        unsafe {
            unsafe extern "C" {
                fn __android_log_write(prio: i32, tag: *const u8, text: *const u8) -> i32;
            }
            let mut buf = msg.into_bytes();
            buf.push(0);
            __android_log_write(6, b"ragedroid-jni\0".as_ptr(), buf.as_ptr());
        }
    }));
    jni::sys::JNI_VERSION_1_6
}

fn jbyte_array_to_vec(env: &mut Env<'_>, arr: &JByteArray<'_>) -> Option<Vec<u8>> {
    match env.convert_byte_array(arr) {
        Ok(v) => Some(v),
        Err(e) => {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("byte[] convert: {e}")),
            );
            None
        }
    }
}

fn vec_to_jbyte_array(env: &mut Env<'_>, bytes: &[u8]) -> jbyteArray {
    match env.byte_array_from_slice(bytes) {
        Ok(arr) => arr.into_raw(),
        Err(e) => throw_runtime(env, format!("byte[] alloc: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_selfTestPanic<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jni::sys::jint {
    guarded(env, |_env| panic!("selfTestPanic"))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_smoke<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jni::sys::jstring {
    guarded(env, |env| match env.new_string("ragedroid-jni linked") {
        Ok(s) => s.into_raw(),
        Err(e) => {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("smoke: {e}")),
            );
            std::ptr::null_mut()
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_encrypt<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    plaintext: JByteArray<'local>,
    recipient_pubkey: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(plaintext_bytes) = jbyte_array_to_vec(env, &plaintext) else {
            return std::ptr::null_mut();
        };
        let Some(pubkey_bytes) = jbyte_array_to_vec(env, &recipient_pubkey) else {
            return std::ptr::null_mut();
        };

        if pubkey_bytes.len() != 32 {
            return throw_kind(
                env,
                ExKind::MalformedStanza,
                format!(
                    "recipient pubkey must be 32 bytes, got {}",
                    pubkey_bytes.len()
                ),
            );
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_bytes);

        let recipient = Recipient::X25519 { public_key: pubkey };
        let blob = match encrypt(&plaintext_bytes, &[recipient]) {
            Ok(b) => b,
            Err(e) => return throw_kind(env, ExKind::AeadFailure, format!("encrypt: {e}")),
        };

        vec_to_jbyte_array(env, blob.as_bytes())
    })
}

/// One PRF evaluation from Kotlin. `credential_id` names the credential that
/// evaluated `salt`; when it is empty the entry names the recipient enrolled
/// with that salt (the per-recipient form; see `core::PrfEntry`).
#[derive(serde::Deserialize)]
struct PrfInputDto {
    rp_id: String,
    #[serde(default)]
    credential_id: Vec<u8>,
    salt: [u8; 32],
    prf_output: [u8; 32],
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_encryptToRecipients<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    plaintext: JByteArray<'local>,
    recipients_json: JByteArray<'local>,
    prf_inputs_json: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(plaintext_bytes) = jbyte_array_to_vec(env, &plaintext) else {
            return std::ptr::null_mut();
        };
        let Some(recipients_bytes) = jbyte_array_to_vec(env, &recipients_json) else {
            return std::ptr::null_mut();
        };
        let Some(prf_inputs_bytes) = jbyte_array_to_vec(env, &prf_inputs_json) else {
            return std::ptr::null_mut();
        };

        let recipients: Vec<Recipient> = match serde_json::from_slice(&recipients_bytes) {
            Ok(v) => v,
            Err(e) => {
                return throw_kind(
                    env,
                    ExKind::MalformedStanza,
                    format!("recipients_json: {e}"),
                );
            }
        };

        let prf_owned: Vec<PrfInputDto> = if prf_inputs_bytes.is_empty() {
            Vec::new()
        } else {
            match serde_json::from_slice(&prf_inputs_bytes) {
                Ok(v) => v,
                Err(e) => {
                    return throw_kind(
                        env,
                        ExKind::MalformedStanza,
                        format!("prf_inputs_json: {e}"),
                    );
                }
            }
        };

        let prf_table: Vec<PrfEntry<'_>> = prf_owned
            .iter()
            .map(|p| PrfEntry {
                rp_id: p.rp_id.as_str(),
                credential_id: &p.credential_id,
                salt: &p.salt,
                prf_output: &p.prf_output,
            })
            .collect();

        let blob = match encrypt_with_prf(&plaintext_bytes, &recipients, &prf_table) {
            Ok(b) => b,
            Err(e) => return throw_kind(env, ExKind::AeadFailure, format!("encrypt: {e}")),
        };

        vec_to_jbyte_array(env, blob.as_bytes())
    })
}

/// The canonical recipient-selection policy, reached from Kotlin.
///
/// `BitwardenVaultRepository.collectActiveRecipients` used to reimplement this
/// in Kotlin and threw `RecipientKind.Software` away, so an item written on the
/// phone had no stanza for the terminal's or the browser's software key and was
/// cryptographically unopenable there -- silently, with the save reporting
/// success. rageterm and ragemanifest each had their own different filter. All
/// three now run `ragewarden_core::policy::select_for_encrypt`.
///
/// In:  `registry_json` and `local_json` are `registry::WireDocument`s (the
///      cross-device registry and this device's own entries);
///      `local_prf_ids_json` is a JSON array of registry ids whose
///      authenticator this device can evaluate during a wrap -- the one
///      sanctioned per-client divergence.
/// Out: `policy::Selection` as JSON. `recipients` is exactly what
///      `encryptToRecipients` consumes; `skipped` carries a named reason per
///      dropped entry so the caller can warn instead of losing coverage
///      quietly.
/// The Android route into the shared recipient policy: the registry and
/// local-recipient documents and the ids of the PRF authenticators this
/// device holds, each as the JSON Kotlin passes (empty = none).
fn select_encrypt_recipients(
    registry_json: &[u8],
    local_json: &[u8],
    local_prf_ids_json: &[u8],
) -> Result<ragewarden_core::policy::Selection, String> {
    use ragewarden_core::policy;
    use ragewarden_core::registry::WireDocument;
    fn parse_doc(bytes: &[u8], what: &str) -> Result<WireDocument, String> {
        if bytes.is_empty() {
            return Ok(WireDocument::default());
        }
        serde_json::from_slice(bytes).map_err(|e| format!("{what}: {e}"))
    }
    let registry = parse_doc(registry_json, "registry_json")?;
    let local = parse_doc(local_json, "local_json")?;
    let prf_ids: Vec<String> = if local_prf_ids_json.is_empty() {
        Vec::new()
    } else {
        serde_json::from_slice(local_prf_ids_json)
            .map_err(|e| format!("local_prf_ids_json: {e}"))?
    };
    Ok(policy::select_for_encrypt(
        &registry.entries,
        &local.entries,
        &policy::LocalAuthenticators::from_ids(prf_ids),
    ))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_selectEncryptRecipients<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    registry_json: JByteArray<'local>,
    local_json: JByteArray<'local>,
    local_prf_ids_json: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(registry_bytes) = jbyte_array_to_vec(env, &registry_json) else {
            return std::ptr::null_mut();
        };
        let Some(local_bytes) = jbyte_array_to_vec(env, &local_json) else {
            return std::ptr::null_mut();
        };
        let Some(prf_ids_bytes) = jbyte_array_to_vec(env, &local_prf_ids_json) else {
            return std::ptr::null_mut();
        };
        let selection = or_throw!(
            env,
            select_encrypt_recipients(&registry_bytes, &local_bytes, &prf_ids_bytes),
            "select_encrypt_recipients"
        );
        json_out(env, &selection, "selection")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_decryptWithSoftwareSecret<
    'local,
>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    blob: JByteArray<'local>,
    armored_secret: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(blob_bytes) = jbyte_array_to_vec(env, &blob) else {
            return std::ptr::null_mut();
        };
        let armored: String = or_throw!(env, armored_secret.try_to_string(env), "get_string");

        let secret = ragewarden_core::ArmoredAgeSecret::from_trusted(armored.trim().to_string());
        let identity = match ragewarden_core::software_passphrase_identity(&secret) {
            Ok(id) => id,
            Err(e) => {
                return throw_kind(env, ExKind::MalformedStanza, format!("identity parse: {e}"));
            }
        };
        let identities: Vec<Box<dyn Identity>> = vec![Box::new(identity)];

        let blob = AgeBlob::from_bytes(blob_bytes);
        let plaintext = match decrypt(&blob, &identities) {
            Ok(p) => p,
            Err(e) => return throw_kind(env, ExKind::IdentityMissing, format!("decrypt: {e}")),
        };

        vec_to_jbyte_array(env, &plaintext)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_generateSoftwareIdentity<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jni::sys::jstring {
    guarded(env, |env| {
        let secret = age::x25519::Identity::generate();
        match env.new_string(secret.to_string().expose_secret()) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                let _ = env.throw_new(
                    jni_str!("java/lang/RuntimeException"),
                    JNIString::from(format!("generateSoftwareIdentity: {e}")),
                );
                std::ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_pubkeyFromArmoredSecret<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    armored_secret: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let armored: String = or_throw!(env, armored_secret.try_to_string(env), "get_string");
        let secret = match age::x25519::Identity::from_str(armored.trim()) {
            Ok(s) => s,
            Err(e) => {
                return throw_kind(env, ExKind::MalformedStanza, format!("identity parse: {e}"));
            }
        };
        let pubkey_armored = secret.to_public().to_string();
        let raw = match ragewarden_core::bech32::decode_age_x25519(&pubkey_armored) {
            Some(r) => r,
            None => {
                return throw_kind(
                    env,
                    ExKind::MalformedStanza,
                    "could not bech32-decode age public key from secret",
                );
            }
        };
        vec_to_jbyte_array(env, &raw)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_totpGenerate<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    uri_or_secret: JString<'local>,
) -> jni::sys::jstring {
    guarded(env, |env| {
        let input: String = match uri_or_secret.try_to_string(env) {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new(
                    jni_str!("java/lang/RuntimeException"),
                    JNIString::from(format!("get_string: {e}")),
                );
                return std::ptr::null_mut();
            }
        };
        let code = match ragewarden_core::totp::generate_for_uri_or_secret(&input) {
            Ok(c) => c,
            Err(e) => {
                let _ = env.throw_new(
                    jni_str!("java/lang/RuntimeException"),
                    JNIString::from(format!("totp: {e}")),
                );
                return std::ptr::null_mut();
            }
        };
        let formatted = format!("{} {} {}", code.code, code.seconds_remaining, code.period);
        match env.new_string(&formatted) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                let _ = env.throw_new(
                    jni_str!("java/lang/RuntimeException"),
                    JNIString::from(format!("new_string: {e}")),
                );
                std::ptr::null_mut()
            }
        }
    })
}

/// `core::generator::password`, the generator every client shares.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_generatePassword<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    length: jni::sys::jint,
    lowercase: jni::sys::jboolean,
    uppercase: jni::sys::jboolean,
    digits: jni::sys::jboolean,
    symbols: jni::sys::jboolean,
) -> jni::sys::jstring {
    guarded(env, |env| {
        let policy = ragewarden_core::generator::PasswordPolicy {
            length: usize::try_from(length).unwrap_or(0),
            lowercase: lowercase == jni::sys::JNI_TRUE,
            uppercase: uppercase == jni::sys::JNI_TRUE,
            digits: digits == jni::sys::JNI_TRUE,
            symbols: symbols == jni::sys::JNI_TRUE,
        };
        generated_to_jstring(env, ragewarden_core::generator::password(&policy))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_generatePassphrase<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    words: jni::sys::jint,
    separator: JString<'local>,
) -> jni::sys::jstring {
    guarded(env, |env| {
        let separator: String = or_throw!(env, separator.try_to_string(env), "separator");
        let words = usize::try_from(words).unwrap_or(0);
        generated_to_jstring(
            env,
            ragewarden_core::generator::passphrase(words, &separator),
        )
    })
}

fn generated_to_jstring(
    env: &mut Env<'_>,
    generated: Result<zeroize::Zeroizing<String>, ragewarden_core::generator::GeneratorError>,
) -> jni::sys::jstring {
    match generated {
        Ok(s) => match env.new_string(s.as_str()) {
            Ok(j) => j.into_raw(),
            Err(e) => {
                let _ = env.throw_new(
                    jni_str!("java/lang/RuntimeException"),
                    JNIString::from(format!("new_string: {e}")),
                );
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            let _ = env.throw_new(
                jni_str!("java/lang/IllegalArgumentException"),
                JNIString::from(format!("generate: {e}")),
            );
            std::ptr::null_mut()
        }
    }
}

use secrecy::ExposeSecret;

fn build_server_or_throw(env: &mut Env<'_>, api_url: &str, identity_url: &str) -> Option<Server> {
    let server = Server::new(api_url, identity_url);
    if let Err(e) = server.require_secure() {
        let _ = env.throw_new(
            jni_str!("java/lang/RuntimeException"),
            JNIString::from(format!("server URL not https / loopback: {e}")),
        );
        return None;
    }
    Some(server)
}

fn server_from_url(env: &mut Env<'_>, server_url: &str) -> Option<Server> {
    let server = Server::self_hosted(server_url);
    if let Err(e) = server.require_secure() {
        let _ = env.throw_new(
            jni_str!("java/lang/RuntimeException"),
            JNIString::from(format!("server URL not https / loopback: {e}")),
        );
        return None;
    }
    Some(server)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_register<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    server_url: JString<'local>,
    email: JString<'local>,
    password: JString<'local>,
    name: JString<'local>,
    kdf_iterations: jni::sys::jint,
) -> jbyteArray {
    guarded(env, |env| {
        let server_url: String =
            or_throw!(env, server_url.try_to_string(env), "get_string(serverUrl)");
        let email: String = or_throw!(env, email.try_to_string(env), "get_string(email)");
        let password: String = or_throw!(env, password.try_to_string(env), "get_string(password)");
        let name: String = or_throw!(env, name.try_to_string(env), "get_string(name)");

        let Some(server) = server_from_url(env, &server_url) else {
            return std::ptr::null_mut();
        };
        let client = or_throw!(env, shared_client(), "http client");

        let res = run_async(async {
            register(
                &client,
                &server,
                &email,
                &password,
                &name,
                kdf_iterations as u32,
            )
            .await
        });
        let out = or_throw!(env, res, "register");
        let dto = RegisterResultDto {
            email: out.email,
            kdf_iterations: out.kdf.iterations,
            kdf_type: out.kdf.kdf,
        };
        json_out(env, &dto, "RegisterResult")
    })
}

fn session_from_dto_or_throw(env: &mut Env<'_>, dto: &SessionDto) -> Option<(Server, Session)> {
    let server = build_server_or_throw(env, &dto.api_url, &dto.identity_url)?;
    let user_enc_key = match B64.decode(&dto.user_enc_key_b64) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("decode user_enc_key_b64: {e}")),
            );
            return None;
        }
    };
    let user_mac_key = match B64.decode(&dto.user_mac_key_b64) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("decode user_mac_key_b64: {e}")),
            );
            return None;
        }
    };
    let session = Session {
        access_token: dto.access_token.clone(),
        refresh_token: dto.refresh_token.clone(),
        user_id: dto.user_id.clone(),
        email: dto.email.clone(),
        user_enc_key: user_enc_key.into(),
        user_mac_key: user_mac_key.into(),
        kdf: core_sync::KdfParams::from_parts(
            dto.kdf_type,
            dto.kdf_iterations,
            dto.kdf_memory_mib,
            dto.kdf_parallelism,
        ),
        device_id: dto.device_id.clone(),
    };
    Some((server, session))
}

fn parse_session_blob(env: &mut Env<'_>, blob: &JByteArray<'_>) -> Option<(Server, Session)> {
    let bytes = jbyte_array_to_vec(env, blob)?;
    let dto: SessionDto = match serde_json::from_slice(&bytes) {
        Ok(d) => d,
        Err(e) => {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("parse Session: {e}")),
            );
            return None;
        }
    };
    session_from_dto_or_throw(env, &dto)
}

fn cipher_in_from_json(bytes: &[u8]) -> Result<CipherIn, serde_json::Error> {
    serde_json::from_slice(bytes)
}

fn build_vault_dto(session: &Session, vault: &core_sync::Vault) -> VaultDto {
    use rayon::prelude::*;

    let folder_names: std::collections::BTreeMap<String, String> = vault
        .folders
        .par_iter()
        .filter_map(|f| {
            core_sync::decrypt_string(session, &f.name)
                .ok()
                .map(|n| (f.id.clone(), n))
        })
        .collect();
    let items: Vec<VaultItemDto> = vault
        .ciphers
        .par_iter()
        .map(|c| shape_cipher(session, c, &folder_names))
        .collect();
    VaultDto { items }
}

/// Recipient descriptors parsed out of an armored age blob's header.
///
/// Replaces a hardcoded `vec!["software-demo"]`, which matched no recipient id
/// the Kotlin side had ever seen. Because `VaultItem.recipients` was therefore
/// always empty after the lookup in `ItemDetailScreen`, every rage-protected
/// item rendered the "Set up this device" card instead of the reveal controls --
/// the main reveal path was unreachable for exactly the items the product exists
/// to protect -- and the multi-identity picker (`recipients.size > 1`) could
/// never open.
///
/// Descriptors are `"<stanza tag>:<identifying arg>"` and are matched against
/// locally derivable values on the Kotlin side
/// (`data/RecipientDescriptors.kt`); no key material or private state is
/// involved, everything here is already public in the blob header.
///
/// `X25519` stanzas are emitted bare: age's X25519 arg is the *ephemeral* share,
/// so a software/paper recipient genuinely cannot be identified from the header
/// without its private key. Reporting them as an anonymous count is the honest
/// answer; inventing an id for them would be worse than saying nothing.
///
/// The result is a **list, not a set**: one entry per recognised stanza, in
/// header order, duplicates kept. Two software recipients must not look like
/// one -- the length is user-visible (`recipients.size > 1` opens the
/// multi-identity picker, and the reveal sheet says "N software or paper
/// recipient(s)"), and `RecipientDescriptors.resolve` on the Kotlin side counts
/// anonymous recipients per element. A previous `if !out.contains(&descriptor)`
/// dedup collapsed every `X25519` stanza into one, so an item wrapped to two
/// software keys reported one.
///
/// Unrecognised tags are **dropped, not reported**. age writes a random
/// anti-ossification GREASE stanza into every non-scrypt header
/// (`age-core::format::grease_the_joint`, tag `"<1-8 random printable>-grease"`,
/// 0-4 random args), and a catch-all `other => other.to_string()` turned it into
/// a recipient: a single-recipient item rendered "RAGE · 2", and because the
/// grease tag is fresh per encryption the miscount was not reproducible. It
/// would also have surfaced as a phantom hardware key via
/// `Resolution.unknownHardware`. Only tags this project or age itself defines
/// name a real recipient, so only those are emitted.
fn rage_recipient_descriptors(armored: &str) -> Vec<String> {
    let recorder = StanzaRecorder::default();
    let seen = recorder.seen();
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(recorder)];
    let _ = decrypt(&AgeBlob::from_bytes(armored.as_bytes()), &identities);

    let stanzas = seen.lock().unwrap_or_else(|e| e.into_inner());
    stanzas.iter().filter_map(stanza_descriptor).collect()
}

/// The descriptor a single header stanza contributes, or `None` if the stanza
/// does not name a recipient (GREASE, or a tag from some future age plugin we
/// cannot speak for). A descriptor names the recipient, not the stanza
/// format: every PIV shape reads `piv-p256:<recipient tag>` and both keystore
/// versions read `ragedroid-keystore-v1:<handle>`, so `RecipientDescriptors`
/// matches a recipient whichever version wrapped it.
fn stanza_descriptor(s: &ragewarden_core::Stanza) -> Option<String> {
    let args = &s.args;
    match s.tag.as_str() {
        TAG_X25519 | TAG_SCRYPT => Some(s.tag.clone()),
        TAG_PIV_P256 | TAG_PIV_X25519_V2 => match piv_stanza_kind(s)? {
            PivStanzaKind::X25519V1 | PivStanzaKind::X25519V2 => {
                Some(format!("{TAG_PIV_P256}:{}", args[1]))
            }
            PivStanzaKind::P256 => Some(format!("{TAG_PIV_P256}:{}", args[0])),
        },
        TAG_RAGEDROID_KEYSTORE_V1 | TAG_RAGEDROID_KEYSTORE_V2 if args.len() == 2 => {
            Some(format!("{TAG_RAGEDROID_KEYSTORE_V1}:{}", args[0]))
        }
        TAG_FIDO2_HMAC if !args.is_empty() => Some(format!("{TAG_FIDO2_HMAC}:{}", args[0])),
        TAG_WEBAUTHN_PRF_V1 if !args.is_empty() => {
            Some(format!("{TAG_WEBAUTHN_PRF_V1}:{}", args[0]))
        }
        _ => None,
    }
}

/// An identity that unwraps nothing and remembers every stanza it was offered.
///
/// `core::decrypt` hands each header stanza to each identity in turn until one
/// claims it; answering "not mine" to all of them yields the full recipient
/// list as a side effect, which is the only way to read an age header through
/// age's parser without a private key. `Identity` is `Send + Sync`, hence the
/// `Mutex` rather than a `RefCell`.
#[derive(Default)]
struct StanzaRecorder {
    seen: std::sync::Arc<std::sync::Mutex<Vec<ragewarden_core::Stanza>>>,
}

impl StanzaRecorder {
    fn seen(&self) -> std::sync::Arc<std::sync::Mutex<Vec<ragewarden_core::Stanza>>> {
        std::sync::Arc::clone(&self.seen)
    }
}

impl Identity for StanzaRecorder {
    fn try_unwrap_stanza(
        &self,
        stanza: &ragewarden_core::Stanza,
    ) -> Result<Option<ragewarden_core::FileKey>, ragewarden_core::IdentityError> {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(stanza.clone());
        Ok(None)
    }

    fn display(&self) -> &str {
        "stanza-recorder"
    }
}

fn shape_cipher(
    session: &Session,
    c: &core_sync::Cipher,
    folder_names: &std::collections::BTreeMap<String, String>,
) -> VaultItemDto {
    let id = c.id.clone().unwrap_or_default();
    let name = core_sync::decrypt_string(session, &c.name).unwrap_or_default();
    let folder = c
        .folder_id
        .as_ref()
        .and_then(|fid| folder_names.get(fid).cloned())
        .unwrap_or_else(|| "All".to_string());
    let rage_blob = extract_rage_blob(session, c).ok().flatten();
    let rage = rage_blob.is_some();
    let protected_fields = if rage {
        core_sync::protected_field_names(session, c).unwrap_or_default()
    } else {
        Vec::new()
    };
    let open = |name: &str, v: Option<String>| -> Option<String> {
        v.filter(|s| {
            s != core_sync::RAGE_MARKER_NOTE && !protected_fields.iter().any(|p| p == name)
        })
    };
    let (username, plain_password, totp_seed) = if let Some(login) = &c.login {
        let u = login
            .username
            .as_ref()
            .and_then(|s| core_sync::decrypt_string(session, s).ok())
            .unwrap_or_default();
        let p = if rage {
            String::new()
        } else {
            login
                .password
                .as_ref()
                .and_then(|s| core_sync::decrypt_string(session, s).ok())
                .unwrap_or_default()
        };
        let t = login
            .totp
            .as_ref()
            .and_then(|s| core_sync::decrypt_string(session, s).ok());
        (u, p, open("totp", t))
    } else {
        (String::new(), String::new(), None)
    };
    let site = c
        .login
        .as_ref()
        .and_then(|l| l.uris.as_ref())
        .and_then(|uris| uris.first())
        .and_then(|u| core_sync::decrypt_string(session, &u.uri).ok())
        .unwrap_or_default();
    let notes = open(
        "notes",
        c.notes
            .as_ref()
            .and_then(|s| core_sync::decrypt_string(session, s).ok()),
    );
    let recipients: Vec<String> = match &rage_blob {
        Some(armored) => rage_recipient_descriptors(armored),
        None => Vec::new(),
    };
    let dec = |t: &Option<ragewarden_core::Type2EncString>| -> Option<String> {
        t.as_ref()
            .and_then(|s| core_sync::decrypt_string(session, s).ok())
    };
    let card = c.card.as_ref().map(|cc| CardDto {
        cardholder_name: open("cardholderName", dec(&cc.cardholder_name)),
        brand: open("brand", dec(&cc.brand)),
        number: open("number", dec(&cc.number)),
        exp_month: open("expMonth", dec(&cc.exp_month)),
        exp_year: open("expYear", dec(&cc.exp_year)),
        code: open("code", dec(&cc.code)),
    });
    let identity = c.identity.as_ref().map(|ci| IdentityDto {
        first_name: open("firstName", dec(&ci.first_name)),
        middle_name: open("middleName", dec(&ci.middle_name)),
        last_name: open("lastName", dec(&ci.last_name)),
        address1: open("address1", dec(&ci.address1)),
        address2: open("address2", dec(&ci.address2)),
        address3: open("address3", dec(&ci.address3)),
        city: open("city", dec(&ci.city)),
        state: open("state", dec(&ci.state)),
        postal_code: open("postalCode", dec(&ci.postal_code)),
        country: open("country", dec(&ci.country)),
        phone: open("phone", dec(&ci.phone)),
        email: open("email", dec(&ci.email)),
        ssn: open("ssn", dec(&ci.ssn)),
        passport_number: open("passportNumber", dec(&ci.passport_number)),
        dob: open("dob", dec(&ci.dob)),
    });
    let ssh = c.ssh_key.as_ref().map(|sk| SshDto {
        key_type: open("keyType", dec(&sk.key_type)),
        fingerprint: open(
            "keyFingerprint",
            dec(&sk.key_fingerprint).or_else(|| dec(&sk.fingerprint)),
        ),
        public_key: open("publicKey", dec(&sk.public_key)),
        private_key: open("privateKey", dec(&sk.private_key)),
        comment: open("comment", dec(&sk.comment)),
        passphrase: open("passphrase", dec(&sk.passphrase)),
    });
    VaultItemDto {
        id,
        name,
        username,
        site,
        folder,
        folder_id: c.folder_id.clone(),
        rage,
        recipients,
        last_used: String::new(),
        history: 0,
        rage_blob,
        plain_password,
        totp_seed,
        notes,
        favorite: c.favorite,
        cipher_type: c.cipher_type,
        card,
        identity,
        ssh,
        protected_fields,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_extractRageBlob<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_json: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((_server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let cipher_str: String = or_throw!(
            env,
            cipher_json.try_to_string(env),
            "get_string(cipherJson)"
        );
        let cipher: core_sync::Cipher =
            or_throw!(env, serde_json::from_str(&cipher_str), "parse cipher");
        match extract_rage_blob(&session, &cipher) {
            Ok(Some(blob)) => vec_to_jbyte_array(env, blob.as_bytes()),
            Ok(None) => std::ptr::null_mut(),
            Err(e) => throw_runtime(env, format!("extract_rage_blob: {e}")),
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_buildRageCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    name: JString<'local>,
    armored_blob: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((_server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let name_s: String = or_throw!(env, name.try_to_string(env), "get_string(name)");
        let armored: String = or_throw!(
            env,
            armored_blob.try_to_string(env),
            "get_string(armoredBlob)"
        );
        let cipher_in = or_throw!(
            env,
            build_rage_cipher(&session, &name_s, &armored),
            "build_rage_cipher"
        );
        json_out(env, &cipher_in, "CipherIn")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_buildRageCipherInFolder<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    name: JString<'local>,
    armored_blob: JString<'local>,
    folder_id: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((_server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let name_s: String = or_throw!(env, name.try_to_string(env), "get_string(name)");
        let armored: String = or_throw!(
            env,
            armored_blob.try_to_string(env),
            "get_string(armoredBlob)"
        );
        let folder_str: Option<String> = if folder_id.is_null() {
            None
        } else {
            match folder_id.try_to_string(env) {
                Ok(s) => {
                    let v: String = s;
                    if v.is_empty() { None } else { Some(v) }
                }
                Err(e) => return throw_runtime(env, format!("get_string(folderId): {e}")),
            }
        };
        let cipher_in =
            match build_rage_cipher_in_folder(&session, &name_s, &armored, folder_str.as_deref()) {
                Ok(c) => c,
                Err(e) => return throw_runtime(env, format!("build_rage_cipher_in_folder: {e}")),
            };
        json_out(env, &cipher_in, "CipherIn")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_buildMetaCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    name: JString<'local>,
    notes: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((_server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let name_s: String = or_throw!(env, name.try_to_string(env), "get_string(name)");
        let notes_s: String = or_throw!(env, notes.try_to_string(env), "get_string(notes)");
        let cipher_in = or_throw!(
            env,
            build_meta_cipher(&session, &name_s, &notes_s),
            "build_meta_cipher"
        );
        json_out(env, &cipher_in, "CipherIn")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_createCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_in_json: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let Some(bytes) = jbyte_array_to_vec(env, &cipher_in_json) else {
            return std::ptr::null_mut();
        };
        let cipher_in = or_throw!(env, cipher_in_from_json(&bytes), "parse CipherIn");
        let client = or_throw!(env, shared_client(), "http client");
        let res = run_async(async { create_cipher(&client, &server, &session, &cipher_in).await });
        let saved = or_throw!(env, res, "create_cipher");
        json_out(env, &saved, "Cipher")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_updateCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_id: JString<'local>,
    cipher_in_json: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let id: String = or_throw!(env, cipher_id.try_to_string(env), "get_string(cipherId)");
        let Some(bytes) = jbyte_array_to_vec(env, &cipher_in_json) else {
            return std::ptr::null_mut();
        };
        let cipher_in = or_throw!(env, cipher_in_from_json(&bytes), "parse CipherIn");
        let client = or_throw!(env, shared_client(), "http client");
        let res = run_async(async {
            let existing = core_sync::get_cipher(&client, &server, &session, &id).await?;
            let merged = core_sync::overlay_preserving(&session, &existing, &cipher_in)?;
            update_cipher(&client, &server, &session, &id, &merged).await
        });
        let saved = or_throw!(env, res, "update_cipher");
        json_out(env, &saved, "Cipher")
    })
}

fn optional_jstring(env: &mut Env<'_>, s: &JString<'_>) -> Result<Option<String>, String> {
    if s.is_null() {
        return Ok(None);
    }
    s.try_to_string(env)
        .map(|v: String| Some(v))
        .map_err(|e| e.to_string())
}

/// A new item from a JSON [`core_sync::CipherDraft`]; `armoredBlob` null builds
/// an unprotected item.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_buildCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    draft_json: JByteArray<'local>,
    armored_blob: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((_server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let Some(bytes) = jbyte_array_to_vec(env, &draft_json) else {
            return std::ptr::null_mut();
        };
        let draft: core_sync::CipherDraft =
            or_throw!(env, serde_json::from_slice(&bytes), "parse CipherDraft");
        let armored = or_throw!(
            env,
            optional_jstring(env, &armored_blob),
            "get_string(armoredBlob)"
        );
        let cipher_in = or_throw!(
            env,
            core_sync::build_cipher(&session, &draft, armored.as_deref()),
            "build_cipher"
        );
        json_out(env, &cipher_in, "CipherIn")
    })
}

/// Read-modify-write of one server cipher: applies a JSON
/// [`core_sync::CipherEdit`] and, when `armoredBlob` is non-null, sets its rage
/// blob, keeping every other field the server holds.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_updateCipherPreserving<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_id: JString<'local>,
    armored_blob: JString<'local>,
    edit_json: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let id: String = or_throw!(env, cipher_id.try_to_string(env), "get_string(cipherId)");
        let armored = or_throw!(
            env,
            optional_jstring(env, &armored_blob),
            "get_string(armoredBlob)"
        );
        let Some(bytes) = jbyte_array_to_vec(env, &edit_json) else {
            return std::ptr::null_mut();
        };
        let edit: core_sync::CipherEdit =
            or_throw!(env, serde_json::from_slice(&bytes), "parse CipherEdit");
        let client = or_throw!(env, shared_client(), "http client");
        let res = run_async(async {
            core_sync::update_preserving(&client, &server, &session, &id, armored.as_deref(), &edit)
                .await
        });
        let saved = or_throw!(env, res, "update_preserving");
        json_out(env, &saved, "Cipher")
    })
}

/// Moves a cipher to `folderId` (null clears it) without touching any encrypted
/// field.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_setFolder<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_id: JString<'local>,
    folder_id: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let id: String = or_throw!(env, cipher_id.try_to_string(env), "get_string(cipherId)");
        let folder = or_throw!(
            env,
            optional_jstring(env, &folder_id),
            "get_string(folderId)"
        );
        let client = or_throw!(env, shared_client(), "http client");
        let res = run_async(async {
            core_sync::set_folder_on(&client, &server, &session, &id, folder.as_deref()).await
        });
        let saved = or_throw!(env, res, "set_folder");
        json_out(env, &saved, "Cipher")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_unwrapStanza<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    stanza_tag: JString<'local>,
    stanza_args: JObjectArray<'local, JString<'local>>,
    stanza_body: JByteArray<'local>,
    secret: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        unwrap_stanza_jni(env, &stanza_tag, &stanza_args, &stanza_body, &secret, None)
    })
}

/// `unwrapStanza` for the stanzas that bind the recipient's own public key
/// into their body key (`piv-x25519-v2`, `ragedroid-keystore-v2`, and
/// `age-plugin-yubikey`'s P-256 `piv-p256`): `recipientPublicKey` is the
/// device key's public key (32 raw bytes for X25519, 33 compressed SEC1 bytes
/// for P-256). The v1 formats ignore it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_unwrapStanzaForRecipient<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    stanza_tag: JString<'local>,
    stanza_args: JObjectArray<'local, JString<'local>>,
    stanza_body: JByteArray<'local>,
    secret: JByteArray<'local>,
    recipient_public_key: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(recipient) = jbyte_array_to_vec(env, &recipient_public_key) else {
            return std::ptr::null_mut();
        };
        unwrap_stanza_jni(
            env,
            &stanza_tag,
            &stanza_args,
            &stanza_body,
            &secret,
            Some(recipient),
        )
    })
}

fn unwrap_stanza_jni(
    env: &mut Env<'_>,
    stanza_tag: &JString<'_>,
    stanza_args: &JObjectArray<'_, JString<'_>>,
    stanza_body: &JByteArray<'_>,
    secret: &JByteArray<'_>,
    recipient_public_key: Option<Vec<u8>>,
) -> jbyteArray {
    let tag: String = or_throw!(env, stanza_tag.try_to_string(env), "stanzaTag");
    let Some(args) = jstring_array_to_vec(env, stanza_args) else {
        return std::ptr::null_mut();
    };
    let Some(body) = jbyte_array_to_vec(env, stanza_body) else {
        return std::ptr::null_mut();
    };
    let Some(secret_bytes) = jbyte_array_to_fixed::<32>(env, secret, "secret") else {
        return std::ptr::null_mut();
    };
    let stanza = ragewarden_core::Stanza {
        tag: tag.clone(),
        args,
        body,
    };
    match unwrap_with_secret(&stanza, &secret_bytes, recipient_public_key.as_deref()) {
        Ok(fk) => vec_to_jbyte_array(env, fk.as_ref()),
        Err((kind, msg)) => throw_kind(env, kind, format!("{tag} unwrap: {msg}")),
    }
}

/// The stanza-format half of `unwrapStanza`: the device has already produced
/// `secret` (an ECDH share or a PRF output); this picks the derivation by tag
/// and shape.
fn unwrap_with_secret(
    stanza: &ragewarden_core::Stanza,
    secret: &[u8; 32],
    recipient_public_key: Option<&[u8]>,
) -> Result<ragewarden_core::FileKey, (ExKind, String)> {
    use ragewarden_core::stanza_format::{
        StanzaFormatError, decrypt_fido2_hmac_with_prf, decrypt_piv_ec_p256_with_ecdh_share,
        decrypt_piv_x25519_with_ecdh_share, decrypt_ragedroid_keystore_with_ecdh_share,
        decrypt_webauthn_prf_with_prf,
    };
    let malformed = |m: String| (ExKind::MalformedStanza, m);
    let result = match stanza.tag.as_str() {
        TAG_PIV_P256 | TAG_PIV_X25519_V2 => match piv_stanza_kind(stanza) {
            Some(PivStanzaKind::P256) => {
                let recipient = recipient_public_key.ok_or_else(|| {
                    malformed("a P-256 piv-p256 stanza needs the slot public key".into())
                })?;
                decrypt_piv_ec_p256_with_ecdh_share(stanza, secret, recipient)
            }
            Some(_) => {
                let recipient: Option<[u8; 32]> = match recipient_public_key {
                    None => None,
                    Some(k) => Some(k.try_into().map_err(|_| {
                        malformed(format!(
                            "X25519 slot public key must be 32 bytes, got {}",
                            k.len()
                        ))
                    })?),
                };
                decrypt_piv_x25519_with_ecdh_share(stanza, secret, recipient.as_ref())
            }
            None => return Err(malformed("not a PIV stanza shape this build reads".into())),
        },
        TAG_RAGEDROID_KEYSTORE_V1 | TAG_RAGEDROID_KEYSTORE_V2 => {
            decrypt_ragedroid_keystore_with_ecdh_share(stanza, secret, recipient_public_key)
        }
        TAG_WEBAUTHN_PRF_V1 => decrypt_webauthn_prf_with_prf(stanza, secret),
        TAG_FIDO2_HMAC => decrypt_fido2_hmac_with_prf(stanza, secret),
        other => return Err(malformed(format!("unknown stanza tag: {other}"))),
    };
    result.map_err(|e| {
        let kind = match e {
            StanzaFormatError::AeadFailed => ExKind::AeadFailure,
            StanzaFormatError::Shape(_)
            | StanzaFormatError::Base64(_)
            | StanzaFormatError::BodyLength { .. } => ExKind::MalformedStanza,
        };
        (kind, e.to_string())
    })
}

/// How many pre-`wrap_salt` PRF stanzas the armored rage blob's header
/// carries (`core::legacy_prf_wraps`); non-zero means the secret should be
/// rotated and the item re-saved. -1 when the header does not parse.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_legacyPrfWraps<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    armored: JString<'local>,
) -> jni::sys::jint {
    guarded(env, |env| {
        let Ok(armored) = armored.try_to_string(env) else {
            return -1;
        };
        legacy_prf_wraps_of(&armored)
    })
}

fn legacy_prf_wraps_of(armored: &str) -> jni::sys::jint {
    ragewarden_core::legacy_prf_wraps(&AgeBlob::from_bytes(armored.as_bytes()))
        .map_or(-1, |n| n.try_into().unwrap_or(jni::sys::jint::MAX))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_x25519Diffie<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    private_key: JByteArray<'local>,
    public_key: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        use x25519_dalek::{PublicKey, StaticSecret};
        let Some(priv_arr) = jbyte_array_to_fixed::<32>(env, &private_key, "privateKey") else {
            return std::ptr::null_mut();
        };
        let Some(pub_arr) = jbyte_array_to_fixed::<32>(env, &public_key, "publicKey") else {
            return std::ptr::null_mut();
        };
        let secret = StaticSecret::from(priv_arr);
        let public = PublicKey::from(pub_arr);
        let shared = secret.diffie_hellman(&public);
        vec_to_jbyte_array(env, shared.as_bytes())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_generateRecoveryMnemonic<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let generated = or_throw!(
            env,
            ragewarden_core::recovery::generate(),
            "recovery::generate"
        );
        let dto = serde_json::json!({
            "mnemonic": generated.mnemonic.to_string(),
            "armoredPubkey": generated.armored_pubkey.as_str(),
            "armoredSecret": generated.armored_secret.expose_secret(),
        });
        json_out(env, &dto, "GeneratedRecovery")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_recoveryFromPhrase<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    phrase: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let phrase: String = or_throw!(env, phrase.try_to_string(env), "get_string(phrase)");
        let identity = or_throw!(
            env,
            ragewarden_core::recovery::from_phrase(phrase.trim()),
            "recovery::from_phrase"
        );
        let armored = identity.to_string().expose_secret().to_string();
        vec_to_jbyte_array(env, armored.as_bytes())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_x25519PublicFromPrivate<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    private_key: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        use x25519_dalek::{PublicKey, StaticSecret};
        let Some(priv_arr) = jbyte_array_to_fixed::<32>(env, &private_key, "privateKey") else {
            return std::ptr::null_mut();
        };
        let secret = StaticSecret::from(priv_arr);
        let public = PublicKey::from(&secret);
        vec_to_jbyte_array(env, public.as_bytes())
    })
}

fn jstring_array_to_vec(
    env: &mut Env<'_>,
    arr: &JObjectArray<'_, JString<'_>>,
) -> Option<Vec<String>> {
    let n = match arr.len(env) {
        Ok(n) => n,
        Err(e) => {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("array length: {e}")),
            );
            return None;
        }
    };
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let s = match arr.get_element(env, i) {
            Ok(o) => o,
            Err(e) => {
                let _ = env.throw_new(
                    jni_str!("java/lang/RuntimeException"),
                    JNIString::from(format!("array element {i}: {e}")),
                );
                return None;
            }
        };
        let val: String = match s.try_to_string(env) {
            Ok(v) => v,
            Err(e) => {
                let _ = env.throw_new(
                    jni_str!("java/lang/RuntimeException"),
                    JNIString::from(format!("get_string element {i}: {e}")),
                );
                return None;
            }
        };
        out.push(val);
    }
    Some(out)
}

fn jbyte_array_to_fixed<const N: usize>(
    env: &mut Env<'_>,
    arr: &JByteArray<'_>,
    name: &str,
) -> Option<[u8; N]> {
    let v = jbyte_array_to_vec(env, arr)?;
    if v.len() != N {
        let _ = env.throw_new(
            jni_str!("java/lang/RuntimeException"),
            JNIString::from(format!("{name} must be {N} bytes, got {}", v.len())),
        );
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Some(out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_decryptWithIdentities<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    blob: JByteArray<'local>,
    identities: JObjectArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(blob_bytes) = jbyte_array_to_vec(env, &blob) else {
            return std::ptr::null_mut();
        };

        let n = or_throw!(env, identities.len(env), "identity array length");
        let mut wrapped: Vec<Box<dyn Identity>> = Vec::with_capacity(n as usize);
        for i in 0..n {
            let obj = match identities.get_element(env, i) {
                Ok(o) => o,
                Err(e) => return throw_runtime(env, format!("identity array element {i}: {e}")),
            };
            match JniIdentity::from_jobject(env, &obj, format!("KotlinIdentity#{i}")) {
                Ok(jid) => wrapped.push(Box::new(jid)),
                Err(e) => return throw_runtime(env, format!("wrap identity {i}: {e}")),
            }
        }

        let blob = AgeBlob::from_bytes(blob_bytes);
        let plaintext = or_throw!(env, decrypt(&blob, &wrapped), "decrypt");
        vec_to_jbyte_array(env, &plaintext)
    })
}

#[allow(dead_code)]
fn _force_use_jobject(_o: JObject<'_>, _r: jobject) {}

#[derive(serde::Serialize)]
struct FolderJniDto {
    id: String,
    name: String,
}

fn folder_to_dto(session: &Session, folder: &core_sync::Folder) -> FolderJniDto {
    let name = core_sync::decrypt_string(session, &folder.name).unwrap_or_default();
    FolderJniDto {
        id: folder.id.clone(),
        name,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_createFolder<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    name: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let name_s: String = or_throw!(env, name.try_to_string(env), "get_string(name)");
        let client = or_throw!(env, shared_client(), "http client");
        let res = run_async(async {
            core_sync::create_folder(&client, &server, &session, &name_s).await
        });
        let folder = or_throw!(env, res, "create_folder");
        let dto = folder_to_dto(&session, &folder);
        json_out(env, &dto, "Folder")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_updateFolder<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    folder_id: JString<'local>,
    name: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let id: String = or_throw!(env, folder_id.try_to_string(env), "get_string(folderId)");
        let name_s: String = or_throw!(env, name.try_to_string(env), "get_string(name)");
        let client = or_throw!(env, shared_client(), "http client");
        let res = run_async(async {
            core_sync::update_folder(&client, &server, &session, &id, &name_s).await
        });
        let folder = or_throw!(env, res, "update_folder");
        let dto = folder_to_dto(&session, &folder);
        json_out(env, &dto, "Folder")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_deleteFolder<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    folder_id: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let id: String = or_throw!(env, folder_id.try_to_string(env), "get_string(folderId)");
        let client = or_throw!(env, shared_client(), "http client");
        let res =
            run_async(async { core_sync::delete_folder(&client, &server, &session, &id).await });
        match res {
            Ok(()) => vec_to_jbyte_array(env, &[]),
            Err(e) => throw_runtime(env, format!("delete_folder: {e}")),
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_listFolders<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let client = or_throw!(env, shared_client(), "http client");
        let res = run_async(async { fetch_vault(&client, &server, &session).await });
        let vault = or_throw!(env, res, "fetch_vault");
        let dtos: Vec<FolderJniDto> = vault
            .folders
            .iter()
            .map(|f| folder_to_dto(&session, f))
            .collect();
        json_out(env, &dtos, "Folders")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_deleteCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_id: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let id: String = or_throw!(env, cipher_id.try_to_string(env), "get_string(cipherId)");
        let client = or_throw!(env, shared_client(), "http client");
        let res =
            run_async(async { core_sync::delete_cipher(&client, &server, &session, &id).await });
        match res {
            Ok(()) => vec_to_jbyte_array(env, &[]),
            Err(e) => throw_runtime(env, format!("delete_cipher: {e}")),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_round_trip_via_helpers() {
        let secret = age::x25519::Identity::generate();
        let secret_str = secret.to_string().expose_secret().to_string();
        let pubkey_armored = secret.to_public().to_string();
        let raw_pubkey =
            ragewarden_core::bech32::decode_age_x25519(&pubkey_armored).expect("decode");

        let plaintext = b"hello ragedroid";
        let blob = ragewarden_core::encrypt(
            plaintext,
            &[Recipient::X25519 {
                public_key: raw_pubkey,
            }],
        )
        .expect("encrypt");

        let secret = ragewarden_core::ArmoredAgeSecret::from_trusted(secret_str.clone());
        let identity =
            ragewarden_core::software_passphrase_identity(&secret).expect("parse identity");
        let identities: Vec<Box<dyn Identity>> = vec![Box::new(identity)];
        let recovered = ragewarden_core::decrypt(&blob, &identities).expect("decrypt");
        assert_eq!(&recovered[..], plaintext);
    }

    fn software_recipient() -> Recipient {
        let sw = age::x25519::Identity::generate();
        Recipient::X25519 {
            public_key: ragewarden_core::bech32::decode_age_x25519(&sw.to_public().to_string())
                .expect("decode"),
        }
    }

    /// The Kotlin conformance test's golden vectors, read in at compile time.
    ///
    /// `RecipientDescriptorsTest.kt` is the consumer half of this contract, and
    /// its vectors are copies of what the tests below emit. Embedding the file
    /// turns "copied by hand, hopefully still in sync" into a checked claim:
    /// before this, both halves could pass while disagreeing -- the Kotlin side
    /// was feeding `resolve()` two `"X25519"` entries at a time when the
    /// producer deduped and could only ever emit one.
    const KOTLIN_CONFORMANCE_TEST: &str = include_str!(
        "../../app/src/test/kotlin/ragewarden/ragedroid/data/RecipientDescriptorsTest.kt"
    );

    /// Fails if a descriptor this producer emits is absent from the Kotlin
    /// golden vectors, so an encoding change (base32 of the key handle, the
    /// truncated-sha256 PIV tag, url-safe-unpadded credential ids) cannot land
    /// on one side alone.
    ///
    /// Matches on the quoted literal because the Kotlin side spells the hardware
    /// descriptors as `const val`s and builds its lists from those -- the literal
    /// is the shared text, the rendered list is not.
    fn assert_kotlin_goldens_agree(descriptors: &[String]) {
        for d in descriptors {
            assert!(
                KOTLIN_CONFORMANCE_TEST.contains(&format!("\"{d}\"")),
                "descriptor {d:?} appears in no Kotlin golden vector; \
                 RecipientDescriptorsTest.kt must be updated in the same commit",
            );
        }
    }

    /// age pushes a random GREASE stanza into every non-scrypt header it writes
    /// (`age-core::format::grease_the_joint`). A catch-all in the descriptor
    /// parser turned it into a recipient, so a one-recipient item rendered
    /// "RAGE · 2" and -- because the tag is fresh per encryption
    /// (`["X25519", "6-grease"]`, `["X25519", ")d8-grease"]`, ...) -- the miscount
    /// moved around and never reproduced twice the same way.
    ///
    /// Length is the assertion that matters here: `contains` could not have
    /// caught this, which is exactly why it went unnoticed in both languages.
    #[test]
    fn grease_stanza_is_not_a_recipient() {
        for _ in 0..32 {
            let blob = ragewarden_core::encrypt(b"x", &[software_recipient()]).expect("encrypt");
            let armored = blob.as_str().expect("armor is UTF-8");
            assert!(
                armored_header_has_grease(armored),
                "age stopped writing grease; this test no longer proves anything",
            );
            let descriptors = rage_recipient_descriptors(armored);
            assert_eq!(descriptors, vec!["X25519".to_string()], "{descriptors:?}");
        }
    }

    /// Decodes the armor far enough to see the stanza tags, so the grease test
    /// can assert its own precondition without going through the parser under
    /// test.
    fn armored_header_has_grease(armored: &str) -> bool {
        use base64::engine::general_purpose::STANDARD as B64_PAD;

        let b64: String = armored
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("-----"))
            .collect();
        let raw = B64_PAD.decode(b64.as_bytes()).expect("armor is base64");
        String::from_utf8_lossy(&raw).contains("-grease")
    }

    /// Two software recipients must report as two. The producer used to dedup
    /// descriptors (`if !out.contains(&descriptor)`), which collapsed every
    /// `X25519` stanza into one entry -- so an item wrapped to two software keys
    /// told the user about one, and the Kotlin conformance test asserted a
    /// two-`X25519` input the producer could not emit.
    #[test]
    fn two_software_recipients_are_two_descriptors() {
        let blob = ragewarden_core::encrypt(b"x", &[software_recipient(), software_recipient()])
            .expect("encrypt");
        let descriptors = rage_recipient_descriptors(blob.as_str().expect("armor is UTF-8"));
        assert_eq!(
            descriptors,
            vec!["X25519".to_string(), "X25519".to_string()],
            "{descriptors:?}",
        );
    }

    #[test]
    fn recipient_descriptors_name_the_real_recipients() {
        let credential_id = b"test-credential";
        let salt = [0x44u8; 32];
        let prf = [0x55u8; 32];
        let sw = age::x25519::Identity::generate();
        let raw_pubkey = ragewarden_core::bech32::decode_age_x25519(&sw.to_public().to_string())
            .expect("decode");
        let blob = ragewarden_core::encrypt_with_prf(
            b"secret",
            &[
                Recipient::PasskeyPrf {
                    credential_id: credential_id.to_vec(),
                    salt,
                    rp_id: "ragewarden".to_string(),
                    label: "test".to_string(),
                },
                Recipient::X25519 {
                    public_key: raw_pubkey,
                },
            ],
            &[ragewarden_core::PrfEntry {
                rp_id: "ragewarden",
                credential_id: &[],
                salt: &salt,
                prf_output: &prf,
            }],
        )
        .expect("encrypt");

        let descriptors = rage_recipient_descriptors(blob.as_str().expect("armor is UTF-8"));
        let expected_cred = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id);
        assert_eq!(
            descriptors,
            vec![
                "X25519".to_string(),
                format!("{TAG_WEBAUTHN_PRF_V1}:{expected_cred}"),
            ],
            "{descriptors:?}",
        );
        assert_kotlin_goldens_agree(&descriptors);
    }

    /// Golden values for the cross-language descriptor contract. The Kotlin half
    /// consumes exactly this vector -- see
    /// `app/src/test/kotlin/.../RecipientDescriptorsTest.kt`, whose
    /// `GOLDEN_MIXED` is a copy of the list asserted here -- and
    /// `RecipientDescriptors.forStored` must derive the same strings from the
    /// same inputs.
    ///
    /// The order is header order, and the length is part of the contract: this
    /// blob has four recipients, so four descriptors, no more (grease) and no
    /// fewer (the two `X25519` stanzas must not collapse into one).
    ///
    /// Header order is not argument order: `core::encrypt_with_prf` partitions
    /// recipients into age-native ones and hardware ones and writes the
    /// age-native stanzas first (`core/src/lib.rs:131-132`), so the `X25519`
    /// pair leads.
    #[test]
    fn recipient_descriptors_are_stable_for_fixed_inputs() {
        const KEYSTORE_FIXTURE_DESCRIPTOR: &str =
            "ragedroid-keystore-v1:OJQWOZLXMFZGIZLOFVVWK6LTORXXEZJNMZUXQ5DVOJSQ"; // gitleaks:allow
        for stanza_version in [1u8, 2] {
            let piv_pubkey = [0x07u8; 32];
            let keystore_pubkey =
                hex_to_bytes("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
            let blob = ragewarden_core::encrypt(
                b"x",
                &[
                    Recipient::YubiKeyPiv {
                        public_key: piv_pubkey,
                        serial: 1,
                        slot: 0x9a,
                        stanza_version,
                    },
                    Recipient::AndroidKeystore {
                        public_key: keystore_pubkey.clone(),
                        key_handle: "ragewarden-keystore-fixture".to_string(),
                        stanza_version,
                    },
                    software_recipient(),
                    software_recipient(),
                ],
            )
            .expect("encrypt");

            let descriptors = rage_recipient_descriptors(blob.as_str().expect("armor is UTF-8"));
            assert_eq!(
                descriptors,
                vec![
                    "X25519".to_string(),
                    "X25519".to_string(),
                    "piv-p256:S7Bvjg".to_string(),
                    KEYSTORE_FIXTURE_DESCRIPTOR.to_string(),
                ],
                "descriptor contract drifted at stanza version {stanza_version}: {descriptors:?}",
            );
            assert_kotlin_goldens_agree(&descriptors);
        }
    }

    #[test]
    fn unwrap_with_secret_reads_every_stanza_version_given_the_recipient_key() {
        use p256::elliptic_curve::{Generate, sec1::ToSec1Point};
        use ragewarden_core::stanza_format::{
            EcdhStanzaVersion, encrypt_piv_ec_p256_stanza, encrypt_piv_x25519_stanza,
            encrypt_ragedroid_keystore_stanza, piv_ec_p256_ephemeral_pub, piv_x25519_ephemeral_pub,
            ragedroid_keystore_ephemeral_pub,
        };
        let fk = [0x5au8; 16];
        let p256_share = |sk: &p256::SecretKey, peer: &[u8]| -> [u8; 32] {
            let peer = p256::PublicKey::from_sec1_bytes(peer).unwrap();
            let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
            shared.raw_secret_bytes().as_slice().try_into().unwrap()
        };

        let x = x25519_dalek::StaticSecret::from([0x19u8; 32]);
        let x_pub = *x25519_dalek::PublicKey::from(&x).as_bytes();
        for version in [EcdhStanzaVersion::V1, EcdhStanzaVersion::V2] {
            let stanza = encrypt_piv_x25519_stanza(&fk, &x_pub, version);
            let eph = x25519_dalek::PublicKey::from(piv_x25519_ephemeral_pub(&stanza).unwrap());
            let share = *x.diffie_hellman(&eph).as_bytes();
            assert_eq!(
                *unwrap_with_secret(&stanza, &share, Some(&x_pub)).unwrap(),
                fk
            );
            assert_eq!(
                unwrap_with_secret(&stanza, &share, None).is_ok(),
                version == EcdhStanzaVersion::V1,
                "only v1 opens without the recipient key"
            );
        }

        let sk = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let pk = sk.public_key().to_sec1_point(true).as_bytes().to_vec();
        for version in [EcdhStanzaVersion::V1, EcdhStanzaVersion::V2] {
            let stanza = encrypt_ragedroid_keystore_stanza(&fk, &pk, "h", version).unwrap();
            let share = p256_share(&sk, &ragedroid_keystore_ephemeral_pub(&stanza).unwrap());
            assert_eq!(*unwrap_with_secret(&stanza, &share, Some(&pk)).unwrap(), fk);
        }

        let stanza = encrypt_piv_ec_p256_stanza(&fk, &pk).unwrap();
        let share = p256_share(&sk, &piv_ec_p256_ephemeral_pub(&stanza).unwrap());
        assert_eq!(*unwrap_with_secret(&stanza, &share, Some(&pk)).unwrap(), fk);
        assert!(matches!(
            unwrap_with_secret(&stanza, &share, None),
            Err((ExKind::MalformedStanza, _))
        ));
    }

    #[test]
    fn legacy_prf_wraps_reads_the_header_or_reports_minus_one() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../core/tests/vectors/stanza_formats_v1_frozen.json"
        ))
        .unwrap();
        let legacy = v["webauthn_prf_v1_legacy_3arg"]["blob"].as_str().unwrap();
        let current = v["webauthn_prf_v1_wrap_salt"]["blob"].as_str().unwrap();
        assert_eq!(legacy_prf_wraps_of(legacy), 1);
        assert_eq!(legacy_prf_wraps_of(current), 0);
        assert_eq!(legacy_prf_wraps_of("not age"), -1);
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn recipient_descriptors_on_garbage_are_empty_not_fabricated() {
        assert!(rage_recipient_descriptors("not an age blob").is_empty());
        assert!(rage_recipient_descriptors("").is_empty());
    }

    #[test]
    fn mock_webauthn_prf_round_trip_via_decrypt() {
        use ragewarden_core::{
            FileKey, Identity as IdentityTrait, IdentityError, stanza::Stanza as OurStanza,
        };
        let credential_id = b"test-credential";
        let salt = [0x11u8; 32];
        let prf = [0x33u8; 32];
        let plaintext = b"phase3 mock identity round-trip";
        let prf_entry = ragewarden_core::PrfEntry {
            rp_id: "ragewarden",
            credential_id: &[],
            salt: &salt,
            prf_output: &prf,
        };
        let recipient = Recipient::PasskeyPrf {
            credential_id: credential_id.to_vec(),
            salt,
            rp_id: "ragewarden".to_string(),
            label: "test".to_string(),
        };
        let blob = ragewarden_core::encrypt_with_prf(plaintext, &[recipient], &[prf_entry])
            .expect("encrypt webauthn-prf");

        struct MockPrfIdentity {
            prf: [u8; 32],
        }
        impl IdentityTrait for MockPrfIdentity {
            fn try_unwrap_stanza(
                &self,
                stanza: &OurStanza,
            ) -> Result<Option<FileKey>, IdentityError> {
                if stanza.tag != TAG_WEBAUTHN_PRF_V1 {
                    return Ok(None);
                }
                let fk = ragewarden_core::stanza_format::decrypt_webauthn_prf_with_prf(
                    stanza, &self.prf,
                )
                .map_err(|e| IdentityError::Crypto(e.to_string()))?;
                Ok(Some(fk))
            }
            fn display(&self) -> &str {
                "mock-prf"
            }
        }
        let identities: Vec<Box<dyn IdentityTrait>> = vec![Box::new(MockPrfIdentity { prf })];
        let recovered = ragewarden_core::decrypt(&blob, &identities).expect("decrypt");
        assert_eq!(&recovered[..], plaintext);
    }

    #[test]
    fn recipient_selection_matches_the_core_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../core/tests/vectors/recipient_policy_v1.json"
        ))
        .unwrap();
        for (registry, ids, expected) in [
            ("registry", "", "no_local_authenticator"),
            ("registry", r#"["e-fido2"]"#, "holds_fido2"),
            (
                "browser_passkey_registry",
                "",
                "browser_passkey_no_local_authenticator",
            ),
            (
                "browser_passkey_registry",
                r#"["e-browser-passkey"]"#,
                "browser_passkey_holds_prf",
            ),
        ] {
            let reg = serde_json::to_vec(&vectors[registry]).unwrap();
            let sel = select_encrypt_recipients(&reg, b"", ids.as_bytes()).unwrap();
            let wire: serde_json::Value =
                serde_json::from_slice(&serde_json::to_vec(&sel).unwrap()).unwrap();
            assert_eq!(wire, vectors[expected], "{expected}");
        }
    }

    #[test]
    fn cipher_in_json_round_trip() {
        use ragewarden_core::Type2EncString;
        use ragewarden_core::sync::{CipherIn, CipherLogin, CipherUri, SecureNote};
        let t = |s: &str| Type2EncString::from_trusted(s.to_string());
        let original = CipherIn {
            cipher_type: 1,
            name: t("encName"),
            notes: Some(t("encNotes")),
            login: Some(CipherLogin {
                username: Some(t("encUser")),
                password: Some(t("encPw")),
                totp: None,
                uris: Some(vec![CipherUri {
                    uri: t("encUri"),
                    match_type: None,
                    extra: Default::default(),
                }]),
                extra: Default::default(),
            }),
            secure_note: Some(SecureNote { note_type: 0 }),
            ..CipherIn::default()
        };
        let bytes = serde_json::to_vec(&original).unwrap();
        let parsed = cipher_in_from_json(&bytes).expect("parse");
        let bytes2 = serde_json::to_vec(&parsed).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn bech32_decode_round_trips() {
        let secret = age::x25519::Identity::generate();
        let pubkey_armored = secret.to_public().to_string();
        let raw = ragewarden_core::bech32::decode_age_x25519(&pubkey_armored)
            .expect("decode back to bytes");

        let blob =
            ragewarden_core::encrypt(b"round-trip", &[Recipient::X25519 { public_key: raw }])
                .expect("encrypt to decoded recipient");
        let secret_str = secret.to_string().expose_secret().to_string();
        let secret = ragewarden_core::ArmoredAgeSecret::from_trusted(secret_str.clone());
        let identity =
            ragewarden_core::software_passphrase_identity(&secret).expect("parse identity");
        let identities: Vec<Box<dyn Identity>> = vec![Box::new(identity)];
        let recovered = ragewarden_core::decrypt(&blob, &identities).expect("decrypt");
        assert_eq!(&recovered[..], b"round-trip");
    }
}
