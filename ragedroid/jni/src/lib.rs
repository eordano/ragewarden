#![allow(unsafe_code)]
#![warn(rust_2018_idioms)]

use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD_NO_PAD as B64, Engine};
use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString};
use jni::strings::JNIString;
use jni::sys::{jbyteArray, jobject};
use jni::{jni_str, AttachGuard, Env, EnvUnowned};

use ragewarden_core::stanza_format::{
    TAG_FIDO2_HMAC, TAG_PIV_P256, TAG_RAGEDROID_KEYSTORE_V1, TAG_SCRYPT, TAG_WEBAUTHN_PRF_V1,
    TAG_X25519,
};
use ragewarden_core::sync::{
    self as core_sync, build_meta_cipher, build_rage_cipher, build_rage_cipher_in_folder,
    create_cipher, extract_rage_blob, fetch_vault, login, register, update_cipher, CipherIn,
    Server, Session,
};
use ragewarden_core::{decrypt, encrypt, encrypt_with_prf, AgeBlob, Identity, PrfEntry, Recipient};

mod error;
mod http;
mod jni_identity;
mod sync_jni;

use error::{throw_kind, ExKind};
use http::{run_async, shared_client};
use jni_identity::JniIdentity;
use sync_jni::{
    CardDto, IdentityDto, RegisterResultDto, SessionDto, SshDto, VaultDto, VaultItemDto,
};

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
    {
        let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
        let env = guard.borrow_env_mut();
        if let Err(e) = rustls_platform_verifier::android::init_with_env(env, context) {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("rustls-platform-verifier init failed: {e:?}")),
            );
        }
    }
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
        let msg = format!("PANIC at {} :: {}", loc, info);
        eprintln!("[ragedroid-jni] {}", msg);
        #[cfg(target_os = "android")]
        unsafe {
            extern "C" {
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
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_smoke<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jni::sys::jstring {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    match env.new_string("ragedroid-jni linked") {
        Ok(s) => s.into_raw(),
        Err(e) => {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("smoke: {e}")),
            );
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_encrypt<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    plaintext: JByteArray<'local>,
    recipient_pubkey: JByteArray<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let plaintext_bytes = match jbyte_array_to_vec(env, &plaintext) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let pubkey_bytes = match jbyte_array_to_vec(env, &recipient_pubkey) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
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
}

#[derive(serde::Deserialize)]
struct PrfInputDto {
    rp_id: String,
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
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let plaintext_bytes = match jbyte_array_to_vec(env, &plaintext) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let recipients_bytes = match jbyte_array_to_vec(env, &recipients_json) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let prf_inputs_bytes = match jbyte_array_to_vec(env, &prf_inputs_json) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    let recipients: Vec<Recipient> = match serde_json::from_slice(&recipients_bytes) {
        Ok(v) => v,
        Err(e) => {
            return throw_kind(
                env,
                ExKind::MalformedStanza,
                format!("recipients_json: {e}"),
            )
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
                )
            }
        }
    };

    let prf_table: Vec<PrfEntry<'_>> = prf_owned
        .iter()
        .map(|p| PrfEntry {
            rp_id: p.rp_id.as_str(),
            salt: &p.salt,
            prf_output: &p.prf_output,
        })
        .collect();

    let blob = match encrypt_with_prf(&plaintext_bytes, &recipients, &prf_table) {
        Ok(b) => b,
        Err(e) => return throw_kind(env, ExKind::AeadFailure, format!("encrypt: {e}")),
    };

    vec_to_jbyte_array(env, blob.as_bytes())
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
#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_selectEncryptRecipients<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    registry_json: JByteArray<'local>,
    local_json: JByteArray<'local>,
    local_prf_ids_json: JByteArray<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    use ragewarden_core::policy;
    use ragewarden_core::registry::WireDocument;

    let registry_bytes = match jbyte_array_to_vec(env, &registry_json) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let local_bytes = match jbyte_array_to_vec(env, &local_json) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let prf_ids_bytes = match jbyte_array_to_vec(env, &local_prf_ids_json) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    fn parse_doc(bytes: &[u8]) -> Result<WireDocument, serde_json::Error> {
        if bytes.is_empty() {
            return Ok(WireDocument::default());
        }
        serde_json::from_slice(bytes)
    }

    let registry = match parse_doc(&registry_bytes) {
        Ok(d) => d,
        Err(e) => return throw_runtime(env, format!("registry_json: {e}")),
    };
    let local = match parse_doc(&local_bytes) {
        Ok(d) => d,
        Err(e) => return throw_runtime(env, format!("local_json: {e}")),
    };
    let prf_ids: Vec<String> = if prf_ids_bytes.is_empty() {
        Vec::new()
    } else {
        match serde_json::from_slice(&prf_ids_bytes) {
            Ok(v) => v,
            Err(e) => return throw_runtime(env, format!("local_prf_ids_json: {e}")),
        }
    };

    let selection = policy::select_for_encrypt(
        &registry.entries,
        &local.entries,
        &policy::LocalAuthenticators {
            prf_entry_ids: prf_ids,
        },
    );

    match serde_json::to_vec(&selection) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode selection: {e}")),
    }
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
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let blob_bytes = match jbyte_array_to_vec(env, &blob) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let armored: String = match armored_secret.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string: {e}")),
    };

    let secret = ragewarden_core::ArmoredAgeSecret::from_trusted(armored.trim().to_string());
    let identity = match ragewarden_core::software_passphrase_identity(&secret) {
        Ok(id) => id,
        Err(e) => return throw_kind(env, ExKind::MalformedStanza, format!("identity parse: {e}")),
    };
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(identity)];

    let blob = AgeBlob::from_bytes(blob_bytes);
    let plaintext = match decrypt(&blob, &identities) {
        Ok(p) => p,
        Err(e) => return throw_kind(env, ExKind::IdentityMissing, format!("decrypt: {e}")),
    };

    vec_to_jbyte_array(env, &plaintext)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_generateSoftwareIdentity<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jni::sys::jstring {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let secret = age::x25519::Identity::generate();
    let secret_str = secret.to_string().expose_secret().to_string();
    let pubkey_str = secret.to_public().to_string();
    let combined = format!("{secret_str} {pubkey_str}");
    match env.new_string(combined) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            let _ = env.throw_new(
                jni_str!("java/lang/RuntimeException"),
                JNIString::from(format!("generateSoftwareIdentity: {e}")),
            );
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_pubkeyFromArmoredSecret<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    armored_secret: JString<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let armored: String = match armored_secret.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string: {e}")),
    };
    let secret = match age::x25519::Identity::from_str(armored.trim()) {
        Ok(s) => s,
        Err(e) => return throw_kind(env, ExKind::MalformedStanza, format!("identity parse: {e}")),
    };
    let pubkey_armored = secret.to_public().to_string();
    let raw = match ragewarden_core::bech32::decode_age_x25519(&pubkey_armored) {
        Some(r) => r,
        None => {
            return throw_kind(
                env,
                ExKind::MalformedStanza,
                "could not bech32-decode age public key from secret",
            )
        }
    };
    vec_to_jbyte_array(env, &raw)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_totpGenerate<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    uri_or_secret: JString<'local>,
) -> jni::sys::jstring {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let input: String = match uri_or_secret.try_to_string(env) {
        Ok(s) => s.into(),
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
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let server_url: String = match server_url.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(serverUrl): {e}")),
    };
    let email: String = match email.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(email): {e}")),
    };
    let password: String = match password.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(password): {e}")),
    };
    let name: String = match name.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(name): {e}")),
    };

    let server = match server_from_url(env, &server_url) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };

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
    let out = match res {
        Ok(o) => o,
        Err(e) => return throw_runtime(env, format!("register: {e}")),
    };
    let dto = RegisterResultDto {
        email: out.email,
        kdf_iterations: out.kdf_iterations,
    };
    match serde_json::to_vec(&dto) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode RegisterResult: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_login<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    server_url: JString<'local>,
    email: JString<'local>,
    password: JString<'local>,
    device_name: JString<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let server_url: String = match server_url.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(serverUrl): {e}")),
    };
    let email: String = match email.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(email): {e}")),
    };
    let password: String = match password.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(password): {e}")),
    };
    let device_name: String = match device_name.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(deviceName): {e}")),
    };

    let server = match server_from_url(env, &server_url) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };

    let res = run_async(async { login(&client, &server, &email, &password, &device_name).await });
    let session = match res {
        Ok(s) => s,
        Err(e) => return throw_runtime(env, format!("login: {e}")),
    };
    let dto = SessionDto {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        user_id: session.user_id,
        email: session.email,
        user_enc_key_b64: B64.encode(&session.user_enc_key),
        user_mac_key_b64: B64.encode(&session.user_mac_key),
        kdf_iterations: session.kdf_iterations,
        device_id: session.device_id,
        api_url: server.api_url.clone(),
        identity_url: server.identity_url.clone(),
    };
    match serde_json::to_vec(&dto) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode Session: {e}")),
    }
}

fn session_from_dto_or_throw(env: &mut Env<'_>, dto: &SessionDto) -> Option<(Server, Session)> {
    let server = match build_server_or_throw(env, &dto.api_url, &dto.identity_url) {
        Some(s) => s,
        None => return None,
    };
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
        kdf_iterations: dto.kdf_iterations,
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_fetchVault<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };
    let res = run_async(async { fetch_vault(&client, &server, &session).await });
    let vault = match res {
        Ok(v) => v,
        Err(e) => return throw_runtime(env, format!("fetch_vault: {e}")),
    };
    let dto = build_vault_dto(&session, &vault);
    match serde_json::to_vec(&dto) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode Vault: {e}")),
    }
}

fn cipher_in_from_json(bytes: &[u8]) -> Result<CipherIn, serde_json::Error> {
    use core_sync::{CipherFieldIn, CipherLogin, CipherUri, SecureNote};
    use ragewarden_core::Type2EncString;
    let v: serde_json::Value = serde_json::from_slice(bytes)?;
    let obj = v
        .as_object()
        .ok_or_else(|| serde::de::Error::custom("expected object"))?;
    let cipher_type = obj
        .get("type")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| serde::de::Error::custom("missing type"))? as u8;
    let name = obj
        .get("name")
        .and_then(|x| x.as_str())
        .map(|s| Type2EncString::from_trusted(s.to_string()))
        .ok_or_else(|| serde::de::Error::custom("missing name"))?;
    let notes = obj
        .get("notes")
        .and_then(|x| x.as_str())
        .map(|s| Type2EncString::from_trusted(s.to_string()));
    let folder_id = obj
        .get("folderId")
        .and_then(|x| x.as_str())
        .map(String::from);
    let organization_id = obj
        .get("organizationId")
        .and_then(|x| x.as_str())
        .map(String::from);
    let favorite = obj
        .get("favorite")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let secure_note = obj.get("secureNote").map(|sn| SecureNote {
        note_type: sn.get("type").and_then(|x| x.as_u64()).unwrap_or(0) as u8,
    });
    let login = obj.get("login").and_then(|l| l.as_object()).map(|lo| {
        let pick = |a: &str, b: &str| -> Option<Type2EncString> {
            lo.get(a)
                .or_else(|| lo.get(b))
                .and_then(|x| x.as_str())
                .map(|s| Type2EncString::from_trusted(s.to_string()))
        };
        let username = pick("Username", "username");
        let password = pick("Password", "password");
        let totp = pick("Totp", "totp");
        let uris_val = lo.get("Uris").or_else(|| lo.get("uris"));
        let uris = uris_val.and_then(|x| x.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|u| {
                    let uri = u
                        .get("Uri")
                        .or_else(|| u.get("uri"))
                        .and_then(|x| x.as_str())
                        .map(|s| Type2EncString::from_trusted(s.to_string()))?;
                    let match_type = u
                        .get("Match")
                        .or_else(|| u.get("match"))
                        .and_then(|x| x.as_u64())
                        .map(|n| n as u8);
                    Some(CipherUri { uri, match_type })
                })
                .collect()
        });
        CipherLogin {
            username,
            password,
            totp,
            uris,
        }
    });
    let fields = obj.get("fields").and_then(|x| x.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|f| {
                let name = f
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| Type2EncString::from_trusted(s.to_string()))?;
                let value = f
                    .get("value")
                    .and_then(|x| x.as_str())
                    .map(|s| Type2EncString::from_trusted(s.to_string()));
                let field_type = f.get("type").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
                Some(CipherFieldIn {
                    name,
                    value,
                    field_type,
                })
            })
            .collect()
    });
    Ok(CipherIn {
        cipher_type,
        name,
        notes,
        login,
        secure_note,
        fields,
        folder_id,
        organization_id,
        favorite,
    })
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
    // The recorder never unwraps anything, so this always fails; the walk over
    // the header is the point. Going through core's decrypt path means age's own
    // header parser does the framing -- the same route ragemanifest's scanner
    // takes (`ragemanifest/src/wasm/sync.rs`) -- instead of a hand-rolled
    // dearmor + `-> ` line split that had to guess at stanza syntax.
    let _ = decrypt(&AgeBlob::from_bytes(armored.as_bytes()), &identities);

    let stanzas = seen.lock().unwrap_or_else(|e| e.into_inner());
    stanzas.iter().filter_map(stanza_descriptor).collect()
}

/// The descriptor a single header stanza contributes, or `None` if the stanza
/// does not name a recipient (GREASE, or a tag from some future age plugin we
/// cannot speak for).
fn stanza_descriptor(s: &ragewarden_core::Stanza) -> Option<String> {
    let args = &s.args;
    match s.tag.as_str() {
        // age's own recipient types. Both are anonymous by construction, so the
        // bare tag *is* the descriptor; Kotlin counts them as
        // `anonymousSoftwareCount`.
        TAG_X25519 | TAG_SCRYPT => Some(s.tag.clone()),
        TAG_PIV_P256 if args.len() == 2 => Some(format!("{TAG_PIV_P256}:{}", args[1])),
        TAG_RAGEDROID_KEYSTORE_V1 if args.len() == 2 => {
            Some(format!("{TAG_RAGEDROID_KEYSTORE_V1}:{}", args[0]))
        }
        // PRF stanza arity is 3 (legacy) or 4 (current); core accepts both, so
        // the descriptor must not be pickier than the decryptor.
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
        (u, p, t)
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
    let notes = c
        .notes
        .as_ref()
        .and_then(|s| core_sync::decrypt_string(session, s).ok());
    let recipients: Vec<String> = match &rage_blob {
        Some(armored) => rage_recipient_descriptors(armored),
        None => Vec::new(),
    };
    let dec = |t: &Option<ragewarden_core::Type2EncString>| -> Option<String> {
        t.as_ref()
            .and_then(|s| core_sync::decrypt_string(session, s).ok())
    };
    let card = c.card.as_ref().map(|cc| CardDto {
        cardholder_name: dec(&cc.cardholder_name),
        brand: dec(&cc.brand),
        number: dec(&cc.number),
        exp_month: dec(&cc.exp_month),
        exp_year: dec(&cc.exp_year),
        code: dec(&cc.code),
    });
    let identity = c.identity.as_ref().map(|ci| IdentityDto {
        first_name: dec(&ci.first_name),
        middle_name: dec(&ci.middle_name),
        last_name: dec(&ci.last_name),
        address1: dec(&ci.address1),
        address2: dec(&ci.address2),
        address3: dec(&ci.address3),
        city: dec(&ci.city),
        state: dec(&ci.state),
        postal_code: dec(&ci.postal_code),
        country: dec(&ci.country),
        phone: dec(&ci.phone),
        email: dec(&ci.email),
        ssn: dec(&ci.ssn),
        passport_number: dec(&ci.passport_number),
        dob: dec(&ci.dob),
    });
    let ssh = c.ssh_key.as_ref().map(|sk| SshDto {
        key_type: dec(&sk.key_type),
        fingerprint: dec(&sk.fingerprint),
        public_key: dec(&sk.public_key),
        private_key: dec(&sk.private_key),
        comment: dec(&sk.comment),
        passphrase: dec(&sk.passphrase),
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
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_extractRageBlob<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_json: JString<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (_server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let cipher_str: String = match cipher_json.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(cipherJson): {e}")),
    };
    let cipher: core_sync::Cipher = match serde_json::from_str(&cipher_str) {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("parse cipher: {e}")),
    };
    match extract_rage_blob(&session, &cipher) {
        Ok(Some(blob)) => vec_to_jbyte_array(env, blob.as_bytes()),
        Ok(None) => std::ptr::null_mut(),
        Err(e) => throw_runtime(env, format!("extract_rage_blob: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_buildRageCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    name: JString<'local>,
    armored_blob: JString<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (_server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let name_s: String = match name.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(name): {e}")),
    };
    let armored: String = match armored_blob.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(armoredBlob): {e}")),
    };
    let cipher_in = match build_rage_cipher(&session, &name_s, &armored) {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("build_rage_cipher: {e}")),
    };
    match serde_json::to_vec(&cipher_in) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode CipherIn: {e}")),
    }
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
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (_server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let name_s: String = match name.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(name): {e}")),
    };
    let armored: String = match armored_blob.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(armoredBlob): {e}")),
    };
    let folder_str: Option<String> = if folder_id.is_null() {
        None
    } else {
        match folder_id.try_to_string(env) {
            Ok(s) => {
                let v: String = s.into();
                if v.is_empty() {
                    None
                } else {
                    Some(v)
                }
            }
            Err(e) => return throw_runtime(env, format!("get_string(folderId): {e}")),
        }
    };
    let cipher_in =
        match build_rage_cipher_in_folder(&session, &name_s, &armored, folder_str.as_deref()) {
            Ok(c) => c,
            Err(e) => return throw_runtime(env, format!("build_rage_cipher_in_folder: {e}")),
        };
    match serde_json::to_vec(&cipher_in) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode CipherIn: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_buildMetaCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    name: JString<'local>,
    notes: JString<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (_server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let name_s: String = match name.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(name): {e}")),
    };
    let notes_s: String = match notes.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(notes): {e}")),
    };
    let cipher_in = match build_meta_cipher(&session, &name_s, &notes_s) {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("build_meta_cipher: {e}")),
    };
    match serde_json::to_vec(&cipher_in) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode CipherIn: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_createCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_in_json: JByteArray<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let bytes = match jbyte_array_to_vec(env, &cipher_in_json) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let cipher_in = match cipher_in_from_json(&bytes) {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("parse CipherIn: {e}")),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };
    let res = run_async(async { create_cipher(&client, &server, &session, &cipher_in).await });
    let saved = match res {
        Ok(s) => s,
        Err(e) => return throw_runtime(env, format!("create_cipher: {e}")),
    };
    match serde_json::to_vec(&saved) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode Cipher: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_updateCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_id: JString<'local>,
    cipher_in_json: JByteArray<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let id: String = match cipher_id.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(cipherId): {e}")),
    };
    let bytes = match jbyte_array_to_vec(env, &cipher_in_json) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let cipher_in = match cipher_in_from_json(&bytes) {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("parse CipherIn: {e}")),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };
    let res = run_async(async { update_cipher(&client, &server, &session, &id, &cipher_in).await });
    let saved = match res {
        Ok(s) => s,
        Err(e) => return throw_runtime(env, format!("update_cipher: {e}")),
    };
    match serde_json::to_vec(&saved) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode Cipher: {e}")),
    }
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
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let tag: String = match stanza_tag.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("stanzaTag: {e}")),
    };
    let args = match jstring_array_to_vec(env, &stanza_args) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let body = match jbyte_array_to_vec(env, &stanza_body) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let secret_bytes = match jbyte_array_to_fixed::<32>(env, &secret, "secret") {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let stanza = ragewarden_core::Stanza {
        tag: tag.clone(),
        args,
        body,
    };

    use ragewarden_core::stanza_format::{
        decrypt_fido2_hmac_with_prf, decrypt_piv_p256_with_ecdh_share,
        decrypt_ragedroid_keystore_with_ecdh_share, decrypt_webauthn_prf_with_prf,
        StanzaFormatError,
    };
    let result = match tag.as_str() {
        TAG_PIV_P256 => decrypt_piv_p256_with_ecdh_share(&stanza, &secret_bytes),
        TAG_RAGEDROID_KEYSTORE_V1 => {
            decrypt_ragedroid_keystore_with_ecdh_share(&stanza, &secret_bytes)
        }
        TAG_WEBAUTHN_PRF_V1 => decrypt_webauthn_prf_with_prf(&stanza, &secret_bytes),
        TAG_FIDO2_HMAC => decrypt_fido2_hmac_with_prf(&stanza, &secret_bytes),
        other => {
            return throw_kind(
                env,
                ExKind::MalformedStanza,
                format!("unknown stanza tag: {other}"),
            );
        }
    };
    match result {
        Ok(fk) => vec_to_jbyte_array(env, fk.as_ref()),
        Err(e) => {
            let kind = match e {
                StanzaFormatError::AeadFailed => ExKind::AeadFailure,
                StanzaFormatError::Shape(_)
                | StanzaFormatError::Base64(_)
                | StanzaFormatError::BodyLength { .. } => ExKind::MalformedStanza,
            };
            throw_kind(env, kind, format!("{tag} unwrap: {e}"))
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_x25519Diffie<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    private_key: JByteArray<'local>,
    public_key: JByteArray<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    use x25519_dalek::{PublicKey, StaticSecret};
    let priv_arr = match jbyte_array_to_fixed::<32>(env, &private_key, "privateKey") {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let pub_arr = match jbyte_array_to_fixed::<32>(env, &public_key, "publicKey") {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let secret = StaticSecret::from(priv_arr);
    let public = PublicKey::from(pub_arr);
    let shared = secret.diffie_hellman(&public);
    vec_to_jbyte_array(env, shared.as_bytes())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_generateRecoveryMnemonic<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let gen = match ragewarden_core::recovery::generate() {
        Ok(g) => g,
        Err(e) => return throw_runtime(env, format!("recovery::generate: {e}")),
    };
    let dto = serde_json::json!({
        "mnemonic": gen.mnemonic.to_string(),
        "armoredPubkey": gen.armored_pubkey.as_str(),
        "armoredSecret": gen.armored_secret.expose_secret(),
    });
    match serde_json::to_vec(&dto) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode GeneratedRecovery: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_recoveryFromPhrase<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    phrase: JString<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let phrase: String = match phrase.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(phrase): {e}")),
    };
    let identity = match ragewarden_core::recovery::from_phrase(phrase.trim()) {
        Ok(id) => id,
        Err(e) => return throw_runtime(env, format!("recovery::from_phrase: {e}")),
    };
    let armored = identity.to_string().expose_secret().to_string();
    vec_to_jbyte_array(env, armored.as_bytes())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_x25519PublicFromPrivate<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    private_key: JByteArray<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    use x25519_dalek::{PublicKey, StaticSecret};
    let priv_arr = match jbyte_array_to_fixed::<32>(env, &private_key, "privateKey") {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let secret = StaticSecret::from(priv_arr);
    let public = PublicKey::from(&secret);
    vec_to_jbyte_array(env, public.as_bytes())
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
            Ok(v) => v.into(),
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
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let blob_bytes = match jbyte_array_to_vec(env, &blob) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    let n = match identities.len(env) {
        Ok(n) => n,
        Err(e) => return throw_runtime(env, format!("identity array length: {e}")),
    };
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
    let plaintext = match decrypt(&blob, &wrapped) {
        Ok(p) => p,
        Err(e) => return throw_runtime(env, format!("decrypt: {e}")),
    };
    vec_to_jbyte_array(env, &plaintext)
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
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let name_s: String = match name.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(name): {e}")),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };
    let res =
        run_async(async { core_sync::create_folder(&client, &server, &session, &name_s).await });
    let folder = match res {
        Ok(f) => f,
        Err(e) => return throw_runtime(env, format!("create_folder: {e}")),
    };
    let dto = folder_to_dto(&session, &folder);
    match serde_json::to_vec(&dto) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode Folder: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_updateFolder<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    folder_id: JString<'local>,
    name: JString<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let id: String = match folder_id.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(folderId): {e}")),
    };
    let name_s: String = match name.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(name): {e}")),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };
    let res = run_async(async {
        core_sync::update_folder(&client, &server, &session, &id, &name_s).await
    });
    let folder = match res {
        Ok(f) => f,
        Err(e) => return throw_runtime(env, format!("update_folder: {e}")),
    };
    let dto = folder_to_dto(&session, &folder);
    match serde_json::to_vec(&dto) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode Folder: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_deleteFolder<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    folder_id: JString<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let id: String = match folder_id.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(folderId): {e}")),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };
    let res = run_async(async { core_sync::delete_folder(&client, &server, &session, &id).await });
    match res {
        Ok(()) => vec_to_jbyte_array(env, &[]),
        Err(e) => throw_runtime(env, format!("delete_folder: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_listFolders<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };
    let res = run_async(async { fetch_vault(&client, &server, &session).await });
    let vault = match res {
        Ok(v) => v,
        Err(e) => return throw_runtime(env, format!("fetch_vault: {e}")),
    };
    let dtos: Vec<FolderJniDto> = vault
        .folders
        .iter()
        .map(|f| folder_to_dto(&session, f))
        .collect();
    match serde_json::to_vec(&dtos) {
        Ok(b) => vec_to_jbyte_array(env, &b),
        Err(e) => throw_runtime(env, format!("encode Folders: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_deleteCipher<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    cipher_id: JString<'local>,
) -> jbyteArray {
    let mut guard = unsafe { AttachGuard::from_unowned(env.into_raw()) };
    let env = guard.borrow_env_mut();
    let (server, session) = match parse_session_blob(env, &session_blob) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let id: String = match cipher_id.try_to_string(env) {
        Ok(s) => s.into(),
        Err(e) => return throw_runtime(env, format!("get_string(cipherId): {e}")),
    };
    let client = match shared_client() {
        Ok(c) => c,
        Err(e) => return throw_runtime(env, format!("http client: {e}")),
    };
    let res = run_async(async { core_sync::delete_cipher(&client, &server, &session, &id).await });
    match res {
        Ok(()) => vec_to_jbyte_array(env, &[]),
        Err(e) => throw_runtime(env, format!("delete_cipher: {e}")),
    }
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
            // The header really does carry grease; without this the loop could
            // pass by never exercising the case.
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
        // A blob wrapped to one hardware recipient (webauthn-prf) and one
        // software recipient must report the hardware one identifiably and the
        // software one anonymously.
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
                salt: &salt,
                prf_output: &prf,
            }],
        )
        .expect("encrypt");

        let descriptors = rage_recipient_descriptors(blob.as_str().expect("armor is UTF-8"));
        let expected_cred = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id);
        // Exact vector, not `contains`: the count is what the UI renders, and a
        // `contains`-only assertion is what let a GREASE stanza ride along as a
        // third "recipient" unnoticed.
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
        let piv_pubkey = [0x07u8; 32];
        // SEC1-compressed secp256r1 generator point; any valid point will do,
        // the descriptor is derived from the key handle, not the key.
        let keystore_pubkey =
            hex_to_bytes("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        let blob = ragewarden_core::encrypt(
            b"x",
            &[
                Recipient::YubiKeyPiv {
                    public_key: piv_pubkey,
                    serial: 1,
                    slot: 0x9a,
                },
                Recipient::AndroidKeystore {
                    public_key: keystore_pubkey,
                    key_handle: "ragewarden-keystore-fixture".to_string(),
                },
                // A software key and a paper key: both are plain age X25519
                // stanzas, indistinguishable from each other and from the
                // header alone.
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
                "ragedroid-keystore-v1:OJQWOZLXMFZGIZLOFVVWK6LTORXXEZJNMZUXQ5DVOJSQ".to_string(),
            ],
            "descriptor contract drifted: {descriptors:?}",
        );
        assert_kotlin_goldens_agree(&descriptors);
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
            stanza::Stanza as OurStanza, FileKey, Identity as IdentityTrait, IdentityError,
        };
        let credential_id = b"test-credential";
        let salt = [0x11u8; 32];
        let prf = [0x33u8; 32];
        let plaintext = b"phase3 mock identity round-trip";
        let prf_entry = ragewarden_core::PrfEntry {
            rp_id: "ragewarden",
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
    fn cipher_in_json_round_trip() {
        use ragewarden_core::sync::{CipherIn, CipherLogin, CipherUri, SecureNote};
        use ragewarden_core::Type2EncString;
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
                }]),
            }),
            secure_note: Some(SecureNote { note_type: 0 }),
            fields: None,
            folder_id: None,
            organization_id: None,
            favorite: false,
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
