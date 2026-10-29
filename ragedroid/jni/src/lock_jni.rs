use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as B64};
use jni::EnvUnowned;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jbyteArray;
use ragewarden_core::bitwarden::{Type2Error, decrypt_type2, encrypt_type2, stretch_master_key};
use ragewarden_core::sync::{
    self as core_sync, KdfParams, LoginOptions, fetch_vault, login_with_options,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::guarded;
use crate::http::{run_async, shared_client};
use crate::sync_jni::SessionDto;
use crate::{
    build_vault_dto, jbyte_array_to_vec, json_out, parse_session_blob, server_from_url,
    throw_runtime, vec_to_jbyte_array,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct RawVaultDto {
    pub ciphers: Vec<core_sync::Cipher>,
    pub folders: Vec<core_sync::Folder>,
    pub organizations: Vec<core_sync::Organization>,
}

pub fn protect_user_keys(
    email: &str,
    kdf: &KdfParams,
    password: &str,
    enc_key: &[u8],
    mac_key: &[u8],
) -> Result<String, String> {
    let master = kdf
        .derive_master_key(password, email)
        .map_err(|e| format!("derive master key: {e}"))?;
    let (s_enc, s_mac) = stretch_master_key(&master);
    let mut joined = Zeroizing::new(Vec::with_capacity(enc_key.len() + mac_key.len()));
    joined.extend_from_slice(enc_key);
    joined.extend_from_slice(mac_key);
    Ok(encrypt_type2(&joined, &s_enc, &s_mac))
}

fn dto_kdf(dto: &SessionDto) -> KdfParams {
    KdfParams::from_parts(
        dto.kdf_type,
        dto.kdf_iterations,
        dto.kdf_memory_mib,
        dto.kdf_parallelism,
    )
}

pub fn unlock_session(blob: &[u8], password: &str) -> Result<Option<Vec<u8>>, String> {
    let mut dto: SessionDto =
        serde_json::from_slice(blob).map_err(|e| format!("parse Session: {e}"))?;
    if dto.protected_user_key.is_empty() {
        return Err("session has no protected user key".into());
    }
    let master = dto_kdf(&dto)
        .derive_master_key(password, &dto.email)
        .map_err(|e| format!("derive master key: {e}"))?;
    let (s_enc, s_mac) = stretch_master_key(&master);
    let raw = match decrypt_type2(&dto.protected_user_key, &s_enc, &s_mac) {
        Ok(v) => v,
        Err(Type2Error::MacFailed) => return Ok(None),
        Err(e) => return Err(format!("unwrap user key: {e}")),
    };
    if raw.len() != 64 {
        return Err(format!("user key has wrong length {}", raw.len()));
    }
    dto.user_enc_key_b64 = B64.encode(&raw[..32]);
    dto.user_mac_key_b64 = B64.encode(&raw[32..]);
    serde_json::to_vec(&dto)
        .map(Some)
        .map_err(|e| format!("encode Session: {e}"))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_loginWithDevice<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    server_url: JString<'local>,
    email: JString<'local>,
    password: JString<'local>,
    device_name: JString<'local>,
    device_id: JString<'local>,
    kdf_pin_json: JString<'local>,
    allow_legacy_kdf: jni::sys::jboolean,
) -> jbyteArray {
    guarded(env, |env| {
        let strings = (|| -> Result<_, jni::errors::Error> {
            Ok((
                server_url.try_to_string(env)?,
                email.try_to_string(env)?,
                Zeroizing::new(password.try_to_string(env)?),
                device_name.try_to_string(env)?,
                device_id.try_to_string(env)?,
            ))
        })();
        let (server_url, email, password, device_name, device_id) = match strings {
            Ok(v) => v,
            Err(e) => return throw_runtime(env, format!("get_string: {e}")),
        };
        let kdf_pin: Option<KdfParams> = if kdf_pin_json.is_null() {
            None
        } else {
            match kdf_pin_json
                .try_to_string(env)
                .map_err(|e| e.to_string())
                .and_then(|j| serde_json::from_str(&j).map_err(|e| e.to_string()))
            {
                Ok(k) => Some(k),
                Err(e) => return throw_runtime(env, format!("kdf pin: {e}")),
            }
        };
        let Some(server) = server_from_url(env, &server_url) else {
            return std::ptr::null_mut();
        };
        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => return throw_runtime(env, format!("http client: {e}")),
        };
        let res = run_async(async {
            let opts = LoginOptions {
                device_id: Some(device_id.clone()),
                kdf_pin,
                allow_legacy_kdf,
            };
            login_with_options(&client, &server, &email, &password, &device_name, &opts).await
        });
        let session = match res {
            Ok(s) => s,
            Err(e) => return throw_runtime(env, format!("login: {e}")),
        };
        let protected_user_key = match protect_user_keys(
            &session.email,
            &session.kdf,
            &password,
            &session.user_enc_key,
            &session.user_mac_key,
        ) {
            Ok(p) => p,
            Err(e) => return throw_runtime(env, e),
        };
        json_out(
            env,
            &session_dto(session, &server, protected_user_key),
            "Session",
        )
    })
}

fn session_dto(
    session: core_sync::Session,
    server: &core_sync::Server,
    protected_user_key: String,
) -> SessionDto {
    SessionDto {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        user_id: session.user_id,
        email: session.email,
        user_enc_key_b64: B64.encode(&session.user_enc_key),
        user_mac_key_b64: B64.encode(&session.user_mac_key),
        kdf_iterations: session.kdf.iterations,
        kdf_type: Some(session.kdf.kdf),
        kdf_memory_mib: session.kdf.memory_mib,
        kdf_parallelism: session.kdf.parallelism,
        device_id: session.device_id,
        api_url: server.api_url.clone(),
        identity_url: server.identity_url.clone(),
        protected_user_key,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_refreshSession<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(bytes) = jbyte_array_to_vec(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let bytes = Zeroizing::new(bytes);
        let mut dto: SessionDto = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(e) => return throw_runtime(env, format!("parse Session: {e}")),
        };
        let Some((server, mut session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => return throw_runtime(env, format!("http client: {e}")),
        };
        if let Err(e) =
            run_async(async { core_sync::refresh_session(&client, &server, &mut session).await })
        {
            return throw_runtime(env, format!("refresh_session: {e}"));
        }
        dto.access_token = session.access_token;
        dto.refresh_token = session.refresh_token;
        json_out(env, &dto, "Session")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_upgradeKdf<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    password: JString<'local>,
    device_name: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let (password, device_name) =
            match (password.try_to_string(env), device_name.try_to_string(env)) {
                (Ok(p), Ok(d)) => (Zeroizing::new(p), d),
                _ => return throw_runtime(env, "get_string(password/deviceName)"),
            };
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => return throw_runtime(env, format!("http client: {e}")),
        };
        let target = KdfParams::pbkdf2(ragewarden_core::bitwarden::KDF_ITERATIONS_DEFAULT);
        let upgraded = match run_async(async {
            core_sync::upgrade_kdf(&client, &server, &session, &password, &device_name, target)
                .await
        }) {
            Ok(s) => s,
            Err(e) => return throw_runtime(env, format!("upgrade_kdf: {e}")),
        };
        let protected = match protect_user_keys(
            &upgraded.email,
            &upgraded.kdf,
            &password,
            &upgraded.user_enc_key,
            &upgraded.user_mac_key,
        ) {
            Ok(p) => p,
            Err(e) => return throw_runtime(env, e),
        };
        json_out(env, &session_dto(upgraded, &server, protected), "Session")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_unlockSession<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    password: JString<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some(bytes) = jbyte_array_to_vec(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let password = match password.try_to_string(env) {
            Ok(p) => Zeroizing::new(p),
            Err(e) => return throw_runtime(env, format!("get_string(password): {e}")),
        };
        match unlock_session(&bytes, &password) {
            Ok(Some(out)) => {
                let out = Zeroizing::new(out);
                vec_to_jbyte_array(env, &out)
            }
            Ok(None) => vec_to_jbyte_array(env, &[]),
            Err(e) => throw_runtime(env, e),
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_fetchVaultRaw<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => return throw_runtime(env, format!("http client: {e}")),
        };
        let vault = match run_async(async { fetch_vault(&client, &server, &session).await }) {
            Ok(v) => v,
            Err(e) => return throw_runtime(env, format!("fetch_vault: {e}")),
        };
        let raw = RawVaultDto {
            ciphers: vault.ciphers,
            folders: vault.folders,
            organizations: vault.organizations,
        };
        json_out(env, &raw, "RawVault")
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_ragewarden_ragedroid_jni_RageNative_decryptVault<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    session_blob: JByteArray<'local>,
    raw_vault: JByteArray<'local>,
) -> jbyteArray {
    guarded(env, |env| {
        let Some((_server, session)) = parse_session_blob(env, &session_blob) else {
            return std::ptr::null_mut();
        };
        let Some(raw) = jbyte_array_to_vec(env, &raw_vault) else {
            return std::ptr::null_mut();
        };
        let raw: RawVaultDto = match serde_json::from_slice(&raw) {
            Ok(r) => r,
            Err(e) => return throw_runtime(env, format!("parse RawVault: {e}")),
        };
        let vault = core_sync::Vault {
            ciphers: raw.ciphers,
            folders: raw.folders,
            organizations: raw.organizations,
        };
        let dto = build_vault_dto(&session, &vault);
        json_out(env, &dto, "Vault")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_json(enc: &[u8], mac: &[u8], protected: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "accessToken": "at", "refreshToken": "rt", "userId": "u", "email": "a@example.org",
            "userEncKeyB64": B64.encode(enc), "userMacKeyB64": B64.encode(mac),
            "kdfIterations": 5000, "deviceId": "dev-1",
            "apiUrl": "https://vault.example.org/api", "identityUrl": "https://vault.example.org/identity",
            "protectedUserKey": protected,
        }))
        .unwrap()
    }

    #[test]
    fn lock_drops_the_keys_and_the_right_password_restores_them() {
        let enc = [7u8; 32];
        let mac = [9u8; 32];
        let protected = protect_user_keys(
            "a@example.org",
            &KdfParams::pbkdf2(5000),
            "correct horse",
            &enc,
            &mac,
        )
        .unwrap();
        let locked = session_json(b"", b"", &protected);

        assert!(unlock_session(&locked, "wrong").unwrap().is_none());
        let unlocked = unlock_session(&locked, "correct horse").unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&unlocked).unwrap();
        assert_eq!(v["userEncKeyB64"], B64.encode(enc));
        assert_eq!(v["userMacKeyB64"], B64.encode(mac));
    }

    #[test]
    fn a_legacy_session_without_a_protected_key_cannot_unlock_offline() {
        let blob = session_json(&[1u8; 32], &[2u8; 32], "");
        let legacy: SessionDto = serde_json::from_slice(&blob).unwrap();
        assert!(legacy.protected_user_key.is_empty());
        assert!(unlock_session(&blob, "anything").is_err());
    }

    #[test]
    fn raw_vault_round_trips_and_stays_ciphertext() {
        let raw = RawVaultDto {
            ciphers: vec![],
            folders: vec![],
            organizations: vec![],
        };
        let bytes = serde_json::to_vec(&raw).unwrap();
        let back: RawVaultDto = serde_json::from_slice(&bytes).unwrap();
        assert!(back.ciphers.is_empty());
    }
}
