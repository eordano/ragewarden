use std::fs;
use std::io;
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ragewarden_core::sync::{Server, Session};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session io: {0}")]
    Io(#[from] io::Error),

    #[error("session parse: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("session base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("session version {0} not supported (expected 1)")]
    UnsupportedVersion(u32),

    #[error("session.json is encrypted to identity.age: {0}")]
    Sealed(String),
}

const SEALED_HEADER: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

/// The session carries the user key, so when `identity.age` is passphrase
/// protected the session is encrypted to that identity too: one passphrase
/// guards both, and a reader of the config directory gets neither.
fn seal_if_identity_protected(json: Vec<u8>) -> Result<Vec<u8>, SessionError> {
    use std::io::Write;
    let id_path = config::identity_path()?;
    if !id_path.exists() || !crate::idfile::is_protected(&id_path).unwrap_or(false) {
        return Ok(json);
    }
    let pubkey = crate::idfile::read_public_key_armored(&id_path)
        .map_err(|e| SessionError::Sealed(e.to_string()))?;
    let recipient: age::x25519::Recipient = pubkey
        .parse()
        .map_err(|e: &str| SessionError::Sealed(e.to_string()))?;
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| SessionError::Sealed(e.to_string()))?;
    let mut out = Vec::new();
    let armor = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)?;
    let mut w = encryptor
        .wrap_output(armor)
        .map_err(|e| SessionError::Sealed(e.to_string()))?;
    w.write_all(&json)?;
    w.finish().and_then(|a| a.finish())?;
    Ok(out)
}

fn unseal(bytes: Vec<u8>) -> Result<zeroize::Zeroizing<Vec<u8>>, SessionError> {
    use std::io::Read;
    if !bytes.starts_with(SEALED_HEADER) {
        return Ok(zeroize::Zeroizing::new(bytes));
    }
    let identity = crate::idfile::read(&config::identity_path()?)
        .map_err(|e| SessionError::Sealed(e.to_string()))?;
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(&bytes[..]))
        .map_err(|e| SessionError::Sealed(e.to_string()))?;
    let mut r = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| SessionError::Sealed(e.to_string()))?;
    let mut out = zeroize::Zeroizing::new(Vec::new());
    r.read_to_end(&mut out)?;
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSession {
    version: u32,
    server: Server,
    email: String,
    user_id: String,
    access_token: ragewarden_core::BearerToken,
    refresh_token: ragewarden_core::RefreshToken,

    user_enc_key_b64: String,

    user_mac_key_b64: String,
    kdf_iterations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf_type: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf_memory_mib: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf_parallelism: Option<u32>,
    #[serde(default)]
    device_id: String,
}

pub struct OpenSession {
    pub server: Server,

    pub session: Session,
}

pub fn session_path() -> io::Result<PathBuf> {
    Ok(config::config_dir()?.join("session.json"))
}

pub fn save(server: &Server, session: &Session) -> Result<(), SessionError> {
    let stored = StoredSession {
        version: 1,
        server: server.clone(),
        email: session.email.clone(),
        user_id: session.user_id.clone(),
        access_token: session.access_token.clone(),
        refresh_token: session.refresh_token.clone(),
        user_enc_key_b64: B64.encode(&session.user_enc_key),
        user_mac_key_b64: B64.encode(&session.user_mac_key),
        kdf_iterations: session.kdf.iterations,
        kdf_type: Some(session.kdf.kdf),
        kdf_memory_mib: session.kdf.memory_mib,
        kdf_parallelism: session.kdf.parallelism,
        device_id: session.device_id.clone(),
    };
    let path = session_path()?;
    config::ensure_config_dir()?;
    let json = serde_json::to_vec_pretty(&stored)?;
    config::write_private(&path, &seal_if_identity_protected(json)?)?;
    Ok(())
}

pub fn load() -> Result<Option<OpenSession>, SessionError> {
    let path = session_path()?;
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let bytes = unseal(bytes)?;
    let stored: StoredSession = serde_json::from_slice(&bytes)?;
    if stored.version != 1 {
        return Err(SessionError::UnsupportedVersion(stored.version));
    }
    let user_enc_key = B64.decode(&stored.user_enc_key_b64)?;
    let user_mac_key = B64.decode(&stored.user_mac_key_b64)?;
    let session = Session {
        access_token: stored.access_token,
        refresh_token: stored.refresh_token,
        user_id: stored.user_id,
        email: stored.email,
        user_enc_key: user_enc_key.into(),
        user_mac_key: user_mac_key.into(),
        kdf: ragewarden_core::sync::KdfParams::from_parts(
            stored.kdf_type,
            stored.kdf_iterations,
            stored.kdf_memory_mib,
            stored.kdf_parallelism,
        ),
        device_id: stored.device_id,
    };
    Ok(Some(OpenSession {
        server: stored.server,
        session,
    }))
}

/// The KDF parameters an account had at its last successful login, keyed by
/// server and email. Kept outside `session.json` so `logout` does not forget
/// them: a later login refuses a server that offers weaker ones.
fn kdf_pins_path() -> io::Result<PathBuf> {
    Ok(config::config_dir()?.join("kdf-pins.json"))
}

fn kdf_pin_key(server_url: &str, email: &str) -> String {
    format!(
        "{}|{}",
        server_url.trim().trim_end_matches('/'),
        email.trim().to_lowercase()
    )
}

fn load_kdf_pins()
-> Result<std::collections::BTreeMap<String, ragewarden_core::sync::KdfParams>, SessionError> {
    match fs::read(kdf_pins_path()?) {
        Ok(b) => Ok(serde_json::from_slice(&b)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(e.into()),
    }
}

pub fn kdf_pin(
    server_url: &str,
    email: &str,
) -> Result<Option<ragewarden_core::sync::KdfParams>, SessionError> {
    Ok(load_kdf_pins()?
        .get(&kdf_pin_key(server_url, email))
        .copied())
}

pub fn save_kdf_pin(
    server_url: &str,
    email: &str,
    kdf: &ragewarden_core::sync::KdfParams,
) -> Result<(), SessionError> {
    let mut pins = load_kdf_pins()?;
    pins.insert(kdf_pin_key(server_url, email), *kdf);
    config::ensure_config_dir()?;
    config::write_private(&kdf_pins_path()?, &serde_json::to_vec_pretty(&pins)?)?;
    Ok(())
}

pub fn clear() -> Result<(), SessionError> {
    let session = session_path()?;
    let vault = config::vault_cache_path()?;
    for p in [session, vault] {
        if let Err(e) = fs::remove_file(&p) {
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_lock::ENV_LOCK;

    #[test]
    fn a_kdf_pin_outlives_logout_and_is_per_server_and_email() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", dir.path());
        let k = ragewarden_core::sync::KdfParams::pbkdf2(600_000);
        save_kdf_pin("https://vault.test/", "Me@X", &k).unwrap();
        clear().unwrap();
        assert_eq!(kdf_pin("https://vault.test", "me@x").unwrap(), Some(k));
        assert_eq!(kdf_pin("https://other.test", "me@x").unwrap(), None);
        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
    }

    #[test]
    fn with_a_protected_identity_the_session_is_sealed_to_it() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", dir.path());
        let id_path = config::identity_path().unwrap();
        crate::idfile::generate_and_write(
            &id_path,
            crate::idfile::AtRest::Passphrase(age::secrecy::SecretString::from("pw".to_string())),
        )
        .unwrap();
        let sealed = seal_if_identity_protected(b"{\"user_enc_key_b64\":\"x\"}".to_vec()).unwrap();
        assert!(sealed.starts_with(SEALED_HEADER));
        assert!(!String::from_utf8_lossy(&sealed).contains("user_enc_key_b64"));
        std::fs::remove_file(&id_path).unwrap();
        let plain = seal_if_identity_protected(b"{}".to_vec()).unwrap();
        assert_eq!(plain, b"{}");
        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
    }
}
