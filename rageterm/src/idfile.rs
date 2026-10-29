use std::fs;
use std::io;
use std::path::Path;

use age::secrecy::ExposeSecret;
use thiserror::Error;

use crate::config;

#[derive(Debug, Error)]
pub enum IdFileError {
    #[error("identity file io: {0}")]
    Io(#[from] io::Error),

    #[error("identity file parse: {0}")]
    Parse(String),

    #[error("no identity enrolled at {path} -- run `rageterm enroll-software-identity`")]
    NotEnrolled { path: String },

    #[error("wrong passphrase for the identity file")]
    WrongPassphrase,
}

/// How `identity.age` is kept at rest.
pub enum AtRest {
    /// Age-encrypted with a passphrase (scrypt). `age -d -i identity.age`
    /// understands the same file.
    Passphrase(age::secrecy::SecretString),
    /// The bare age secret-key line, readable by anyone who can read the
    /// file.
    Plaintext,
}

const ENCRYPTED_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// The public key beside an encrypted identity, so recipients can be listed
/// and published without the passphrase.
pub fn public_sidecar(path: &Path) -> std::path::PathBuf {
    path.with_extension("pub")
}

pub fn generate_and_write(path: &Path, at_rest: AtRest) -> Result<String, IdFileError> {
    let id = age::x25519::Identity::generate();
    write_identity(path, &id, at_rest)?;
    Ok(id.to_public().to_string())
}

pub fn write_identity(
    path: &Path,
    id: &age::x25519::Identity,
    at_rest: AtRest,
) -> Result<(), IdFileError> {
    let secret_armored = id.to_string();
    let pub_armored = id.to_public().to_string();
    match at_rest {
        AtRest::Plaintext => {
            config::write_private(path, secret_armored.expose_secret().as_bytes())?;
        }
        AtRest::Passphrase(pass) => {
            let encrypted =
                encrypt_with_passphrase(secret_armored.expose_secret().as_bytes(), pass)?;
            config::write_private(&public_sidecar(path), format!("{pub_armored}\n").as_bytes())?;
            config::write_private(path, &encrypted)?;
        }
    }
    Ok(())
}

fn encrypt_with_passphrase(
    plaintext: &[u8],
    pass: age::secrecy::SecretString,
) -> Result<Vec<u8>, IdFileError> {
    use std::io::Write;
    let encryptor = age::Encryptor::with_user_passphrase(pass);
    let mut out = Vec::new();
    let armor = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)?;
    let mut w = encryptor
        .wrap_output(armor)
        .map_err(|e| IdFileError::Parse(e.to_string()))?;
    w.write_all(plaintext)?;
    w.finish().and_then(|armor| armor.finish())?;
    Ok(out)
}

fn decrypt_with_passphrase(
    armored: &[u8],
    pass: age::secrecy::SecretString,
) -> Result<zeroize::Zeroizing<Vec<u8>>, IdFileError> {
    use std::io::Read;
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(armored))
        .map_err(|e| IdFileError::Parse(e.to_string()))?;
    let identity = age::scrypt::Identity::new(pass);
    let mut r = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| IdFileError::WrongPassphrase)?;
    let mut out = zeroize::Zeroizing::new(Vec::new());
    r.read_to_end(&mut out)?;
    Ok(out)
}

pub fn is_protected(path: &Path) -> Result<bool, IdFileError> {
    Ok(fs::read_to_string(path)?
        .trim_start()
        .starts_with(ENCRYPTED_HEADER))
}

static UNLOCKED: std::sync::Mutex<Option<(std::path::PathBuf, age::secrecy::SecretString)>> =
    std::sync::Mutex::new(None);

fn passphrase_for(path: &Path) -> Result<age::secrecy::SecretString, IdFileError> {
    if let Some((p, pass)) = UNLOCKED.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        if p == path {
            return Ok(pass.clone());
        }
    }
    let typed = crate::pin::read_pin(
        "Identity passphrase: ",
        &format!(
            "{} is protected by a passphrase; it is needed to open software-wrapped items.",
            path.display()
        ),
    )
    .map_err(|e| IdFileError::Parse(e.to_string()))?;
    Ok(age::secrecy::SecretString::from(typed.to_string()))
}

pub fn read(path: &Path) -> Result<age::x25519::Identity, IdFileError> {
    let bytes = match fs::read_to_string(path) {
        Ok(s) => zeroize::Zeroizing::new(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(IdFileError::NotEnrolled {
                path: path.display().to_string(),
            });
        }
        Err(e) => return Err(e.into()),
    };

    if bytes.trim_start().starts_with(ENCRYPTED_HEADER) {
        let pass = passphrase_for(path)?;
        let plain = decrypt_with_passphrase(bytes.as_bytes(), pass.clone())?;
        let text = std::str::from_utf8(&plain).map_err(|e| IdFileError::Parse(e.to_string()))?;
        let id = parse_identity(text)?;
        *UNLOCKED.lock().unwrap_or_else(|e| e.into_inner()) = Some((path.to_path_buf(), pass));
        return Ok(id);
    }
    parse_identity(&bytes)
}

fn parse_identity(text: &str) -> Result<age::x25519::Identity, IdFileError> {
    let line = text
        .lines()
        .find(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .ok_or_else(|| IdFileError::Parse("identity file empty".into()))?;
    line.trim()
        .parse()
        .map_err(|e: &str| IdFileError::Parse(e.to_string()))
}

pub fn read_public_key_armored(path: &Path) -> Result<String, IdFileError> {
    if is_protected(path).unwrap_or(false) {
        if let Ok(pubkey) = fs::read_to_string(public_sidecar(path)) {
            let pubkey = pubkey.trim();
            if !pubkey.is_empty() {
                return Ok(pubkey.to_string());
            }
        }
    }
    let id = read(path)?;
    Ok(id.to_public().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_protected_identity_holds_no_secret_key_and_reopens_with_its_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.age");
        let pass = || age::secrecy::SecretString::from("correct horse".to_string());
        let pubkey = generate_and_write(&path, AtRest::Passphrase(pass())).unwrap();
        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains(concat!("AGE-SECRET", "-KEY-")));
        assert!(is_protected(&path).unwrap());
        assert_eq!(read_public_key_armored(&path).unwrap(), pubkey);
        let plain = decrypt_with_passphrase(on_disk.as_bytes(), pass()).unwrap();
        let id = parse_identity(std::str::from_utf8(&plain).unwrap()).unwrap();
        assert_eq!(id.to_public().to_string(), pubkey);
        assert!(matches!(
            decrypt_with_passphrase(
                on_disk.as_bytes(),
                age::secrecy::SecretString::from("wrong".to_string())
            ),
            Err(IdFileError::WrongPassphrase)
        ));
    }

    #[test]
    fn a_plaintext_identity_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.age");
        let pubkey = generate_and_write(&path, AtRest::Plaintext).unwrap();
        assert!(!is_protected(&path).unwrap());
        assert_eq!(read(&path).unwrap().to_public().to_string(), pubkey);
    }
}
