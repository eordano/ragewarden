use age::secrecy::ExposeSecret;
use keyring::Entry;
use ragewarden_core::{FileKey, Identity, IdentityError, Stanza};
use thiserror::Error;
use zeroize::Zeroizing;

pub const KEYRING_SERVICE: &str = "ragewarden";

#[derive(Debug, Error)]
pub enum KeyringIdentityError {
    #[error("keyring: {0}")]
    Keyring(String),

    #[error("keyring entry parse: {0}")]
    Parse(String),
}

impl From<keyring::Error> for KeyringIdentityError {
    fn from(e: keyring::Error) -> Self {
        Self::Keyring(e.to_string())
    }
}

pub fn enroll(service: &str, user: &str) -> Result<EnrolledKeyring, KeyringIdentityError> {
    let id = age::x25519::Identity::generate();
    let armored_secret = Zeroizing::new(id.to_string().expose_secret().to_string());
    let armored_pubkey =
        ragewarden_core::ArmoredAgeRecipient::from_trusted(id.to_public().to_string());

    let entry = Entry::new(service, user)?;
    entry.set_password(armored_secret.as_str())?;
    drop(armored_secret);

    Ok(EnrolledKeyring {
        service: service.to_string(),
        user: user.to_string(),
        armored_pubkey,
    })
}

#[derive(Debug, Clone)]
pub struct EnrolledKeyring {
    pub service: String,

    pub user: String,

    pub armored_pubkey: ragewarden_core::ArmoredAgeRecipient,
}

pub fn read_identity(
    service: &str,
    user: &str,
) -> Result<age::x25519::Identity, KeyringIdentityError> {
    let entry = Entry::new(service, user)?;
    let secret = entry.get_password()?;
    let id: age::x25519::Identity = secret
        .parse()
        .map_err(|e: &str| KeyringIdentityError::Parse(e.to_string()))?;
    Ok(id)
}

pub fn delete(service: &str, user: &str) -> Result<(), KeyringIdentityError> {
    let entry = Entry::new(service, user)?;
    entry.delete_credential()?;
    Ok(())
}

pub struct KeyringIdentity {
    inner: age::x25519::Identity,
    label: String,
}

impl KeyringIdentity {
    pub fn open(
        service: &str,
        user: &str,
        label: impl Into<String>,
    ) -> Result<Self, KeyringIdentityError> {
        let inner = read_identity(service, user)?;
        Ok(Self {
            inner,
            label: label.into(),
        })
    }
}

impl Identity for KeyringIdentity {
    fn try_unwrap_stanza(&self, _stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        Ok(None)
    }

    fn display(&self) -> &str {
        &self.label
    }

    fn as_software_age_identity(&self) -> Option<&age::x25519::Identity> {
        Some(&self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_then_read_then_delete_round_trip() {
        let user = format!("test-{}", uuid_like());
        let r = enroll(KEYRING_SERVICE, &user);
        let enrolled = match r {
            Ok(e) => e,
            Err(KeyringIdentityError::Keyring(s)) => {
                eprintln!("test skipped: keyring backend unavailable: {s}");
                return;
            }
            Err(other) => panic!("unexpected error: {other}"),
        };

        let id = read_identity(KEYRING_SERVICE, &user).expect("read");
        assert_eq!(id.to_public().to_string(), enrolled.armored_pubkey.as_str());
        delete(KEYRING_SERVICE, &user).expect("delete");
    }

    fn uuid_like() -> String {
        use rand::Rng;
        let mut b = [0u8; 8];
        rand::rng().fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
