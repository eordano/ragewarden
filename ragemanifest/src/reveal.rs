use ragewarden_core::sync::{decrypt_string, Cipher, Session};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RevealError {
    #[error("this item has no `{field}` to reveal")]
    MissingField { field: String },

    #[error("decrypt: {0}")]
    Decrypt(String),
}

impl RevealError {
    /// Stable machine-readable code, mirrored onto the JS `Error.code` at the
    /// WASM boundary so the UI never string-matches messages.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingField { .. } => "missing_field",
            Self::Decrypt(_) => "decrypt_failed",
        }
    }
}

const CIPHER_TYPE_NOTE: u8 = 2;

/// The popup's default reveal target is "password", which a SecureNote does
/// not have -- its secret is the note body. Resolving the field by cipher kind
/// here means a note-type item can never be asked for `login.password`.
pub fn resolve_reveal_field<'a>(cipher: &Cipher, requested: &'a str) -> &'a str {
    if cipher.cipher_type == CIPHER_TYPE_NOTE && (requested.is_empty() || requested == "password")
    {
        return "notes";
    }
    requested
}

pub fn decrypt_non_rage_field(
    session: &Session,
    cipher: &Cipher,
    field: &str,
) -> Result<Vec<u8>, RevealError> {
    let field = resolve_reveal_field(cipher, field);
    let missing = |name: &str| RevealError::MissingField {
        field: name.to_string(),
    };
    let ciphertext = match field {
        "password" => cipher
            .login
            .as_ref()
            .and_then(|l| l.password.clone())
            .ok_or_else(|| missing("login.password"))?,
        "username" => cipher
            .login
            .as_ref()
            .and_then(|l| l.username.clone())
            .ok_or_else(|| missing("login.username"))?,
        "totp" => cipher
            .login
            .as_ref()
            .and_then(|l| l.totp.clone())
            .ok_or_else(|| missing("login.totp"))?,
        "notes" => cipher.notes.clone().ok_or_else(|| missing("notes"))?,
        other => match cipher.fields.as_ref() {
            Some(fields) => {
                let mut found = None;
                for f in fields {
                    let plaintext_name = decrypt_string(session, &f.name).unwrap_or_default();
                    if plaintext_name == other {
                        found = f.value.clone();
                        break;
                    }
                }
                found.ok_or_else(|| missing(other))?
            }
            None => return Err(missing(other)),
        },
    };

    let bytes = ragewarden_core::bitwarden::decrypt_type2(
        ciphertext.as_str(),
        &expect32(&session.user_enc_key, "user_enc_key")?,
        &expect32(&session.user_mac_key, "user_mac_key")?,
    )
    .map_err(|e| RevealError::Decrypt(format!("type2 decrypt: {e}")))?;
    Ok(bytes)
}

fn expect32(slice: &[u8], label: &'static str) -> Result<[u8; 32], RevealError> {
    slice
        .try_into()
        .map_err(|_| RevealError::Decrypt(format!("{label} wrong length: {}", slice.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragewarden_core::bitwarden::{derive_master_key, encrypt_type2, make_user_key};
    use ragewarden_core::sync::{CipherField, CipherLogin, SecureNote};
    use ragewarden_core::Type2EncString;

    fn make_session() -> Session {
        let master = derive_master_key("hunter2", "test@example.com", 100);
        let user_key = make_user_key(&master);
        Session {
            access_token: ragewarden_core::BearerToken::from_trusted("access-stub".into()),
            refresh_token: ragewarden_core::RefreshToken::from_trusted("refresh-stub".into()),
            user_id: "00000000-0000-0000-0000-000000000000".into(),
            email: "test@example.com".into(),
            user_enc_key: user_key.enc_key.to_vec().into(),
            user_mac_key: user_key.mac_key.to_vec().into(),
            kdf_iterations: 100,
            device_id: "test-device".into(),
        }
    }

    fn type2(s: &str, session: &Session) -> Type2EncString {
        let enc: [u8; 32] = session.user_enc_key[..].try_into().unwrap();
        let mac: [u8; 32] = session.user_mac_key[..].try_into().unwrap();
        Type2EncString::from_trusted(encrypt_type2(s.as_bytes(), &enc, &mac))
    }

    fn note_cipher(session: &Session, notes: Option<&str>) -> Cipher {
        Cipher {
            id: Some("note-1".into()),
            cipher_type: 2,
            name: type2("A note", session),
            notes: notes.map(|n| type2(n, session)),
            secure_note: Some(SecureNote { note_type: 0 }),
            ..Default::default()
        }
    }

    #[test]
    fn note_reveal_of_password_returns_the_note_body() {
        let session = make_session();
        let cipher = note_cipher(&session, Some("the note body"));
        let got = decrypt_non_rage_field(&session, &cipher, "password").expect("reveal");
        assert_eq!(got, b"the note body");
    }

    #[test]
    fn note_reveal_with_empty_field_also_returns_the_note_body() {
        let session = make_session();
        let cipher = note_cipher(&session, Some("the note body"));
        let got = decrypt_non_rage_field(&session, &cipher, "").expect("reveal");
        assert_eq!(got, b"the note body");
    }

    #[test]
    fn note_without_body_reports_notes_missing_never_login_password() {
        let session = make_session();
        let cipher = note_cipher(&session, None);
        let err = decrypt_non_rage_field(&session, &cipher, "password").unwrap_err();
        assert_eq!(err.code(), "missing_field");
        let msg = format!("{err}");
        assert!(msg.contains("notes"), "got: {msg}");
        assert!(!msg.contains("login.password"), "got: {msg}");
    }

    #[test]
    fn login_password_reveal_is_unchanged() {
        let session = make_session();
        let cipher = Cipher {
            id: Some("login-1".into()),
            cipher_type: 1,
            name: type2("Spotify", &session),
            login: Some(CipherLogin {
                password: Some(type2("s3cret", &session)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let got = decrypt_non_rage_field(&session, &cipher, "password").expect("reveal");
        assert_eq!(got, b"s3cret");
    }

    #[test]
    fn custom_field_lookup_still_works_on_notes() {
        let session = make_session();
        let mut cipher = note_cipher(&session, Some("body"));
        cipher.fields = Some(vec![CipherField {
            name: type2("api-key", &session),
            value: Some(type2("xyzzy", &session)),
            field_type: 1,
        }]);
        let got = decrypt_non_rage_field(&session, &cipher, "api-key").expect("reveal");
        assert_eq!(got, b"xyzzy");

        let err = decrypt_non_rage_field(&session, &cipher, "absent").unwrap_err();
        assert_eq!(err.code(), "missing_field");
    }
}
