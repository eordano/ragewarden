use ragewarden_core::sync::{Cipher, Session};
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

/// Whether reading `requested` takes the item's rage blob: the field is one
/// the blob holds (core's `rage:fields` marker, or the item's primary field
/// for a single-field item) and the item has a blob. A note's "password" is
/// its body.
pub fn rage_protects_field(
    session: &Session,
    cipher: &Cipher,
    requested: &str,
) -> Result<bool, RevealError> {
    ragewarden_core::sync::protects_field(session, cipher, requested)
        .map_err(|e| RevealError::Decrypt(e.to_string()))
}

/// An unprotected field from the Type-2 layer: login password, username or
/// TOTP, notes, a card, identity or SSH key field, or a custom field.
pub fn decrypt_non_rage_field(
    session: &Session,
    cipher: &Cipher,
    field: &str,
) -> Result<ragewarden_core::Plaintext, RevealError> {
    let name = ragewarden_core::protected::canonical_field(cipher.cipher_type, field);
    match ragewarden_core::sync::outer_field(session, cipher, &name) {
        Ok(Some(v)) => Ok(zeroize::Zeroizing::new(v.into_bytes())),
        Ok(None) => Err(RevealError::MissingField { field: name }),
        Err(e) => Err(RevealError::Decrypt(e.to_string())),
    }
}

/// One field of a decrypted rage payload (v1 or v2, core::protected).
pub fn protected_field(
    cipher: &Cipher,
    payload: &[u8],
    requested: &str,
) -> Result<ragewarden_core::Plaintext, RevealError> {
    ragewarden_core::protected::field(cipher.cipher_type, payload, requested).map_err(|e| match e {
        ragewarden_core::protected::PayloadError::MissingField(field) => {
            RevealError::MissingField { field }
        }
        other => RevealError::Decrypt(other.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragewarden_core::Type2EncString;
    use ragewarden_core::bitwarden::{derive_master_key, encrypt_type2, make_user_key};
    use ragewarden_core::sync::{CipherField, CipherLogin, SecureNote};

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
            kdf: ragewarden_core::sync::KdfParams::pbkdf2(100),
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
        assert_eq!(got.as_slice(), b"the note body");
    }

    #[test]
    fn note_reveal_with_empty_field_also_returns_the_note_body() {
        let session = make_session();
        let cipher = note_cipher(&session, Some("the note body"));
        let got = decrypt_non_rage_field(&session, &cipher, "").expect("reveal");
        assert_eq!(got.as_slice(), b"the note body");
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
        assert_eq!(got.as_slice(), b"s3cret");
    }

    #[test]
    fn rage_blob_answers_only_the_protected_field() {
        let session = make_session();
        let as_cipher = |c: ragewarden_core::sync::CipherIn| -> Cipher {
            serde_json::from_value(serde_json::to_value(c).unwrap()).unwrap()
        };
        let login = as_cipher(
            ragewarden_core::sync::build_cipher(
                &session,
                &ragewarden_core::sync::CipherDraft {
                    login: true,
                    name: "Spotify".into(),
                    username: Some("me".into()),
                    ..Default::default()
                },
                Some("BLOB"),
            )
            .unwrap(),
        );
        assert!(rage_protects_field(&session, &login, "password").unwrap());
        assert!(rage_protects_field(&session, &login, "").unwrap());
        assert!(!rage_protects_field(&session, &login, "username").unwrap());
        assert!(!rage_protects_field(&session, &login, "totp").unwrap());
        let note =
            as_cipher(ragewarden_core::sync::build_rage_cipher(&session, "n", "BLOB").unwrap());
        assert!(rage_protects_field(&session, &note, "password").unwrap());
        assert!(rage_protects_field(&session, &note, "notes").unwrap());
        assert!(!rage_protects_field(&session, &note, "api-key").unwrap());
        let plain = note_cipher(&session, Some("body"));
        assert!(
            !rage_protects_field(&session, &plain, "notes").unwrap(),
            "no blob, nothing protected"
        );

        let v2 = ragewarden_core::protected::seal(
            3,
            &[("number", "4111"), ("code", "123")]
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        zeroize::Zeroizing::new(v.as_bytes().to_vec()),
                    )
                })
                .collect(),
        )
        .unwrap();
        let card = Cipher {
            cipher_type: 3,
            ..Default::default()
        };
        assert_eq!(
            protected_field(&card, &v2, "code").unwrap().as_slice(),
            b"123"
        );
        assert_eq!(protected_field(&card, &v2, "").unwrap().as_slice(), b"4111");
        assert_eq!(
            protected_field(&card, &v2, "brand").unwrap_err().code(),
            "missing_field"
        );
    }

    #[test]
    fn custom_field_lookup_still_works_on_notes() {
        let session = make_session();
        let mut cipher = note_cipher(&session, Some("body"));
        cipher.fields = Some(vec![CipherField {
            name: type2("api-key", &session),
            value: Some(type2("xyzzy", &session)),
            field_type: 1,
            extra: Default::default(),
        }]);
        let got = decrypt_non_rage_field(&session, &cipher, "api-key").expect("reveal");
        assert_eq!(got.as_slice(), b"xyzzy");

        let err = decrypt_non_rage_field(&session, &cipher, "absent").unwrap_err();
        assert_eq!(err.code(), "missing_field");
    }
}

/// Why writing `replacement` as an item's whole rage payload would lose
/// protected fields, or `None` when it would not: the item protects a field
/// other than its primary one and `replacement` is a single secret rather
/// than a whole v2 payload (what a `*` read returns).
pub fn single_secret_overwrite_refusal(
    cipher_type: u8,
    protected: &[String],
    replacement: &[u8],
) -> Option<String> {
    if replacement.starts_with(ragewarden_core::protected::V2_MAGIC) {
        return None;
    }
    let primary = ragewarden_core::protected::primary_field(cipher_type);
    protected.iter().any(|f| f != primary).then(|| {
        format!(
            "this item protects several fields ({}); writing one secret would discard the \
             rest. Save it with wasm_save_item, or re-wrap the payload read with the field \
             name `*`.",
            protected.join(", ")
        )
    })
}

#[cfg(test)]
mod overwrite_tests {
    use super::single_secret_overwrite_refusal as refusal;
    use ragewarden_core::protected::{TYPE_CARD, TYPE_LOGIN, TYPE_SSH_KEY, V2_MAGIC, seal};
    use std::collections::BTreeMap;
    use zeroize::Zeroizing;

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn one_secret_over_a_multi_field_item_is_refused() {
        let msg = refusal(TYPE_CARD, &names(&["code", "number"]), b"4111").expect("refused");
        assert!(msg.contains("code, number"), "{msg}");
        assert!(refusal(TYPE_LOGIN, &names(&["password", "totp"]), b"hunter2").is_some());
        assert!(refusal(TYPE_SSH_KEY, &names(&["publicKey", "privateKey"]), b"k").is_some());
    }

    #[test]
    fn the_whole_payload_and_primary_only_items_pass() {
        let mut fields = BTreeMap::new();
        fields.insert("number".to_string(), Zeroizing::new(b"4111".to_vec()));
        fields.insert("code".to_string(), Zeroizing::new(b"123".to_vec()));
        let whole = seal(TYPE_CARD, &fields).unwrap();
        assert!(whole.starts_with(V2_MAGIC));
        assert_eq!(
            refusal(TYPE_CARD, &names(&["code", "number"]), &whole),
            None
        );
        assert_eq!(refusal(TYPE_CARD, &names(&["number"]), b"4111"), None);
        assert_eq!(refusal(TYPE_LOGIN, &names(&["password"]), b"hunter2"), None);
        assert_eq!(refusal(TYPE_LOGIN, &[], b"hunter2"), None);
    }
}
