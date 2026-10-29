//! What a rage blob seals: the plaintext inside the age encryption.
//!
//! v1 is the secret itself, raw bytes: the item's primary field (a login's
//! password, a note's body, a card's number, ...). v2 is [`V2_MAGIC`]
//! followed by a JSON object mapping field names to string values, and is
//! written whenever more than one field -- or a field other than the primary
//! one -- is protected. A v1 plaintext never starts with [`V2_MAGIC`]:
//! [`seal`] writes a primary-only value that does as v2.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

/// A NUL byte cannot start a secret typed into any client, so no v1 payload
/// written before v2 existed carries it.
pub const V2_MAGIC: &[u8] = b"\x00ragewarden:fields:v2\n";

pub const TYPE_LOGIN: u8 = 1;
pub const TYPE_SECURE_NOTE: u8 = 2;
pub const TYPE_CARD: u8 = 3;
pub const TYPE_IDENTITY: u8 = 4;
pub const TYPE_SSH_KEY: u8 = 5;

/// The field a v1 payload holds for an item of `cipher_type`.
pub fn primary_field(cipher_type: u8) -> &'static str {
    match cipher_type {
        TYPE_SECURE_NOTE => "notes",
        TYPE_CARD => "number",
        TYPE_IDENTITY => "ssn",
        TYPE_SSH_KEY => "privateKey",
        _ => "password",
    }
}

/// The field a request names: an empty name is the primary field, and a
/// secure note's "password" is its body, as the clients have always asked.
pub fn canonical_field(cipher_type: u8, requested: &str) -> String {
    if requested.is_empty() || (cipher_type == TYPE_SECURE_NOTE && requested == "password") {
        primary_field(cipher_type).to_string()
    } else {
        requested.to_string()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("nothing to protect")]
    Empty,

    #[error("protected field `{0}` is not valid UTF-8; only the primary field may hold raw bytes")]
    NotText(String),

    #[error("this item's protected payload has no `{0}` field")]
    MissingField(String),

    #[error("the protected payload is a v2 field map that does not parse: {0}")]
    Malformed(String),
}

#[derive(Serialize, Deserialize)]
struct V2<'a> {
    v: u32,
    #[serde(borrow)]
    fields: BTreeMap<&'a str, &'a str>,
}

#[derive(Deserialize)]
struct V2Owned {
    fields: BTreeMap<String, String>,
}

/// The plaintext to encrypt for `fields` on an item of `cipher_type`.
pub fn seal(
    cipher_type: u8,
    fields: &BTreeMap<String, Zeroizing<Vec<u8>>>,
) -> Result<Zeroizing<Vec<u8>>, PayloadError> {
    if fields.is_empty() {
        return Err(PayloadError::Empty);
    }
    let primary = primary_field(cipher_type);
    if fields.len() == 1 {
        if let Some(value) = fields.get(primary) {
            if !value.starts_with(V2_MAGIC) {
                return Ok(value.clone());
            }
        }
    }
    let mut text = BTreeMap::new();
    for (name, value) in fields {
        let s = std::str::from_utf8(value).map_err(|_| PayloadError::NotText(name.clone()))?;
        text.insert(name.as_str(), s);
    }
    let json = Zeroizing::new(
        serde_json::to_vec(&V2 { v: 2, fields: text })
            .map_err(|e| PayloadError::Malformed(e.to_string()))?,
    );
    let mut out = Zeroizing::new(Vec::with_capacity(V2_MAGIC.len() + json.len()));
    out.extend_from_slice(V2_MAGIC);
    out.extend_from_slice(&json);
    Ok(out)
}

/// [`seal`] for one value of the primary field.
pub fn seal_primary(cipher_type: u8, value: &[u8]) -> Result<Zeroizing<Vec<u8>>, PayloadError> {
    let mut fields = BTreeMap::new();
    fields.insert(
        primary_field(cipher_type).to_string(),
        Zeroizing::new(value.to_vec()),
    );
    seal(cipher_type, &fields)
}

/// Every protected field in `plaintext`, by name.
pub fn open(
    cipher_type: u8,
    plaintext: &[u8],
) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>, PayloadError> {
    let mut out = BTreeMap::new();
    match plaintext.strip_prefix(V2_MAGIC) {
        None => {
            out.insert(
                primary_field(cipher_type).to_string(),
                Zeroizing::new(plaintext.to_vec()),
            );
        }
        Some(json) => {
            let doc: V2Owned =
                serde_json::from_slice(json).map_err(|e| PayloadError::Malformed(e.to_string()))?;
            for (name, value) in doc.fields {
                out.insert(name, Zeroizing::new(value.into_bytes()));
            }
        }
    }
    Ok(out)
}

/// The request that answers with the whole payload, unparsed: for re-wrapping
/// an item (rotation, restriction) without touching its format.
pub const WHOLE_PAYLOAD: &str = "*";

/// One field out of `plaintext`; `requested` goes through
/// [`canonical_field`], so an empty name is the primary field, and
/// [`WHOLE_PAYLOAD`] returns `plaintext` itself.
pub fn field(
    cipher_type: u8,
    plaintext: &[u8],
    requested: &str,
) -> Result<Zeroizing<Vec<u8>>, PayloadError> {
    if requested == WHOLE_PAYLOAD {
        return Ok(Zeroizing::new(plaintext.to_vec()));
    }
    let name = canonical_field(cipher_type, requested);
    let mut fields = open(cipher_type, plaintext)?;
    fields.remove(&name).ok_or(PayloadError::MissingField(name))
}

/// The names [`open`] would return, without keeping any value.
pub fn field_names(cipher_type: u8, plaintext: &[u8]) -> Result<Vec<String>, PayloadError> {
    Ok(open(cipher_type, plaintext)?.into_keys().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, Zeroizing<Vec<u8>>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.as_bytes().to_vec())))
            .collect()
    }

    #[test]
    fn a_single_primary_field_is_written_as_v1() {
        let sealed = seal(TYPE_LOGIN, &map(&[("password", "hunter2")])).unwrap();
        assert_eq!(&sealed[..], b"hunter2");
        assert_eq!(&field(TYPE_LOGIN, &sealed, "").unwrap()[..], b"hunter2");
        assert_eq!(
            &field(TYPE_LOGIN, &sealed, "password").unwrap()[..],
            b"hunter2"
        );
    }

    #[test]
    fn several_fields_or_a_non_primary_one_are_written_as_v2() {
        let sealed = seal(TYPE_CARD, &map(&[("number", "4111"), ("code", "123")])).unwrap();
        assert!(sealed.starts_with(V2_MAGIC));
        assert_eq!(&field(TYPE_CARD, &sealed, "code").unwrap()[..], b"123");
        assert_eq!(&field(TYPE_CARD, &sealed, "").unwrap()[..], b"4111");
        assert_eq!(field_names(TYPE_CARD, &sealed).unwrap(), ["code", "number"]);

        let only_code = seal(TYPE_CARD, &map(&[("code", "123")])).unwrap();
        assert!(only_code.starts_with(V2_MAGIC));
        assert_eq!(
            field(TYPE_CARD, &only_code, "number").unwrap_err(),
            PayloadError::MissingField("number".into())
        );
    }

    #[test]
    fn a_primary_value_that_looks_like_v2_is_written_as_v2() {
        let mut tricky = V2_MAGIC.to_vec();
        tricky.extend_from_slice(br#"{"v":2,"fields":{"password":"forged"}}"#);
        let mut fields = BTreeMap::new();
        fields.insert("password".to_string(), Zeroizing::new(tricky.clone()));
        let sealed = seal(TYPE_LOGIN, &fields).unwrap();
        assert_eq!(
            &field(TYPE_LOGIN, &sealed, "password").unwrap()[..],
            &tricky[..]
        );
    }

    #[test]
    fn raw_bytes_survive_as_v1_but_not_as_a_v2_field() {
        let raw = [0xff, 0xfe, 0x00, 0x01];
        let sealed = seal_primary(TYPE_LOGIN, &raw).unwrap();
        assert_eq!(&sealed[..], &raw);
        let mut fields = map(&[("notes", "x")]);
        fields.insert("password".into(), Zeroizing::new(raw.to_vec()));
        assert_eq!(
            seal(TYPE_LOGIN, &fields).unwrap_err(),
            PayloadError::NotText("password".into())
        );
    }

    #[test]
    fn a_note_asked_for_its_password_answers_with_its_body() {
        let sealed = seal_primary(TYPE_SECURE_NOTE, b"body").unwrap();
        assert_eq!(
            &field(TYPE_SECURE_NOTE, &sealed, "password").unwrap()[..],
            b"body"
        );
        assert_eq!(canonical_field(TYPE_LOGIN, "password"), "password");
        assert_eq!(canonical_field(TYPE_SSH_KEY, ""), "privateKey");
    }

    #[test]
    fn the_whole_payload_is_returned_as_is_for_rewrapping() {
        let sealed = seal(TYPE_CARD, &map(&[("number", "4111"), ("code", "123")])).unwrap();
        assert_eq!(
            &field(TYPE_CARD, &sealed, WHOLE_PAYLOAD).unwrap()[..],
            &sealed[..]
        );
    }

    #[test]
    fn empty_and_malformed_payloads_are_errors() {
        assert_eq!(
            seal(TYPE_LOGIN, &BTreeMap::new()).unwrap_err(),
            PayloadError::Empty
        );
        let mut bad = V2_MAGIC.to_vec();
        bad.extend_from_slice(b"{not json");
        assert!(matches!(
            open(TYPE_LOGIN, &bad),
            Err(PayloadError::Malformed(_))
        ));
    }
}
