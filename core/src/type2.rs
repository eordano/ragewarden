use serde::{Deserialize, Deserializer, Serialize};

use crate::bitwarden::Type2Error;

/// A Bitwarden EncString as the server sent it. Bitwarden also sends
/// encryption types this crate does not decrypt (RSA `4.`/`6.` for
/// organisation keys, COSE `7.`), so deserializing never fails on one: it
/// records whether the string is a well-formed Type-2 (`2.iv|ct|mac`), and
/// decryption refuses anything else with a named reason instead of parsing a
/// string that was never validated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Type2EncString {
    raw: String,
    #[serde(skip)]
    kind: EncStringKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncStringKind {
    Type2,
    /// Another `N.` encryption type, or `None` when the string has no
    /// recognisable type prefix at all.
    Unsupported(Option<u32>),
}

fn classify(s: &str) -> EncStringKind {
    let Some((prefix, body)) = s.split_once('.') else {
        return EncStringKind::Unsupported(None);
    };
    let enc_type = prefix.parse::<u32>().ok();
    if enc_type == Some(2) && body.split('|').count() == 3 {
        EncStringKind::Type2
    } else {
        EncStringKind::Unsupported(enc_type)
    }
}

/// The empty string, which no decryption accepts: it exists so records
/// such as `sync::Cipher` can derive `Default`, not as a placeholder value.
impl Default for Type2EncString {
    fn default() -> Self {
        Self {
            raw: String::new(),
            kind: EncStringKind::Unsupported(None),
        }
    }
}

impl<'de> Deserialize<'de> for Type2EncString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(Self {
            kind: classify(&raw),
            raw,
        })
    }
}

impl Type2EncString {
    pub fn from_trusted(s: String) -> Self {
        Self {
            kind: classify(&s),
            raw: s,
        }
    }

    pub fn try_new(s: String) -> Result<Self, Type2Error> {
        match classify(&s) {
            EncStringKind::Type2 => Ok(Self {
                raw: s,
                kind: EncStringKind::Type2,
            }),
            EncStringKind::Unsupported(Some(n)) if n != 2 => Err(Type2Error::UnsupportedEncType(n)),
            EncStringKind::Unsupported(_) => Err(Type2Error::Malformed),
        }
    }

    pub fn kind(&self) -> EncStringKind {
        self.kind
    }

    /// The string, if it is a well-formed Type-2 this crate can decrypt.
    pub fn as_type2(&self) -> Result<&str, Type2Error> {
        match self.kind {
            EncStringKind::Type2 => Ok(&self.raw),
            EncStringKind::Unsupported(Some(n)) if n != 2 => Err(Type2Error::UnsupportedEncType(n)),
            EncStringKind::Unsupported(_) => Err(Type2Error::Malformed),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn into_inner(self) -> String {
        self.raw
    }
}

impl AsRef<str> for Type2EncString {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

impl std::fmt::Display for Type2EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_accepts_well_formed() {
        let s = "2.aGVsbG8=|d29ybGQ=|bWFj".to_string();
        let t = Type2EncString::try_new(s.clone()).unwrap();
        assert_eq!(t.as_str(), s.as_str());
    }

    #[test]
    fn try_new_rejects_wrong_prefix() {
        assert!(Type2EncString::try_new("1.foo|bar|baz".into()).is_err());
        assert!(Type2EncString::try_new("foo|bar|baz".into()).is_err());
    }

    #[test]
    fn try_new_rejects_wrong_part_count() {
        assert!(Type2EncString::try_new("2.foo".into()).is_err());
        assert!(Type2EncString::try_new("2.foo|bar".into()).is_err());
        assert!(Type2EncString::try_new("2.a|b|c|d".into()).is_err());
    }

    #[test]
    fn deserializing_validates_without_failing_the_vault() {
        let t: Type2EncString = serde_json::from_str("\"2.a|b|c\"").unwrap();
        assert_eq!(t.kind(), EncStringKind::Type2);
        assert_eq!(t.as_type2().unwrap(), "2.a|b|c");

        let rsa: Type2EncString = serde_json::from_str("\"4.b2Fr\"").unwrap();
        assert_eq!(rsa.kind(), EncStringKind::Unsupported(Some(4)));
        assert!(matches!(
            rsa.as_type2().unwrap_err(),
            Type2Error::UnsupportedEncType(4)
        ));

        let cose: Type2EncString = serde_json::from_str("\"7.xyz\"").unwrap();
        assert_eq!(cose.kind(), EncStringKind::Unsupported(Some(7)));

        let short: Type2EncString = serde_json::from_str("\"2.a|b\"").unwrap();
        assert!(matches!(
            short.as_type2().unwrap_err(),
            Type2Error::Malformed
        ));

        assert!(Type2EncString::default().as_type2().is_err());

        let junk: Type2EncString = serde_json::from_str("\"no prefix\"").unwrap();
        assert_eq!(junk.kind(), EncStringKind::Unsupported(None));
        for raw in ["\"7.xyz\"", "\"2.a|b\"", "\"no prefix\""] {
            let t: Type2EncString = serde_json::from_str(raw).unwrap();
            assert_eq!(serde_json::to_string(&t).unwrap(), raw);
        }
    }

    #[test]
    fn serde_round_trip_is_transparent() {
        let t = Type2EncString::from_trusted("2.x|y|z".into());
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"2.x|y|z\"");
        let back: Type2EncString = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}
