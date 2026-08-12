use serde::{Deserialize, Serialize};

use crate::bitwarden::Type2Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct Type2EncString(String);

impl Type2EncString {
    pub fn from_trusted(s: String) -> Self {
        Self(s)
    }

    pub fn try_new(s: String) -> Result<Self, Type2Error> {
        let body = s.strip_prefix("2.").ok_or(Type2Error::Malformed)?;
        let mut parts = body.split('|');
        let _ = parts.next().ok_or(Type2Error::Malformed)?;
        let _ = parts.next().ok_or(Type2Error::Malformed)?;
        let _ = parts.next().ok_or(Type2Error::Malformed)?;
        if parts.next().is_some() {
            return Err(Type2Error::Malformed);
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Type2EncString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Type2EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
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
    fn serde_round_trip_is_transparent() {
        let t = Type2EncString::from_trusted("2.x|y|z".into());
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"2.x|y|z\"");
        let back: Type2EncString = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}
