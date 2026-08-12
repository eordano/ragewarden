use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum ArmoredKeyError {
    #[error("expected prefix `{expected}`; got `{got}`")]
    WrongPrefix { expected: &'static str, got: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct ArmoredAgeRecipient(String);

impl ArmoredAgeRecipient {
    pub fn from_trusted(s: String) -> Self {
        Self(s)
    }

    pub fn try_new(s: String) -> Result<Self, ArmoredKeyError> {
        if !s.starts_with("age1") {
            return Err(ArmoredKeyError::WrongPrefix {
                expected: "age1",
                got: prefix_sample(&s),
            });
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

impl AsRef<str> for ArmoredAgeRecipient {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ArmoredAgeRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct ArmoredAgeSecret(Zeroizing<String>);

impl ArmoredAgeSecret {
    pub fn from_trusted(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    pub fn from_zeroizing(s: Zeroizing<String>) -> Self {
        Self(s)
    }

    pub fn try_new(s: String) -> Result<Self, ArmoredKeyError> {
        if !s.starts_with("AGE-SECRET-KEY-1") {
            return Err(ArmoredKeyError::WrongPrefix {
                expected: "AGE-SECRET-KEY-1",
                got: prefix_sample(&s),
            });
        }
        Ok(Self(Zeroizing::new(s)))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl PartialEq for ArmoredAgeSecret {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for ArmoredAgeSecret {}

fn prefix_sample(s: &str) -> String {
    s.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_try_new_accepts_age1_prefix() {
        let s = "age1xyz000".to_string();
        let r = ArmoredAgeRecipient::try_new(s.clone()).unwrap();
        assert_eq!(r.as_str(), s);
    }

    #[test]
    fn recipient_try_new_rejects_other_prefix() {
        assert!(ArmoredAgeRecipient::try_new("AGE-SECRET-KEY-1xyz".into()).is_err());
        assert!(ArmoredAgeRecipient::try_new("not-armored".into()).is_err());
    }

    #[test]
    fn secret_try_new_accepts_age_secret_prefix() {
        let s = "AGE-SECRET-KEY-1FAKE".to_string();
        let sec = ArmoredAgeSecret::try_new(s.clone()).unwrap();
        assert_eq!(sec.expose_secret(), s);
    }

    #[test]
    fn secret_try_new_rejects_pubkey_prefix() {
        assert!(ArmoredAgeSecret::try_new("age1xyz".into()).is_err());
    }

    #[test]
    fn recipient_serde_round_trip_is_transparent() {
        let r = ArmoredAgeRecipient::from_trusted("age1abc".into());
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"age1abc\"");
        let back: ArmoredAgeRecipient = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
