use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub struct BearerToken(Zeroizing<String>);

impl BearerToken {
    pub fn from_trusted(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn header_value(&self) -> String {
        format!("Bearer {}", self.0.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

impl PartialEq for BearerToken {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for BearerToken {}

impl Serialize for BearerToken {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BearerToken {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(Zeroizing::new(String::deserialize(d)?)))
    }
}

#[derive(Clone, Default)]
pub struct RefreshToken(Zeroizing<String>);

impl RefreshToken {
    pub fn from_trusted(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshToken(<redacted>)")
    }
}

impl PartialEq for RefreshToken {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for RefreshToken {}

impl Serialize for RefreshToken {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RefreshToken {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(Zeroizing::new(String::deserialize(d)?)))
    }
}

#[derive(Clone, Default)]
pub struct VaultKey(Zeroizing<Vec<u8>>);

impl VaultKey {
    pub fn from_trusted(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

impl std::ops::Deref for VaultKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for VaultKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for VaultKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_trusted(bytes)
    }
}

impl From<&[u8]> for VaultKey {
    fn from(bytes: &[u8]) -> Self {
        Self::from_trusted(bytes.to_vec())
    }
}

impl PartialEq for VaultKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.0.len() != other.0.len() {
            return false;
        }
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for VaultKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_key_debug_does_not_leak() {
        let k = VaultKey::from_trusted(b"\x01\x02\x03\x04aabbccdd".to_vec());
        let s = format!("{k:?}");
        assert_eq!(s, "VaultKey(<redacted>)");
        assert!(!s.contains("aabbccdd"), "leaked: {s}");
        assert!(!s.contains('1') && !s.contains('2'), "leaked bytes: {s}");
    }

    #[test]
    fn vault_key_exposes_the_bytes_deliberately() {
        let k = VaultKey::from_trusted(vec![0xaa; 32]);
        assert_eq!(k.len(), 32);
        assert_eq!(k.expose(), &[0xaa; 32]);
        assert_eq!(&k[..4], &[0xaa; 4]);
    }

    #[test]
    fn bearer_debug_does_not_leak() {
        let t = BearerToken::from_trusted("super-secret-jwt".into());
        let s = format!("{t:?}");
        assert!(!s.contains("super-secret"), "leaked: {s}");
    }

    #[test]
    fn refresh_debug_does_not_leak() {
        let t = RefreshToken::from_trusted("rt-xyz".into());
        let s = format!("{t:?}");
        assert!(!s.contains("rt-xyz"), "leaked: {s}");
    }

    #[test]
    fn bearer_header_value_is_prefixed() {
        let t = BearerToken::from_trusted("abc".into());
        assert_eq!(t.header_value(), "Bearer abc");
    }

    #[test]
    fn bearer_serde_round_trip_is_transparent() {
        let t = BearerToken::from_trusted("xyz".into());
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"xyz\"");
        let back: BearerToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn bearer_and_refresh_are_distinct_types() {
        let _b = BearerToken::from_trusted("x".into());
        let _r = RefreshToken::from_trusted("x".into());
    }
}
