use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,

    Sha256,

    Sha512,
}

#[derive(Debug, Clone)]
pub struct TotpConfig {
    pub secret: Zeroizing<Vec<u8>>,

    pub digits: u32,

    pub period: u64,

    pub algorithm: TotpAlgorithm,
}

impl TotpConfig {
    pub fn from_base32_secret(secret: &str) -> Result<Self, TotpError> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            secret
                .chars()
                .filter(|c| !c.is_whitespace())
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let bytes = decode_base32(&cleaned)?;
        if bytes.is_empty() {
            return Err(TotpError::EmptySecret);
        }
        Ok(Self {
            secret: bytes,
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
        })
    }

    pub fn from_otpauth_uri(uri: &str) -> Result<Self, TotpError> {
        let rest = uri
            .strip_prefix("otpauth://totp/")
            .ok_or(TotpError::InvalidUri)?;
        let (_label, query) = rest.split_once('?').ok_or(TotpError::InvalidUri)?;
        let mut secret: Option<String> = None;
        let mut digits: u32 = 6;
        let mut period: u64 = 30;
        let mut algorithm: TotpAlgorithm = TotpAlgorithm::Sha1;
        for kv in query.split('&') {
            let (k, v) = kv.split_once('=').ok_or(TotpError::InvalidUri)?;
            let v = url_decode(v);
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(v),
                "digits" => digits = v.parse().map_err(|_| TotpError::InvalidUri)?,
                "period" => period = v.parse().map_err(|_| TotpError::InvalidUri)?,
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => return Err(TotpError::UnknownAlgorithm(v)),
                    };
                }
                _ => {}
            }
        }
        if period == 0 {
            return Err(TotpError::InvalidPeriod);
        }
        if digits == 0 {
            return Err(TotpError::InvalidDigits);
        }
        let secret = secret.ok_or(TotpError::InvalidUri)?;
        let mut cfg = Self::from_base32_secret(&secret)?;
        cfg.digits = digits;
        cfg.period = period;
        cfg.algorithm = algorithm;
        Ok(cfg)
    }
}

#[derive(Debug, Clone)]
pub struct TotpCode {
    pub code: String,

    pub seconds_remaining: u64,

    pub period: u64,
}

pub fn generate(cfg: &TotpConfig) -> Result<TotpCode, TotpError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TotpError::ClockBeforeEpoch)?
        .as_secs();
    generate_at(cfg, now)
}

pub fn generate_at(cfg: &TotpConfig, unix_ts: u64) -> Result<TotpCode, TotpError> {
    if cfg.period == 0 {
        return Err(TotpError::InvalidPeriod);
    }
    if cfg.digits == 0 {
        return Err(TotpError::InvalidDigits);
    }
    let counter = unix_ts / cfg.period;
    let counter_bytes = counter.to_be_bytes();
    let hmac_out: Zeroizing<Vec<u8>> = match cfg.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(&cfg.secret).map_err(|_| TotpError::Hmac)?;
            mac.update(&counter_bytes);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&cfg.secret).map_err(|_| TotpError::Hmac)?;
            mac.update(&counter_bytes);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(&cfg.secret).map_err(|_| TotpError::Hmac)?;
            mac.update(&counter_bytes);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
    };

    let offset = (hmac_out[hmac_out.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(hmac_out[offset]) & 0x7f) << 24)
        | (u32::from(hmac_out[offset + 1]) << 16)
        | (u32::from(hmac_out[offset + 2]) << 8)
        | u32::from(hmac_out[offset + 3]);

    let modulus: u32 = 10u32
        .checked_pow(cfg.digits)
        .ok_or(TotpError::DigitsTooLarge)?;
    let value = binary % modulus;
    let code = format!("{:0>width$}", value, width = cfg.digits as usize);

    let elapsed_in_period = unix_ts - (counter * cfg.period);
    let seconds_remaining = cfg.period - elapsed_in_period;

    Ok(TotpCode {
        code,
        seconds_remaining,
        period: cfg.period,
    })
}

pub fn generate_for_uri_or_secret(input: &str) -> Result<TotpCode, TotpError> {
    let cfg = if input.starts_with("otpauth://") {
        TotpConfig::from_otpauth_uri(input)?
    } else {
        TotpConfig::from_base32_secret(input)?
    };
    generate(&cfg)
}

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("totp: empty secret")]
    EmptySecret,

    /// Names the offending position only: the character is part of a seed.
    #[error("totp: invalid base32 character at position {position}")]
    InvalidBase32 { position: usize },

    #[error("totp: invalid otpauth uri")]
    InvalidUri,

    #[error("totp: unknown algorithm {0}")]
    UnknownAlgorithm(String),

    #[error("totp: hmac keying failed")]
    Hmac,

    #[error("totp: digits too large")]
    DigitsTooLarge,

    #[error("totp: period must be at least 1 second")]
    InvalidPeriod,

    #[error("totp: digits must be at least 1")]
    InvalidDigits,

    #[error("totp: clock before epoch")]
    ClockBeforeEpoch,
}

/// Decodes a TOTP seed without branching on its characters: every character
/// is mapped arithmetically and the first invalid position is only reported
/// after the whole string has been read.
fn decode_base32(s: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let trimmed = s.trim_end_matches('=').as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(trimmed.len() * 5 / 8));
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut first_invalid = usize::MAX;
    for (i, &c) in trimmed.iter().enumerate() {
        let (v, valid) = base32_value(c);
        let unseen = 0usize.wrapping_sub((first_invalid == usize::MAX) as usize);
        let invalid_here = 0usize.wrapping_sub((valid ^ 1) as usize);
        first_invalid = (i & unseen & invalid_here) | (first_invalid & !(unseen & invalid_here));
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if first_invalid != usize::MAX {
        return Err(TotpError::InvalidBase32 {
            position: first_invalid,
        });
    }
    Ok(out)
}

/// RFC 4648 base32 value of `c` and whether it was valid, computed with
/// masks rather than a branch per character class.
fn base32_value(c: u8) -> (u32, u32) {
    let letter = c.wrapping_sub(b'A') as u32;
    let digit = c.wrapping_sub(b'2') as u32;
    let is_letter = (letter.wrapping_sub(26) >> 31) & 1;
    let is_digit = (digit.wrapping_sub(6) >> 31) & 1;
    let value =
        (letter & 0u32.wrapping_sub(is_letter)) | ((digit + 26) & 0u32.wrapping_sub(is_digit));
    (value, is_letter | is_digit)
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_seed_character_is_reported_by_position_not_by_value() {
        let err = TotpConfig::from_base32_secret("JBSW Y3DP 1HPK 3PXP").unwrap_err();
        assert!(matches!(err, TotpError::InvalidBase32 { position: 8 }));
        let shown = err.to_string();
        assert!(!shown.contains('1'), "seed character leaked: {shown}");
    }

    #[test]
    fn branch_free_base32_matches_rfc4648_for_every_byte() {
        for c in 0u8..=255 {
            let want = match c {
                b'A'..=b'Z' => Some(u32::from(c - b'A')),
                b'2'..=b'7' => Some(u32::from(c - b'2') + 26),
                _ => None,
            };
            let (v, valid) = base32_value(c);
            assert_eq!(valid == 1, want.is_some(), "byte {c}");
            if let Some(w) = want {
                assert_eq!(v, w, "byte {c}");
            }
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha1_vectors() {
        let secret = b"12345678901234567890";
        let cfg = TotpConfig {
            secret: Zeroizing::new(secret.to_vec()),
            digits: 8,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
        };
        let cases: &[(u64, &str)] = &[
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (ts, expected) in cases {
            let got = generate_at(&cfg, *ts).unwrap();
            assert_eq!(&got.code, expected, "ts={ts}");
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha256_vectors() {
        let secret = b"12345678901234567890123456789012";
        let cfg = TotpConfig {
            secret: Zeroizing::new(secret.to_vec()),
            digits: 8,
            period: 30,
            algorithm: TotpAlgorithm::Sha256,
        };
        let got = generate_at(&cfg, 59).unwrap();
        assert_eq!(&got.code, "46119246");
    }

    #[test]
    fn rfc6238_appendix_b_sha512_vectors() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let cfg = TotpConfig {
            secret: Zeroizing::new(secret.to_vec()),
            digits: 8,
            period: 30,
            algorithm: TotpAlgorithm::Sha512,
        };
        let got = generate_at(&cfg, 59).unwrap();
        assert_eq!(&got.code, "90693936");
    }

    #[test]
    fn base32_roundtrip() {
        let s = "JBSWY3DPEHPK3PXP";
        let bytes = decode_base32(s).unwrap();
        assert_eq!(bytes.as_slice(), b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn base32_with_whitespace_and_lowercase() {
        let cfg = TotpConfig::from_base32_secret("jbswy 3dpehpk 3pxp").unwrap();
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.period, 30);
    }

    #[test]
    fn otpauth_uri_full() {
        let uri = "otpauth://totp/Example:alice@example.com?\
                   secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=15";
        let cfg = TotpConfig::from_otpauth_uri(uri).unwrap();
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.period, 15);
        assert_eq!(cfg.algorithm, TotpAlgorithm::Sha256);
    }

    #[test]
    fn otpauth_uri_minimal_defaults() {
        let cfg = TotpConfig::from_otpauth_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.period, 30);
        assert_eq!(cfg.algorithm, TotpAlgorithm::Sha1);
    }

    #[test]
    fn seconds_remaining_decrements() {
        let cfg = TotpConfig::from_base32_secret("JBSWY3DPEHPK3PXP").unwrap();
        let a = generate_at(&cfg, 0).unwrap();
        let b = generate_at(&cfg, 1).unwrap();
        assert_eq!(a.seconds_remaining, 30);
        assert_eq!(b.seconds_remaining, 29);
    }

    #[test]
    fn unknown_algorithm_rejected() {
        let err =
            TotpConfig::from_otpauth_uri("otpauth://totp/x?secret=A&algorithm=md5").unwrap_err();
        match err {
            TotpError::UnknownAlgorithm(_) => {}
            _ => panic!("expected UnknownAlgorithm"),
        }
    }

    #[test]
    fn zero_period_in_uri_is_rejected_not_a_panic() {
        let err = TotpConfig::from_otpauth_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0")
            .unwrap_err();
        assert!(
            matches!(err, TotpError::InvalidPeriod),
            "expected InvalidPeriod, got {err:?}"
        );
    }

    #[test]
    fn zero_period_config_is_rejected_not_a_panic() {
        let cfg = TotpConfig {
            secret: Zeroizing::new(b"12345678901234567890".to_vec()),
            digits: 6,
            period: 0,
            algorithm: TotpAlgorithm::Sha1,
        };
        assert!(matches!(
            generate_at(&cfg, 59).unwrap_err(),
            TotpError::InvalidPeriod
        ));
        assert!(matches!(
            generate(&cfg).unwrap_err(),
            TotpError::InvalidPeriod
        ));
    }

    #[test]
    fn zero_digits_is_rejected_not_an_empty_code() {
        let err = TotpConfig::from_otpauth_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=0")
            .unwrap_err();
        assert!(matches!(err, TotpError::InvalidDigits), "got {err:?}");

        let cfg = TotpConfig {
            secret: Zeroizing::new(b"12345678901234567890".to_vec()),
            digits: 0,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
        };
        assert!(matches!(
            generate_at(&cfg, 59).unwrap_err(),
            TotpError::InvalidDigits
        ));
    }

    #[test]
    fn hostile_server_totp_field_never_panics() {
        let hostile = [
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0&digits=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=11",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=99999999999999999999",
            "otpauth://totp/x?secret=!!!!",
            "otpauth://totp/x?secret=",
            "otpauth://totp/x",
            "otpauth://totp/",
        ];
        for uri in hostile {
            let r = generate_for_uri_or_secret(uri);
            assert!(r.is_err(), "expected an error for {uri}, got {r:?}");
        }
    }

    #[test]
    fn dispatches_uri_vs_secret() {
        assert!(generate_for_uri_or_secret("JBSWY3DPEHPK3PXP").is_ok());
        assert!(generate_for_uri_or_secret("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").is_ok());
    }
}
