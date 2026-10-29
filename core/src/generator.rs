//! The one password and passphrase generator every client calls, so the
//! three frontends cannot drift into different alphabets or a biased draw.

use thiserror::Error;
use zeroize::Zeroizing;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*-_=+?.:";

pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 128;
pub const MIN_PASSPHRASE_WORDS: usize = 4;
pub const MAX_PASSPHRASE_WORDS: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GeneratorError {
    #[error("length must be {MIN_PASSWORD_LENGTH}..={MAX_PASSWORD_LENGTH}, got {0}")]
    Length(usize),

    #[error("at least one character class must be enabled")]
    NoClasses,

    #[error("word count must be {MIN_PASSPHRASE_WORDS}..={MAX_PASSPHRASE_WORDS}, got {0}")]
    Words(usize),
}

/// A password of `policy.length` characters drawn uniformly from the enabled
/// classes, containing at least one character of each enabled class.
pub fn password(policy: &PasswordPolicy) -> Result<Zeroizing<String>, GeneratorError> {
    password_from(policy, &mut os_u32)
}

/// `words` BIP39 English words joined by `separator`: 11 bits of entropy per
/// word.
pub fn passphrase(words: usize, separator: &str) -> Result<Zeroizing<String>, GeneratorError> {
    passphrase_from(words, separator, &mut os_u32)
}

fn os_u32() -> u32 {
    use rand_core::Rng;
    rand::rng().next_u32()
}

/// A draw from `0..n` with no modulo bias: values from the incomplete top
/// bucket are rejected and redrawn.
fn uniform(n: u32, next: &mut dyn FnMut() -> u32) -> u32 {
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let v = next();
        if v < zone {
            return v % n;
        }
    }
}

fn password_from(
    policy: &PasswordPolicy,
    next: &mut dyn FnMut() -> u32,
) -> Result<Zeroizing<String>, GeneratorError> {
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&policy.length) {
        return Err(GeneratorError::Length(policy.length));
    }
    let classes: Vec<&[u8]> = [
        (policy.lowercase, LOWERCASE),
        (policy.uppercase, UPPERCASE),
        (policy.digits, DIGITS),
        (policy.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter_map(|(on, set)| on.then_some(set))
    .collect();
    if classes.is_empty() {
        return Err(GeneratorError::NoClasses);
    }
    let alphabet: Vec<u8> = classes.concat();
    loop {
        let mut out = Zeroizing::new(String::with_capacity(policy.length));
        for _ in 0..policy.length {
            out.push(alphabet[uniform(alphabet.len() as u32, next) as usize] as char);
        }
        if classes
            .iter()
            .all(|set| out.bytes().any(|b| set.contains(&b)))
        {
            return Ok(out);
        }
    }
}

fn passphrase_from(
    words: usize,
    separator: &str,
    next: &mut dyn FnMut() -> u32,
) -> Result<Zeroizing<String>, GeneratorError> {
    if !(MIN_PASSPHRASE_WORDS..=MAX_PASSPHRASE_WORDS).contains(&words) {
        return Err(GeneratorError::Words(words));
    }
    let list = bip39::Language::English.word_list();
    let mut out = Zeroizing::new(String::new());
    for i in 0..words {
        if i > 0 {
            out.push_str(separator);
        }
        out.push_str(list[(next() & 0x7ff) as usize]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter(start: u32) -> impl FnMut() -> u32 {
        let mut x = start;
        move || {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            x
        }
    }

    #[test]
    fn every_enabled_class_appears_and_no_disabled_one_does() {
        for _ in 0..200 {
            let p = password(&PasswordPolicy::default()).unwrap();
            assert_eq!(p.len(), 20);
            assert!(p.bytes().any(|b| LOWERCASE.contains(&b)));
            assert!(p.bytes().any(|b| UPPERCASE.contains(&b)));
            assert!(p.bytes().any(|b| DIGITS.contains(&b)));
            assert!(p.bytes().any(|b| SYMBOLS.contains(&b)));
        }
        let digits_only = PasswordPolicy {
            length: 12,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
        };
        let p = password(&digits_only).unwrap();
        assert!(p.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn out_of_range_requests_are_refused() {
        let short = PasswordPolicy {
            length: 4,
            ..Default::default()
        };
        assert_eq!(password(&short).unwrap_err(), GeneratorError::Length(4));
        let none = PasswordPolicy {
            length: 16,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
        };
        assert_eq!(password(&none).unwrap_err(), GeneratorError::NoClasses);
        assert_eq!(passphrase(3, "-").unwrap_err(), GeneratorError::Words(3));
    }

    #[test]
    fn uniform_rejects_the_biased_top_bucket() {
        let zone = u32::MAX - (u32::MAX % 10);
        let mut draws = [zone, zone + 1, 7].into_iter();
        assert_eq!(uniform(10, &mut || draws.next().unwrap()), 7);
    }

    #[test]
    fn character_frequencies_are_flat() {
        let policy = PasswordPolicy {
            length: 128,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
        };
        let mut counts = [0u32; 10];
        for _ in 0..200 {
            for b in password(&policy).unwrap().bytes() {
                counts[(b - b'0') as usize] += 1;
            }
        }
        let mean = counts.iter().sum::<u32>() / 10;
        for c in counts {
            assert!(c.abs_diff(mean) < mean / 10, "{counts:?}");
        }
    }

    #[test]
    fn same_draws_same_output() {
        let a = password_from(&PasswordPolicy::default(), &mut counter(1)).unwrap();
        let b = password_from(&PasswordPolicy::default(), &mut counter(1)).unwrap();
        assert_eq!(*a, *b);
        let p = passphrase_from(6, " ", &mut counter(3)).unwrap();
        assert_eq!(p.split(' ').count(), 6);
        let list = bip39::Language::English.word_list();
        assert!(p.split(' ').all(|w| list.contains(&w)));
    }
}
