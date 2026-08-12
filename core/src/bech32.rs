const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

pub fn encode(hrp: &str, data: &[u8]) -> String {
    let mut bits = Vec::with_capacity(data.len().saturating_mul(8) / 5 + 1);
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        acc_bits += 8;
        while acc_bits >= 5 {
            acc_bits -= 5;
            bits.push(((acc >> acc_bits) & 0x1f) as u8);
        }
    }
    if acc_bits > 0 {
        bits.push(((acc << (5 - acc_bits)) & 0x1f) as u8);
    }
    let cs = checksum(hrp, &bits);
    let mut out = String::with_capacity(hrp.len() + 1 + bits.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for &v in bits.iter().chain(cs.iter()) {
        out.push(CHARSET[v as usize] as char);
    }
    out
}

pub fn decode(s: &str, expected_hrp: &str) -> Option<Vec<u8>> {
    let s = s.trim().to_ascii_lowercase();
    let (hrp, data) = s.rsplit_once('1')?;
    if hrp != expected_hrp.to_ascii_lowercase() {
        return None;
    }
    if data.len() < 6 {
        return None;
    }
    let mut values = Vec::with_capacity(data.len());
    for c in data.bytes() {
        let v = CHARSET.iter().position(|&x| x == c)?;
        values.push(v as u8);
    }
    if !verify_checksum(hrp, &values) {
        return None;
    }
    let payload_5 = &values[..values.len() - 6];

    let mut out = Vec::with_capacity(payload_5.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    for &v in payload_5 {
        acc = (acc << 5) | v as u32;
        acc_bits += 5;
        if acc_bits >= 8 {
            acc_bits -= 8;
            out.push(((acc >> acc_bits) & 0xff) as u8);
        }
    }
    Some(out)
}

pub fn decode_age_x25519(s: &str) -> Option<[u8; 32]> {
    let bytes = decode(s, "age")?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub fn encode_age_x25519(pubkey: &[u8; 32]) -> String {
    encode("age", pubkey)
}

pub fn encode_age_secret_key(bytes: &[u8; 32]) -> String {
    encode("age-secret-key-", bytes).to_ascii_uppercase()
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v as u32;
        for (i, gen) in GEN.iter().enumerate() {
            chk ^= gen & 0u32.wrapping_sub((top >> i) & 1);
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.bytes() {
        out.push(c >> 5);
    }
    out.push(0);
    for c in hrp.bytes() {
        out.push(c & 0x1f);
    }
    out
}

fn verify_checksum(hrp: &str, values: &[u8]) -> bool {
    let mut all = hrp_expand(hrp);
    all.extend_from_slice(values);
    polymod(&all) == 1
}

fn checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let polymod = polymod(&values) ^ 1;
    let mut out = [0u8; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ((polymod >> (5 * (5 - i))) & 0x1f) as u8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_round_trip() {
        let pk = [0xab; 32];
        let s = encode_age_x25519(&pk);
        assert!(s.starts_with("age1"));
        assert_eq!(decode_age_x25519(&s), Some(pk));
    }

    #[test]
    fn rejects_wrong_hrp() {
        let s = encode("notage", &[1, 2, 3]);
        assert!(decode_age_x25519(&s).is_none());
    }

    #[test]
    fn polymod_matches_the_branching_reference() {
        fn reference(values: &[u8]) -> u32 {
            let mut chk = 1u32;
            for &v in values {
                let top = chk >> 25;
                chk = ((chk & 0x01ff_ffff) << 5) ^ v as u32;
                for (i, gen) in GEN.iter().enumerate() {
                    if (top >> i) & 1 == 1 {
                        chk ^= gen;
                    }
                }
            }
            chk
        }
        for len in 0..40usize {
            let values: Vec<u8> = (0..len).map(|i| ((i * 7 + 3) % 32) as u8).collect();
            assert_eq!(polymod(&values), reference(&values), "len={len}");
        }
    }

    fn corrupt_at(s: &str, idx: usize) -> String {
        let mut bytes = s.as_bytes().to_vec();
        let pos = CHARSET.iter().position(|&c| c == bytes[idx]).unwrap();
        bytes[idx] = CHARSET[(pos + 1) % CHARSET.len()];
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn single_character_typo_anywhere_is_rejected() {
        let pk = [0xab; 32];
        let good = encode_age_x25519(&pk);
        assert_eq!(decode_age_x25519(&good), Some(pk));

        let start = "age1".len();
        for idx in start..good.len() {
            let bad = corrupt_at(&good, idx);
            assert_ne!(bad, good, "idx={idx} produced no change");
            assert_eq!(
                decode_age_x25519(&bad),
                None,
                "one-character typo at index {idx} was accepted: {bad}"
            );
        }
    }

    #[test]
    fn payload_typo_never_silently_yields_a_different_key() {
        let pk = [0x11; 32];
        let good = encode_age_x25519(&pk);
        let payload_end = good.len() - 6;
        for idx in "age1".len()..payload_end {
            let bad = corrupt_at(&good, idx);
            match decode_age_x25519(&bad) {
                None => {}
                Some(other) => panic!(
                    "typo at {idx} silently decoded to a different key: {other:?} (expected rejection)"
                ),
            }
        }
    }

    #[test]
    fn checksum_typo_is_rejected() {
        let good = encode_age_x25519(&[0x5c; 32]);
        let last = good.len() - 1;
        assert_eq!(decode_age_x25519(&corrupt_at(&good, last)), None);
    }

    #[test]
    fn truncated_and_extended_strings_are_rejected() {
        let good = encode_age_x25519(&[0x33; 32]);
        assert_eq!(decode_age_x25519(&good[..good.len() - 1]), None);
        assert_eq!(decode_age_x25519(&format!("{good}q")), None);
    }

    #[test]
    fn bip173_reference_vectors_round_trip_and_reject() {
        assert!(decode("a12uel5l", "a").is_some());
        assert!(decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", "abcdef").is_some());
        assert!(decode("A12UEL5L", "a").is_some());

        assert!(decode("a12uel5m", "a").is_none());
        assert!(decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxx", "abcdef").is_none());
    }

    #[test]
    fn secret_key_encoding_is_uppercase_and_prefixed() {
        let s = encode_age_secret_key(&[0x5a; 32]);
        assert!(s.starts_with("AGE-SECRET-KEY-1"));
        assert_eq!(s, s.to_ascii_uppercase());
    }
}
