//! PIV (NIST SP 800-73-4) command APDUs and BER-TLV parsing.
//!
//! Pure byte-shuffling: no device, no I/O, no `pcsc`. Everything here is unit
//! tested against hand-checked vectors so the wire format is not device-blocked
//! even though the transmit is. `piv_pcsc.rs` is the only thing that touches a
//! reader.

use std::fmt;

use thiserror::Error;

/// SP 800-73-4 part 1, table 3. The applet is selected by its 9-byte AID.
pub const PIV_AID: [u8; 9] = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

/// YubiKey PIV algorithm identifiers (Yubico PIV extensions). `0x11` is the
/// NIST P-256 ECDH the PIV spec itself defines; `0xE1` is Yubico's X25519,
/// available on firmware 5.7.0 and newer.
pub const ALG_ECC_P256: u8 = 0x11;
pub const ALG_X25519: u8 = 0xE1;

pub const INS_SELECT: u8 = 0xA4;
pub const INS_VERIFY: u8 = 0x20;
pub const INS_GENERAL_AUTHENTICATE: u8 = 0x87;
pub const INS_GET_RESPONSE: u8 = 0xC0;
/// Yubico extension: read the device serial number.
pub const INS_GET_SERIAL: u8 = 0xF8;
/// Yubico extension: read a slot's metadata (algorithm, policies, origin,
/// public key). Firmware 5.3.0 and newer only -- older keys answer `6D00`, and
/// there is no other way to ask them what a slot's touch policy is.
pub const INS_GET_METADATA: u8 = 0xF7;

pub const P2_PIV_PIN: u8 = 0x80;

const TAG_DYNAMIC_AUTH: u8 = 0x7C;
const TAG_RESPONSE: u8 = 0x82;
const TAG_EXPONENTIATION: u8 = 0x85;

/// GET METADATA response tags (Yubico PIV extensions, `ykman/piv.py`):
/// 0x01 algorithm, 0x02 policy, 0x03 origin, 0x04 public key, 0x05 default,
/// 0x06 retries. Only the first two are of interest here.
const TAG_METADATA_ALGORITHM: u8 = 0x01;
const TAG_METADATA_POLICY: u8 = 0x02;

/// Touch policy byte values from the Yubico PIV extensions. `0x00` is the
/// "no explicit policy" marker; the device default for every key slot is
/// *never*, which is why `Default` is grouped with the ungated policies below
/// rather than treated as a touch requirement.
const TOUCH_POLICY_DEFAULT: u8 = 0x00;
const TOUCH_POLICY_NEVER: u8 = 0x01;
const TOUCH_POLICY_ALWAYS: u8 = 0x02;
const TOUCH_POLICY_CACHED: u8 = 0x03;

pub const SW_OK: u16 = 0x9000;
pub const SW_SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6982;
pub const SW_AUTH_METHOD_BLOCKED: u16 = 0x6983;
pub const SW_INCORRECT_PARAMETERS: u16 = 0x6A80;
pub const SW_REFERENCE_NOT_FOUND: u16 = 0x6A88;
pub const SW_FILE_NOT_FOUND: u16 = 0x6A82;
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
/// Both are "this card has never heard of that command". Seen instead of
/// `6D00` on some readers/applets for the Yubico extensions.
pub const SW_FUNCTION_NOT_SUPPORTED: u16 = 0x6A81;
pub const SW_CLASS_NOT_SUPPORTED: u16 = 0x6E00;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApduError {
    #[error("card response too short ({0} bytes, need at least the 2 status bytes)")]
    TooShort(usize),

    #[error("malformed BER-TLV: {0}")]
    Tlv(String),

    #[error("PIN must be 6-8 ASCII digits (got {0} bytes)")]
    BadPin(usize),

    #[error("peer public key must be {expected} bytes for this algorithm, got {got}")]
    BadPeerKeyLength { expected: usize, got: usize },
}

/// SELECT the PIV applet: `00 A4 04 00 09 <AID>`.
pub fn select_piv() -> Vec<u8> {
    let mut v = vec![0x00, INS_SELECT, 0x04, 0x00, PIV_AID.len() as u8];
    v.extend_from_slice(&PIV_AID);
    v
}

/// VERIFY with no data probes the retry counter without spending a try.
/// A card that needs no PIN answers 90 00; otherwise 63 CX with X tries left.
pub fn verify_pin_status() -> Vec<u8> {
    vec![0x00, INS_VERIFY, 0x00, P2_PIV_PIN]
}

/// VERIFY the application PIN. PIV pads the PIN to 8 bytes with 0xFF.
pub fn verify_pin(pin: &str) -> Result<Vec<u8>, ApduError> {
    let bytes = pin.as_bytes();
    if bytes.len() < 6 || bytes.len() > 8 || !bytes.iter().all(|b| b.is_ascii_graphic()) {
        return Err(ApduError::BadPin(bytes.len()));
    }
    let mut padded = [0xFFu8; 8];
    padded[..bytes.len()].copy_from_slice(bytes);
    let mut v = vec![0x00, INS_VERIFY, 0x00, P2_PIV_PIN, 0x08];
    v.extend_from_slice(&padded);
    Ok(v)
}

/// Number of PIN retries left, decoded from a `63 CX` status word.
pub fn pin_retries_from_sw(sw: u16) -> Option<u8> {
    if sw & 0xFFF0 == 0x63C0 {
        Some((sw & 0x000F) as u8)
    } else {
        None
    }
}

pub fn peer_key_len(algorithm: u8) -> usize {
    match algorithm {
        // SEC1 uncompressed point 04 || X || Y.
        ALG_ECC_P256 => 65,
        // Raw little-endian u-coordinate.
        ALG_X25519 => 32,
        _ => 0,
    }
}

/// GENERAL AUTHENTICATE with an exponentiation (0x85) template -- the ECDH
/// primitive. The card multiplies the slot's private key by `peer_public` and
/// returns the shared point's X coordinate in an 0x82 response template.
pub fn general_authenticate_ecdh(
    algorithm: u8,
    slot: u8,
    peer_public: &[u8],
) -> Result<Vec<u8>, ApduError> {
    let expected = peer_key_len(algorithm);
    if expected == 0 || peer_public.len() != expected {
        return Err(ApduError::BadPeerKeyLength {
            expected,
            got: peer_public.len(),
        });
    }

    let mut inner = Vec::with_capacity(peer_public.len() + 4);
    inner.push(TAG_RESPONSE);
    inner.push(0x00);
    inner.push(TAG_EXPONENTIATION);
    inner.extend_from_slice(&encode_len(peer_public.len()));
    inner.extend_from_slice(peer_public);

    let mut data = Vec::with_capacity(inner.len() + 4);
    data.push(TAG_DYNAMIC_AUTH);
    data.extend_from_slice(&encode_len(inner.len()));
    data.extend_from_slice(&inner);

    let mut apdu = vec![0x00, INS_GENERAL_AUTHENTICATE, algorithm, slot];
    if data.len() < 256 {
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(&data);
        // Le=0: accept up to 256 response bytes.
        apdu.push(0x00);
    } else {
        // Extended-length APDU.
        apdu.push(0x00);
        apdu.push((data.len() >> 8) as u8);
        apdu.push((data.len() & 0xFF) as u8);
        apdu.extend_from_slice(&data);
        apdu.push(0x00);
        apdu.push(0x00);
    }
    Ok(apdu)
}

pub fn get_response(le: u8) -> Vec<u8> {
    vec![0x00, INS_GET_RESPONSE, 0x00, 0x00, le]
}

/// Yubico extension `00 F8 00 00`: 4-byte big-endian serial.
pub fn get_serial() -> Vec<u8> {
    vec![0x00, INS_GET_SERIAL, 0x00, 0x00, 0x00]
}

/// Yubico extension `00 F7 00 <slot> 00`: metadata for one key slot.
///
/// The slot number goes in P2, exactly like GENERAL AUTHENTICATE. No touch and
/// no PIN are needed to read it, so this is safe to issue before deciding what
/// to print to the user.
pub fn get_slot_metadata(slot: u8) -> Vec<u8> {
    vec![0x00, INS_GET_METADATA, 0x00, slot, 0x00]
}

/// Whether the card will physically block on a finger before it will use a
/// slot's private key.
///
/// This is the whole basis for rageterm's touch ceremony, so every case that is
/// not a byte this build recognises as touch-gating resolves to "no promise" --
/// never to `Always`. Announcing a touch that does not happen trains the user
/// to treat the absence of a blink as normal, which is worse than announcing
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPolicy {
    /// `0x00` -- the slot was created without an explicit policy. The YubiKey's
    /// default is *never*, so this gates nothing.
    Default,
    /// `0x01` -- the key is used without any touch. `ykman piv keys generate`
    /// produces this unless `--touch-policy` says otherwise.
    Never,
    /// `0x02` -- every private-key operation waits for a touch.
    Always,
    /// `0x03` -- a touch is required, but one touch covers roughly the next 15
    /// seconds; operations inside that window complete untouched.
    Cached,
    /// A policy byte this build does not know. Fails closed: not treated as a
    /// touch requirement, and refused at enrollment.
    Unknown(u8),
    /// The card did not answer GET METADATA at all (firmware older than 5.3.0,
    /// or a non-Yubico PIV applet), or answered something unparseable. Says
    /// nothing about the slot in either direction -- which is exactly why it
    /// must not be reported as a touch requirement.
    Unavailable,
}

impl TouchPolicy {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            TOUCH_POLICY_DEFAULT => TouchPolicy::Default,
            TOUCH_POLICY_NEVER => TouchPolicy::Never,
            TOUCH_POLICY_ALWAYS => TouchPolicy::Always,
            TOUCH_POLICY_CACHED => TouchPolicy::Cached,
            other => TouchPolicy::Unknown(other),
        }
    }

    /// True only when a touch is genuinely part of the operation. `Cached`
    /// counts: the first use inside the window really does wait for a finger.
    pub fn requires_touch(self) -> bool {
        matches!(self, TouchPolicy::Always | TouchPolicy::Cached)
    }

    /// True when the card told us, in a byte we understand, what it will do.
    /// `Unknown`/`Unavailable` are the fail-closed cases: policy not learned.
    pub fn is_known(self) -> bool {
        !matches!(self, TouchPolicy::Unknown(_) | TouchPolicy::Unavailable)
    }
}

impl fmt::Display for TouchPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TouchPolicy::Default => f.write_str("default (the device default is `never`)"),
            TouchPolicy::Never => f.write_str("never"),
            TouchPolicy::Always => f.write_str("always"),
            TouchPolicy::Cached => f.write_str("cached (one touch covers ~15 seconds)"),
            TouchPolicy::Unknown(b) => write!(f, "unrecognised policy byte {b:#04x}"),
            TouchPolicy::Unavailable => f.write_str("not reported by this card"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotMetadata {
    /// Tag 0x01. `None` if the card omitted it; nothing here depends on it, it
    /// is carried so callers can cross-check the slot's algorithm.
    pub algorithm: Option<u8>,
    /// First byte of the policy tag. Kept raw: rageterm gates on touch, and the
    /// PIN policy only changes how many VERIFYs a session needs, which the
    /// existing `63 CX` handling already discovers.
    pub pin_policy: u8,
    pub touch_policy: TouchPolicy,
}

/// Parse a GET METADATA response body.
///
/// The policy element (tag 0x02) is two bytes, PIN policy first and touch
/// policy second. A missing or wrong-length policy element is an error rather
/// than a default: the only reason to call this is to find out whether a touch
/// is real, and a card that will not say has to be handled as "did not say".
pub fn parse_slot_metadata(body: &[u8]) -> Result<SlotMetadata, ApduError> {
    let policy = tlv_find(body, TAG_METADATA_POLICY)
        .ok_or_else(|| ApduError::Tlv("GET METADATA answer has no 0x02 policy element".into()))?;
    if policy.len() != 2 {
        return Err(ApduError::Tlv(format!(
            "0x02 policy element is {} bytes, expected 2 (PIN policy then touch policy)",
            policy.len()
        )));
    }
    Ok(SlotMetadata {
        algorithm: tlv_find(body, TAG_METADATA_ALGORITHM).and_then(|v| v.first().copied()),
        pin_policy: policy[0],
        touch_policy: TouchPolicy::from_byte(policy[1]),
    })
}

/// Split a raw card response into (body, status word).
pub fn split_sw(response: &[u8]) -> Result<(&[u8], u16), ApduError> {
    if response.len() < 2 {
        return Err(ApduError::TooShort(response.len()));
    }
    let split = response.len() - 2;
    let sw = u16::from_be_bytes([response[split], response[split + 1]]);
    Ok((&response[..split], sw))
}

/// `61 XX` means "XX more bytes waiting"; the caller must issue GET RESPONSE.
pub fn more_data_available(sw: u16) -> Option<u8> {
    if sw & 0xFF00 == 0x6100 {
        Some((sw & 0x00FF) as u8)
    } else {
        None
    }
}

/// Pull the shared secret out of `7C L 82 L <secret>`.
pub fn parse_ecdh_response(body: &[u8], expected_len: usize) -> Result<Vec<u8>, ApduError> {
    let template = tlv_find(body, TAG_DYNAMIC_AUTH)
        .ok_or_else(|| ApduError::Tlv("no 0x7C dynamic authentication template".into()))?;
    let secret = tlv_find(template, TAG_RESPONSE)
        .ok_or_else(|| ApduError::Tlv("no 0x82 response element inside 0x7C".into()))?;
    if secret.len() != expected_len {
        return Err(ApduError::Tlv(format!(
            "shared secret is {} bytes, expected {expected_len}",
            secret.len()
        )));
    }
    Ok(secret.to_vec())
}

fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// Minimal BER-TLV search over one level. PIV's dynamic authentication
/// templates only use single-byte tags, which is all this handles; anything
/// else is reported rather than guessed at.
pub fn tlv_find(data: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0usize;
    while i < data.len() {
        let t = data[i];
        i += 1;
        if t & 0x1F == 0x1F {
            // Multi-byte tag: not used by PIV auth templates.
            return None;
        }
        if i >= data.len() {
            return None;
        }
        let first = data[i];
        i += 1;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7F) as usize;
            if n == 0 || n > 3 || i + n > data.len() {
                return None;
            }
            let mut acc = 0usize;
            for b in &data[i..i + n] {
                acc = (acc << 8) | (*b as usize);
            }
            i += n;
            acc
        };
        if i + len > data.len() {
            return None;
        }
        if t == tag {
            return Some(&data[i..i + len]);
        }
        i += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_is_the_documented_nine_byte_aid() {
        let apdu = select_piv();
        assert_eq!(&apdu[..5], &[0x00, 0xA4, 0x04, 0x00, 0x09]);
        assert_eq!(&apdu[5..], &PIV_AID);
    }

    #[test]
    fn verify_pin_pads_with_ff_to_eight_bytes() {
        let apdu = verify_pin("123456").unwrap();
        assert_eq!(&apdu[..5], &[0x00, 0x20, 0x00, 0x80, 0x08]);
        assert_eq!(&apdu[5..], b"123456\xFF\xFF");
    }

    #[test]
    fn verify_pin_rejects_out_of_range_lengths() {
        assert!(matches!(verify_pin("12345"), Err(ApduError::BadPin(5))));
        assert!(matches!(verify_pin("123456789"), Err(ApduError::BadPin(9))));
    }

    #[test]
    fn pin_retries_decoded_from_63cx() {
        assert_eq!(pin_retries_from_sw(0x63C3), Some(3));
        assert_eq!(pin_retries_from_sw(0x63C0), Some(0));
        assert_eq!(pin_retries_from_sw(0x9000), None);
    }

    #[test]
    fn x25519_general_authenticate_matches_hand_encoding() {
        let peer = [0xAAu8; 32];
        let apdu = general_authenticate_ecdh(ALG_X25519, 0x9D, &peer).unwrap();
        // 00 87 E1 9D Lc 7C 24 82 00 85 20 <32> 00
        assert_eq!(&apdu[..4], &[0x00, 0x87, 0xE1, 0x9D]);
        assert_eq!(apdu[4], 38);
        assert_eq!(&apdu[5..11], &[0x7C, 0x24, 0x82, 0x00, 0x85, 0x20]);
        assert_eq!(&apdu[11..43], &peer);
        assert_eq!(apdu[43], 0x00);
        assert_eq!(apdu.len(), 44);
    }

    #[test]
    fn p256_general_authenticate_uses_a_65_byte_point() {
        let mut peer = [0u8; 65];
        peer[0] = 0x04;
        let apdu = general_authenticate_ecdh(ALG_ECC_P256, 0x9A, &peer).unwrap();
        assert_eq!(&apdu[..4], &[0x00, 0x87, 0x11, 0x9A]);
        assert_eq!(apdu[4], 71);
        assert_eq!(&apdu[5..11], &[0x7C, 0x45, 0x82, 0x00, 0x85, 0x41]);
    }

    #[test]
    fn general_authenticate_rejects_a_wrong_length_peer_key() {
        let err = general_authenticate_ecdh(ALG_X25519, 0x9D, &[0u8; 33]).unwrap_err();
        assert_eq!(
            err,
            ApduError::BadPeerKeyLength {
                expected: 32,
                got: 33
            }
        );
    }

    #[test]
    fn split_sw_separates_body_and_status() {
        let (body, sw) = split_sw(&[0x01, 0x02, 0x90, 0x00]).unwrap();
        assert_eq!(body, &[0x01, 0x02]);
        assert_eq!(sw, SW_OK);
        assert!(matches!(split_sw(&[0x90]), Err(ApduError::TooShort(1))));
    }

    #[test]
    fn more_data_available_reads_61xx() {
        assert_eq!(more_data_available(0x611D), Some(0x1D));
        assert_eq!(more_data_available(0x9000), None);
    }

    #[test]
    fn parse_ecdh_response_extracts_the_shared_secret() {
        let secret = [0x5Au8; 32];
        let mut body = vec![0x7C, 0x22, 0x82, 0x20];
        body.extend_from_slice(&secret);
        assert_eq!(parse_ecdh_response(&body, 32).unwrap(), secret.to_vec());
    }

    #[test]
    fn parse_ecdh_response_rejects_a_short_secret() {
        let body = vec![0x7C, 0x04, 0x82, 0x02, 0xAA, 0xBB];
        assert!(matches!(
            parse_ecdh_response(&body, 32),
            Err(ApduError::Tlv(_))
        ));
    }

    #[test]
    fn parse_ecdh_response_rejects_a_missing_template() {
        assert!(matches!(
            parse_ecdh_response(&[0x53, 0x01, 0x00], 32),
            Err(ApduError::Tlv(_))
        ));
    }

    /// `01 01 E1 | 02 02 <pin> <touch> | 03 01 01` -- algorithm, policy, origin,
    /// the shape a YubiKey 5.7 answers with for an X25519 slot.
    fn metadata_body(pin_policy: u8, touch_policy: u8) -> Vec<u8> {
        vec![
            0x01,
            0x01,
            ALG_X25519,
            0x02,
            0x02,
            pin_policy,
            touch_policy,
            0x03,
            0x01,
            0x01,
        ]
    }

    #[test]
    fn get_slot_metadata_puts_the_slot_in_p2() {
        assert_eq!(get_slot_metadata(0x9D), vec![0x00, 0xF7, 0x00, 0x9D, 0x00]);
    }

    #[test]
    fn metadata_policy_is_pin_then_touch() {
        // 0x02 = PIN policy "once", 0x02 = touch policy "always".
        let meta = parse_slot_metadata(&metadata_body(0x02, 0x02)).unwrap();
        assert_eq!(meta.algorithm, Some(ALG_X25519));
        assert_eq!(meta.pin_policy, 0x02);
        assert_eq!(meta.touch_policy, TouchPolicy::Always);
        assert!(meta.touch_policy.requires_touch());
    }

    #[test]
    fn every_documented_touch_policy_byte_decodes() {
        assert_eq!(TouchPolicy::from_byte(0x00), TouchPolicy::Default);
        assert_eq!(TouchPolicy::from_byte(0x01), TouchPolicy::Never);
        assert_eq!(TouchPolicy::from_byte(0x02), TouchPolicy::Always);
        assert_eq!(TouchPolicy::from_byte(0x03), TouchPolicy::Cached);
    }

    #[test]
    fn only_always_and_cached_count_as_a_touch() {
        // The bug this guards: `ykman piv keys generate` leaves a slot at
        // "never", the ECDH returns instantly, and the UI claims a tap.
        assert!(!TouchPolicy::Never.requires_touch());
        assert!(!TouchPolicy::Default.requires_touch());
        assert!(TouchPolicy::Always.requires_touch());
        assert!(TouchPolicy::Cached.requires_touch());
    }

    #[test]
    fn an_unrecognised_policy_byte_fails_closed() {
        let meta = parse_slot_metadata(&metadata_body(0x02, 0x7F)).unwrap();
        assert_eq!(meta.touch_policy, TouchPolicy::Unknown(0x7F));
        assert!(!meta.touch_policy.requires_touch());
        assert!(!meta.touch_policy.is_known());
        assert!(!TouchPolicy::Unavailable.requires_touch());
        assert!(!TouchPolicy::Unavailable.is_known());
    }

    #[test]
    fn metadata_without_a_policy_element_is_rejected() {
        // Algorithm and origin only: nothing here says anything about a touch.
        let body = vec![0x01, 0x01, ALG_X25519, 0x03, 0x01, 0x01];
        assert!(matches!(parse_slot_metadata(&body), Err(ApduError::Tlv(_))));
    }

    #[test]
    fn a_one_byte_policy_element_is_rejected_rather_than_read_as_touch() {
        // If this were read positionally, the PIN policy byte 0x02 ("once")
        // would be mistaken for touch policy 0x02 ("always").
        let body = vec![0x02, 0x01, 0x02];
        assert!(matches!(parse_slot_metadata(&body), Err(ApduError::Tlv(_))));
    }

    #[test]
    fn metadata_tolerates_a_trailing_public_key_element() {
        let mut body = metadata_body(0x01, 0x01);
        body.extend_from_slice(&[0x04, 0x24, 0x86, 0x22]);
        body.extend_from_slice(&[0xCC; 0x22]);
        let meta = parse_slot_metadata(&body).unwrap();
        assert_eq!(meta.touch_policy, TouchPolicy::Never);
    }

    #[test]
    fn tlv_find_handles_long_form_lengths() {
        let mut data = vec![0x53, 0x81, 0x80];
        data.extend_from_slice(&[0x11u8; 0x80]);
        let found = tlv_find(&data, 0x53).unwrap();
        assert_eq!(found.len(), 0x80);
    }

    #[test]
    fn tlv_find_skips_preceding_elements() {
        let data = vec![0x80, 0x01, 0xAA, 0x82, 0x02, 0xBB, 0xCC];
        assert_eq!(tlv_find(&data, 0x82).unwrap(), &[0xBB, 0xCC]);
    }

    #[test]
    fn tlv_find_refuses_a_truncated_value() {
        assert!(tlv_find(&[0x82, 0x05, 0x01], 0x82).is_none());
    }
}
