//! YubiKey PIV identity.
//!
//! Layering, outermost first:
//!
//! * `PivIdentity` -- implements `core::Identity`; picks a backend from the flag
//!   recorded at enrollment time, never from ambient state.
//! * `PivSession<T: CardTransport>` -- the PIV conversation (SELECT, VERIFY,
//!   GENERAL AUTHENTICATE). Pure logic over a transport; unit-tested against a
//!   scripted transport in `tests_piv.rs`.
//! * `CardTransport` -- the boundary. Exactly one implementation talks to real
//!   hardware: `piv_pcsc::PcscTransport`. That is the only device-blocked code
//!   in this file.
//!
//! ## What the card must already hold
//!
//! rageterm does not generate keys on the card: that needs the PIV management
//! key and is `ykman`'s job. Enrollment reads a public key the user supplies and
//! *proves* the card holds the matching private key by running one live ECDH
//! against a locally generated ephemeral (see
//! `real_enroll_allowing_untouched_slot`). A card that cannot
//! answer the challenge is refused, so a mistyped public key can never become a
//! recipient that nothing can decrypt.
//!
//! ## The touch is verified, not assumed
//!
//! The slot's touch policy is read off the card with Yubico's GET METADATA
//! (`piv_apdu::get_slot_metadata`, firmware 5.3.0+) at enrollment *and* before
//! every unwrap. Nothing in this file says "touch the YubiKey" unless that read
//! came back `always` or `cached`. This was a real hole: `ykman`'s default touch
//! policy is `never`, ECDH on such a slot returns instantly, and the old code
//! announced a tap regardless -- so the user was trained to accept a ceremony
//! that had no device behind it, on the browser native-host path where that
//! touch is the only gate. Firmware that has no GET METADATA reports
//! `TouchPolicy::Unavailable`, which is refused at enrollment (overridable, see
//! `ALLOW_UNTOUCHED_SLOT_FLAG`) and never announced as a touch.
//!
//! ## Which curve
//!
//! New slots are **P-256** (every YubiKey 4/5, `ykman piv keys generate
//! --algorithm ECCP256`): their stanza is `age-plugin-yubikey`'s `piv-p256`, and
//! the slot also signs the native host's per-unwrap proof. **X25519** slots
//! (firmware 5.7.0+, `--x25519` at enrollment) remain readable: their stanzas
//! are `piv-x25519-v2` or, written before that tag existed, the X25519-shaped
//! `piv-p256` (`stanza_format::PivStanzaKind`), and `migrate-piv` moves their
//! items to a P-256 slot.

use ragewarden_core::stanza_format::{
    self, PivStanzaKind, decrypt_piv_x25519_with_ecdh_share, piv_recipient_tag, piv_stanza_kind,
    piv_x25519_ephemeral_pub, piv_x25519_recipient_tag,
};
use ragewarden_core::{FileKey, Identity, IdentityError, Stanza};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::ceremony;
use crate::piv_apdu::{self as apdu, ApduError, TouchPolicy};

/// The CLI spelling of the enrollment override, kept next to the code that
/// enforces it so the flag, the refusal and the warning cannot drift apart.
/// Deliberately unwieldy: enrolling a slot that decrypts without a touch turns
/// the YubiKey into a file on a keyring, and nobody should reach for this by
/// accident or paste it from a forum post without reading it.
pub const ALLOW_UNTOUCHED_SLOT_FLAG: &str = "--i-accept-this-slot-needs-no-touch";

#[derive(Debug, Error)]
pub enum PivError {
    #[error("pcsc: {0}")]
    Pcsc(String),

    #[error(
        "no smart-card reader found. Plug in the YubiKey, and check that pcscd is \
         running (`systemctl status pcscd`)."
    )]
    NoReader,

    #[error("reader `{0}` is empty -- insert the YubiKey")]
    NoCard(String),

    #[error(
        "reader `{0}` has a card but no PIV applet (SELECT failed). Is this the right \
         token?"
    )]
    NoPivApplet(String),

    #[error(
        "PIV slot {slot:#04x} holds no key, or it is not an ECDH-capable key. Create \
         one with `ykman piv keys generate --algorithm ECCP256 --touch-policy always \
         {slot:02x} pub.pem`."
    )]
    SlotEmpty { slot: u8 },

    #[error(
        "this YubiKey rejected algorithm {algorithm:#04x}. X25519 in PIV needs firmware \
         5.7.0 or newer; use a P-256 slot (`ykman piv keys generate --algorithm \
         ECCP256`), which every YubiKey 4/5 supports."
    )]
    AlgorithmUnsupported { algorithm: u8 },

    #[error("wrong PIN -- {tries_left} attempt(s) left before the PIV applet locks")]
    PinIncorrect { tries_left: u8 },

    #[error("PIV PIN is blocked; unblock it with `ykman piv access unblock-pin`")]
    PinBlocked,

    #[error(
        "the PIV slot needs its PIN, but there is no terminal and no `pinentry` program on \
         PATH to ask for it"
    )]
    NoPinPrompt,

    #[error("PIV PIN entry: {0}")]
    Pin(String),

    #[error("{0}")]
    Busy(String),

    #[error(
        "wrong YubiKey: this identity was enrolled against serial {expected:08x}, the \
         connected card reports {found:08x}"
    )]
    WrongDevice { expected: u32, found: u32 },

    #[error(
        "{count} smart cards are connected and rageterm cannot tell which one to use; \
         unplug the others and retry"
    )]
    AmbiguousCard { count: usize },

    #[error(
        "the card did not answer the ECDH challenge -- the touch was not registered, or \
         the operation was declined"
    )]
    TouchNotRegistered,

    #[error("card refused the operation (SW={sw:#06x}) during {context}")]
    Apdu { sw: u16, context: String },

    #[error("apdu: {0}")]
    ApduFormat(#[from] ApduError),

    #[error(
        "the card answered the challenge but the shared secret does not match the public \
         key you supplied -- slot {slot:#04x} holds a different key"
    )]
    ProofOfPossessionFailed { slot: u8 },

    #[error(
        "PIV slot {slot:#04x} has touch policy `{policy}`: it will decrypt without a touch \
         for every use (`cached` lets one touch cover the next ~15 seconds), so the tap \
         rageterm announces before every unwrap would not always happen. Regenerate the slot \
         with `ykman piv keys generate --algorithm ECCP256 --touch-policy always --pin-policy \
         once {slot:02x} pub.pem` (this replaces the key -- re-export the public key \
         afterwards), or re-run enrollment with `{override_flag}` if you genuinely want an \
         identity that nothing physical gates."
    )]
    SlotDoesNotRequireTouch {
        slot: u8,
        policy: String,
        override_flag: &'static str,
    },

    #[error(
        "cannot read the touch policy of PIV slot {slot:#04x} from this card ({policy}). \
         Reading it back needs the Yubico GET METADATA command, which arrived in firmware \
         5.3.0; on older keys there is no way to tell a touch-gated slot from one that \
         decrypts silently. rageterm refuses to enroll a touch it cannot verify -- pass \
         `{override_flag}` if you accept that the announced tap may never be required."
    )]
    TouchPolicyUnverifiable {
        slot: u8,
        policy: String,
        override_flag: &'static str,
    },

    #[error("public key: {0}")]
    PublicKey(String),

    #[error("stanza: {0}")]
    Stanza(#[from] stanza_format::StanzaFormatError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(not(any(test, feature = "mock-hardware")))]
    #[error(
        "this identity was enrolled with the software stand-in (RAGEWARDEN_MOCK_HARDWARE=1) \
         and this build has no mock support. Re-enroll against a real YubiKey with \
         `rageterm enroll-yubikey`."
    )]
    MockIdentityOnRealBuild,

    #[cfg(any(test, feature = "mock-hardware"))]
    #[error("mock hardware: {0}")]
    Mock(String),
}

/// The one thing that needs a physical card. Implemented for real by
/// `piv_pcsc::PcscTransport`, and by scripted fakes in tests.
pub trait CardTransport {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, PivError>;
    fn describe(&self) -> String;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    NotRequired,
    Required { tries_left: u8 },
    Blocked,
}

pub struct PivSession<T: CardTransport> {
    transport: T,
    pin_verified: bool,
}

impl<T: CardTransport> PivSession<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            pin_verified: false,
        }
    }

    /// Transmit, follow `61 XX` chaining, return (body, sw).
    fn raw(&mut self, command: &[u8]) -> Result<(Vec<u8>, u16), PivError> {
        let response = self.transport.transmit(command)?;
        let (body, sw) = apdu::split_sw(&response)?;
        let mut acc = body.to_vec();
        let mut sw = sw;
        while let Some(more) = apdu::more_data_available(sw) {
            let next = self.transport.transmit(&apdu::get_response(more))?;
            let (body, next_sw) = apdu::split_sw(&next)?;
            acc.extend_from_slice(body);
            sw = next_sw;
        }
        Ok((acc, sw))
    }

    pub fn select(&mut self) -> Result<(), PivError> {
        let (_, sw) = self.raw(&apdu::select_piv())?;
        if sw != apdu::SW_OK {
            return Err(PivError::NoPivApplet(self.transport.describe()));
        }
        Ok(())
    }

    /// Yubico's serial extension. Absent on non-Yubico PIV cards, which is not
    /// an error -- the caller falls back to 0 and skips the device check.
    pub fn serial(&mut self) -> Result<Option<u32>, PivError> {
        let (body, sw) = self.raw(&apdu::get_serial())?;
        if sw != apdu::SW_OK || body.len() < 4 {
            return Ok(None);
        }
        Ok(Some(u32::from_be_bytes([
            body[0], body[1], body[2], body[3],
        ])))
    }

    /// The slot's touch policy, read back from the card.
    ///
    /// The only honest source for "will this blink?". Needs no PIN and no
    /// touch, so it is safe to issue *before* anything is printed to the user.
    ///
    /// Everything the card does not spell out in a byte this build understands
    /// comes back as `TouchPolicy::Unavailable` -- never as `Always`. That
    /// includes firmware older than 5.3.0 (which has no GET METADATA at all and
    /// answers `6D00`), non-Yubico PIV applets, and answers that do not parse.
    /// Callers decide what to do with "unknown"; what they must not be able to
    /// do is mistake it for a verified touch.
    pub fn slot_touch_policy(&mut self, slot: u8) -> Result<TouchPolicy, PivError> {
        let (body, sw) = self.raw(&apdu::get_slot_metadata(slot))?;
        match sw {
            apdu::SW_OK => Ok(apdu::parse_slot_metadata(&body)
                .map(|m| m.touch_policy)
                .unwrap_or(TouchPolicy::Unavailable)),
            apdu::SW_REFERENCE_NOT_FOUND | apdu::SW_FILE_NOT_FOUND => {
                Err(PivError::SlotEmpty { slot })
            }
            apdu::SW_INS_NOT_SUPPORTED
            | apdu::SW_CLASS_NOT_SUPPORTED
            | apdu::SW_FUNCTION_NOT_SUPPORTED => Ok(TouchPolicy::Unavailable),
            _ => Ok(TouchPolicy::Unavailable),
        }
    }

    pub fn pin_status(&mut self) -> Result<PinStatus, PivError> {
        let (_, sw) = self.raw(&apdu::verify_pin_status())?;
        if sw == apdu::SW_OK {
            return Ok(PinStatus::NotRequired);
        }
        if sw == apdu::SW_AUTH_METHOD_BLOCKED {
            return Ok(PinStatus::Blocked);
        }
        match apdu::pin_retries_from_sw(sw) {
            Some(0) => Ok(PinStatus::Blocked),
            Some(tries_left) => Ok(PinStatus::Required { tries_left }),
            None => Ok(PinStatus::Required { tries_left: 3 }),
        }
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<(), PivError> {
        let (_, sw) = self.raw(&apdu::verify_pin(pin)?)?;
        match sw {
            apdu::SW_OK => {
                self.pin_verified = true;
                Ok(())
            }
            apdu::SW_AUTH_METHOD_BLOCKED => Err(PivError::PinBlocked),
            other => match apdu::pin_retries_from_sw(other) {
                Some(0) => Err(PivError::PinBlocked),
                Some(tries_left) => Err(PivError::PinIncorrect { tries_left }),
                None => Err(PivError::Apdu {
                    sw: other,
                    context: "VERIFY".into(),
                }),
            },
        }
    }

    /// One ECDH on the card. `algorithm` is `apdu::ALG_X25519` or
    /// `apdu::ALG_ECC_P256`; `peer_public` is the ephemeral public key.
    pub fn ecdh(
        &mut self,
        algorithm: u8,
        slot: u8,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, PivError> {
        let command = apdu::general_authenticate_ecdh(algorithm, slot, peer_public)?;
        let (body, sw) = self.raw(&command)?;
        match sw {
            apdu::SW_OK => Ok(apdu::parse_ecdh_response(&body, 32)?),
            apdu::SW_SECURITY_STATUS_NOT_SATISFIED | apdu::SW_CONDITIONS_NOT_SATISFIED => {
                Err(PivError::Apdu {
                    sw,
                    context: "GENERAL AUTHENTICATE (PIN or touch policy not satisfied)".into(),
                })
            }
            apdu::SW_REFERENCE_NOT_FOUND | apdu::SW_FILE_NOT_FOUND => {
                Err(PivError::SlotEmpty { slot })
            }
            apdu::SW_INCORRECT_PARAMETERS | apdu::SW_INS_NOT_SUPPORTED => {
                Err(PivError::AlgorithmUnsupported { algorithm })
            }
            other => Err(PivError::Apdu {
                sw: other,
                context: "GENERAL AUTHENTICATE".into(),
            }),
        }
    }

    /// ECDH, retrying once behind a PIN prompt if the card demands one.
    /// ECDSA P-256 over `digest` with the slot's key, as raw r||s.
    pub fn sign(&mut self, slot: u8, digest: &[u8; 32]) -> Result<[u8; 64], PivError> {
        let (body, sw) = self.raw(&apdu::general_authenticate_sign(slot, digest))?;
        if sw != apdu::SW_OK {
            return Err(PivError::Apdu {
                sw,
                context: "GENERAL AUTHENTICATE (sign)".into(),
            });
        }
        let der = apdu::parse_sign_response(&body)?;
        let sig = p256::ecdsa::Signature::from_der(&der)
            .map_err(|e| PivError::PublicKey(format!("card signature is not DER ECDSA: {e}")))?;
        Ok(sig.to_bytes().into())
    }

    pub fn ecdh_with_pin_retry(
        &mut self,
        algorithm: u8,
        slot: u8,
        peer_public: &[u8],
        prompt_pin: &dyn Fn() -> Result<zeroize::Zeroizing<String>, PivError>,
    ) -> Result<Vec<u8>, PivError> {
        let touch_refused = |e: PivError| match e {
            PivError::Apdu { sw, .. }
                if sw == apdu::SW_SECURITY_STATUS_NOT_SATISFIED
                    || sw == apdu::SW_CONDITIONS_NOT_SATISFIED
                    || sw == apdu::SW_SECURITY_ISSUE =>
            {
                PivError::TouchNotRegistered
            }
            other => other,
        };
        match self.ecdh(algorithm, slot, peer_public) {
            Err(PivError::Apdu { sw, .. }) if sw == apdu::SW_SECURITY_ISSUE => {
                Err(PivError::TouchNotRegistered)
            }
            Err(PivError::Apdu { sw, .. })
                if sw == apdu::SW_SECURITY_STATUS_NOT_SATISFIED
                    || sw == apdu::SW_CONDITIONS_NOT_SATISFIED =>
            {
                if self.pin_verified {
                    return Err(PivError::TouchNotRegistered);
                }
                if self.pin_status()? == PinStatus::Blocked {
                    return Err(PivError::PinBlocked);
                }
                let pin = prompt_pin()?;
                self.verify_pin(&pin)?;
                self.ecdh(algorithm, slot, peer_public)
                    .map_err(touch_refused)
            }
            other => other,
        }
    }
}

/// A PIV slot's public key: X25519 (firmware 5.7+) or P-256 (every YubiKey 4/5),
/// the latter as a 33-byte compressed SEC1 point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PivPublicKey {
    X25519([u8; 32]),
    P256([u8; 33]),
}

impl PivPublicKey {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::X25519(k) => k,
            Self::P256(k) => k,
        }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes())
    }

    /// 64 hex characters are an X25519 key, 66 a compressed P-256 point -- the
    /// form `identities.json` and the registry store.
    pub fn from_hex(s: &str) -> Result<Self, PivError> {
        let bytes = hex::decode(s.trim()).map_err(|e| PivError::PublicKey(format!("hex: {e}")))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PivError> {
        match bytes.len() {
            32 => Ok(Self::X25519(bytes.try_into().expect("checked length"))),
            33 | 65 => Ok(Self::P256(p256_compress(bytes)?)),
            n => Err(PivError::PublicKey(format!(
                "a PIV public key is 32 bytes (X25519) or a 33/65-byte P-256 point, got {n}"
            ))),
        }
    }

    pub fn algorithm(&self) -> u8 {
        match self {
            Self::X25519(_) => apdu::ALG_X25519,
            Self::P256(_) => apdu::ALG_ECC_P256,
        }
    }

    pub fn curve(&self) -> &'static str {
        match self {
            Self::X25519(_) => "X25519",
            Self::P256(_) => "P-256",
        }
    }
}

fn p256_point(sec1: &[u8]) -> Result<p256::PublicKey, PivError> {
    p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|_| PivError::PublicKey("not a point on P-256".into()))
}

pub fn p256_compress(sec1: &[u8]) -> Result<[u8; 33], PivError> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let point = p256_point(sec1)?.to_sec1_point(true);
    point
        .as_bytes()
        .try_into()
        .map_err(|_| PivError::PublicKey("compressed P-256 point is not 33 bytes".into()))
}

/// The card's GENERAL AUTHENTICATE takes the peer point uncompressed.
pub fn p256_uncompressed(sec1: &[u8]) -> Result<[u8; 65], PivError> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let point = p256_point(sec1)?.to_sec1_point(false);
    point
        .as_bytes()
        .try_into()
        .map_err(|_| PivError::PublicKey("uncompressed P-256 point is not 65 bytes".into()))
}

#[derive(Debug, Clone)]
pub struct EnrolledPiv {
    pub public_key: PivPublicKey,
    pub serial: u32,
    pub slot: u8,
    /// True only for the software stand-in. Propagated into `identities.json`,
    /// into every label, and used to refuse registry publication.
    pub mock: bool,
    /// What the card said about the slot when it was enrolled, read back with
    /// GET METADATA rather than assumed from the `ykman` line the user was told
    /// to run. Anything other than `Always`/`Cached` means enrollment only
    /// happened because the operator passed `ALLOW_UNTOUCHED_SLOT_FLAG`.
    pub touch_policy: TouchPolicy,
}

/// `--public-key` accepts what `ykman piv keys export <slot> -` prints (a PEM
/// SubjectPublicKeyInfo, X25519 or P-256), 64 hex characters (X25519), or a
/// 66/130-hex P-256 point.
pub fn parse_public_key(input: &str) -> Result<PivPublicKey, PivError> {
    const X25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00,
    ];

    let trimmed = input.trim();
    if trimmed.contains("BEGIN PUBLIC KEY") {
        let b64: String = trimmed
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| l.chars())
            .filter(|c| !c.is_whitespace())
            .collect();
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        let der = B64
            .decode(b64.as_bytes())
            .map_err(|e| PivError::PublicKey(format!("PEM body is not base64: {e}")))?;
        if der.len() == 44 && der[..12] == X25519_SPKI_PREFIX {
            let mut out = [0u8; 32];
            out.copy_from_slice(&der[12..]);
            return Ok(PivPublicKey::X25519(out));
        }
        use p256::pkcs8::DecodePublicKey;
        if let Ok(pk) = p256::PublicKey::from_public_key_der(&der) {
            use p256::elliptic_curve::sec1::ToSec1Point;
            return PivPublicKey::from_bytes(pk.to_sec1_point(true).as_bytes());
        }
        return Err(PivError::PublicKey(format!(
            "expected an X25519 or P-256 SubjectPublicKeyInfo, got {} bytes with a \
             different algorithm. Export the slot with `ykman piv keys export <slot> -`.",
            der.len()
        )));
    }

    let hex_only: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if matches!(hex_only.len(), 64 | 66 | 130) && hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
        return PivPublicKey::from_hex(&hex_only);
    }

    Err(PivError::PublicKey(
        "expected a PEM public key (X25519 or P-256), 64 hex characters (X25519) or a \
         66/130-hex P-256 point"
            .into(),
    ))
}

/// Enroll against a real card. Two checks stand between a card and a recorded
/// identity, and both happen before anything is written:
///
/// 1. **Possession.** A fresh ephemeral is generated here, the card is asked to
///    ECDH it against the slot key, and the result is compared with the same
///    ECDH computed locally from the public key the user supplied. A mistyped
///    public key can never become a recipient that nothing can decrypt.
///
/// 2. **Touch.** The slot's policy is read back with GET METADATA. This used to
///    be assumed: enrollment announced a touch, `ykman`'s default touch policy
///    is *never*, and the ECDH on such a slot returns instantly -- so the UI
///    claimed a tap that had not happened, on every unwrap, forever after. For
///    the browser native-host path that unverified touch is the entire gate, so
///    a slot that cannot prove it demands one is refused unless
///    `allow_untouched_slot` is set (`ALLOW_UNTOUCHED_SLOT_FLAG`), which prints
///    a warning and records the real policy either way.
pub fn real_enroll_allowing_untouched_slot(
    slot: u8,
    claimed_public_key: PivPublicKey,
    allow_untouched_slot: bool,
) -> Result<EnrolledPiv, PivError> {
    let _device = crate::lock::device_session().map_err(|e| PivError::Busy(e.to_string()))?;
    let transport = crate::piv_pcsc::open_piv_card(0)?;
    let mut session = PivSession::new(transport);
    session.select()?;
    let serial = session.serial()?.unwrap_or(0);

    let touch_policy = session.slot_touch_policy(slot)?;
    if !touch_policy.touch_every_use() {
        if !allow_untouched_slot {
            return Err(if touch_policy.is_known() {
                PivError::SlotDoesNotRequireTouch {
                    slot,
                    policy: touch_policy.to_string(),
                    override_flag: ALLOW_UNTOUCHED_SLOT_FLAG,
                }
            } else {
                PivError::TouchPolicyUnverifiable {
                    slot,
                    policy: touch_policy.to_string(),
                    override_flag: ALLOW_UNTOUCHED_SLOT_FLAG,
                }
            });
        }
        eprintln!(
            "rageterm: WARNING -- enrolling PIV slot {slot:#04x} with touch policy \
             `{touch_policy}`. Decryption with this identity is gated by possession of the \
             card (and the PIN, if the slot asks for one) and by nothing else; rageterm will \
             not tell you to touch anything when it uses it. This is what \
             `{ALLOW_UNTOUCHED_SLOT_FLAG}` means."
        );
    }

    let (challenge_public, expected) = possession_challenge(&claimed_public_key)?;

    announce_for_policy(
        &describe_device(serial, slot),
        "Proving the card holds the private key for the public key you supplied",
        touch_policy,
    );
    let device_share = session.ecdh_with_pin_retry(
        claimed_public_key.algorithm(),
        slot,
        &challenge_public,
        &prompt_pin,
    )?;

    if device_share.as_slice() != expected.as_slice() {
        return Err(PivError::ProofOfPossessionFailed { slot });
    }

    let enrolled = EnrolledPiv {
        public_key: claimed_public_key,
        serial,
        slot,
        mock: false,
        touch_policy,
    };
    ceremony::announce_step(&format!(
        "PIV slot {slot:#04x} ({}) enrolled with touch policy `{}`, read from the card \
         rather than assumed from the `ykman` line you ran.",
        enrolled.public_key.curve(),
        enrolled.touch_policy
    ));
    Ok(enrolled)
}

/// A fresh ephemeral public key to send the card, and the shared secret it
/// must answer with if it holds the private half of `claimed`.
fn possession_challenge(
    claimed: &PivPublicKey,
) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), PivError> {
    match claimed {
        PivPublicKey::X25519(pk) => {
            let mut seed = [0u8; 32];
            rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
            let secret = X25519Secret::from(seed);
            let public = X25519Public::from(&secret);
            let expected = secret.diffie_hellman(&X25519Public::from(*pk));
            Ok((
                public.as_bytes().to_vec(),
                zeroize::Zeroizing::new(expected.as_bytes().to_vec()),
            ))
        }
        PivPublicKey::P256(pk) => {
            use p256::elliptic_curve::Generate;
            use p256::elliptic_curve::sec1::ToSec1Point;
            let secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
            let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
            let shared =
                p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), p256_point(pk)?.as_affine());
            Ok((
                public,
                zeroize::Zeroizing::new(shared.raw_secret_bytes().to_vec()),
            ))
        }
    }
}

/// Print the line the user reads immediately before the card is asked to work.
///
/// `ceremony::announce_touch` says "touch X now", which is a claim about the
/// hardware. It is only allowed out when the slot's policy, read from the card,
/// says a touch is genuinely coming. Everything else goes through
/// `announce_step`, which never demands a touch -- and the two ungated cases are
/// worded differently on purpose: "this slot needs no touch" and "this card
/// would not tell me" are very different things to be told.
fn announce_for_policy(device: &str, why: &str, policy: TouchPolicy) {
    if policy.touch_every_use() || policy == TouchPolicy::Cached {
        let why = if policy == TouchPolicy::Cached {
            format!(
                "{why} (slot touch policy `cached`: a touch in the last ~15 seconds may \
                 already count for this one)"
            )
        } else {
            why.to_string()
        };
        ceremony::announce_touch(device, &why);
        return;
    }
    if policy.is_known() {
        ceremony::announce_step(&format!(
            "{why} on {device}. Slot touch policy is `{policy}`: the card will do this \
             without waiting for you, so nothing physical is confirming it."
        ));
    } else {
        ceremony::announce_step(&format!(
            "{why} on {device}. This card will not report the slot's touch policy \
             ({policy}), so rageterm cannot promise a touch is required -- do not read the \
             absence of a prompt as proof either way. If the device starts blinking it is \
             waiting for a touch."
        ));
    }
}

pub fn describe_device(serial: u32, slot: u8) -> String {
    if serial == 0 {
        format!("the YubiKey in the reader (PIV slot {slot:#04x})")
    } else {
        format!("YubiKey #{serial:08x} (PIV slot {slot:#04x})")
    }
}

fn prompt_pin() -> Result<zeroize::Zeroizing<String>, PivError> {
    let description = match ceremony::current() {
        Some(c) => format!("{c}\nThe PIV slot requires its PIN before it will use its key."),
        None => "The PIV slot requires its PIN before it will use its key.".to_string(),
    };
    crate::pin::read_pin("PIV PIN: ", &description).map_err(|e| match e {
        crate::pin::PinError::NoPinSource => PivError::NoPinPrompt,
        crate::pin::PinError::Io(io) => PivError::Io(io),
        other => PivError::Pin(other.to_string()),
    })
}

/// The ECDH share, plus a signature over `sign` made in the same session.
fn real_ecdh(
    serial: u32,
    slot: u8,
    algorithm: u8,
    ephemeral_pub: &[u8],
    sign: Option<&[u8; 32]>,
) -> Result<([u8; 32], Option<[u8; 64]>), PivError> {
    let _device = crate::lock::device_session().map_err(|e| PivError::Busy(e.to_string()))?;
    let transport = crate::piv_pcsc::open_piv_card(serial)?;
    let mut session = PivSession::new(transport);
    session.select()?;

    if serial != 0 {
        if let Some(found) = session.serial()? {
            if found != serial {
                return Err(PivError::WrongDevice {
                    expected: serial,
                    found,
                });
            }
        }
    }

    let touch_policy = session
        .slot_touch_policy(slot)
        .unwrap_or(TouchPolicy::Unavailable);
    announce_for_policy(
        &describe_device(serial, slot),
        "Unwrapping this credential",
        touch_policy,
    );
    let share = session.ecdh_with_pin_retry(algorithm, slot, ephemeral_pub, &prompt_pin)?;
    let share: [u8; 32] = share
        .as_slice()
        .try_into()
        .map_err(|_| PivError::PublicKey(format!("ECDH share is {} bytes", share.len())))?;

    let Some(digest) = sign else {
        return Ok((share, None));
    };
    announce_for_policy(
        &describe_device(serial, slot),
        "Signing the browser's challenge for this unwrap",
        touch_policy,
    );
    let signature = match session.sign(slot, digest) {
        Err(PivError::Apdu { sw, .. }) if sw == apdu::SW_SECURITY_STATUS_NOT_SATISFIED => {
            let pin = prompt_pin()?;
            session.verify_pin(&pin)?;
            session.sign(slot, digest)
        }
        other => other,
    }?;
    Ok((share, Some(signature)))
}

pub struct PivIdentity {
    pub public_key: PivPublicKey,
    pub serial: u32,
    pub slot: u8,
    pub label: String,
    /// Recorded at enrollment. Not read from the environment: flipping
    /// `RAGEWARDEN_MOCK_HARDWARE` cannot turn a real identity into a mock one
    /// or vice versa.
    pub mock: bool,
}

impl PivIdentity {
    /// Whether this stanza is addressed to this slot's key, without touching the card.
    pub fn names(&self, stanza: &Stanza) -> Result<bool, IdentityError> {
        let own = piv_recipient_tag(self.public_key.bytes());
        Ok(match (&self.public_key, piv_stanza_kind(stanza)) {
            (PivPublicKey::X25519(_), Some(PivStanzaKind::X25519V1 | PivStanzaKind::X25519V2)) => {
                piv_x25519_recipient_tag(stanza).ok() == Some(own)
            }
            (PivPublicKey::P256(_), Some(PivStanzaKind::P256)) => {
                stanza_format::piv_ec_p256_recipient_tag(stanza).ok() == Some(own)
            }
            _ => false,
        })
    }
}

impl Identity for PivIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if !self.names(stanza)? {
            return Ok(None);
        }

        let crypto = |e: stanza_format::StanzaFormatError| IdentityError::Crypto(e.to_string());
        let hardware = |e: PivError| IdentityError::Hardware(e.to_string());
        let fk = match &self.public_key {
            PivPublicKey::X25519(own) => {
                let eph_pub = piv_x25519_ephemeral_pub(stanza).map_err(crypto)?;
                let share = if self.mock {
                    mock_ecdh_dispatch(self.serial, self.slot, &eph_pub).map_err(hardware)?
                } else {
                    real_ecdh(self.serial, self.slot, apdu::ALG_X25519, &eph_pub, None)
                        .map(|(share, _)| share)
                        .map_err(hardware)?
                };
                decrypt_piv_x25519_with_ecdh_share(stanza, &share, Some(own)).map_err(crypto)?
            }
            PivPublicKey::P256(own) => {
                let eph = stanza_format::piv_ec_p256_ephemeral_pub(stanza).map_err(crypto)?;
                let digest =
                    crate::native_proof::pending_message().map(|m| crate::native_proof::digest(&m));
                let (share, signature) = if self.mock {
                    let share =
                        mock_ecdh_p256_dispatch(self.serial, self.slot, &eph).map_err(hardware)?;
                    let signature = digest
                        .map(|d| mock_sign_dispatch(self.serial, self.slot, &d))
                        .transpose()
                        .map_err(hardware)?;
                    (share, signature)
                } else {
                    let peer = p256_uncompressed(&eph).map_err(hardware)?;
                    real_ecdh(
                        self.serial,
                        self.slot,
                        apdu::ALG_ECC_P256,
                        &peer,
                        digest.as_ref(),
                    )
                    .map_err(hardware)?
                };
                if let Some(signature) = signature {
                    crate::native_proof::record(crate::native_proof::DeviceSignature::Piv {
                        signature,
                        public_key: *own,
                    });
                }
                stanza_format::decrypt_piv_ec_p256_with_ecdh_share(stanza, &share, own)
                    .map_err(crypto)?
            }
        };
        Ok(Some(fk))
    }

    fn display(&self) -> &str {
        &self.label
    }
}

#[cfg(not(any(test, feature = "mock-hardware")))]
fn mock_ecdh_dispatch(_serial: u32, _slot: u8, _eph: &[u8; 32]) -> Result<[u8; 32], PivError> {
    Err(PivError::MockIdentityOnRealBuild)
}

#[cfg(any(test, feature = "mock-hardware"))]
fn mock_ecdh_dispatch(serial: u32, slot: u8, eph: &[u8; 32]) -> Result<[u8; 32], PivError> {
    use crate::hw;
    if !hw::mock_enabled() {
        return Err(PivError::Mock(format!(
            "identity is a software stand-in but {} is not set to 1; refusing to \
             decrypt without either a device or an explicit mock opt-in",
            hw::MOCK_ENV
        )));
    }
    hw::warn_banner_once();
    mock::ecdh(serial, slot, eph)
}

#[cfg(not(any(test, feature = "mock-hardware")))]
fn mock_ecdh_p256_dispatch(_serial: u32, _slot: u8, _eph: &[u8; 33]) -> Result<[u8; 32], PivError> {
    Err(PivError::MockIdentityOnRealBuild)
}

#[cfg(any(test, feature = "mock-hardware"))]
fn mock_ecdh_p256_dispatch(serial: u32, slot: u8, eph: &[u8; 33]) -> Result<[u8; 32], PivError> {
    if !crate::hw::mock_enabled() {
        return Err(PivError::Mock(format!(
            "identity is a software stand-in but {} is not set to 1",
            crate::hw::MOCK_ENV
        )));
    }
    mock::ecdh_p256(serial, slot, eph)
}

#[cfg(any(test, feature = "mock-hardware"))]
pub fn mock_enroll_p256(slot: u8) -> Result<EnrolledPiv, PivError> {
    crate::hw::warn_banner_once();
    mock::enroll_p256(slot)
}

#[cfg(any(test, feature = "mock-hardware"))]
pub fn mock_enroll(slot: u8) -> Result<EnrolledPiv, PivError> {
    crate::hw::warn_banner_once();
    mock::enroll(slot)
}

#[cfg(any(test, feature = "mock-hardware"))]
mod mock {
    use super::*;
    use rand::Rng;
    use std::path::PathBuf;

    pub fn enroll(slot: u8) -> Result<EnrolledPiv, PivError> {
        let mut serial_bytes = [0u8; 4];
        rand::rng().fill_bytes(&mut serial_bytes);
        let serial = u32::from_be_bytes(serial_bytes);
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let secret = X25519Secret::from(seed);
        let public = X25519Public::from(&secret);
        write_secret(serial, slot, &seed)?;
        Ok(EnrolledPiv {
            public_key: PivPublicKey::X25519(*public.as_bytes()),
            serial,
            slot,
            mock: true,
            touch_policy: TouchPolicy::Never,
        })
    }

    pub fn ecdh(serial: u32, slot: u8, ephemeral_pub: &[u8; 32]) -> Result<[u8; 32], PivError> {
        let secret = read_secret(serial, slot)?;
        let shared = secret.diffie_hellman(&X25519Public::from(*ephemeral_pub));
        Ok(*shared.as_bytes())
    }

    pub fn enroll_p256(slot: u8) -> Result<EnrolledPiv, PivError> {
        use p256::elliptic_curve::Generate;
        use p256::elliptic_curve::sec1::ToSec1Point;
        let mut serial_bytes = [0u8; 4];
        rand::rng().fill_bytes(&mut serial_bytes);
        let serial = u32::from_be_bytes(serial_bytes);
        let secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let path = p256_secret_path(serial, slot)?;
        crate::config::ensure_config_dir()?;
        crate::config::write_private(&path, &secret.to_bytes())?;
        Ok(EnrolledPiv {
            public_key: PivPublicKey::from_bytes(
                secret.public_key().to_sec1_point(true).as_bytes(),
            )?,
            serial,
            slot,
            mock: true,
            touch_policy: TouchPolicy::Never,
        })
    }

    pub fn ecdh_p256(serial: u32, slot: u8, eph: &[u8; 33]) -> Result<[u8; 32], PivError> {
        let bytes = std::fs::read(p256_secret_path(serial, slot)?)?;
        let secret = p256::SecretKey::from_slice(&bytes)
            .map_err(|_| PivError::Mock("mock P-256 secret is malformed".into()))?;
        let shared =
            p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), p256_point(eph)?.as_affine());
        shared
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| PivError::Mock("P-256 share is not 32 bytes".into()))
    }

    pub fn sign_p256(serial: u32, slot: u8, digest: &[u8; 32]) -> Result<[u8; 64], PivError> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let bytes = std::fs::read(p256_secret_path(serial, slot)?)?;
        let key = p256::ecdsa::SigningKey::from_slice(&bytes)
            .map_err(|_| PivError::Mock("mock P-256 secret is malformed".into()))?;
        let sig: p256::ecdsa::Signature = key
            .sign_prehash(digest)
            .map_err(|e| PivError::Mock(e.to_string()))?;
        Ok(sig.to_bytes().into())
    }

    fn p256_secret_path(serial: u32, slot: u8) -> std::io::Result<PathBuf> {
        Ok(crate::config::config_dir()?.join(format!("mock-piv-p256-{serial:08x}-{slot:02x}.bin")))
    }

    fn secret_path(serial: u32, slot: u8) -> std::io::Result<PathBuf> {
        Ok(crate::config::config_dir()?.join(format!("mock-piv-{serial:08x}-{slot:02x}.bin")))
    }

    fn write_secret(serial: u32, slot: u8, secret: &[u8; 32]) -> Result<(), PivError> {
        let path = secret_path(serial, slot)?;
        crate::config::ensure_config_dir()?;
        crate::config::write_private(&path, secret)?;
        Ok(())
    }

    fn read_secret(serial: u32, slot: u8) -> Result<X25519Secret, PivError> {
        let path = secret_path(serial, slot)?;
        let bytes = std::fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(PivError::Mock(format!(
                "mock secret at {} is {} bytes, expected 32",
                path.display(),
                bytes.len()
            )));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        Ok(X25519Secret::from(buf))
    }
}

/// Which connected card to talk to, given each card's serial (`None` when it
/// would not say) and the enrolled serial (0 when none was recorded).
pub fn choose_card(serials: &[Option<u32>], wanted: u32) -> Result<usize, PivError> {
    if wanted != 0 {
        if let Some(i) = serials.iter().position(|s| *s == Some(wanted)) {
            return Ok(i);
        }
        if serials.len() == 1 {
            return Ok(0);
        }
        if let Some(found) = serials.iter().flatten().next() {
            return Err(PivError::WrongDevice {
                expected: wanted,
                found: *found,
            });
        }
    }
    match serials.len() {
        1 => Ok(0),
        count => Err(PivError::AmbiguousCard { count }),
    }
}

#[cfg(not(any(test, feature = "mock-hardware")))]
fn mock_sign_dispatch(_serial: u32, _slot: u8, _digest: &[u8; 32]) -> Result<[u8; 64], PivError> {
    Err(PivError::MockIdentityOnRealBuild)
}

#[cfg(any(test, feature = "mock-hardware"))]
fn mock_sign_dispatch(serial: u32, slot: u8, digest: &[u8; 32]) -> Result<[u8; 64], PivError> {
    mock::sign_p256(serial, slot, digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw;
    use crate::tests_lock::ENV_LOCK;

    #[test]
    fn mock_identity_round_trip_is_labelled_as_mock() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::TempDir::new().unwrap();
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        crate::tests_lock::set_var(hw::MOCK_ENV, "1");

        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                crate::tests_lock::remove_var(hw::MOCK_ENV);
                crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
            }
        }
        let _cleanup = Cleanup;

        let enrolled = mock_enroll(0x95).expect("mock enroll");
        assert!(enrolled.mock);

        let mut file_key = [0u8; 16];
        for (i, b) in file_key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let PivPublicKey::X25519(x25519_pub) = enrolled.public_key.clone() else {
            panic!("mock enrolment is X25519")
        };
        let stanza = ragewarden_core::stanza_format::encrypt_piv_x25519_stanza(
            &file_key,
            &x25519_pub,
            ragewarden_core::stanza_format::EcdhStanzaVersion::V2,
        );

        let id = PivIdentity {
            public_key: enrolled.public_key.clone(),
            serial: enrolled.serial,
            slot: enrolled.slot,
            label: hw::mock_label("mock-piv"),
            mock: true,
        };
        assert!(hw::is_mock_label(id.display()));
        let recovered = id.try_unwrap_stanza(&stanza).unwrap().expect("matches");
        assert_eq!(&*recovered, &file_key);
    }

    #[test]
    fn a_p256_slot_opens_its_age_plugin_yubikey_stanza() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        crate::tests_lock::set_var(hw::MOCK_ENV, "1");
        let enrolled = mock_enroll_p256(0x9a).expect("mock p256 enroll");
        let file_key = [0x5Au8; 16];
        let recipients = [ragewarden_core::Recipient::YubiKeyPivP256 {
            public_key: enrolled.public_key.bytes().to_vec(),
            serial: enrolled.serial,
            slot: enrolled.slot,
        }];
        let blob = ragewarden_core::encrypt(&file_key, &recipients).expect("encrypt");
        let id = PivIdentity {
            public_key: enrolled.public_key.clone(),
            serial: enrolled.serial,
            slot: enrolled.slot,
            label: hw::mock_label("mock-p256"),
            mock: true,
        };
        let stanzas = ragewarden_core::parse_header_stanzas(&blob).unwrap();
        assert!(id.names(&stanzas[0]).unwrap());
        let ids: Vec<Box<dyn Identity>> = vec![Box::new(id)];
        let out = ragewarden_core::decrypt(&blob, &ids).expect("decrypt");
        crate::tests_lock::remove_var(hw::MOCK_ENV);
        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
        assert_eq!(out.as_slice(), &file_key);
    }

    #[test]
    fn a_p256_pem_or_point_parses_and_an_x25519_key_does_not_name_a_p256_stanza() {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        use p256::elliptic_curve::Generate;
        use p256::elliptic_curve::sec1::ToSec1Point;
        use p256::pkcs8::EncodePublicKey;
        let sk = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let der = sk.public_key().to_public_key_der().unwrap();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(der.as_bytes())
        );
        let compressed: [u8; 33] = sk
            .public_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_eq!(
            parse_public_key(&pem).unwrap(),
            PivPublicKey::P256(compressed)
        );
        let uncompressed = hex::encode(sk.public_key().to_sec1_point(false).as_bytes());
        assert_eq!(
            parse_public_key(&uncompressed).unwrap(),
            PivPublicKey::P256(compressed)
        );
        assert_eq!(PivPublicKey::P256(compressed).to_hex().len(), 66);
    }

    #[test]
    fn a_mock_identity_refuses_to_decrypt_without_the_opt_in() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        crate::tests_lock::set_var(hw::MOCK_ENV, "1");
        let enrolled = mock_enroll(0x95).expect("mock enroll");
        crate::tests_lock::remove_var(hw::MOCK_ENV);

        let mut file_key = [0u8; 16];
        file_key[0] = 9;
        let PivPublicKey::X25519(x25519_pub) = enrolled.public_key.clone() else {
            panic!("mock enrolment is X25519")
        };
        let stanza = ragewarden_core::stanza_format::encrypt_piv_x25519_stanza(
            &file_key,
            &x25519_pub,
            ragewarden_core::stanza_format::EcdhStanzaVersion::V2,
        );
        let id = PivIdentity {
            public_key: enrolled.public_key.clone(),
            serial: enrolled.serial,
            slot: enrolled.slot,
            label: hw::mock_label("mock-piv"),
            mock: true,
        };
        let err = id.try_unwrap_stanza(&stanza).unwrap_err();
        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
        assert!(err.to_string().contains("refusing to decrypt"));
    }

    /// Enough of a card to answer one GET METADATA. `tests_piv.rs` has the
    /// full-session version; this one lives here so the touch-policy status-word
    /// mapping is tested next to the code that decides what to print.
    struct OneAnswer(Vec<u8>);

    impl CardTransport for OneAnswer {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, PivError> {
            assert_eq!(command, &[0x00, 0xF7, 0x00, 0x9D, 0x00]);
            Ok(self.0.clone())
        }
        fn describe(&self) -> String {
            "scripted card".into()
        }
    }

    fn policy_for(answer: Vec<u8>) -> Result<TouchPolicy, PivError> {
        PivSession::new(OneAnswer(answer)).slot_touch_policy(0x9D)
    }

    #[test]
    fn touch_policy_is_read_from_the_metadata_answer() {
        let always = vec![0x01, 0x01, 0xE1, 0x02, 0x02, 0x02, 0x02, 0x90, 0x00];
        assert_eq!(policy_for(always).unwrap(), TouchPolicy::Always);

        let never = vec![0x01, 0x01, 0xE1, 0x02, 0x02, 0x02, 0x01, 0x90, 0x00];
        assert_eq!(policy_for(never).unwrap(), TouchPolicy::Never);
    }

    #[test]
    fn firmware_without_get_metadata_is_unavailable_not_a_touch() {
        for sw in [
            vec![0x6D, 0x00],
            vec![0x6E, 0x00],
            vec![0x6A, 0x81],
            vec![0x01, 0x01, 0xE1, 0x90, 0x00],
        ] {
            let policy = policy_for(sw).unwrap();
            assert_eq!(policy, TouchPolicy::Unavailable);
            assert!(!policy.touch_every_use());
        }
    }

    #[test]
    fn metadata_on_an_empty_slot_says_so() {
        assert!(matches!(
            policy_for(vec![0x6A, 0x88]),
            Err(PivError::SlotEmpty { slot: 0x9D })
        ));
    }

    #[test]
    fn parse_public_key_accepts_hex_and_pem_and_rejects_the_rest() {
        let hex = "a".repeat(64);
        assert_eq!(
            parse_public_key(&hex).unwrap(),
            PivPublicKey::X25519([0xAAu8; 32])
        );

        let mut der = vec![
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(&[0x11u8; 32]);
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(&der)
        );
        assert_eq!(
            parse_public_key(&pem).unwrap(),
            PivPublicKey::X25519([0x11u8; 32])
        );

        assert!(parse_public_key("not a key").is_err());
        assert!(parse_public_key(&"a".repeat(62)).is_err());

        let mut ed = vec![
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        ed.extend_from_slice(&[0x22u8; 32]);
        let ed_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(&ed)
        );
        assert!(parse_public_key(&ed_pem).is_err());
    }
}
