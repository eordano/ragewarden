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
//! against a locally generated ephemeral (see `real_enroll`). A card that cannot
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
//! `core::stanza_format::encrypt_piv_p256_stanza` is X25519 despite the
//! `piv-p256` tag: the recipient key and the ephemeral are both 32 raw bytes
//! (`core/src/stanza_format.rs:67-91`). Only a slot holding an **X25519** key
//! (YubiKey firmware 5.7.0+, `ykman piv keys generate --algorithm X25519`) can
//! satisfy that stanza. `ALG_ECC_P256` is implemented in `piv_apdu.rs` and
//! wired through `PivSession::ecdh`, but there is no stanza tag for it yet;
//! adding one is a `core/` change. See `docs/ragewarden/hardware-rageterm.md`.

use ragewarden_core::stanza_format::{
    self, decrypt_piv_p256_with_ecdh_share, piv_p256_ephemeral_pub, piv_recipient_tag,
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
         one with `ykman piv keys generate --algorithm X25519 {slot:02x} pub.pem` \
         (firmware 5.7.0+)."
    )]
    SlotEmpty { slot: u8 },

    #[error(
        "this YubiKey rejected algorithm {algorithm:#04x}. X25519 in PIV needs firmware \
         5.7.0 or newer; older keys can only do P-256, which the current `piv-p256` \
         stanza format cannot carry."
    )]
    AlgorithmUnsupported { algorithm: u8 },

    #[error("wrong PIN -- {tries_left} attempt(s) left before the PIV applet locks")]
    PinIncorrect { tries_left: u8 },

    #[error("PIV PIN is blocked; unblock it with `ykman piv access unblock-pin`")]
    PinBlocked,

    #[error("no terminal available to read the PIV PIN on")]
    NoPinPrompt,

    #[error(
        "wrong YubiKey: this identity was enrolled against serial {expected:08x}, the \
         connected card reports {found:08x}"
    )]
    WrongDevice { expected: u32, found: u32 },

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
        "PIV slot {slot:#04x} has touch policy `{policy}`: it will decrypt with no touch, so \
         the tap rageterm announces before every unwrap would be theatre. Regenerate the slot \
         with `ykman piv keys generate --algorithm X25519 --touch-policy always --pin-policy \
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

// ---------------------------------------------------------------------------
// Transport boundary
// ---------------------------------------------------------------------------

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
        Ok(Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]])))
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
            // Unambiguous in PIV, and worth a precise message: there is no key
            // in there to have a policy.
            apdu::SW_REFERENCE_NOT_FOUND | apdu::SW_FILE_NOT_FOUND => {
                Err(PivError::SlotEmpty { slot })
            }
            // "No such command" -- pre-5.3.0 firmware, or a PIV applet without
            // the Yubico extensions.
            apdu::SW_INS_NOT_SUPPORTED
            | apdu::SW_CLASS_NOT_SUPPORTED
            | apdu::SW_FUNCTION_NOT_SUPPORTED => Ok(TouchPolicy::Unavailable),
            // Cards vary in what they answer for an extension they do not
            // implement, so every other status word lands in the same place: we
            // did not learn the policy. Failing the whole operation here would
            // make rageterm unusable on cards it can otherwise drive perfectly
            // well; claiming a touch would be the lie this is fixing.
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
    pub fn ecdh_with_pin_retry(
        &mut self,
        algorithm: u8,
        slot: u8,
        peer_public: &[u8],
        prompt_pin: &dyn Fn() -> Result<String, PivError>,
    ) -> Result<Vec<u8>, PivError> {
        match self.ecdh(algorithm, slot, peer_public) {
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
            }
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EnrolledPiv {
    pub public_key: [u8; 32],
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
/// SubjectPublicKeyInfo) or a bare 64-character hex string.
pub fn parse_x25519_public_key(input: &str) -> Result<[u8; 32], PivError> {
    const SPKI_PREFIX: [u8; 12] = [
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
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let der = B64
            .decode(b64.as_bytes())
            .map_err(|e| PivError::PublicKey(format!("PEM body is not base64: {e}")))?;
        if der.len() != 44 || der[..12] != SPKI_PREFIX {
            return Err(PivError::PublicKey(format!(
                "expected a 44-byte X25519 SubjectPublicKeyInfo, got {} bytes with a \
                 different algorithm identifier. Export the slot with \
                 `ykman piv keys export <slot> -` after generating an X25519 key.",
                der.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&der[12..]);
        return Ok(out);
    }

    let hex_only: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if hex_only.len() == 64 && hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        hex::decode_to_slice(&hex_only, &mut out)
            .map_err(|e| PivError::PublicKey(format!("hex: {e}")))?;
        return Ok(out);
    }

    Err(PivError::PublicKey(
        "expected a PEM X25519 public key or 64 hex characters".into(),
    ))
}

/// Enroll against a real card, refusing any slot whose touch policy does not
/// actually gate on a finger. Equivalent to
/// [`real_enroll_allowing_untouched_slot`] with the override off, which is what
/// every normal caller wants.
pub fn real_enroll(slot: u8, claimed_public_key: [u8; 32]) -> Result<EnrolledPiv, PivError> {
    real_enroll_allowing_untouched_slot(slot, claimed_public_key, false)
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
    claimed_public_key: [u8; 32],
    allow_untouched_slot: bool,
) -> Result<EnrolledPiv, PivError> {
    let transport = crate::piv_pcsc::open_first_piv_card()?;
    let mut session = PivSession::new(transport);
    session.select()?;
    let serial = session.serial()?.unwrap_or(0);

    // Before the ECDH, so the announcement below can tell the truth about
    // whether the card is going to wait for a finger.
    let touch_policy = session.slot_touch_policy(slot)?;
    if !touch_policy.requires_touch() {
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

    let mut seed = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
    let challenge_secret = X25519Secret::from(seed);
    let challenge_public = X25519Public::from(&challenge_secret);

    announce_for_policy(
        &describe_device(serial, slot),
        "Proving the card holds the private key for the public key you supplied",
        touch_policy,
    );
    let device_share = session.ecdh_with_pin_retry(
        apdu::ALG_X25519,
        slot,
        challenge_public.as_bytes(),
        &prompt_pin,
    )?;

    let expected = challenge_secret.diffie_hellman(&X25519Public::from(claimed_public_key));
    if device_share.as_slice() != expected.as_bytes() {
        return Err(PivError::ProofOfPossessionFailed { slot });
    }

    let enrolled = EnrolledPiv {
        public_key: claimed_public_key,
        serial,
        slot,
        mock: false,
        touch_policy,
    };
    // Printed off the record rather than off the local, so the confirmation the
    // user reads is literally the value the identity will carry.
    ceremony::announce_step(&format!(
        "PIV slot {slot:#04x} enrolled with touch policy `{}`, read from the card rather \
         than assumed from the `ykman` line you ran.",
        enrolled.touch_policy
    ));
    Ok(enrolled)
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
    if policy.requires_touch() {
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

fn prompt_pin() -> Result<String, PivError> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(PivError::NoPinPrompt);
    }
    ceremony::announce_step("the PIV slot requires the PIN before it will do ECDH");
    rpassword::prompt_password("PIV PIN: ").map_err(PivError::Io)
}

// ---------------------------------------------------------------------------
// Use
// ---------------------------------------------------------------------------

fn real_ecdh(serial: u32, slot: u8, ephemeral_pub: &[u8; 32]) -> Result<[u8; 32], PivError> {
    let transport = crate::piv_pcsc::open_first_piv_card()?;
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

    // Asked again on every use rather than trusted from the enrollment record:
    // `ykman piv keys generate` can put a new key in the slot with a different
    // policy at any time, and the sentence about to be printed is a claim about
    // the card that is in the reader *now*.
    //
    // Deliberately NOT `?`. This is the unwrap path: the metadata query decides
    // only what sentence to print, and the user's data is already encrypted to
    // this slot. Propagating here would mean a card that answers GET METADATA
    // unexpectedly -- a mapped 6A88 on a slot that does hold a key, a non-Yubico
    // applet, anything the parser rejects -- locks its owner out of their own
    // secrets over a message. Enrollment is where strictness belongs, because
    // there the choice is still free; see `real_enroll`, which does use `?`.
    // `Unavailable` exists for precisely this, and announce_for_policy says
    // plainly that nothing was learned rather than implying a touch.
    let touch_policy = session
        .slot_touch_policy(slot)
        .unwrap_or(TouchPolicy::Unavailable);
    announce_for_policy(
        &describe_device(serial, slot),
        "Unwrapping this credential",
        touch_policy,
    );
    let share = session.ecdh_with_pin_retry(apdu::ALG_X25519, slot, ephemeral_pub, &prompt_pin)?;

    let mut out = [0u8; 32];
    out.copy_from_slice(&share);
    Ok(out)
}

pub struct PivIdentity {
    pub public_key: [u8; 32],
    pub serial: u32,
    pub slot: u8,
    pub label: String,
    /// Recorded at enrollment. Not read from the environment: flipping
    /// `RAGEWARDEN_MOCK_HARDWARE` cannot turn a real identity into a mock one
    /// or vice versa.
    pub mock: bool,
}

impl Identity for PivIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if stanza.tag != stanza_format::TAG_PIV_P256 {
            return Ok(None);
        }

        let stanza_tag = stanza_format::piv_p256_recipient_tag(stanza)
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        let our_tag = piv_recipient_tag(&self.public_key);
        if stanza_tag != our_tag {
            return Ok(None);
        }

        let eph_pub =
            piv_p256_ephemeral_pub(stanza).map_err(|e| IdentityError::Crypto(e.to_string()))?;

        let share = if self.mock {
            mock_ecdh_dispatch(self.serial, self.slot, &eph_pub)
                .map_err(|e| IdentityError::Hardware(e.to_string()))?
        } else {
            real_ecdh(self.serial, self.slot, &eph_pub)
                .map_err(|e| IdentityError::Hardware(e.to_string()))?
        };

        let fk = decrypt_piv_p256_with_ecdh_share(stanza, &share)
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        Ok(Some(fk))
    }

    fn display(&self) -> &str {
        &self.label
    }
}

// ---------------------------------------------------------------------------
// Software stand-in -- compiled out of every non-test, non-`mock-hardware` build
// ---------------------------------------------------------------------------

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
            public_key: *public.as_bytes(),
            serial,
            slot,
            mock: true,
            // Honest: the stand-in is a file, it has no finger to wait for.
            // Recording `Always` here would put the one lie this module just
            // removed back in, wearing a test hat.
            touch_policy: TouchPolicy::Never,
        })
    }

    pub fn ecdh(serial: u32, slot: u8, ephemeral_pub: &[u8; 32]) -> Result<[u8; 32], PivError> {
        let secret = read_secret(serial, slot)?;
        let shared = secret.diffie_hellman(&X25519Public::from(*ephemeral_pub));
        Ok(*shared.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw;
    use crate::tests_lock::ENV_LOCK;

    #[test]
    fn mock_identity_round_trip_is_labelled_as_mock() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::TempDir::new().unwrap();
        std::env::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        std::env::set_var(hw::MOCK_ENV, "1");

        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                std::env::remove_var(hw::MOCK_ENV);
                std::env::remove_var("RAGEWARDEN_CONFIG_DIR");
            }
        }
        let _cleanup = Cleanup;

        let enrolled = mock_enroll(0x95).expect("mock enroll");
        assert!(enrolled.mock);

        let mut file_key = [0u8; 16];
        for (i, b) in file_key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let stanza = ragewarden_core::stanza_format::encrypt_piv_p256_stanza(
            &file_key,
            &enrolled.public_key,
        );

        let id = PivIdentity {
            public_key: enrolled.public_key,
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
    fn a_mock_identity_refuses_to_decrypt_without_the_opt_in() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        std::env::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        std::env::set_var(hw::MOCK_ENV, "1");
        let enrolled = mock_enroll(0x95).expect("mock enroll");
        std::env::remove_var(hw::MOCK_ENV);

        let mut file_key = [0u8; 16];
        file_key[0] = 9;
        let stanza = ragewarden_core::stanza_format::encrypt_piv_p256_stanza(
            &file_key,
            &enrolled.public_key,
        );
        let id = PivIdentity {
            public_key: enrolled.public_key,
            serial: enrolled.serial,
            slot: enrolled.slot,
            label: hw::mock_label("mock-piv"),
            mock: true,
        };
        let err = id.try_unwrap_stanza(&stanza).unwrap_err();
        std::env::remove_var("RAGEWARDEN_CONFIG_DIR");
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
        // Pre-5.3.0 answers 6D00. The failure this guards against is treating
        // "the card did not say" as "the card said always".
        for sw in [
            vec![0x6D, 0x00],
            vec![0x6E, 0x00],
            vec![0x6A, 0x81],
            // Well-formed status, garbage body.
            vec![0x01, 0x01, 0xE1, 0x90, 0x00],
        ] {
            let policy = policy_for(sw).unwrap();
            assert_eq!(policy, TouchPolicy::Unavailable);
            assert!(!policy.requires_touch());
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
        assert_eq!(parse_x25519_public_key(&hex).unwrap(), [0xAAu8; 32]);

        let mut der = vec![
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(&[0x11u8; 32]);
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(&der)
        );
        assert_eq!(parse_x25519_public_key(&pem).unwrap(), [0x11u8; 32]);

        assert!(parse_x25519_public_key("not a key").is_err());
        assert!(parse_x25519_public_key(&"a".repeat(62)).is_err());

        // An Ed25519 SPKI has the same length but a different OID.
        let mut ed = vec![
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        ed.extend_from_slice(&[0x22u8; 32]);
        let ed_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(&ed)
        );
        assert!(parse_x25519_public_key(&ed_pem).is_err());
    }
}
