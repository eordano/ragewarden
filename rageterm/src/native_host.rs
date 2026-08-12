use std::io::{self, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ragewarden_core::Stanza;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::commands;
use crate::identities::{Identities, IdentityKind};
use crate::piv_apdu::{self as apdu, TouchPolicy};

const MAX_MESSAGE_LEN: u32 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum NativeHostError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame: {0}")]
    Frame(String),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("identity build: {0}")]
    Identities(String),

    #[error("{0}")]
    ConsentUnavailable(String),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    UnwrapStanza {
        stanza: WireStanza,
        #[serde(default)]
        context: RequestContext,
    },
    /// "What can you serve, and can any of it prove a touch?" -- answered
    /// without opening a credential, without a notification and without asking
    /// the device for anything that blocks. The browser calls this *before* it
    /// commits to a hardware unlock so it can fail closed with a useful
    /// sentence instead of after a round trip that raised a desktop
    /// notification and demanded a tap nobody could honour.
    Probe {},
}

#[derive(Debug, Default, Deserialize)]
pub struct RequestContext {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct WireStanza {
    pub tag: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub body: String,
}

/// Which device class the stanza is addressed to.
///
/// `Software` is not in the browser-side contract on purpose: the extension
/// only knows `piv-p256` and `fido2-hmac`, so a reply carrying `software` is
/// rejected by a consumer that has never heard of it. That is the intended
/// outcome. Calling a disk read `piv-p256` because the *stanza* said so would
/// be exactly the optimistic label this whole block exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TapBackend {
    #[serde(rename = "piv-p256")]
    PivP256,
    #[serde(rename = "fido2-hmac")]
    Fido2Hmac,
    #[serde(rename = "software")]
    Software,
}

impl TapBackend {
    /// From the stanza tag, not from whatever answered it. `webauthn-prf-v1`
    /// lands in `Software` deliberately: rageterm enrolls no identity for it
    /// (the browser opens those itself with a real WebAuthn assertion), so a
    /// `webauthn-prf-v1` reply from this host could only ever have come from
    /// somewhere other than a FIDO2 device.
    pub fn for_tag(tag: &str) -> Self {
        use ragewarden_core::stanza_format::{TAG_FIDO2_HMAC, TAG_PIV_P256};
        if tag == TAG_PIV_P256 {
            TapBackend::PivP256
        } else if tag == TAG_FIDO2_HMAC {
            TapBackend::Fido2Hmac
        } else {
            TapBackend::Software
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TapBackend::PivP256 => "piv-p256",
            TapBackend::Fido2Hmac => "fido2-hmac",
            TapBackend::Software => "software",
        }
    }
}

/// The evidence that rides alongside `file_key`.
///
/// Every field is something the host observed. `touched` in particular is never
/// set because a ceremony was *announced* or because an identity is nominally a
/// hardware one -- only because the card's own slot metadata said a touch was
/// required and the operation that needed it then succeeded.
#[derive(Debug, Clone, Serialize)]
pub struct TapAttestation {
    pub backend: TapBackend,
    pub touched: bool,
    pub verified: bool,
    pub device: String,
    pub slot: String,
    pub at: u64,
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    Ok {
        ok: bool,
        file_key: String,
        tap: TapAttestation,
    },
    Probe(ProbeReport),
    Err {
        ok: bool,
        error: String,
    },
}

impl Response {
    pub fn ok(file_key_b64: String, tap: TapAttestation) -> Self {
        Response::Ok {
            ok: true,
            file_key: file_key_b64,
            tap,
        }
    }
    pub fn err(error: String) -> Self {
        Response::Err { ok: false, error }
    }
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, NativeHostError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(NativeHostError::Io(e)),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE_LEN {
        return Err(NativeHostError::Frame(format!(
            "message length {len} exceeds maximum {MAX_MESSAGE_LEN}"
        )));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), NativeHostError> {
    let len = payload.len();
    if len > MAX_MESSAGE_LEN as usize {
        return Err(NativeHostError::Frame(format!(
            "outbound message length {len} exceeds maximum {MAX_MESSAGE_LEN}"
        )));
    }
    let len_le = (len as u32).to_le_bytes();
    writer.write_all(&len_le)?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

pub fn run() -> Result<(), NativeHostError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    loop {
        let Some(payload) = read_frame(&mut reader)? else {
            return Ok(());
        };
        let response_json = handle_payload(&payload);
        write_frame(&mut writer, response_json.as_bytes())?;
    }
}

fn handle_payload(payload: &[u8]) -> String {
    let response = match serde_json::from_slice::<Request>(payload) {
        Ok(req) => dispatch(req),
        Err(e) => Response::err(format!("malformed request: {e}")),
    };
    serde_json::to_string(&response)
        .unwrap_or_else(|e| format!("{{\"ok\":false,\"error\":\"serialize: {e}\"}}"))
}

fn dispatch(req: Request) -> Response {
    match req {
        Request::UnwrapStanza { stanza, context } => match unwrap_stanza(stanza, &context) {
            Ok((file_key_b64, tap)) => Response::ok(file_key_b64, tap),
            Err(e) => Response::err(e.to_string()),
        },
        Request::Probe {} => Response::Probe(probe()),
    }
}

/// Stanza tags whose unwrap is gated by a physical device.
///
/// Anything else -- the `identity.age` software key, the OS keyring key, paper
/// recovery -- unwraps with no interaction at all. Served over native messaging
/// that meant any local process able to reach the host could pull file keys for
/// the whole vault in a loop, unattended (`DESIGN.md` §6 assumed a tap that did
/// not exist). The host now refuses those tags.
fn tag_is_hardware_gated(tag: &str) -> bool {
    use ragewarden_core::stanza_format::{TAG_FIDO2_HMAC, TAG_PIV_P256, TAG_WEBAUTHN_PRF_V1};
    matches!(tag, t if t == TAG_PIV_P256 || t == TAG_FIDO2_HMAC || t == TAG_WEBAUTHN_PRF_V1)
}

/// Escape hatch for a deliberately software-only installation. Off by default;
/// the operator has to set it in the environment the browser launches the host
/// with, which is not something a page or a content script can do.
const ALLOW_SOFTWARE_ENV: &str = "RAGEWARDEN_NATIVE_HOST_ALLOW_SOFTWARE";

fn software_unwrap_allowed() -> bool {
    matches!(std::env::var(ALLOW_SOFTWARE_ENV).as_deref(), Ok("1"))
}

fn unwrap_stanza(
    wire: WireStanza,
    context: &RequestContext,
) -> Result<(String, TapAttestation), NativeHostError> {
    let body = B64.decode(wire.body.as_bytes())?;
    let stanza = Stanza {
        tag: wire.tag,
        args: wire.args,
        body,
    };

    // `mock_enabled()` turns every PIV / FIDO2 ceremony in this process into a
    // file read, so the hardware allowance above would be handing out file keys
    // with no touch after all. Same escape hatch, deliberately the same one: an
    // operator who sets both env vars knows there is no device.
    if crate::hw::mock_enabled() && !software_unwrap_allowed() {
        return Err(NativeHostError::ConsentUnavailable(format!(
            "refusing to serve native-messaging unwraps while {}=1: the PIV / FIDO2 \
             ceremonies are simulated in software, so nothing would block on a \
             physical touch. Unset it, or set {ALLOW_SOFTWARE_ENV}=1 as well to \
             accept unattended unwraps deliberately.",
            crate::hw::MOCK_ENV
        )));
    }

    if !tag_is_hardware_gated(&stanza.tag) && !software_unwrap_allowed() {
        return Err(NativeHostError::ConsentUnavailable(format!(
            "refusing to unwrap a `{}` stanza over native messaging: that stanza kind \
             decrypts with a key on disk, so serving it here would hand file keys to any \
             local process with no user action. Protect the item with a hardware \
             recipient (`rageterm reencrypt <item>` after `enroll-yubikey` / `enroll-fido2`), \
             or set {ALLOW_SOFTWARE_ENV}=1 in the browser's environment to accept that \
             risk deliberately.",
            stanza.tag
        )));
    }

    // Read the device's own account of what it is about to do, *before* the
    // ceremony text and before the unwrap. GET METADATA needs neither PIN nor
    // touch, so this cannot itself be mistaken for the gate; it is the only
    // honest source for "is a finger genuinely part of this?", and reading it
    // afterwards would let a card swapped mid-operation write its own receipt.
    let evidence = DeviceEvidence::gather(&stanza);

    // Advisory only, and only for the hardware path: the consent is the touch
    // that `PivIdentity` / `FidoIdentity` block on next. A failed notification
    // used to be discarded silently while the unwrap proceeded regardless; now
    // the failure is reported on stderr (which the browser captures) and the
    // gate that matters is unaffected because it is on the device.
    let _ceremony = crate::ceremony::set(crate::ceremony::Ceremony::new(
        pretty_action(if context.action.is_empty() {
            "use"
        } else {
            &context.action
        }),
        "a credential",
        if context.domain.is_empty() {
            "the browser extension"
        } else {
            &context.domain
        },
    ));
    notify_action(context);

    // Belt and braces with the tag check above: even for a hardware-gated tag,
    // only device-backed identities are offered, so a software or stand-in key
    // cannot answer a native-messaging request unless the operator opted in.
    let policy = if software_unwrap_allowed() {
        crate::consent::IdentityPolicy::SoftwareAllowed
    } else {
        crate::consent::IdentityPolicy::HardwareOnly
    };
    let identities = commands::build_identity_list_for(policy)
        .map_err(|e| NativeHostError::Identities(e.to_string()))?;

    for id in &identities {
        let started = Instant::now();
        match id.try_unwrap_stanza(&stanza) {
            Ok(Some(file_key)) => {
                let tap = evidence.seal(started.elapsed(), id.display());
                if !tap.touched {
                    // Visible in the browser's native-host stderr capture. A
                    // file key leaving here with no proof of a touch is not an
                    // error -- the operator may have asked for exactly that --
                    // but it should never be silent.
                    eprintln!(
                        "rageterm native-host: served a `{}` file key with `touched: false`. \
                         Nothing in this reply evidences a physical touch; a caller that \
                         requires one must refuse it.",
                        tap.backend.as_str()
                    );
                }
                return Ok((B64.encode(&file_key[..]), tap));
            }
            Ok(None) => continue,
            Err(e) => {
                return Err(NativeHostError::Identities(format!(
                    "identity `{}` failed: {e}",
                    id.display()
                )));
            }
        }
    }

    Err(NativeHostError::Identities(
        "no enrolled identity matched the stanza".into(),
    ))
}

// ---------------------------------------------------------------------------
// Tap attestation
// ---------------------------------------------------------------------------

/// YubiKey PIV PIN-policy bytes. `piv_apdu` keeps `SlotMetadata::pin_policy`
/// raw because nothing there needed to interpret it; the meanings are Yubico's
/// and match the touch-policy encoding one for one.
const PIN_POLICY_DEFAULT: u8 = 0x00;
const PIN_POLICY_NEVER: u8 = 0x01;
const PIN_POLICY_ONCE: u8 = 0x02;
const PIN_POLICY_ALWAYS: u8 = 0x03;

/// How long a `cached`-policy operation must block before the host will call it
/// a touch.
///
/// `TouchPolicy::Cached` means one touch covers roughly the next 15 seconds, so
/// What the host learned about the device *before* it asked for the key.
///
/// Constructed only by [`DeviceEvidence::gather`]; the only way to turn one into
/// a `TapAttestation` is [`DeviceEvidence::seal`], which takes how long the
/// unwrap actually blocked. There is no constructor that produces
/// `touched: true` out of nothing.
#[derive(Debug, Clone)]
struct DeviceEvidence {
    backend: TapBackend,
    device: String,
    slot: String,
    /// `None` when the card was not reached, did not answer GET METADATA, or
    /// was never consulted because the path is a software one.
    touch_policy: Option<TouchPolicy>,
    pin_policy: Option<u8>,
    /// The key material can come from a file: the `mock` stand-in, the software
    /// escape hatch, or an identity that is not device-backed at all. Nails
    /// `touched` and `verified` to false regardless of anything else here.
    software: bool,
}

impl DeviceEvidence {
    fn software_only(backend: TapBackend) -> Self {
        Self {
            backend,
            device: String::new(),
            slot: String::new(),
            touch_policy: None,
            pin_policy: None,
            software: true,
        }
    }

    fn gather(stanza: &Stanza) -> Self {
        let backend = TapBackend::for_tag(&stanza.tag);
        // The operator opted into unattended unwraps. Whatever answers, this
        // host cannot vouch for a touch, so the card is not even consulted --
        // but the identity is still named, because a caller comparing this
        // reply with a hardware one should see the same fields and differ only
        // where it matters.
        let forced_software = software_unwrap_allowed();

        match backend {
            TapBackend::PivP256 => Self::gather_piv(stanza, forced_software),
            TapBackend::Fido2Hmac => Self::gather_fido(stanza),
            TapBackend::Software => Self::software_only(backend),
        }
    }

    fn gather_piv(stanza: &Stanza, forced_software: bool) -> Self {
        let Some(entry) = find_piv_entry(stanza) else {
            return Self::software_only(TapBackend::PivP256);
        };

        let mut ev = Self {
            backend: TapBackend::PivP256,
            // A stand-in has no serial worth printing; its label is the thing
            // that says NOT REAL HARDWARE, so that is what goes on the wire.
            device: if entry.mock || entry.serial == 0 {
                entry.label.clone()
            } else {
                entry.serial.to_string()
            },
            slot: format_slot(entry.slot),
            touch_policy: None,
            pin_policy: None,
            // A mock identity reads a file in the config directory: a
            // `piv-p256` stanza opened by no card at all.
            software: forced_software || entry.mock,
        };
        if ev.software {
            return ev;
        }

        // Failure here is not fatal: the unwrap can still succeed on a card
        // that will not describe its own slot. It just cannot be attested, and
        // `touch_policy: None` says exactly that.
        match read_piv_slot_facts(entry.slot) {
            Ok(facts) => {
                if facts.serial != 0 {
                    ev.device = facts.serial.to_string();
                }
                ev.touch_policy = Some(facts.touch_policy);
                ev.pin_policy = facts.pin_policy;
            }
            Err(e) => {
                eprintln!(
                    "rageterm native-host: could not read the touch policy for PIV slot {} \
                     ({e}). The unwrap may still succeed, but this reply will report \
                     `touched: false` because nothing proved a touch was required.",
                    ev.slot
                );
            }
        }
        ev
    }

    /// FIDO2 carries its proof in the assertion's authenticatorData UP flag,
    /// and `fido_ctap::hmac_secret` never looks at it -- `Fido2Device` hands back
    /// only the 32-byte hmac-secret output, so by the time the key reaches this
    /// file the flag has been dropped on the floor. Rather than infer a touch
    /// from "the authenticator answered", this reports what it can prove, which
    /// is nothing -- so every `fido2-hmac` reply carries `touched: false` and a
    /// caller that requires a tap will refuse it.
    ///
    /// Making FIDO2 attestable is a change one layer down, not here:
    /// `Fido2Device::hmac_secret` has to return the assertion's UP/UV flags
    /// alongside the PRF (`ctap_hid_fido2`'s `Assertion` carries them), and
    /// `FidoIdentity::try_unwrap_stanza` has to carry them back out. Until then
    /// this stays honest by staying negative.
    fn gather_fido(stanza: &Stanza) -> Self {
        let mut ev = Self::software_only(TapBackend::Fido2Hmac);
        if let Some(entry) = find_fido_entry(stanza) {
            ev.device = entry.label;
            ev.slot = entry.credential_id_b64;
        }
        ev
    }

    // `_blocked_for` is received and deliberately ignored. It stays in the
    // signature so every caller keeps handing the elapsed time over -- the
    // comment on the Cached arm below is the reason it must never be read.
    fn seal(&self, _blocked_for: Duration, answered_by: &str) -> TapAttestation {
        let touched = !self.software
            && match self.touch_policy {
                // The card will not do a private-key operation on this slot
                // without a finger, and it just did one.
                Some(TouchPolicy::Always) => true,
                // One touch covers ~15s, so success alone proves nothing -- and
                // neither does elapsed time. A duration threshold was tried here
                // (`blocked_for >= CACHED_TOUCH_MIN_BLOCK`) and removed: it can
                // only ever be wrong in the UNSAFE direction. A card that is
                // slow for any other reason -- a busy reader, a contended PC/SC
                // stack, a laptop resuming -- answers late with no finger
                // involved and would be attested as touched. Every other arm of
                // this match errs toward refusing an unlock; this one errs
                // toward releasing a secret, which is not a trade this file gets
                // to make.
                //
                // So `cached` is not attestable, and only `always` is. A user
                // who wants browser unlocks from a PIV slot should generate it
                // with `--touch-policy always`; the refusal names that.
                Some(TouchPolicy::Cached) => false,
                Some(TouchPolicy::Never)
                | Some(TouchPolicy::Default)
                | Some(TouchPolicy::Unknown(_))
                | Some(TouchPolicy::Unavailable)
                | None => false,
            };
        // The card will not do a private-key operation on a PIN-gated slot
        // until a VERIFY has succeeded, so an unwrap that completed under
        // `once` or `always` is proof the PIN was entered. `default` and
        // `never` prove the opposite; an unrecognised byte proves nothing.
        let verified = !self.software
            && match self.pin_policy {
                Some(PIN_POLICY_ONCE) | Some(PIN_POLICY_ALWAYS) => true,
                Some(PIN_POLICY_DEFAULT) | Some(PIN_POLICY_NEVER) => false,
                Some(_) | None => false,
            };
        TapAttestation {
            backend: self.backend,
            touched,
            verified,
            device: if self.device.is_empty() {
                answered_by.to_string()
            } else {
                self.device.clone()
            },
            slot: self.slot.clone(),
            at: unix_millis(),
        }
    }
}

fn format_slot(slot: u8) -> String {
    format!("{slot:#04x}")
}

struct PivRegistryEntry {
    serial: u32,
    slot: u8,
    mock: bool,
    label: String,
}

/// Which enrolled PIV identity this stanza is addressed to, by the *same*
/// criterion `PivIdentity::try_unwrap_stanza` uses (the 4-byte recipient tag
/// derived from the slot's public key). Matching on anything looser -- the
/// label, "the first PIV entry" -- would let the attestation describe a
/// different slot from the one that answered.
fn find_piv_entry(stanza: &Stanza) -> Option<PivRegistryEntry> {
    use ragewarden_core::stanza_format::{piv_p256_recipient_tag, piv_recipient_tag};
    let want = piv_p256_recipient_tag(stanza).ok()?;
    let registry = Identities::load().ok()?;
    let found = registry.iter_chronological().find_map(|entry| {
        let IdentityKind::YubiKeyPiv {
            public_key_hex,
            serial,
            slot,
            mock,
        } = &entry.kind
        else {
            return None;
        };
        let mut pubkey = [0u8; 32];
        hex::decode_to_slice(public_key_hex, &mut pubkey).ok()?;
        (piv_recipient_tag(&pubkey) == want).then(|| PivRegistryEntry {
            serial: *serial,
            slot: *slot,
            mock: *mock,
            label: entry.label.clone(),
        })
    });
    found
}

struct FidoRegistryEntry {
    label: String,
    credential_id_b64: String,
}

fn find_fido_entry(stanza: &Stanza) -> Option<FidoRegistryEntry> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use ragewarden_core::stanza_format::fido2_hmac_credential_id;
    let want = fido2_hmac_credential_id(stanza).ok()?;
    let registry = Identities::load().ok()?;
    let found = registry.iter_chronological().find_map(|entry| {
        let IdentityKind::Fido2HmacSecret {
            credential_id_b64, ..
        } = &entry.kind
        else {
            return None;
        };
        let id = B64URL.decode(credential_id_b64.as_bytes()).ok()?;
        (id == want).then(|| FidoRegistryEntry {
            label: entry.label.clone(),
            credential_id_b64: credential_id_b64.clone(),
        })
    });
    found
}

struct PivSlotFacts {
    serial: u32,
    touch_policy: TouchPolicy,
    pin_policy: Option<u8>,
}

/// SELECT, GET SERIAL, GET METADATA. No PIN, no touch, no private-key
/// operation: this is a description of the slot, not a use of it.
///
/// `PivSession::slot_touch_policy` would cover the touch half, but the PIN
/// policy shares the same two-byte element and `PivSession` exposes no way to
/// read it, so the three exchanges are issued here against the transport
/// directly.
fn read_piv_slot_facts(slot: u8) -> Result<PivSlotFacts, String> {
    let mut transport = crate::piv_pcsc::open_first_piv_card().map_err(|e| e.to_string())?;

    let (_, sw) = card_exchange(&mut transport, &apdu::select_piv())?;
    if sw != apdu::SW_OK {
        return Err(format!("the card refused PIV SELECT (SW={sw:#06x})"));
    }

    let serial = match card_exchange(&mut transport, &apdu::get_serial()) {
        Ok((body, apdu::SW_OK)) if body.len() >= 4 => {
            u32::from_be_bytes([body[0], body[1], body[2], body[3]])
        }
        _ => 0,
    };

    let (body, sw) = card_exchange(&mut transport, &apdu::get_slot_metadata(slot))?;
    let meta = if sw == apdu::SW_OK {
        apdu::parse_slot_metadata(&body).ok()
    } else {
        None
    };

    Ok(PivSlotFacts {
        serial,
        touch_policy: meta
            .map(|m| m.touch_policy)
            .unwrap_or(TouchPolicy::Unavailable),
        pin_policy: meta.map(|m| m.pin_policy),
    })
}

fn card_exchange(
    transport: &mut dyn crate::piv::CardTransport,
    command: &[u8],
) -> Result<(Vec<u8>, u16), String> {
    let response = transport.transmit(command).map_err(|e| e.to_string())?;
    let (body, sw) = apdu::split_sw(&response).map_err(|e| e.to_string())?;
    let mut acc = body.to_vec();
    let mut sw = sw;
    while let Some(more) = apdu::more_data_available(sw) {
        let next = transport
            .transmit(&apdu::get_response(more))
            .map_err(|e| e.to_string())?;
        let (body, next_sw) = apdu::split_sw(&next).map_err(|e| e.to_string())?;
        acc.extend_from_slice(body);
        sw = next_sw;
    }
    Ok((acc, sw))
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct BackendReport {
    pub backend: TapBackend,
    /// An identity of this kind exists in `identities.json`.
    pub enrolled: bool,
    /// The host believes it could complete an unwrap for this backend now.
    pub available: bool,
    /// The host can produce `tap.touched == true` for this backend. The only
    /// field a caller deciding whether to offer a hardware unlock should read.
    pub can_attest_touch: bool,
    pub device: String,
    pub slot: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub ok: bool,
    /// Bumped when the wire shape changes. 1 was `{ok, file_key}` with no tap.
    pub protocol: u32,
    pub host: String,
    pub version: String,
    pub backends: Vec<BackendReport>,
    /// True when at least one backend can prove a touch. False here means every
    /// unwrap this host serves will come back `touched: false`, so a caller that
    /// requires a real tap should refuse *now*, before a notification is raised
    /// and a finger is asked for.
    pub can_attest_touch: bool,
    /// `RAGEWARDEN_NATIVE_HOST_ALLOW_SOFTWARE=1`: this host will hand out file
    /// keys with no device involved at all.
    pub software_fallback: bool,
    /// `RAGEWARDEN_MOCK_HARDWARE=1` and this build honours it: every "hardware"
    /// ceremony in this process is a file read.
    pub mock_hardware: bool,
}

fn probe() -> ProbeReport {
    let software_fallback = software_unwrap_allowed();
    let mock_hardware = crate::hw::mock_enabled();
    let registry = Identities::load().ok().unwrap_or_default();

    let backends = vec![
        probe_piv(&registry, software_fallback, mock_hardware),
        probe_fido(&registry, software_fallback, mock_hardware),
    ];
    let can_attest_touch = backends.iter().any(|b| b.can_attest_touch);

    ProbeReport {
        ok: true,
        protocol: 2,
        host: crate::install_native_host::HOST_NAME.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        backends,
        can_attest_touch,
        software_fallback,
        mock_hardware,
    }
}

fn probe_piv(registry: &Identities, software_fallback: bool, mock_hardware: bool) -> BackendReport {
    let mut report = BackendReport {
        backend: TapBackend::PivP256,
        enrolled: false,
        available: false,
        can_attest_touch: false,
        device: String::new(),
        slot: String::new(),
        detail: String::new(),
    };

    let entry = registry.iter_chronological().find_map(|e| match &e.kind {
        IdentityKind::YubiKeyPiv {
            serial, slot, mock, ..
        } => Some((e.label.clone(), *serial, *slot, *mock)),
        _ => None,
    });

    let Some((label, serial, slot, mock)) = entry else {
        report.detail = "no PIV identity is enrolled (`rageterm enroll-yubikey`)".into();
        return report;
    };
    report.enrolled = true;
    report.slot = format_slot(slot);
    report.device = if serial != 0 {
        serial.to_string()
    } else {
        label
    };

    if mock {
        report.detail =
            "the enrolled PIV identity is a software stand-in: its ECDH is a file in the \
             config directory, so there is no card and no touch to attest"
                .into();
        return report;
    }
    if mock_hardware {
        report.detail = format!(
            "{}=1 is set, so every PIV ceremony in this process is simulated in software \
             and no touch can be attested",
            crate::hw::MOCK_ENV
        );
        return report;
    }
    if software_fallback {
        report.available = true;
        report.detail = format!(
            "{ALLOW_SOFTWARE_ENV}=1 is set: this host will serve unattended unwraps, so \
             every reply reports `touched: false` whatever the card says"
        );
        return report;
    }

    match read_piv_slot_facts(slot) {
        Ok(facts) => {
            if facts.serial != 0 {
                report.device = facts.serial.to_string();
            }
            report.available = true;
            report.can_attest_touch = facts.touch_policy.requires_touch();
            report.detail = format!("slot touch policy is `{}`", facts.touch_policy);
        }
        Err(e) => {
            report.detail = format!("the card could not be read: {e}");
        }
    }
    report
}

fn probe_fido(
    registry: &Identities,
    software_fallback: bool,
    mock_hardware: bool,
) -> BackendReport {
    let mut report = BackendReport {
        backend: TapBackend::Fido2Hmac,
        enrolled: false,
        available: false,
        // Never true, and not because no key is plugged in. See
        // `DeviceEvidence::gather_fido`.
        can_attest_touch: false,
        device: String::new(),
        slot: String::new(),
        detail: String::new(),
    };

    let entry = registry.iter_chronological().find_map(|e| match &e.kind {
        IdentityKind::Fido2HmacSecret {
            credential_id_b64,
            mock,
            ..
        } => Some((e.label.clone(), credential_id_b64.clone(), *mock)),
        _ => None,
    });

    let Some((label, credential_id_b64, mock)) = entry else {
        report.detail =
            "no FIDO2 hmac-secret identity is enrolled (`rageterm enroll-fido2`)".into();
        return report;
    };
    report.enrolled = true;
    report.device = label;
    report.slot = credential_id_b64;
    report.available = !(mock || mock_hardware);
    report.detail = if mock {
        "the enrolled FIDO2 credential is a software stand-in: the PRF comes from a file \
         in the config directory, not from an authenticator"
            .into()
    } else if mock_hardware {
        format!(
            "{}=1 is set, so the PRF comes from a file in the config directory rather \
             than from an authenticator",
            crate::hw::MOCK_ENV
        )
    } else if software_fallback {
        format!(
            "{ALLOW_SOFTWARE_ENV}=1 is set, and separately this host does not read the \
             assertion's user-presence flag, so no FIDO2 unwrap can be attested"
        )
    } else {
        "this host does not read the assertion's authenticatorData user-presence flag \
         (fido_ctap::hmac_secret returns only the hmac-secret output), so a FIDO2 unwrap \
         cannot be distinguished from one that skipped the touch. Every FIDO2 reply \
         reports `touched: false`."
            .into()
    };
    report
}

fn notify_action(context: &RequestContext) {
    let summary = action_prompt(context);
    let body = "Touch your security key to authorize.";
    if let Err(e) = notify_rust::Notification::new()
        .summary(&summary)
        .body(body)
        .appname("rageterm")
        .show()
    {
        eprintln!(
            "rageterm native-host: could not show the desktop notification ({e}). \
             Proceeding: the notification is advisory, and the request still cannot \
             complete without the physical touch."
        );
    }
}

pub fn action_prompt(context: &RequestContext) -> String {
    let action = if context.action.is_empty() {
        "Use credential"
    } else {
        context.action.as_str()
    };
    if context.domain.is_empty() {
        format!("{action}?")
    } else {
        let pretty = pretty_action(action);
        format!("{pretty} into {}?", context.domain)
    }
}

fn pretty_action(action: &str) -> &str {
    match action {
        "autofill" => "Autofill",
        "copy" => "Copy",
        "reveal" => "Reveal",
        "fill" => "Fill",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip_little_endian() {
        let mut out = Vec::new();
        write_frame(&mut out, b"hello").unwrap();
        assert_eq!(&out[..4], &5u32.to_le_bytes());
        assert_eq!(&out[4..], b"hello");

        let mut cur = Cursor::new(out);
        let read = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(read, b"hello");
    }

    #[test]
    fn read_frame_eof_returns_none() {
        let buf: Vec<u8> = vec![];
        let mut cur = Cursor::new(buf);
        let res = read_frame(&mut cur).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn read_frame_rejects_oversize_length() {
        let mut buf = Vec::new();
        let oversize = (MAX_MESSAGE_LEN + 1).to_le_bytes();
        buf.extend_from_slice(&oversize);
        let mut cur = Cursor::new(buf);
        let err = read_frame(&mut cur).unwrap_err();
        assert!(matches!(err, NativeHostError::Frame(_)));
    }

    #[test]
    fn read_frame_short_payload_errors() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(b"only5");
        let mut cur = Cursor::new(buf);
        let err = read_frame(&mut cur).unwrap_err();
        assert!(matches!(err, NativeHostError::Io(_)));
    }

    #[test]
    fn handle_payload_returns_error_for_unknown_method() {
        let payload = br#"{"method":"does_not_exist"}"#;
        let resp = handle_payload(payload);
        assert!(resp.contains("\"ok\":false"));
        assert!(resp.to_lowercase().contains("malformed"));
    }

    #[test]
    fn handle_payload_returns_error_for_invalid_json() {
        let payload = b"not even json";
        let resp = handle_payload(payload);
        assert!(resp.contains("\"ok\":false"));
    }

    #[test]
    fn action_prompt_includes_domain_and_action() {
        let ctx = RequestContext {
            action: "autofill".into(),
            domain: "github.com".into(),
        };
        let s = action_prompt(&ctx);
        assert!(s.contains("Autofill"));
        assert!(s.contains("github.com"));
    }

    #[test]
    fn action_prompt_handles_missing_context() {
        let ctx = RequestContext::default();
        let s = action_prompt(&ctx);
        assert_eq!(s, "Use credential?");
    }

    #[test]
    fn unwrap_stanza_request_parses() {
        let payload = br#"{
            "method": "unwrap_stanza",
            "stanza": { "tag": "piv-p256", "args": ["a","b"], "body": "AAAA" },
            "context": { "action": "autofill", "domain": "example.com" }
        }"#;
        let req: Request = serde_json::from_slice(payload).unwrap();
        match req {
            Request::UnwrapStanza { stanza, context } => {
                assert_eq!(stanza.tag, "piv-p256");
                assert_eq!(stanza.args, vec!["a", "b"]);
                assert_eq!(stanza.body, "AAAA");
                assert_eq!(context.action, "autofill");
                assert_eq!(context.domain, "example.com");
            }
            other => panic!("expected an unwrap_stanza request, got {other:?}"),
        }
    }

    #[test]
    fn hardware_gated_tags_are_exactly_the_device_backed_ones() {
        assert!(tag_is_hardware_gated("piv-p256"));
        assert!(tag_is_hardware_gated("fido2-hmac"));
        assert!(tag_is_hardware_gated("webauthn-prf-v1"));
        assert!(!tag_is_hardware_gated("X25519"));
        assert!(!tag_is_hardware_gated("scrypt"));
        assert!(!tag_is_hardware_gated("ragedroid-keystore-v1"));
    }

    /// Holds `ENV_LOCK` and clears both variables `unwrap_stanza` reads.
    ///
    /// Without the lock this test failed on roughly half of parallel `cargo
    /// test` runs: `piv::tests`, `fido::tests` and `tests::enroll_yubikey_mock_*`
    /// set `RAGEWARDEN_MOCK_HARDWARE=1` on the same process, and `unwrap_stanza`
    /// checks that variable *before* the tag check, so the response came back as
    /// the mock-hardware refusal instead of the software-stanza refusal.
    #[test]
    fn a_software_stanza_is_refused_without_the_explicit_opt_in() {
        let _guard = crate::tests_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev_allow = std::env::var_os(ALLOW_SOFTWARE_ENV);
        let prev_mock = std::env::var_os(crate::hw::MOCK_ENV);
        std::env::remove_var(ALLOW_SOFTWARE_ENV);
        std::env::remove_var(crate::hw::MOCK_ENV);

        struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var(ALLOW_SOFTWARE_ENV, v),
                    None => std::env::remove_var(ALLOW_SOFTWARE_ENV),
                }
                match self.1.take() {
                    Some(v) => std::env::set_var(crate::hw::MOCK_ENV, v),
                    None => std::env::remove_var(crate::hw::MOCK_ENV),
                }
            }
        }
        let _restore = Restore(prev_allow, prev_mock);

        let payload = br#"{
            "method": "unwrap_stanza",
            "stanza": { "tag": "X25519", "args": ["a"], "body": "AAAA" },
            "context": { "action": "autofill", "domain": "example.com" }
        }"#;
        let resp = handle_payload(payload);
        assert!(resp.contains("\"ok\":false"), "{resp}");
        assert!(resp.contains("refusing to unwrap"), "{resp}");
    }

    fn hardware_evidence(touch: TouchPolicy, pin: Option<u8>) -> DeviceEvidence {
        DeviceEvidence {
            backend: TapBackend::PivP256,
            device: "12345678".into(),
            slot: "0x9d".into(),
            touch_policy: Some(touch),
            pin_policy: pin,
            software: false,
        }
    }

    /// The rule the whole contract rests on: only a slot whose policy the card
    /// itself reported as touch-gating may ever produce `touched: true`.
    #[test]
    fn only_an_always_slot_can_report_a_touch() {
        let long = Duration::from_secs(3);
        let instant = Duration::from_millis(5);

        assert!(hardware_evidence(TouchPolicy::Always, None)
            .seal(instant, "x")
            .touched);
        // `cached` is NOT attestable at any duration. A slow answer proves a
        // slow reader, not a finger, and guessing from elapsed time is the one
        // rule here that could be wrong in the direction of releasing a secret.
        assert!(!hardware_evidence(TouchPolicy::Cached, None)
            .seal(long, "x")
            .touched);
        assert!(!hardware_evidence(TouchPolicy::Cached, None)
            .seal(instant, "x")
            .touched);

        for policy in [
            TouchPolicy::Cached,
            TouchPolicy::Never,
            TouchPolicy::Default,
            TouchPolicy::Unknown(0x7F),
            TouchPolicy::Unavailable,
        ] {
            assert!(
                !hardware_evidence(policy, None).seal(long, "x").touched,
                "{policy} must never be reported as a touch"
            );
        }

        // The card was never reached at all.
        let mut unread = hardware_evidence(TouchPolicy::Always, None);
        unread.touch_policy = None;
        assert!(!unread.seal(long, "x").touched);
    }

    #[test]
    fn a_software_path_is_never_touched_or_verified_however_strong_the_policy() {
        let mut ev = hardware_evidence(TouchPolicy::Always, Some(PIN_POLICY_ALWAYS));
        ev.software = true;
        let tap = ev.seal(Duration::from_secs(30), "identity.age");
        assert!(!tap.touched);
        assert!(!tap.verified);
    }

    #[test]
    fn verified_follows_the_slots_pin_policy() {
        let long = Duration::from_secs(3);
        assert!(
            hardware_evidence(TouchPolicy::Always, Some(PIN_POLICY_ONCE))
                .seal(long, "x")
                .verified
        );
        assert!(
            hardware_evidence(TouchPolicy::Always, Some(PIN_POLICY_ALWAYS))
                .seal(long, "x")
                .verified
        );
        for pin in [
            Some(PIN_POLICY_DEFAULT),
            Some(PIN_POLICY_NEVER),
            Some(0x7Fu8),
            None,
        ] {
            assert!(
                !hardware_evidence(TouchPolicy::Always, pin)
                    .seal(long, "x")
                    .verified
            );
        }
    }

    #[test]
    fn the_backend_comes_from_the_stanza_tag_and_never_flatters_a_software_read() {
        assert_eq!(TapBackend::for_tag("piv-p256"), TapBackend::PivP256);
        assert_eq!(TapBackend::for_tag("fido2-hmac"), TapBackend::Fido2Hmac);
        // rageterm enrolls no webauthn-prf identity, so a reply for that tag
        // cannot have come off a FIDO2 device.
        assert_eq!(TapBackend::for_tag("webauthn-prf-v1"), TapBackend::Software);
        assert_eq!(TapBackend::for_tag("X25519"), TapBackend::Software);
        assert_eq!(TapBackend::for_tag("scrypt"), TapBackend::Software);
    }

    #[test]
    fn an_ok_response_serialises_the_tap_block_the_contract_specifies() {
        let tap = hardware_evidence(TouchPolicy::Always, Some(PIN_POLICY_ALWAYS))
            .seal(Duration::from_secs(2), "unused");
        let json = serde_json::to_string(&Response::ok("QUJD".into(), tap)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["file_key"], serde_json::json!("QUJD"));
        assert_eq!(v["tap"]["backend"], serde_json::json!("piv-p256"));
        assert_eq!(v["tap"]["touched"], serde_json::json!(true));
        assert_eq!(v["tap"]["verified"], serde_json::json!(true));
        assert_eq!(v["tap"]["device"], serde_json::json!("12345678"));
        assert_eq!(v["tap"]["slot"], serde_json::json!("0x9d"));
        assert!(v["tap"]["at"].as_u64().unwrap() > 1_600_000_000_000);
    }

    /// `seal` falls back to the label of whatever identity actually answered,
    /// so a reply never carries an empty `device`.
    #[test]
    fn device_falls_back_to_the_answering_identitys_label() {
        let tap = DeviceEvidence::software_only(TapBackend::Software)
            .seal(Duration::from_millis(1), "the software key file");
        assert_eq!(tap.device, "the software key file");
        assert_eq!(tap.backend.as_str(), "software");
    }

    /// The evidence gathered for a FIDO2 stanza is software-grade by
    /// construction: `fido_ctap::hmac_secret` discards the assertion's
    /// user-presence flag, so there is nothing to attest with.
    #[test]
    fn fido2_evidence_cannot_yet_attest_a_touch() {
        let stanza = Stanza {
            tag: "fido2-hmac".into(),
            args: vec!["not-a-credential".into()],
            body: vec![],
        };
        let tap = DeviceEvidence::gather(&stanza).seal(Duration::from_secs(9), "key");
        assert_eq!(tap.backend, TapBackend::Fido2Hmac);
        assert!(!tap.touched);
        assert!(!tap.verified);
    }

    #[test]
    fn probe_request_parses_and_answers_without_opening_anything() {
        let _guard = crate::tests_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let payload = br#"{"method":"probe"}"#;
        let req: Request = serde_json::from_slice(payload).unwrap();
        assert!(matches!(req, Request::Probe {}));

        let resp = handle_payload(payload);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["protocol"], serde_json::json!(2));
        assert_eq!(v["host"], serde_json::json!("com.ragewarden.host"));
        let backends = v["backends"].as_array().unwrap();
        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0]["backend"], serde_json::json!("piv-p256"));
        assert_eq!(backends[1]["backend"], serde_json::json!("fido2-hmac"));
        // No authenticator UP flag is ever read, with or without a device.
        assert_eq!(backends[1]["can_attest_touch"], serde_json::json!(false));
        assert!(v["can_attest_touch"].is_boolean());
        assert!(v["software_fallback"].is_boolean());
        assert!(v["mock_hardware"].is_boolean());
    }

    #[test]
    fn write_frame_produces_correct_le_length() {
        let mut out = Vec::new();
        let payload = b"abcdefghij";
        write_frame(&mut out, payload).unwrap();
        let len = u32::from_le_bytes(out[..4].try_into().unwrap());
        assert_eq!(len as usize, payload.len());
    }
}
