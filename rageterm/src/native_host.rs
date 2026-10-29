use std::io::{self, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
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
        /// native-unwrap-proof-v1: base64 of 32 fresh bytes the device signs
        /// together with the stanza (see `native_proof`).
        #[serde(default)]
        challenge: Option<String>,
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
    #[serde(default)]
    pub destination: String,
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
        use ragewarden_core::stanza_format::{TAG_FIDO2_HMAC, TAG_PIV_P256, TAG_PIV_X25519_V2};
        if tag == TAG_PIV_P256 || tag == TAG_PIV_X25519_V2 {
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
    /// The device's signature over the request's challenge, when it holds a
    /// P-256 key to sign with (a P-256 PIV slot).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<crate::native_proof::UnwrapProof>,
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
        Request::UnwrapStanza {
            stanza,
            context,
            challenge,
        } => match unwrap_stanza(stanza, &context, challenge.as_deref()) {
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
    use ragewarden_core::stanza_format::{
        TAG_FIDO2_HMAC, TAG_PIV_P256, TAG_PIV_X25519_V2, TAG_WEBAUTHN_PRF_V1,
    };
    [
        TAG_PIV_P256,
        TAG_PIV_X25519_V2,
        TAG_FIDO2_HMAC,
        TAG_WEBAUTHN_PRF_V1,
    ]
    .contains(&tag)
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
    challenge: Option<&str>,
) -> Result<(String, TapAttestation), NativeHostError> {
    let proof_message = challenge.map(|c| {
        crate::native_proof::message(
            c,
            &wire.tag,
            &wire.args,
            &wire.body,
            &context.action,
            &context.destination,
        )
    });
    let body = B64.decode(wire.body.as_bytes())?;
    let stanza = Stanza {
        tag: wire.tag,
        args: wire.args,
        body,
    };

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

    let evidence = DeviceEvidence::gather(&stanza);
    if !software_unwrap_allowed() {
        if let Some(why) = evidence.why_no_touch_can_be_attested() {
            return Err(NativeHostError::ConsentUnavailable(format!(
                "refusing to unwrap: {why}. Nothing physical would confirm this request, so \
                 it is not served. Use a slot with touch policy `always` or a FIDO2 key, or \
                 set {ALLOW_SOFTWARE_ENV}=1 in the browser's environment to accept \
                 unconfirmed unwraps deliberately."
            )));
        }
    }

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
    notify_action(context, &evidence);

    let policy = if software_unwrap_allowed() {
        crate::consent::IdentityPolicy::SoftwareAllowed
    } else {
        crate::consent::IdentityPolicy::HardwareOnly
    };
    let identities = commands::build_identity_list_for(policy)
        .map_err(|e| NativeHostError::Identities(e.to_string()))?;

    for id in &identities {
        let started = Instant::now();
        crate::fido::reset_observed_flags();
        let (unwrapped, signed) = match &proof_message {
            Some(m) => {
                crate::native_proof::unwrap_with_proof(m.clone(), || id.try_unwrap_stanza(&stanza))
            }
            None => (id.try_unwrap_stanza(&stanza), None),
        };
        match unwrapped {
            Ok(Some(file_key)) => {
                let mut evidence = evidence.clone();
                evidence.fido_flags = crate::fido::take_observed_flags();
                let mut tap = evidence.seal(started.elapsed(), id.display());
                if !tap.touched && !software_unwrap_allowed() {
                    return Err(NativeHostError::ConsentUnavailable(format!(
                        "the `{}` unwrap completed without evidence of a touch, so the key \
                         is not served",
                        tap.backend.as_str()
                    )));
                }
                if let Some(signed) = signed {
                    tap.proof = Some(signed.into_proof().map_err(NativeHostError::Identities)?);
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

/// YubiKey PIV PIN-policy bytes. `piv_apdu` keeps `SlotMetadata::pin_policy`
/// raw because nothing there needed to interpret it; the meanings are Yubico's
/// and match the touch-policy encoding one for one.
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
    /// `(user_present, user_verified)` from the FIDO2 assertion that produced
    /// the key, filled in after the unwrap.
    fido_flags: Option<(bool, bool)>,
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
            fido_flags: None,
            software: true,
        }
    }

    fn gather(stanza: &Stanza) -> Self {
        let backend = TapBackend::for_tag(&stanza.tag);
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
            device: if entry.mock || entry.serial == 0 {
                entry.label.clone()
            } else {
                entry.serial.to_string()
            },
            slot: format_slot(entry.slot),
            touch_policy: None,
            pin_policy: None,
            fido_flags: None,
            software: forced_software || entry.mock,
        };
        if ev.software {
            return ev;
        }

        match read_piv_slot_facts(entry.serial, entry.slot) {
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
    /// which `fido::observe` records; `seal` reads it after the unwrap.
    fn gather_fido(stanza: &Stanza) -> Self {
        let mut ev = Self::software_only(TapBackend::Fido2Hmac);
        if let Some(entry) = find_fido_entry(stanza) {
            ev.device = entry.label;
            ev.slot = entry.credential_id_b64;
            ev.software = entry.mock || software_unwrap_allowed();
        }
        ev
    }

    /// `Some(reason)` when this request cannot end in `touched: true` whatever
    /// happens next, so the host should not even ask the device.
    fn why_no_touch_can_be_attested(&self) -> Option<String> {
        if self.software {
            return Some("the identity is a software stand-in".into());
        }
        match self.backend {
            TapBackend::Fido2Hmac => None,
            TapBackend::PivP256 => match self.touch_policy {
                Some(TouchPolicy::Always) => None,
                Some(p) => Some(format!(
                    "PIV slot {} has touch policy `{p}`, which does not wait for a touch on \
                     every use",
                    self.slot
                )),
                None => Some(format!(
                    "the touch policy of PIV slot {} could not be read",
                    self.slot
                )),
            },
            TapBackend::Software => Some("the stanza is not hardware-gated".into()),
        }
    }

    fn seal(&self, _blocked_for: Duration, answered_by: &str) -> TapAttestation {
        let touched = !self.software
            && match self.backend {
                TapBackend::Fido2Hmac => matches!(self.fido_flags, Some((true, _))),
                _ => matches!(self.touch_policy, Some(TouchPolicy::Always)),
            };
        let verified = !self.software
            && match self.backend {
                TapBackend::Fido2Hmac => matches!(self.fido_flags, Some((_, true))),
                _ => matches!(
                    self.pin_policy,
                    Some(PIN_POLICY_ONCE) | Some(PIN_POLICY_ALWAYS)
                ),
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
            proof: None,
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
    let registry = Identities::load().ok()?;
    registry.iter_chronological().find_map(|entry| {
        let IdentityKind::YubiKeyPiv {
            public_key_hex,
            serial,
            slot,
            mock,
        } = &entry.kind
        else {
            return None;
        };
        let id = crate::piv::PivIdentity {
            public_key: crate::piv::PivPublicKey::from_hex(public_key_hex).ok()?,
            serial: *serial,
            slot: *slot,
            label: entry.label.clone(),
            mock: *mock,
        };
        id.names(stanza).unwrap_or(false).then(|| PivRegistryEntry {
            serial: *serial,
            slot: *slot,
            mock: *mock,
            label: entry.label.clone(),
        })
    })
}

struct FidoRegistryEntry {
    label: String,
    credential_id_b64: String,
    mock: bool,
}

fn find_fido_entry(stanza: &Stanza) -> Option<FidoRegistryEntry> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use ragewarden_core::stanza_format::fido2_hmac_credential_id;
    let want = fido2_hmac_credential_id(stanza).ok()?;
    let registry = Identities::load().ok()?;
    registry.iter_chronological().find_map(|entry| {
        let IdentityKind::Fido2HmacSecret {
            credential_id_b64,
            mock,
            ..
        } = &entry.kind
        else {
            return None;
        };
        let id = B64URL.decode(credential_id_b64.as_bytes()).ok()?;
        (id == want).then(|| FidoRegistryEntry {
            label: entry.label.clone(),
            credential_id_b64: credential_id_b64.clone(),
            mock: *mock,
        })
    })
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
fn read_piv_slot_facts(serial: u32, slot: u8) -> Result<PivSlotFacts, String> {
    let _device = crate::lock::device_session().map_err(|e| e.to_string())?;
    let mut transport = crate::piv_pcsc::open_piv_card(serial).map_err(|e| e.to_string())?;

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

    match read_piv_slot_facts(serial, slot) {
        Ok(facts) => {
            if facts.serial != 0 {
                report.device = facts.serial.to_string();
            }
            let pin_gated = matches!(
                facts.pin_policy,
                Some(PIN_POLICY_ONCE) | Some(PIN_POLICY_ALWAYS)
            );
            report.can_attest_touch = facts.touch_policy.touch_every_use();
            if pin_gated && !crate::pin::available() {
                report.available = false;
                report.detail = format!(
                    "slot touch policy is `{}`, and its PIN policy needs a PIN that this host \
                     cannot ask for: no terminal and no `pinentry` on PATH",
                    facts.touch_policy
                );
            } else {
                report.available = true;
                report.detail = format!("slot touch policy is `{}`", facts.touch_policy);
            }
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
            "{ALLOW_SOFTWARE_ENV}=1 is set: replies carry the assertion's user-presence \
             flag, but this host also serves unconfirmed unwraps"
        )
    } else if !crate::pin::available() {
        "each unwrap reports the assertion's user-presence flag; an authenticator with a \
         PIN cannot be used here because there is no terminal and no `pinentry` on PATH"
            .into()
    } else {
        "each unwrap reports the assertion's user-presence flag".into()
    };
    report.can_attest_touch = report.available;
    report
}

/// What the notification tells the user to do, which must match what the
/// device will actually wait for.
fn notification_body(evidence: &DeviceEvidence) -> String {
    match (evidence.backend, evidence.why_no_touch_can_be_attested()) {
        (TapBackend::PivP256, None) => format!(
            "Touch YubiKey {} (PIV slot {}) now to authorize.",
            evidence.device, evidence.slot
        ),
        (TapBackend::Fido2Hmac, None) => {
            format!(
                "Touch your FIDO2 key ({}) now to authorize.",
                evidence.device
            )
        }
        (_, Some(why)) => {
            format!("No touch is required ({why}) -- this request is not physically confirmed.")
        }
        (TapBackend::Software, None) => {
            "No touch is required -- this request is not physically confirmed.".into()
        }
    }
}

fn notify_action(context: &RequestContext, evidence: &DeviceEvidence) {
    let summary = action_prompt(context);
    let body = notification_body(evidence);
    if let Err(e) = notify_rust::Notification::new()
        .summary(&summary)
        .body(&body)
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

    fn piv_evidence(policy: Option<TouchPolicy>) -> DeviceEvidence {
        DeviceEvidence {
            backend: TapBackend::PivP256,
            device: "12345".into(),
            slot: "9d".into(),
            touch_policy: policy,
            pin_policy: None,
            fido_flags: None,
            software: false,
        }
    }

    #[test]
    fn a_slot_that_does_not_touch_every_use_is_refused_before_the_card_is_asked() {
        assert!(
            piv_evidence(Some(TouchPolicy::Always))
                .why_no_touch_can_be_attested()
                .is_none()
        );
        for p in [
            Some(TouchPolicy::Cached),
            Some(TouchPolicy::Never),
            Some(TouchPolicy::Default),
            None,
        ] {
            assert!(piv_evidence(p).why_no_touch_can_be_attested().is_some());
        }
        let mut sw = piv_evidence(Some(TouchPolicy::Always));
        sw.software = true;
        assert!(sw.why_no_touch_can_be_attested().is_some());
    }

    #[test]
    fn the_notification_names_a_touch_only_when_one_is_coming() {
        assert!(
            notification_body(&piv_evidence(Some(TouchPolicy::Always)))
                .starts_with("Touch YubiKey 12345")
        );
        assert!(
            notification_body(&piv_evidence(Some(TouchPolicy::Never)))
                .starts_with("No touch is required")
        );
        let mut fido = piv_evidence(None);
        fido.backend = TapBackend::Fido2Hmac;
        fido.device = "Solo".into();
        assert!(notification_body(&fido).contains("FIDO2 key (Solo)"));
    }

    #[test]
    fn a_fido2_reply_is_touched_only_when_the_assertion_had_up_set() {
        let mut fido = piv_evidence(None);
        fido.backend = TapBackend::Fido2Hmac;
        assert!(!fido.seal(Duration::ZERO, "k").touched);
        fido.fido_flags = Some((true, false));
        let tap = fido.seal(Duration::ZERO, "k");
        assert!(tap.touched && !tap.verified);
        fido.fido_flags = Some((false, false));
        assert!(!fido.seal(Duration::ZERO, "k").touched);
    }

    #[test]
    fn a_challenged_p256_unwrap_carries_a_proof_the_browser_verifier_accepts() {
        use crate::identities::{EnrolledIdentity, Identities};
        use crate::tests_lock::ENV_LOCK;
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", dir.path());
        crate::tests_lock::set_var(crate::hw::MOCK_ENV, "1");
        crate::tests_lock::set_var(ALLOW_SOFTWARE_ENV, "1");

        let enrolled = crate::piv::mock_enroll_p256(0x9a).unwrap();
        let mut ids = Identities::default();
        ids.insert(EnrolledIdentity {
            id: "p256".into(),
            kind: IdentityKind::YubiKeyPiv {
                public_key_hex: enrolled.public_key.to_hex(),
                serial: enrolled.serial,
                slot: enrolled.slot,
                mock: true,
            },
            label: "p256 slot".into(),
            created: chrono::Utc::now(),
            last_used: None,
        });
        ids.save().unwrap();

        let blob = ragewarden_core::encrypt(
            b"x",
            &[ragewarden_core::Recipient::YubiKeyPivP256 {
                public_key: enrolled.public_key.bytes().to_vec(),
                serial: enrolled.serial,
                slot: enrolled.slot,
            }],
        )
        .unwrap();
        let stanza = ragewarden_core::parse_header_stanzas(&blob)
            .unwrap()
            .remove(0);
        let body_b64 = B64.encode(&stanza.body);
        let challenge = "c2l4dGVlbi1ieXRlLWNoYWxsZW5nZS4uLi4uLi4uLi4=";
        let req = serde_json::json!({
            "method": "unwrap_stanza",
            "stanza": { "tag": stanza.tag, "args": stanza.args, "body": body_b64 },
            "context": { "action": "autofill", "destination": "github.com" },
            "challenge": challenge,
        });
        let resp: serde_json::Value =
            serde_json::from_str(&handle_payload(req.to_string().as_bytes())).unwrap();

        crate::tests_lock::remove_var(ALLOW_SOFTWARE_ENV);
        crate::tests_lock::remove_var(crate::hw::MOCK_ENV);
        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");

        assert_eq!(resp["ok"], true, "{resp}");
        let proof: crate::native_proof::UnwrapProof =
            serde_json::from_value(resp["tap"]["proof"].clone()).unwrap();
        let spki = crate::native_proof::attestation_key(enrolled.public_key.bytes()).unwrap();
        let verify = |destination: &str| {
            let m = crate::native_proof::message(
                challenge,
                &stanza.tag,
                &stanza.args,
                &body_b64,
                "autofill",
                destination,
            );
            crate::native_proof::verify(Some(&proof), &m, std::slice::from_ref(&spki))
        };
        assert_eq!(verify("github.com"), Ok(true));
        assert!(
            verify("evil.example").is_err(),
            "a proof must not verify for another destination"
        );
    }

    #[test]
    fn a_challenged_fido2_unwrap_carries_an_assertion_proof_the_browser_verifier_accepts() {
        use crate::identities::{EnrolledIdentity, Identities};
        use crate::tests_lock::ENV_LOCK;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", dir.path());
        crate::tests_lock::set_var(crate::hw::MOCK_ENV, "1");
        crate::tests_lock::set_var(ALLOW_SOFTWARE_ENV, "1");

        let enrolled = crate::fido::mock_enroll("ragewarden").unwrap();
        let public_key = enrolled.public_key.expect("a mock credential has a key");
        let mut ids = Identities::default();
        ids.insert(EnrolledIdentity {
            id: "fido".into(),
            kind: IdentityKind::Fido2HmacSecret {
                credential_id_b64: B64URL.encode(&enrolled.credential_id),
                salt_hex: hex::encode(enrolled.salt),
                rp_id: enrolled.rp_id.clone(),
                mock: true,
                uv: enrolled.uv,
                public_key_hex: Some(hex::encode(public_key)),
            },
            label: "fido key".into(),
            created: chrono::Utc::now(),
            last_used: None,
        });
        ids.save().unwrap();

        let recipients = [ragewarden_core::Recipient::Fido2HmacSecret {
            credential_id: enrolled.credential_id.clone(),
            salt: enrolled.salt,
            rp_id: enrolled.rp_id.clone(),
        }];
        let outputs = crate::commands::build_prf_outputs_for(&recipients).unwrap();
        let table = crate::commands::prf_table_from(&outputs);
        let blob = ragewarden_core::encrypt_with_prf(b"x", &recipients, &table).unwrap();
        let stanza = ragewarden_core::parse_header_stanzas(&blob)
            .unwrap()
            .remove(0);
        let body_b64 = B64.encode(&stanza.body);
        let challenge = "ZmlkbzItY2hhbGxlbmdlLWZvci10aGUtdGVzdA==";
        let req = serde_json::json!({
            "method": "unwrap_stanza",
            "stanza": { "tag": stanza.tag, "args": stanza.args, "body": body_b64 },
            "context": { "action": "autofill", "destination": "github.com" },
            "challenge": challenge,
        });
        let resp: serde_json::Value =
            serde_json::from_str(&handle_payload(req.to_string().as_bytes())).unwrap();

        crate::tests_lock::remove_var(ALLOW_SOFTWARE_ENV);
        crate::tests_lock::remove_var(crate::hw::MOCK_ENV);
        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");

        assert_eq!(resp["ok"], true, "{resp}");
        assert_eq!(resp["tap"]["proof"]["kind"], "fido2-assertion", "{resp}");
        let proof: crate::native_proof::UnwrapProof =
            serde_json::from_value(resp["tap"]["proof"].clone()).unwrap();
        let trusted = [crate::native_proof::attestation_key(&public_key).unwrap()];
        let verify = |destination: &str| {
            let m = crate::native_proof::message(
                challenge,
                &stanza.tag,
                &stanza.args,
                &body_b64,
                "autofill",
                destination,
            );
            crate::native_proof::verify(Some(&proof), &m, &trusted)
        };
        assert_eq!(verify("github.com"), Ok(true));
        assert!(verify("evil.example").is_err());
    }

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
            destination: String::new(),
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
            Request::UnwrapStanza {
                stanza, context, ..
            } => {
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
        assert!(tag_is_hardware_gated("piv-x25519-v2"));
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
        crate::tests_lock::remove_var(ALLOW_SOFTWARE_ENV);
        crate::tests_lock::remove_var(crate::hw::MOCK_ENV);

        struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => crate::tests_lock::set_var(ALLOW_SOFTWARE_ENV, v),
                    None => crate::tests_lock::remove_var(ALLOW_SOFTWARE_ENV),
                }
                match self.1.take() {
                    Some(v) => crate::tests_lock::set_var(crate::hw::MOCK_ENV, v),
                    None => crate::tests_lock::remove_var(crate::hw::MOCK_ENV),
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
            fido_flags: None,
            software: false,
        }
    }

    /// The rule the whole contract rests on: only a slot whose policy the card
    /// itself reported as touch-gating may ever produce `touched: true`.
    #[test]
    fn only_an_always_slot_can_report_a_touch() {
        let long = Duration::from_secs(3);
        let instant = Duration::from_millis(5);

        assert!(
            hardware_evidence(TouchPolicy::Always, None)
                .seal(instant, "x")
                .touched
        );
        assert!(
            !hardware_evidence(TouchPolicy::Cached, None)
                .seal(long, "x")
                .touched
        );
        assert!(
            !hardware_evidence(TouchPolicy::Cached, None)
                .seal(instant, "x")
                .touched
        );

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
        for pin in [Some(0x00), Some(0x01), Some(0x7Fu8), None] {
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
        assert_eq!(TapBackend::for_tag("piv-x25519-v2"), TapBackend::PivP256);
        assert_eq!(TapBackend::for_tag("fido2-hmac"), TapBackend::Fido2Hmac);
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
