# Ragewarden -- Ecosystem Design

A Bitwarden-compatible secrets ecosystem where each individual credential is wrapped in a
hardware-tap layer (age recipients backed by YubiKey PIV, FIDO2 hmac-secret, or platform
secure-enclave identities) on top of the regular Bitwarden master-password layer.

Three coordinated products, one shared core:

| product | runtime | purpose |
|---|---|---|
| **ragedroid** | Android (Kotlin + JNI) | mobile client; autofill, accessibility, NFC YubiKey |
| **ragemanifest** | Browser MV3 (Rust -> WASM) | Chromium / Firefox / Safari web extension; webauthn for tap, autofill into pages |
| **rageterm** | Native binary (Rust) | CLI by default, `--tui` for interactive; SSH-agent-style integrations |

The pitch: a phishing-resistant Bitwarden where the master password leaking does not leak any
of the actual secrets. Every individual use of a credential requires a deliberate physical
action.

---

## 0. Design principles

These are non-negotiable across all three frontends.

### 0a. Action chosen before tap; tap consents to that specific action

**The user picks the action first, then taps to authorize it.** The tap is not "unlock the
secret and decide later" -- it's "do *this specific thing* with the secret, now." There is no
intermediate "decrypted but undecided" state in any frontend.

Concretely, the user's options before tapping include (frontend-dependent):

- **Autofill** -- deliver to the active form field (web, Android autofill API, ragedroid IME).
  Plaintext flows from rage-core -> autofill IPC -> the form. Never displayed on screen.
- **Copy to clipboard** -- for pasting into apps without autofill. Cleared after 30s by
  default; cleared immediately when the app loses focus.
- **Reveal on screen** -- display plaintext until the sheet is dismissed. Last-resort path,
  not the headline button.
- **Pipe to stdout / stdin** (rageterm) -- `rageterm get foo | ...` writes plaintext to stdout
  for one process and exits. Useful with `ssh-add`, `aws-vault`, ad-hoc shell scripts.
- **Load into agent** (rageterm) -- push an SSH key into ssh-agent, a token into a credential
  helper.

UI should not present "tap your YubiKey" with no action context. Every tap prompt names the
action (`"Autofill into github.com?"`, `"Copy github.com password to clipboard?"`,
`"Reveal github.com password?"`). This is the user's consent surface -- what they see in the
prompt is exactly what happens on tap. No bait-and-switch path exists.

Why this matters:

- **Plaintext lifetime is microseconds.** Decrypt -> deliver -> zeroize, all in one fire.
  Compare to "decrypt -> user picks -> deliver" where the plaintext sits in a buffer for
  seconds.
- **Consent is bound to use.** The tap authorizes one specific consumption, not ambient
  decryption. A compromised UI that rewrites the action name still has to convince the user
  to tap for *that* action.
- **No one-tap-many-uses.** Reinforces strict tap per use: the action and its tap are atomic;
  doing two actions means two taps.
- **Domain visible at tap.** Autofill prompts include the requesting origin
  (`github.com`, not just "the active page") so the user can cancel a phishing prompt before
  tapping.

### 0b. Strict tap per use

One physical action per use. No caching of decrypted secrets across uses. Repeated autofill
against the same site within seconds = repeated taps. Documented and surfaced in onboarding so
expectations match reality.

(Outer Bitwarden master-key cache is unaffected -- only the rage layer is strict.)

### 0c. Plaintext lifecycle is the shortest possible

Once the rage layer decrypts a secret, the plaintext exists in memory only long enough to
deliver to its consumer (autofill API, clipboard, agent socket), then the holding buffer is
zeroized. No process-wide cache, no plaintext field on a ViewModel state, no plaintext in
logs. The Rust core uses `zeroize` for sensitive byte arrays; frontends pass plaintext
through narrow channels and discard.

### 0d. The server stores no secret it can use

Defense-in-depth: even if Bitwarden / Vaultwarden is fully compromised, the server has only
double-encrypted blobs. The rage layer is opaque to the server; the master-password layer
has always been opaque. Compromising both layers requires the attacker to hold a hardware
recipient -- by design, server compromise alone cannot reach plaintext.

---

## 1. Threat model

| threat | Bitwarden today | Ragewarden |
|---|---|---|
| Server compromise (encrypted blobs leak) | safe | safe (same outer layer + opaque inner layer) |
| Master password phishing / keylogger / reuse | **all secrets exposed** | safe -- secrets stay opaque without a hardware tap |
| Compromised endpoint with clipboard / accessibility / page-script access | accessible secrets stay accessible | each use still requires a tap; no bulk siphon |
| Lost YubiKey | n/a | covered if user enrolled a backup recipient |
| Lost YubiKey + lost backup + skipped recovery identity | n/a | secrets unrecoverable; loud documentation |
| Malicious server flips a feature flag mid-rollout | server has authority | unaffected -- rage layer is inside the cipher payload, opaque to server |
| Autofill triggered by hostile site (phishing form) | risk of phishing the visible secret | tap + visible-domain confirmation in the tap UI; user sees what they're consenting to |

The rage layer is strictly additive. Removing all recipients reduces ragewarden to a vanilla
Bitwarden client.

---

## 2. Crypto layering (unchanged across all three frontends)

```
plaintext credential
      |
      |  rage encrypt to N recipients (X25519 + plugin stanzas)
      ▼
age-encrypted blob (ASCII-armored)
      |
      |  Bitwarden Type-2 (AES-256-CBC + HMAC-SHA-256, user symmetric key)
      ▼
EncString stored as a cipher field (custom field `rage:v1`) on the Bitwarden server
```

Both layers are required. Master password unlocks the vault to recover the age blob; hardware
tap unwraps the age blob to recover the plaintext. Either alone yields nothing useful.

---

## 3. Where the rage blob lives in a Bitwarden cipher -- DECIDED

- **`rage:v1` custom field** of type `HIDDEN` on the cipher. Stores the ASCII-armored age
  blob.
- `login.password` stays empty.
- `notes` gets the marker line `"⛓ Protected with Ragewarden"` so users opening the cipher
  from a non-ragewarden client (web vault, browser extension, official mobile) see something
  explanatory rather than empty.
- A future `rage:v2` migrates by writing the new format and only deleting `v1` after the new
  one verifies; servers and other clients ignore unknown fields.

This format works for any Bitwarden server, including Vaultwarden.

---

## 4. Workspace layout

Cargo workspace at the project root:

```
ragewarden/
+-- Cargo.toml                # workspace
+-- DESIGN.md                 # this file
+-- README.md
+-- core/                     # rage-core: shared Rust library
|   +-- Cargo.toml
|   +-- src/lib.rs            # public API
|   +-- ...
+-- ragedroid/                # Android frontend
|   +-- DESIGN.md             # Android-specific design
|   +-- README.md
|   +-- settings.gradle.kts
|   +-- app/                  # Kotlin Compose app
|   +-- jni/                  # Cargo crate building JNI bridge over rage-core
|   +-- ...
+-- ragemanifest/             # browser extension
|   +-- DESIGN.md             # web-specific design
|   +-- README.md
|   +-- Cargo.toml            # WASM crate (wasm-bindgen)
|   +-- manifest/             # MV3 manifests (chromium, firefox, safari)
|   +-- ts/                   # TypeScript glue, popup UI, content scripts
|   +-- ...
+-- rageterm/                 # CLI / TUI binary
    +-- DESIGN.md
    +-- README.md
    +-- Cargo.toml            # binary crate; depends on core
    +-- src/
        +-- main.rs
        +-- cli.rs
        +-- tui.rs
```

Top-level `Cargo.toml` declares `members = ["core", "ragedroid/jni", "ragemanifest", "rageterm"]`.
The Android Gradle build invokes `cargo-ndk` against `ragedroid/jni`; the web extension build
invokes `wasm-pack build ragemanifest`; the CLI is plain `cargo build -p rageterm`.

---

## 5. The shared `rage-core` API surface

Stable, frontend-agnostic API. Roughly:

```rust
// core/src/lib.rs (sketch)

pub struct AgeBlob(pub Vec<u8>);             // armored ascii bytes
pub struct Plaintext(pub zeroize::Zeroizing<Vec<u8>>);

/// A recipient is "something the encrypter can target."
pub enum Recipient {
    X25519 { public_key: [u8; 32] },
    YubiKeyPiv { public_key: [u8; 32], serial: u32, slot: u8 },
    Fido2HmacSecret { credential_id: Vec<u8>, salt: [u8; 32] },
    AndroidKeystore { wrapped_x25519_pub: [u8; 32], key_alias: String },
    SoftwarePassphrase { armored_pubkey: String },     // recovery
}

/// An identity is "something the decrypter can use." Defined as a trait
/// because hardware identities call back into the frontend.
pub trait Identity: Send {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError>;
}

pub fn encrypt(
    plaintext: &[u8],
    recipients: &[Recipient],
) -> Result<AgeBlob, EncryptError>;

pub fn decrypt(
    blob: &AgeBlob,
    identities: &[Box<dyn Identity>],
) -> Result<Plaintext, DecryptError>;

// Bitwarden-specific helpers, since every frontend needs them:
pub mod bitwarden {
    pub fn pbkdf2_master_key(password: &str, email: &str, iters: u32) -> Zeroizing<[u8; 32]>;
    pub fn master_password_hash(master_key: &[u8; 32], password: &str) -> String; // base64
    pub fn make_user_key(master_key: &[u8; 32]) -> (UserKey, ProtectedUserKey);
    pub fn encrypt_type2(plaintext: &[u8], enc: &[u8], mac: &[u8]) -> String;
    pub fn decrypt_type2(s: &str, enc: &[u8], mac: &[u8]) -> Result<Vec<u8>, _>;
    pub fn rsa_keypair_for_registration(user: &UserKey) -> RegistrationKeys;
}

// Optional sync layer (used by all three frontends).
// HTTP transport is injected so each frontend can use its native client (OkHttp on Android,
// fetch in WASM, reqwest in CLI).
pub mod sync {
    pub trait HttpClient { /* ... */ }
    pub fn login(client: &dyn HttpClient, server: &str, email: &str, password: &str)
        -> Result<Session, LoginError>;
    pub fn fetch_vault(client: &dyn HttpClient, session: &Session) -> Result<Vault, _>;
}
```

The `Identity` trait is the cross-language hot path. Each frontend supplies its own trait
implementations:

| frontend | identity impls (live) | identity impls (recovery only) |
|---|---|---|
| ragedroid | `YubiKeyPivIdentity` (yubikit-android NFC/USB), `Fido2HmacIdentity`, `AndroidKeystoreIdentity`, `PasskeyIdentity` (Credential Manager API on API 34+) | `SoftwarePassphraseIdentity` |
| ragemanifest | `PasskeyIdentity` (WebAuthn + PRF -- covers Touch ID / Windows Hello / NFC YubiKey / USB security key / cross-device phone), `NativeMessagingPivIdentity` (optional PIV via `rageterm`-as-helper) | `SoftwarePassphraseIdentity` |
| rageterm | `PivIdentity` (PCSC), `Fido2Identity` (libfido2), `KeyringIdentity` (OS keyring) | `SoftwarePassphraseIdentity` |

**Passkeys are the browser's primary path** -- we don't prescribe a specific hardware token
in ragemanifest. The browser handles authenticator selection, biometrics, tap UI, and the
cross-device phone flow uniformly. See `ragemanifest/DESIGN.md` §3a for details.

When frontend A encrypts to a recipient that frontend B can't unwrap (e.g., ragedroid encrypts
to its Android Keystore identity, then user opens the same cipher in ragemanifest), B sees
the stanza but has no matching identity -- falls back to the next stanza in the header. This
is age's normal behavior; multi-recipient is what makes it work.

---

## 6. Decisions table

| # | question | decision |
|---|---|---|
| 1 | Code sharing across the three products | **Single Rust workspace; rage-core shared library; thin frontends.** |
| 2 | Browser targets for ragemanifest | **Chromium MV3 + Firefox + Safari from v1.** Three manifests, common WASM core. Safari is a meaningful additional cost (Xcode, App Store, host-app shell). |
| 3 | rageterm shape | **Plain CLI by default, `--tui` flag for interactive ratatui mode.** All operations need both code paths. |
| 4 | age implementation | **`age` Rust crate, shared by all three frontends via `rage-core`.** |
| 5 | Recovery story | **Optional paper identity at first-run.** Add it later by re-encrypting selected ciphers (same machinery as adding a new YubiKey). Per-cipher state observable as "is the recovery pubkey in the stanza list?" |
| 6 | Account scope | **Share existing Bitwarden / Vaultwarden account.** Protected and unprotected ciphers coexist. |
| 7 | Caching | **Strict tap per use, no caching of decrypted secrets.** |
| 8 | Storage location in cipher | **`rage:v1` custom HIDDEN field; `login.password` empty; explanatory marker in `notes`.** |
| 9 | Authenticator (TOTP) integration | **v2.** Higher-value than passwords; deserves the same protection but ships after v1. |

---

## 7. Sequencing

Three phases. Each phase ends with a working demo across all three frontends.

### Phase 1: minimum viable end-to-end

- `rage-core`: encrypt + decrypt with X25519 software identity only; Bitwarden helpers (KDF,
  Type-2, registration); HTTP-injected sync against Vaultwarden.
- `rageterm`: `login`, `list`, `get` (uses), `set`, `enroll-software-identity`. CLI only,
  no TUI yet.
- `ragedroid`: stub Compose app that lists ciphers and uses rage-core via JNI. Software
  identity from settings.
- `ragemanifest`: stub popup that lists ciphers and autofills via WebAuthn `prf` only.

**Goal: same vault, three frontends, software-identity-only round-trip works.**

### Phase 2: hardware identities

- `rageterm`: PCSC-based PIV identity, libfido2-based hmac-secret identity, OS-keyring
  identity. `enroll-yubikey`, `enroll-fido2`, `enroll-keyring`.
- `ragedroid`: yubikit-android PIV (NFC + USB-OTG), FIDO2 hmac-secret, Android Keystore
  identity. Tap UI, autofill API integration.
- `ragemanifest`: WebAuthn `prf` extension for hmac-secret. Native messaging host that calls
  `rageterm` for PIV (since browsers can't talk to PIV directly).
- `rageterm`: also gets the `--tui` mode.

**Goal: tap-to-use works on all three; multi-recipient ciphers round-trip.**

### Phase 3: polish

- Recovery wizard, optional paper identity, back-fill action.
- Browser extension Safari shell + App Store shipping pipeline.
- Bulk-protect-existing-items wizard.
- TOTP support (v2).
- Documentation site, threat-model whitepaper, audit prep.

---

## 8. Out of scope (v1)

- Replacing the Bitwarden server.
- Cross-client editing of rage-protected ciphers (non-ragewarden clients can read metadata
  only). Document loudly.
- Sharing rage-protected ciphers with other Bitwarden users (would require knowing their
  recipients).
- TOTP. v2.
- Sends. Maybe never; the threat model differs.
- Family / org account flows. v2.

---

## 9. Distribution

| product | channel |
|---|---|
| ragedroid | Google Play (`com.ragewarden.android`), F-Droid manifest in repo, signed APK on GitHub releases |
| ragemanifest | Chrome Web Store, Firefox Add-ons (AMO), App Store (Safari requires the macOS host app pattern) |
| rageterm | GitHub releases (linux x86_64, linux aarch64, macos universal, windows x86_64), homebrew formula, optional cargo install |

Reproducible builds for all three. Source-distributed via this repo.
