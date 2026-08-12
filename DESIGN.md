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
  Plaintext flows from ragewarden-core -> autofill IPC -> the form. Never displayed on screen.
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

**Status -- partially enforced. See §0e.** This is a *client policy*, not a cryptographic
property: nothing in the stanza format forces a device round trip per secret. Clients that
honour it do so because they call the ceremony each time. Two live exceptions are described
in §0e.

### 0c. Plaintext lifecycle is the shortest possible

Once the rage layer decrypts a secret, the plaintext exists in memory only long enough to
deliver to its consumer (autofill API, clipboard, agent socket), then the holding buffer is
zeroized. No process-wide cache, no plaintext field on a ViewModel state, no plaintext in
logs. The Rust core uses `zeroize` for sensitive byte arrays; frontends pass plaintext
through narrow channels and discard.

**Status -- mostly holds, with known unwiped copies.** See §0e for the list. The rule is
enforced at the boundaries we own; it is not enforced inside third-party crates we hand a
plaintext to (notably `arboard`, which takes ownership of a clipboard string).

### 0d. The server stores no secret it can use

Defense-in-depth: even if Bitwarden / Vaultwarden is fully compromised, the server has only
double-encrypted blobs. The rage layer is opaque to the server; the master-password layer
has always been opaque. Compromising both layers requires the attacker to hold a hardware
recipient -- by design, server compromise alone cannot reach plaintext.

**Status -- holds, with one caveat.** A vault that has a *software* recipient (`X25519`
`enroll-software-identity`, or a `scrypt` paper identity) is protected by that recipient's
key material, not by a device. That key sits on disk under the user's account. §0d is a
statement about the *server*, and it is true; it is not a statement about a stolen laptop.

### 0e. Implementation status of §0a-d -- what is true today

The four principles above are the design target. This section records where the tree
actually stands, so a reader does not take an aspiration for a guarantee. Items marked
NOT YET IMPLEMENTED are intended, not abandoned.

**Holds today:**

- §0a action-before-tap. Every delivery path names the action and destination before the
  gate runs (rageterm `consent::require`, ragedroid `AutofillAuthActivity` /
  `InlineTapReveal`, ragemanifest's extension-drawn tap window). No frontend has a
  "decrypt now, choose later" state. Note this is a claim about *ordering*, not about the
  gate being a hardware tap -- see the four items under "Does not hold" for where the named
  action is followed by something weaker than a tap.
- §0d server opacity. The rage blob is inside the Type-2 EncString; the server never sees
  either layer's key.
- **Per-secret wrap uniqueness.** `webauthn-prf-v1` and `fido2-hmac` stanzas now carry a
  32-byte CSPRNG `wrap_salt` drawn once per stanza
  (`core/src/stanza_format.rs`, `fresh_wrap_salt`), mixed into the HKDF salt. Before that
  change the body key was `HKDF(recipient.salt, prf_output)` -- constant for every secret
  wrapped to one authenticator -- under a hardcoded zero nonce, which is a ChaCha20
  keystream-reuse and Poly1305 one-time-key-reuse break. That break is fixed for newly
  written stanzas. The zero nonce is retained deliberately and is safe under a per-stanza
  key; see `core/DESIGN.md` §2d.
- **Legacy blobs are still affected.** Three-argument `webauthn-prf-v1` / `fido2-hmac`
  stanzas written before the `wrap_salt` change decrypt under the old derivation and
  should be treated as compromised and rotated. `webauthn_prf_is_legacy_wrap` /
  `fido2_hmac_is_legacy_wrap` let a frontend flag them; **no frontend surfaces that flag
  in its UI yet -- NOT YET IMPLEMENTED.**

**Does not hold today:**

- **"No bulk siphon" is not a cryptographic property for PRF-backed recipients.** The PRF
  salt is a field of the *recipient*, so one authenticator evaluation yields one
  `prf_output` that is valid for every stanza wrapped to that recipient. An attacker who
  captures a single PRF output, plus the vault blobs, can unwrap every PRF-protected secret
  with no further taps. The per-stanza `wrap_salt` diversifies the *body key*; it does not
  make the *authenticator* answer again. Making it per-secret needs a per-secret PRF salt,
  which costs one device round trip per secret at encrypt time. **NOT YET IMPLEMENTED.**
  `piv-p256` and `ragedroid-keystore-v1` do not have this problem: each stanza carries a
  fresh ephemeral public key, so each unwrap needs a fresh ECDH on the device.
- **rageterm does not gate a decryption that can be satisfied in software.**
  `consent::require` branches on a *vault-global* hardware state, not on the stanza set of
  the item in hand. When any real hardware identity is enrolled it prints "this needs a
  hardware tap" and returns without a gate -- while `core::decrypt` tries software X25519
  identities first, so an item that also carries a software stanza unwraps from disk with
  no tap at all. Enrolling a YubiKey therefore currently makes `get` / `copy` *less*
  gated than not enrolling one. **NOT YET IMPLEMENTED**; the fix is to derive the gate
  from the item's own stanza tags.
- **rageterm cannot verify a PIV slot's touch policy.** A slot generated without
  `--touch-policy always` completes ECDH with no touch, while the prompt says a tap is
  required. Reading the policy back needs the YubiKey PIV metadata APDU (`INS 0xF7`),
  which `piv_apdu.rs` does not implement. **NOT YET IMPLEMENTED**; `enroll-yubikey`
  guidance now tells the user to pass `--touch-policy always` and says plainly that
  rageterm cannot confirm it.
- **`core::sync::set_folder` does not call `require_secure()`.** It takes a caller-supplied
  `server_url: &str` rather than a validated `&Server`, and puts the bearer token on the
  wire without checking the scheme. Every other sync entry point is gated. It has no
  in-tree callers, but it is public API. **NOT YET FIXED.**
- **Unwiped plaintext copies survive delivery in a few places.** `arboard::Clipboard`
  takes ownership of the clipboard string in its own owner thread with no zeroizing drop
  (rageterm avoids minting an *extra* owned copy, but cannot reach the one arboard keeps).
  `core::decrypt` / `aead_decrypt_filekey` / `decrypt_type2` keep non-zeroized intermediate
  buffers. **NOT YET IMPLEMENTED.**
- **ragedroid's app lock is a UI boundary on one Activity's composition.** It does not
  zeroise key material, it does not gate `RagewardenInputMethodService` -- which shares the
  process and the repository singleton and reads no lock state, so an *unprotected*
  Bitwarden password can still be typed into a host field while the vault is locked -- and
  it is composition-scoped, so Activity recreation re-derives it. Rage-protected items are
  refused by the IME outright, so nothing Ragewarden-protected escapes that way. Details
  and the fix shape in `ragedroid/docs/THREAT-MODEL.md` §5.3 and §10. **NOT YET
  IMPLEMENTED.**
- **Token refresh does not exist** in any frontend. A 401 forces a full re-login.
  **NOT YET IMPLEMENTED.**

---

## 1. Threat model

| threat | Bitwarden today | Ragewarden |
|---|---|---|
| Server compromise (encrypted blobs leak) | safe | safe (same outer layer + opaque inner layer) |
| Master password phishing / keylogger / reuse | **all secrets exposed** | safe -- secrets stay opaque without a hardware tap |
| Compromised endpoint with clipboard / accessibility / page-script access | accessible secrets stay accessible | each use requires a tap **as a matter of client policy**; see §0e -- a captured PRF output is still a bulk-unwrap capability for PRF-backed recipients, and rageterm does not gate items that also carry a software stanza |
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
+-- core/                     # ragewarden-core: shared Rust library
|   +-- Cargo.toml
|   +-- src/lib.rs            # public API
|   +-- ...
+-- ragedroid/                # Android frontend
|   +-- DESIGN.md             # Android-specific design
|   +-- README.md
|   +-- settings.gradle.kts
|   +-- app/                  # Kotlin Compose app
|   +-- jni/                  # Cargo crate building JNI bridge over ragewarden-core
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

## 5. The shared `ragewarden-core` API surface

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
| rageterm | `PivIdentity` (PCSC), `Fido2Identity` (ctap-hid-fido2), `KeyringIdentity` (OS keyring) | `SoftwarePassphraseIdentity` |

**Passkeys are the browser's primary path** -- we don't prescribe a specific hardware token
in ragemanifest. The browser handles authenticator selection, biometrics, tap UI, and the
cross-device phone flow uniformly. See `ragemanifest/DESIGN.md` §3a for details.

When frontend A encrypts to a recipient that frontend B can't unwrap (e.g., ragedroid encrypts
to its Android Keystore identity, then user opens the same cipher in ragemanifest), B sees
the stanza but has no matching identity -- falls back to the next stanza in the header. This
is age's normal behavior; multi-recipient is what makes it work.

---

## 5b. End-to-end test harness

Manual user testing is replaced where possible by a layered harness documented at
[`E2E.md`](./E2E.md):

- **Tier 1 -- Rust <-> real Vaultwarden in Docker** (✅ ready). `testcontainers` spins up an
  unmodified `vaultwarden/server` per test; `rageterm/tests/e2e_vaultwarden.rs` exercises
  register / login / encrypt / POST / fetch / decrypt and a cross-frontend interop check
  via `ragemanifest::snapshot::build_snapshot`. CI job `e2e-vaultwarden` runs on every push.
- **Tier 2 -- browser extension via Playwright + CDP virtual WebAuthn** (🟡 suite written,
  not yet a gate). `ragemanifest/tests/playwright/` holds `onboarding`, `passkey-prf-
  roundtrip`, `autofill-content-script`, `design-callbacks` and `cross-client-fuzz` specs
  plus a `global-setup` that builds the extension with `--test-hooks`. It needs
  `npm install` and a `wasm-pack` `pkg/`, neither of which is vendored here, so it does
  **not** run from a bare checkout of this tree.
- **Tier 3 -- Android via Gradle Managed Devices + UIAutomator** (🟡 device configured,
  tests not written). `ragedroid/app/build.gradle.kts` declares a `pixel6Api34` managed
  virtual device and the baseline-profile generator uses it. The Espresso / UIAutomator
  screens described here are **NOT YET IMPLEMENTED**; what exists today is the Robolectric
  JVM suite (`:app:test{Standard,Fdroid}DebugUnitTest`).

`SECURITY.md` carries the release-gate checklist of manual ceremonies that genuinely
need a person (real YubiKey tap, real Touch ID, real store submissions); CI catches the rest.

---

## 6. Decisions table

| # | question | decision |
|---|---|---|
| 1 | Code sharing across the three products | **Single Rust workspace; ragewarden-core shared library; thin frontends.** |
| 2 | Browser targets for ragemanifest | **Chromium MV3 + Firefox + Safari from v1.** Three manifests, common WASM core. Safari is a meaningful additional cost (Xcode, App Store, host-app shell). |
| 3 | rageterm shape | **Plain CLI by default, `--tui` flag for interactive ratatui mode.** All operations need both code paths. |
| 4 | age implementation | **`age` Rust crate, shared by all three frontends via `ragewarden-core`.** |
| 5 | Recovery story | **Optional paper identity at first-run.** Add it later by re-encrypting selected ciphers (same machinery as adding a new YubiKey). Per-cipher state observable as "is the recovery pubkey in the stanza list?" |
| 6 | Account scope | **Share existing Bitwarden / Vaultwarden account.** Protected and unprotected ciphers coexist. |
| 7 | Caching | **Strict tap per use, no caching of decrypted secrets.** |
| 8 | Storage location in cipher | **`rage:v1` custom HIDDEN field; `login.password` empty; explanatory marker in `notes`.** |
| 9 | Authenticator (TOTP) integration | **v2.** Higher-value than passwords; deserves the same protection but ships after v1. |

---

## 7. Sequencing

Five phases. Each phase ends with a demoable cross-frontend slice.

### Phase 1 -- software-identity demo end-to-end ✅ DONE (`c4d643e`, `c917f20`, `40782b3`, `c64186d`)

- `ragewarden-core`: encrypt + decrypt for X25519 + scrypt; Bitwarden primitives (PBKDF2 master
  key, master password hash, HKDF-Expand split, Type-2 EncString); `Identity` trait as
  forward-compat surface.
- `rageterm`: full CLI (`enroll-software-identity / set / list / get / copy / reveal /
  exec / --tui`) round-tripping through a local file store at
  `~/.config/ragewarden/store.json`.
- `ragedroid`: Compose app installs and runs on emulator; `Copy github.com password?` ->
  Authorize -> JNI decrypt -> plaintext lands in clipboard with the auto-clear timer running.
- `ragemanifest`: Rust -> WASM core compiles; popup hosts `design/` directly and bridges
  crypto via WASM exports.

**Demoable artifact:** vault list + item detail + tap-bound copy on each frontend, all
sharing one core crate, all enforcing the action-named-before-tap principle.

### Phase 2 -- real vault: Bitwarden / Vaultwarden integration ✅ DONE (core + rageterm `553d19f`; ragedroid JNI + `BitwardenVaultRepository` + `OnboardingScreen` + `EditItemScreen`; ragemanifest 23 WASM exports + onboarding + background worker + glue layer)

- `ragewarden-core`: `sync` module -- HTTP-injected client (frontends supply their native HTTP).
  Login (PBKDF2 master key -> master password hash -> `/identity/connect/token` ->
  bearer + refresh). Sync (`GET /api/sync` -> vault model). Cipher CRUD with Type-2 wrapping
  on the way out, Type-2 unwrap on the way in. Recipient list lives in a single secure
  note titled `Ragewarden Recipients (do not edit)`.
- All three frontends drop their fixture / local-file stores in favor of the real vault.
- ragedroid: replace `DemoVaultStore` with a `BitwardenVaultRepository` that streams
  `DataState<List<DisplayItem>>` via the SDK + rage layer.
- ragemanifest: popup signs into Vaultwarden / bitwarden.com, lists real ciphers, the
  rage-protected ones decrypt via WASM after a software-identity click (still phase 1's
  ceremony -- phase 3 swaps in passkey).
- rageterm: `login [server]`, `logout`, `sync` commands; the local file store becomes a
  cache, not the source of truth.

**Demoable artifact:** register a new account on a Vaultwarden instance from rageterm,
add a rage-protected cipher, see it appear (encrypted) in ragedroid + ragemanifest, decrypt
on each.

### Phase 3 -- hardware identities 🟡 in progress (core stanza paths done; rageterm PIV/FIDO2 code paths written but **never executed against a real device in this tree**; ragedroid dispatch wired through `HardwareTapCoordinator`; ragemanifest tap window brokered by the background worker)

> **Read §0e before treating this phase as finished.** `real_ecdh` (`rageterm/src/piv.rs`)
> and `real_prf` (`rageterm/src/fido.rs`) are no longer `NotImplementedReal` stubs -- they
> drive PCSC / CTAP2 for real. What is still missing is the *gating*: rageterm decides
> whether to demand a tap from a vault-global flag rather than from the item's stanza set,
> and it cannot read a PIV slot's touch policy back. Both are listed in §0e as NOT YET
> IMPLEMENTED. Nothing in this section has been run against physical hardware here.

- `ragewarden-core`: implement the `piv-p256`, `fido2-hmac`, `webauthn-prf-v1`,
  `ragedroid-keystore-v1` stanza paths (parsing + body-wrap) so the trait callback can
  land them without re-implementing the AEAD/ECDH layer per frontend.
- `rageterm`: `enroll-yubikey` (PCSC PIV), `enroll-fido2` (ctap-hid-fido2 hmac-secret),
  `enroll-keyring` (OS keyring), `enroll-recovery` (paper BIP39). Concurrent-access lock
  at `$XDG_RUNTIME_DIR/ragewarden.lock`.
- `ragedroid`: yubikit-android PIV (NFC + USB-OTG); yubikit-android FIDO2 hmac-secret;
  Credential Manager passkey path on API 34+; StrongBox / TEE Keystore identity.
- `ragemanifest`: passkey-first via `navigator.credentials.create({...prf...})` and
  `.get(...)`. Recovery passphrase identity available across all three.
- Multi-recipient round-trips verified: a cipher encrypted on ragedroid to {primary
  YubiKey, backup YubiKey, Keystore, recovery} unlocks on each frontend that owns one of
  those recipient kinds.

**Demoable artifact:** real YubiKey tap on the Pixel 7 emulator (USB-OTG) decrypts a
ragedroid cipher; the same cipher unlocks via Touch ID passkey in ragemanifest; same
cipher unlocks via ctap-hid-fido2 in rageterm -- without ever touching the master password
again after the initial unlock.

### Phase 4 -- platform integrations ✅ scaffolding DONE

- `ragedroid`: ✅ Android Autofill API service (`RagewardenAutofillService` --
  cold-dataset tap ceremony via `AutofillAuthActivity`; action named in the dataset
  remote view before the user authorizes); ✅ IME service (`RagewardenInputMethodService` --
  Compose-hosted vault picker, `commitText` then `switchToPreviousInputMethod()`); ✅
  manifest registration with the right permissions; ✅ standard / fdroid product flavors
  (Play-services-aware `androidx.credentials` lives under `standardImplementation`);
  Robolectric tests for autofill heuristics + host matcher. Real hardware identity
  ceremony lands when phase 3 ragedroid integration completes.
- `rageterm`: ✅ `native-host` mode for ragemanifest (length-prefixed JSON-RPC,
  `unwrap_stanza` routes through enrolled identities; **stubbed pending hardware test** --
  desktop notification names the action before the trait callback runs, mock-mode
  identities answer in-process, real PIV/FIDO2 paths still go through the §3a-3b stubs);
  ✅ `install-native-host` / `uninstall-native-host` for Chromium / Firefox / Safari
  (writes per-OS manifest paths on macOS+Linux, registry keys on Windows); ✅
  `pass-import` one-way migration from `~/.password-store/` (real `gpg --decrypt`
  subprocess, plaintext zeroized after re-encrypt); ✅ `agent add` (parses OpenSSH PEM
  via `ssh-key` and writes directly to `$SSH_AUTH_SOCK` -- the plaintext never touches
  disk or any process's argv; the encoded request buffer is `Zeroizing` and pre-sized so
  it cannot reallocate and strand an unwiped copy; `--lifetime SECS` honoured via
  `SSH_AGENTC_ADD_ID_CONSTRAINED`); ✅ `fill --to <pid:N|class:NAME|title:SUBSTR|focused>`
  autotype dispatch (xdotool / ydotool / cliclick / SendInput; Windows path stubbed
  pending real-platform test, missing-tool errors point at `brew/apt`); ✅ `pass`-style
  command aliases (`show`, `insert`, top-level `-c <NAME>`).

  **argv, precisely.** The *secret itself* reaches every autotype backend over a pipe:
  `xdotool type --file -`, `ydotool type --file -`, and -- since the macOS path was fixed --
  `cliclick -f -` reading its command stream from stdin, rather than the old
  `cliclick t:<secret>` which put the plaintext in `ps` for the child's lifetime. One
  piece of *secret-derived* material does still go through argv: `copy` spawns a detached
  clipboard-clear helper with an unsalted hex SHA-256 of the plaintext as `argv[3]`, so it
  can check the clipboard has not changed before wiping it. That digest is readable in
  `/proc/<pid>/cmdline` for the whole clear window (30 s by default) and is offline-
  guessable for a low-entropy secret. Passing it over a pipe or an inherited fd instead is
  **NOT YET IMPLEMENTED**.
- `ragemanifest`: ✅ scaffolding done -- content-script autofill glue
  (`ragemanifest/ext/content.js`, closed-Shadow-DOM chip + prompt sheet, InputEvent
  typing against the native `value` setter, focus-driven field detection with the same
  heuristic family ragedroid uses); ✅ background service worker
  (`ragemanifest/ext/background.js`, `vault.fetch / lookup / unlock` over
  `runtime.sendMessage`, WASM re-instantiated per cold worker, native-host probe + PIV
  unwrap path); ✅ `glue/native-host.js` adapter that proxies `unwrap_stanza` to
  `rageterm --native-host` when installed (post-MVP cross-frontend interop, see §3b);
  ✅ Firefox MV3 build at parity with Chromium (event-page background script,
  `gecko.id` + `strict_min_version: 132`, `nativeMessaging` dropped per round
  scope, `web-ext lint --self-hosted` clean, manifest-shape assertions in
  `build.mjs`); ✅ Safari host-app skeleton at
  `ragemanifest/safari-host-app/` (Swift `Package.swift` + `RagewardenHost` AppKit/
  SafariServices stub + README documenting Apple Developer ID / App Store submission);
  ✅ `build.mjs` selects the per-browser manifest, drops Safari's `nativeMessaging`
  permission, and emits `dist/ragemanifest-<browser>.zip` with `--zip`. 🟡 still TODO:
  AMO upload pipeline; App Store submission ceremony; production-grade icon set.
- `ragedroid`: F-Droid flavor build + metadata.

**Demoable artifact:** real autofill into a phishing-resistant browser form on Android;
PIV YubiKey unlock from a Chromium extension via the native messaging host; keyboard-
based autotype from rageterm into any Linux X11 window.

### Phase 5 -- production 🟡 TOTP + CI scaffolding + audit policy + baseline profile + reproducible-build verification + QR enrollment + bulk-protect wizard DONE; signed releases + store distribution pending

- ✅ TOTP: `core::totp` exposes RFC 6238 generator (SHA1/SHA256/SHA512); rageterm has a
  `totp <name> [--copy]` subcommand, ragedroid surfaces a TOTP card with countdown on
  the item-detail screen via the `RageNative.totpGenerate` JNI bridge, ragemanifest
  exports `wasm_totp_generate` for the popup glue. Same code, three frontends.
- ✅ QR enrollment: `TotpEnrollScreen` in design (camera viewfinder + manual base32/otpauth entry
  with live TOTP preview); ragedroid `EditItemScreen` QR scan via zxing-android-embedded;
  ragemanifest popup file-upload decode via jsQR.
- ✅ Bulk-protect-existing-items wizard: `BulkProtectWizard` (design + ragemanifest glue +
  ragedroid `BulkProtectScreen`) -- select unprotected items -> pick recipients -> per-item
  re-encrypt with progress tracking.
- Organization sharing: public-key fanout for recipients shared across users
  (separate threat model -- design-doc level only in this phase).
- Cold-start perf budgets and scroll-jank budgets per frontend; ✅ baseline
  profile for ragedroid (`ragedroid/baselineprofile/` runs the
  `BaselineProfileGenerator` macrobenchmark on a pixel6Api34 managed device and
  the `androidx.baselineprofile` plugin packages the result into the APK);
  Speedometer-style scroll bench for ragemanifest still TODO.
- ✅ Security audit prep: `SECURITY.md` documents reporting channel and scope; the
  rest (whitepaper, audit firm engagement, signed disclosure) lands once we cut a
  release-candidate tag.
- ✅ CI/CD: `.github/workflows/ci.yml` + `release.yml` cover the Rust workspace
  (linux + macOS, fmt+clippy+test+doc), ragemanifest wasm-pack build, ragedroid
  android matrix (standard + fdroid), rageterm cross-target builds (linux x86/arm64,
  macos x86/arm64 with universal lipo, windows). Dependabot weekly cargo + gradle.
- ✅ Reproducibility: `scripts/repro/verify-rageterm.sh` /
  `verify-ragemanifest-wasm.sh` / `verify-ragedroid.sh` rebuild each artifact and
  compare the b3sum against `scripts/repro/EXPECTED_HASHES.txt` (regenerated
  per tag with `--update-expected`). The release workflow runs the trio in a
  `repro-build` job that gates the GitHub Release, and uploads
  `EXPECTED_HASHES.txt` as a release artifact so downstream rebuilders can
  diff against ours. See `SECURITY.md` for the verification path.
- Distribution & signing: Play Store + F-Droid for ragedroid; Chrome Web Store + AMO
  + App Store for ragemanifest; Homebrew tap + GitHub Releases (signed) + cargo install
  for rageterm. Apple Developer ID + notarization for the macOS host app and rageterm
  binary; Authenticode for Windows.
- Docs site: ragewarden.dev or similar -- public-facing threat model, install guides,
  ecosystem map.

**Demoable artifact:** end-user installs ragewarden via their preferred channel,
imports their `pass` store, the secrets sync to all their devices, and every reveal
costs one tap on the closest passkey-bearing device.

### Out-of-scope through phase 5

- Sends (Bitwarden's secure-share feature). Different threat model; maybe phase 6+.
- Self-hosting Vaultwarden as a Ragewarden-bundled service. Out of scope; users bring
  their own.
- Cross-vault migration tools beyond `import-pass`. Bitwarden web export -> Ragewarden
  re-encryption belongs in phase 4 if cheap.
- iOS native client (would need a separate `rageios` frontend; ragemanifest-as-Safari-
  extension partially covers iOS Safari users).

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
