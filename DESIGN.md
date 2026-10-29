# Ragewarden -- Ecosystem Design

A Bitwarden-compatible secrets ecosystem where each individual credential is wrapped in a
hardware-tap layer (age recipients backed by YubiKey PIV, FIDO2 hmac-secret, or platform
secure-enclave identities) on top of the regular Bitwarden master-password layer.

Three coordinated products, one shared core:

| product | runtime | purpose |
|---|---|---|
| ragedroid | Android (Kotlin + JNI) | mobile client; autofill, accessibility, NFC YubiKey |
| ragemanifest | Browser MV3 (Rust -> WASM) | Chromium / Firefox / Safari web extension; webauthn for tap, autofill into pages |
| rageterm | Native binary (Rust) | CLI by default, `--tui` for interactive; SSH-agent-style integrations |

The pitch: a phishing-resistant Bitwarden where the master password leaking does not leak any
of the actual secrets. Every individual use of a credential requires a deliberate physical
action.

## 0. Design principles

These are non-negotiable across all three frontends.

### 0a. Action chosen before tap; tap consents to that specific action

The user picks the action first, then taps to authorize it. The tap is not "unlock the
secret and decide later" -- it's "do this specific thing with the secret, now." There is no
intermediate "decrypted but undecided" state in any frontend.

Concretely, the user's options before tapping include (frontend-dependent):

- Autofill -- deliver to the active form field (web, Android autofill API, ragedroid IME).
  Plaintext flows from ragewarden-core -> autofill IPC -> the form. Never displayed on screen.
- Copy to clipboard -- for pasting into apps without autofill. Cleared after 30s by
  default; cleared immediately when the app loses focus.
- Reveal on screen -- display plaintext until the sheet is dismissed. Last-resort path,
  not the headline button.
- Pipe to stdout / stdin (rageterm) -- `rageterm get foo | ...` writes plaintext to stdout
  for one process and exits. Useful with `ssh-add`, `aws-vault`, ad-hoc shell scripts.
- Load into agent (rageterm) -- push an SSH key into ssh-agent, a token into a credential
  helper.

UI should not present "tap your YubiKey" with no action context. Every tap prompt names the
action (`"Autofill into github.com?"`, `"Copy github.com password to clipboard?"`,
`"Reveal github.com password?"`). This is the user's consent surface -- what they see in the
prompt is exactly what happens on tap. No bait-and-switch path exists.

Why this matters:

- Plaintext lifetime is microseconds. Decrypt -> deliver -> zeroize, all in one fire.
  Compare to "decrypt -> user picks -> deliver" where the plaintext sits in a buffer for
  seconds.
- Consent is bound to use. The tap authorizes one specific consumption, not ambient
  decryption. A compromised UI that rewrites the action name still has to convince the user
  to tap for that action.
- No one-tap-many-uses. Reinforces strict tap per use: the action and its tap are atomic;
  doing two actions means two taps.
- Domain visible at tap. Autofill prompts include the requesting origin
  (`github.com`, not just "the active page") so the user can cancel a phishing prompt before
  tapping.

### 0b. Strict tap per use

One physical action per use. No caching of decrypted secrets across uses. Repeated autofill
against the same site within seconds = repeated taps. Documented and surfaced in onboarding so
expectations match reality.

(Outer Bitwarden master-key cache is unaffected -- only the rage layer is strict.)

Every client runs the device ceremony for each use of a hardware-wrapped secret and caches
no plaintext between uses. This is client policy, not a property of the stanza format --
nothing in a stanza forces a device round trip -- so it is tested in each client rather
than proved by the crypto. Recipients without a device confirm differently: rageterm's
software and OS-keyring identities ask y/N, and a paper identity asks for its phrase. On
ragedroid below API 35 an auth-bound Keystore key stays usable for 30 seconds after its
prompt, because Android cannot bind a key agreement to a single prompt before Android 15;
from API 35 every use prompts.

### 0c. Plaintext lifecycle is the shortest possible

Once the rage layer decrypts a secret, the plaintext exists in memory only long enough to
deliver to its consumer (autofill API, clipboard, agent socket), then the holding buffer is
zeroized. No process-wide cache, no plaintext field on a ViewModel state, no plaintext in
logs. The Rust core uses `zeroize` for sensitive byte arrays; frontends pass plaintext
through narrow channels and discard.

Core keeps plaintext, file keys and the user key in zeroizing memory. rageterm's global
allocator (`rageterm/src/zalloc.rs`) wipes every heap block as it is freed, so the copies a
library keeps -- arboard's clipboard value, serde's and the standard library's growing
buffers -- are zeroed when released; a copied value lives in the clipboard serve child for
the clear window and no longer. ragedroid hands secrets to the clipboard, autofill and the
keyboard as char buffers it zeroes after delivery; the String copies Android's own APIs
take are listed in `ragedroid/docs/THREAT-MODEL.md` §5.4. The extension drops values after
delivery and hides reveals after 10 seconds.

### 0d. The server stores no secret it can use

Defense-in-depth: even if Bitwarden / Vaultwarden is fully compromised, the server has only
double-encrypted blobs. The rage layer is opaque to the server; the master-password layer
has always been opaque. Compromising both layers requires the attacker to hold a hardware
recipient -- by design, server compromise alone cannot reach plaintext.

A software recipient (rageterm's `identity.age` or keyring identity, a paper phrase) is
protected by its own key material on the user's device rather than by a hardware device;
§0d is a statement about the server, not about a stolen laptop. rageterm encrypts
`identity.age` under a passphrase unless it is enrolled with `--plaintext` or without a
terminal (`protect-identity` encrypts it later).

### 0e. Data written by earlier versions

Every client writes the current formats. Blobs written before them stay readable, and some
are weaker:

- Three-argument `webauthn-prf-v1` / `fido2-hmac` stanzas, written before the per-stanza
  `wrap_salt`, used one body key for every secret of an authenticator under a zero nonce
  (a ChaCha20 keystream and Poly1305 key reuse). Treat those secrets as exposed and rotate
  them. `core::legacy_prf_wraps` counts them from the header -- rageterm `list` marks
  `[legacy-wrap]`, the extension and ragedroid flag the item -- and `rageterm reencrypt
  --legacy`, the extension's Re-save and ragedroid's re-encrypt offer re-wrap them
  (`core::rewrap`). Current stanzas draw a fresh 32-byte `wrap_salt` each
  (`core/DESIGN.md` §2d).
- PRF stanzas written before per-secret salts carry the recipient's enrolment salt, so one
  captured PRF output opens every such stanza of that recipient. Every client now asks its
  authenticator for a fresh salt per write (`core::prf_requests_for`); re-wrapping the
  item -- a new secret, a rotation, a re-encrypt, a bulk re-wrap -- replaces them.
- v1 PIV and Android-Keystore stanzas derive their body key without the recipient's public
  key. v2 tags bind it; a recipient switches to v2 once its registry entry advertises
  `stanzaVersion: 2` (`core/DESIGN.md`).
- YubiKey X25519 slots cannot sign, so native-host unwraps through them are recorded as
  unattested; `rageterm migrate-piv` moves every item to a P-256 slot.

## 1. Threat model

| threat | Bitwarden today | Ragewarden |
|---|---|---|
| Server compromise (encrypted blobs leak) | safe | safe (same outer layer + opaque inner layer) |
| Master password phishing / keylogger / reuse | all secrets exposed | safe -- secrets stay opaque without a hardware tap |
| Compromised endpoint with clipboard / accessibility / page-script access | accessible secrets stay accessible | each use requires a tap; a captured PRF output opens only the one secret it was evaluated for (older enrolment-salt stanzas: see §0e) |
| Lost YubiKey | n/a | covered if user enrolled a backup recipient |
| Lost YubiKey + lost backup + skipped recovery identity | n/a | secrets unrecoverable; loud documentation |
| Malicious server flips a feature flag mid-rollout | server has authority | unaffected -- rage layer is inside the cipher payload, opaque to server |
| Autofill triggered by hostile site (phishing form) | risk of phishing the visible secret | tap + visible-domain confirmation in the tap UI; user sees what they're consenting to |

The rage layer is strictly additive. Removing all recipients reduces ragewarden to a vanilla
Bitwarden client.

## 2. Crypto layering (unchanged across all three frontends)

The protected value -- one field's bytes, or for an item that protects several fields a
versioned field map (`core::protected`) -- is rage-encrypted to N recipients (X25519 and
plugin stanzas) into an ASCII-armored age blob, which is then wrapped in a Bitwarden
Type-2 EncString (AES-256-CBC + HMAC-SHA-256 under the user symmetric key) and stored as the
`rage:v1` custom cipher field on the Bitwarden server.

Both layers are required. Master password unlocks the vault to recover the age blob; hardware
tap unwraps the age blob to recover the plaintext. Either alone yields nothing useful.

## 3. Where the rage blob lives in a Bitwarden cipher -- DECIDED

- `rage:v1` custom field of type `HIDDEN` on the cipher. Stores the ASCII-armored age
  blob.
- The protected fields are blank in the Type-2 layer (a login's password, a card's number
  and code, ...). An SSH key's protected fields hold marker text instead, because Vaultwarden
  drops an SSH key block with any of its three fields missing.
- `rage:fields` lists the protected field names when they are more than the item type's
  primary field; a blob without it holds the primary field only.
- An item without notes gets the line `"⛓ Protected with Ragewarden"`, so a non-ragewarden
  client (web vault, official apps) shows something explanatory rather than empty.
- The payload inside the blob is versioned -- v1 is the primary field's bytes, v2 a field
  map -- and the field name stays `rage:v1`; servers and other clients ignore it.

This format works for any Bitwarden server, including Vaultwarden.

## 4. Workspace layout

Cargo workspace at the project root: `core/` (ragewarden-core, the shared Rust library),
`ragedroid/` (Android frontend -- Kotlin Compose `app/` plus a `jni/` Cargo crate bridging
to the core), `ragemanifest/` (browser extension -- wasm-bindgen crate, per-browser MV3
manifests, JS glue), and `rageterm/` (CLI / TUI binary crate). Each frontend directory has
its own `DESIGN.md` and `README.md`.

Top-level `Cargo.toml` declares `members = ["core", "ragedroid/jni", "ragemanifest", "rageterm"]`.
The Android Gradle build invokes `cargo-ndk` against `ragedroid/jni`; the web extension build
invokes `wasm-pack build ragemanifest`; the CLI is plain `cargo build -p rageterm`.

## 5. The shared `ragewarden-core` API surface

`core/` is the one crate every frontend links (`core/DESIGN.md` has the detail):

- `encrypt` / `encrypt_with_prf` / `decrypt` over `Recipient` values and `Identity`
  implementations -- the trait hardware identities implement by calling back into the
  frontend -- plus `legacy_prf_wraps` and `rewrap` for older stanzas, and `protected` for
  the single- and multi-field payload.
- `bitwarden`, `kdf`, `type2`: PBKDF2 and Argon2id master keys, the master-password hash,
  Type-2 EncStrings.
- `sync`: login with a KDF pin and consented legacy-KDF upgrade, token refresh, vault
  fetch, and cipher builders that keep every field of the server copy (login, secure note,
  card, identity, SSH key) over an injected HTTP client (OkHttp on Android, `fetch` in wasm,
  reqwest in rageterm).
- `registry`, `policy`, `history`, `audit`: the cross-device recipient registry, the one
  recipient-selection policy, the shared revision-history document and the audit
  vocabulary every client writes.
- `totp`, `generator`, `recovery`: RFC 6238 codes, passwords and passphrases, BIP39 paper
  identities.

Each frontend supplies the identities for its own devices:

| frontend | identities |
|---|---|
| ragedroid | `YubiKeyPivIdentity` (yubikit-android over NFC and USB, P-256 and X25519 slots), `Fido2HmacIdentity`, `AndroidKeystoreIdentity` (StrongBox or TEE), `PasskeyIdentity` (Credential Manager with PRF), the paper recovery identity |
| ragemanifest | WebAuthn PRF passkeys (the browser's own, and phone passkeys through the relay page), PIV and FIDO2 keys through rageterm's native-messaging host, the paper recovery identity |
| rageterm | `PivIdentity` (PC/SC), `Fido2Identity` (CTAP2 hmac-secret), the OS-keyring and software identities, the paper recovery identity |

Passkeys are the browser's primary path -- we don't prescribe a specific hardware token
in ragemanifest. The browser handles authenticator selection, biometrics, tap UI, and the
cross-device phone flow uniformly. See `ragemanifest/DESIGN.md` §2 for details.

When frontend A encrypts to a recipient that frontend B can't unwrap (e.g., ragedroid encrypts
to its Android Keystore identity, then user opens the same cipher in ragemanifest), B sees
the stanza but has no matching identity -- falls back to the next stanza in the header. This
is age's normal behavior; multi-recipient is what makes it work.

## 5b. End-to-end test harness

Manual user testing is replaced where possible by a layered harness documented at
[`E2E.md`](./E2E.md):

- Tier 1 -- Rust against a real Vaultwarden: `rageterm/tests/e2e_vaultwarden.rs` and
  `e2e_protocol.rs` run register, login, KDF upgrade, refresh, typed items, folders and
  cross-frontend decrypts against the native Vaultwarden the dev shell provides, or Docker
  (CI job `e2e-vaultwarden`). The NixOS-config checks add `ragewarden-e2e` (the rageterm
  CLI against `services.vaultwarden`, with the clipboard and Secret Service keyring under
  Xvfb and a session bus), `ragewarden-canokey` and `ragewarden-canokey-touch` (PIV and
  FIDO2 against a virtual CanoKey, touch sensor included).
- Tier 2 -- the extension in Chromium via Playwright with a CDP virtual authenticator
  (CI job `e2e-playwright`), Firefox over WebDriver BiDi, and the hermetic NixOS-config check
  `ragemanifest`.
- Tier 3 -- Android: the Robolectric suite on every build, the instrumented suite on an
  emulator (CI job `e2e-android`), and `tests/journey/run.sh`, which runs rageterm, the
  extension and the phone against one Vaultwarden.

`SECURITY.md` carries the release-gate checklist of manual ceremonies that genuinely
need a person (real YubiKey tap, real Touch ID, real store submissions); CI catches the rest.

## 6. Decisions table

| # | question | decision |
|---|---|---|
| 1 | Code sharing across the three products | Single Rust workspace; ragewarden-core shared library; thin frontends. |
| 2 | Browser targets for ragemanifest | Chromium MV3 + Firefox + Safari from v1. Three manifests, common WASM core. Safari is a meaningful additional cost (Xcode, App Store, host-app shell). |
| 3 | rageterm shape | Plain CLI by default, `--tui` flag for interactive ratatui mode. All operations need both code paths. |
| 4 | age implementation | `age` Rust crate, shared by all three frontends via `ragewarden-core`. |
| 5 | Recovery story | Optional paper identity at first-run. Add it later by re-encrypting selected ciphers (same machinery as adding a new YubiKey). Per-cipher state observable as "is the recovery pubkey in the stanza list?" |
| 6 | Account scope | Share existing Bitwarden / Vaultwarden account. Protected and unprotected ciphers coexist. |
| 7 | Caching | Strict tap per use, no caching of decrypted secrets. |
| 8 | Storage location in cipher | `rage:v1` custom HIDDEN field; `login.password` empty; explanatory marker in `notes`. |
| 9 | Authenticator (TOTP) integration | Codes in all three clients from core's RFC 6238 generator; a TOTP seed can be one of an item's protected fields. |

## 7. Sequencing

Five phases, each ending in a cross-frontend slice.

- Phase 1 -- software-identity demo end-to-end. Done (`c4d643e`, `c917f20`, `40782b3`,
  `c64186d`).
- Phase 2 -- real vault. Done: core `sync` (login, KDF, sync, cipher CRUD, refresh) used by
  all three frontends; the recipient registry note.
- Phase 3 -- hardware identities. Done: `piv-p256` (P-256, age-plugin-yubikey's format),
  `piv-x25519-v2`, `fido2-hmac`, `webauthn-prf-v1` and `ragedroid-keystore-v1/v2` stanzas in
  core; YubiKey PIV and FIDO2 in rageterm and ragedroid, Android Keystore (StrongBox or
  TEE), passkeys with PRF in ragedroid and the extension, paper recovery everywhere. CI and
  the NixOS checks prove them against a virtual CanoKey and emulators; the physical-device
  sign-off is the release checklist in `SECURITY.md`.
- Phase 4 -- platform integrations. Done:
  - ragedroid: Autofill service with inline suggestions on Android 11+, the keyboard (IME)
    with an unlock and tap path, standard and fdroid flavours.
  - rageterm: native-messaging host for the extension (signed touch proofs from P-256 slots
    and FIDO2 credentials; Chromium, Firefox and, through the app, Safari),
    `install-native-host`, `pass-import`, `agent add` (Unix socket and Windows OpenSSH
    pipe), `fill` autotype (xdotool, ydotool and Windows SendKeys with the secret over a
    pipe; on macOS in-process CoreGraphics keyboard events, cliclick as the fallback),
    `exec` (secret on fd 3, or an inherited handle on Windows).
  - ragemanifest: content-script autofill in every frame, Chromium, Firefox and Safari
    builds, the passkey relay for phone passkeys, the Chrome Web Store package and AMO
    signing in the release workflow.
- Phase 5 -- production. Done: TOTP in all three clients; QR enrolment in ragedroid; bulk
  protect and bulk re-encrypt; CI (fmt, clippy, tests, wasm, Android matrix, cross-target
  rageterm, Playwright, emulator); reproducible-build verification (`SECURITY.md`); the
  ragedroid macrobenchmarks and baseline-profile generator (`tests/journey/run.sh` with
  `JOURNEY_BENCH=1`). Remaining: store submissions and signing (Play, Chrome Web Store,
  App Store, notarization, Authenticode), Homebrew and crates.io, a docs site, a scroll
  benchmark for the extension, the third-party audit and v1.0.

Demoable artifact: an end user installs ragewarden from their preferred channel, imports
their `pass` store, the secrets sync to all their devices, and every reveal costs one tap
on the closest passkey-bearing device.

### Out-of-scope through phase 5

- Sends (Bitwarden's secure-share feature). Different threat model; maybe phase 6+.
- Self-hosting Vaultwarden as a Ragewarden-bundled service. Out of scope; users bring
  their own.
- Cross-vault migration tools beyond `pass-import`.
- iOS native client (would need a separate `rageios` frontend; ragemanifest-as-Safari-
  extension partially covers iOS Safari users).

## 8. Out of scope (v1)

- Replacing the Bitwarden server.
- Editing rage-protected values from non-ragewarden clients: they see the metadata and the
  marker note, not the protected fields.
- Sharing rage-protected ciphers with other Bitwarden users (would require knowing their
  recipients).
- Sends. Maybe never; the threat model differs.
- Family / org account flows. v2.

## 9. Distribution

| product | channel |
|---|---|
| ragedroid | Google Play (`ragewarden.ragedroid`), F-Droid (`ragewarden.ragedroid.fdroid`), signed APK on GitHub releases |
| ragemanifest | Chrome Web Store, Firefox Add-ons (AMO), App Store (Safari requires the macOS host app pattern) |
| rageterm | GitHub releases (linux x86_64, linux aarch64, macos universal, windows x86_64), homebrew formula, optional cargo install |

Reproducible builds for all three. Source-distributed via this repo.
