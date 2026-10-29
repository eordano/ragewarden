# RageDroid -- Android frontend

Android client for the [Ragewarden](../DESIGN.md) ecosystem. Read the ecosystem design first
for threat model, crypto layering, and shared decisions. This file is Android-specific.

---

## 1. Modules

Two Gradle modules plus a Cargo crate: `app/` (the Compose app -- data repositories,
identity impls, autofill/IME services, and UI all live under
`app/src/main/kotlin/ragewarden/ragedroid/`), `baselineprofile/` (see §7), and `jni/` (a
Cargo crate whose `src/lib.rs` is the JNI surface over ragewarden-core; cargo-ndk builds
`libragedroid_jni.so`). Reuses `ragewarden-core` (this project's Rust crate) via the
`jni/` bridge for the inner layer; the outer Bitwarden layer also comes from the core's
`bitwarden`/`sync` modules over JNI (no `com.bitwarden:sdk-android` dependency -- see §8).

---

## 2. JNI bridge

Hand-written `extern "system"` JNI exports in `jni/src/lib.rs`, paired with `external fun`
declarations on the Kotlin side (`app/.../jni/RageNative.kt`). We considered UniFFI early on
but kept it hand-written (about 30 exports, `jni/src/lib.rs` and `jni/src/lock_jni.rs`)
because the JNI byte-array lifetime semantics matter enough that we'd rather audit them
ourselves than read generated code.

`RageNative.kt` declares them as `external fun`s on one object that loads
`libragedroid_jni.so`. Hardware identities are Kotlin objects implementing `KotlinIdentity`;
the bridge calls back into them while core decrypts, and Kotlin blocks that JNI thread on
the device ceremony via a dedicated dispatcher, never the main thread. Every export runs
inside `catch_unwind`, so a Rust panic surfaces as `RageNativeException.Internal`.

Build: `gradle :app:assembleStandardRelease` triggers a `cargo-ndk` task that compiles
`jni/` for `arm64-v8a` and `x86_64` (API 31), deposits `libragedroid_jni.so` into
`app/src/main/jniLibs/<abi>/`. Standard NDK pipeline.

---

## 3. Identity implementations

| identity | Kotlin class | stanzas |
|---|---|---|
| YubiKey PIV | `YubiKeyPivIdentity` | `piv-p256` (P-256 slots, age-plugin-yubikey's format), `piv-x25519-v2` and v1 |
| FIDO2 hmac-secret | `Fido2HmacIdentity` | `fido2-hmac` |
| Passkey (Credential Manager) | `PasskeyIdentity` | `webauthn-prf-v1` |
| Android Keystore | `AndroidKeystoreIdentity` | `ragedroid-keystore-v2` and v1 |
| Recovery (BIP39) | not a `KotlinIdentity`: Settings -> Recover from phrase calls `BitwardenVaultRepository.decryptWithRecoveryPhrase` | age X25519 |

Each runs against mocks in CI (`RAGEWARDEN_MOCK_HARDWARE=1`) and the Keystore identity also
against a real Keystore key on the emulator; physical YubiKeys and passkeys are on the
release checklist in `../SECURITY.md`.

The `KotlinIdentity` interface (`app/.../identities/KotlinIdentity.kt`) declares
`tryUnwrap(stanzaTag, stanzaArgs, stanzaBody)`, which the JNI bridge invokes through
`tryUnwrapBlocking`'s `runBlocking { ... }` on `Dispatchers.IO`. Each implementation owns the
match check (`stanzaTag` + arg shape + recipient-tag/credential-id) and dispatches the
hardware ceremony. AEAD body unwrap goes through the small JNI helpers
(`unwrapPivP256` / `unwrapKeystore` / `unwrapWebauthnPrf` / `unwrapFido2Hmac`) so the wire
format lives in `core::stanza_format` and the Kotlin side never re-implements ChaCha20-
Poly1305 / HKDF. `RAGEWARDEN_MOCK_HARDWARE=1` swaps each ceremony for a deterministic
software stand-in so CI exercises every callback path without real hardware.

### 3a. YubiKeyPivIdentity

yubikit-android's NFC and USB managers yield a connection (a key already plugged in when
the prompt opens is used at once); the identity opens a `PivSession`, checks the card's
serial against the enrolled one -- a different YubiKey is named before its PIN is used --
verifies the PIN if the slot needs it, and runs ECDH for the slot (P-256 for new
enrolments, X25519 for older slots). The shared secret goes to the JNI unwrap helper. The
PIN is entered once per tap and never cached across sessions.

### 3b. Fido2HmacIdentity

Credential Manager assertions with the hmac-secret / PRF extension unlock `fido2-hmac`
stanzas, the format rageterm writes for security keys it talks to directly. The stanza
carries the credential id and the evaluated salt.

### 3c. PasskeyIdentity (Credential Manager)

Unlocks `webauthn-prf-v1` stanzas. New passkeys are created for the relying party
`ragewarden.decent.foundation` (`PasskeyRp`), discoverable and ES256; the domain serves
`/.well-known/assetlinks.json` naming this app and its signing certificate, which Credential
Manager requires. The registry entry is a `PasskeyPrf` recipient carrying the RP id, the
credential id and the credential's public key (`attestationPublicKey`, SPKI), which is what
lets the browser use the same passkey through its relay page. Entries stored before the RP
id was recorded keep asserting with `ragewarden.local`, and older Fido2-kind passkey entries
move to `PasskeyPrf` on request. Every write evaluates a fresh salt per passkey.

Availability: the standard flavour uses Play services' Credential Manager on any supported
Android; the F-Droid flavour uses Android 14's built-in one.

### 3d. AndroidKeystoreIdentity

Local-only convenience identity. P-256 EC keypair generated in StrongBox-backed Keystore
(falls back to TEE if StrongBox unavailable). The recipient is the 33-byte SEC1-compressed
P-256 public key; the stanza carries the key handle and an ephemeral P-256 public key whose
ECDH share with the Keystore key wraps the file key.

User authentication: the key requires a biometric or the device credential. On API 35+ every
key agreement is its own prompt (the `KeyAgreement` is the `CryptoObject`); below 35 the
key stays usable for 30 seconds after a prompt run just before the decrypt. A key without
user authentication (no screen lock set) is generated only after the user agrees to it.

Wire format: `ragedroid-keystore-v2` (recipient-bound) and `-v1` in `../core/DESIGN.md`.

---

## 4. UI flows -- action chosen before tap

### 4a. Vault list

Compose `LazyColumn` over decrypted-cipher-metadata (the Bitwarden cipher minus the rage
field, which stays opaque until use). Per-cipher chip indicating "🔒 ragewarden" if `rage:v1`
is present.

### 4b. Item detail

The password area is replaced with explicit-action buttons. **No "show me the decrypted
state" button exists** -- every action names where the plaintext is going.

```
[ Autofill into ...  ]   <- shown when invoked from autofill flow; pre-bound destination
[ Copy password    ]   <- clipboard with 30s auto-clear
[ Send to keyboard ]   <- IME injection (4d)
[ Reveal           ]   <- fallback; small text button
```

Tapping any of these opens the **YubiKey sheet** (4c) with that destination pre-bound. The
sheet's prompt names the destination explicitly so the user's tap consents to *that*.

### 4c. The YubiKey sheet

Bottom sheet with:

- A title naming what's about to happen: `"Copy github.com password?"`,
  `"Autofill into github.com?"`, etc. Domain visible.
- A subtitle showing which recipients can unlock this cipher.
- An animation prompting NFC tap or USB-OTG insertion.
- Passive listener for both NFC and USB; whichever fires first wins.

On successful unwrap:

1. ragewarden-core decrypts the blob.
2. Frontend hands the plaintext directly to the bound destination -- clipboard set,
   `FillResponse` returned, IME `commitText`'d, or reveal text shown.
3. Buffer zeroized.
4. Sheet dismisses with success animation.

On cancel / timeout / hardware error: plaintext was never produced. Sheet dismisses with the
error reason.

The plaintext never lives in a "decrypted but undelivered" state. Bait-and-switch from a
hostile screen overlay would have to convince the user to tap with the *correct destination
already named in the prompt*; the prompt cannot be tampered with post-tap.

**Tapjacking is refused at two levels.** `MainActivity.onCreate` and
`AutofillAuthActivity.onCreate` set `window.decorView.filterTouchesWhenObscured = true`, and
the IME sets it on its input view, so Android discards touches delivered while the window is
obscured by an overlay. On top of that, every control that releases a secret or destroys a
key -- Authorize, Type it, Unlock, the PIV PIN pad, Revoke and its master-password confirm --
rejects any touch carrying `FLAG_WINDOW_IS_OBSCURED` or `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`
(`rejectObscuredTouches`), which also catches a partially-covering overlay the window flag
lets through. `ObscuredClickTest` dispatches flagged presses and checks they are dropped. And
for the `AndroidKeystore` recipient kind the gate is per operation on API 35+ (the
`KeyAgreement` is the `BiometricPrompt.CryptoObject`); below API 35, where it cannot be, the
key falls back to a 30-second `setUserAuthenticationParameters` window and the UI prompts
before each reveal. See `docs/THREAT-MODEL.md` §3.

### 4d. IME injection (`Send to keyboard`)

Ragedroid ships an `InputMethodService` (`ragewarden.ragedroid.ime.RagewardenInputMethodService`)
that the user can switch to per-text-field via the system input picker. When invoked,
`onCreateInputView()` returns a `ComposeView` rendering a vault list scoped to the keyboard
area, and nothing at all while the vault is locked. Every listing and delivery goes through
`ImeDelivery`, which reads `LockState` before the decrypt and again before the commit. On
success the IME calls `currentInputConnection.commitText(plaintext, 1)` then
`switchToPreviousInputMethod()`; the byte buffer is zeroized in the same `finally`.

- An unprotected item gets a plain "Type it" confirmation: no hardware authorizes it, and the
  copy says so.
- A protected item gets "Unlock and type". An `InputMethodService` cannot host
  `BiometricPrompt`, Credential Manager or NFC reader mode, so the IME opens
  `ImeAuthActivity` (secure window, obscured touches rejected), which runs the same
  `InlineTapReveal` + `HardwareTapCoordinator` ceremony as autofill with the purpose
  "Type into <app>". The plaintext comes back through `ImeAuthChannel`, a one-shot slot keyed
  by a fresh nonce, so a sheet left over from an earlier request cannot answer a later one.
  The IME commits only when the same field (package + field id) is focused again after the
  sheet closes and the vault is still unlocked; any other outcome zeroes the buffer and
  commits nothing.
- A PIV PIN asked for inside `ImeAuthActivity` is typed on a digit pad the IME shows for
  Ragewarden's own numeric fields, so the delivery does not need a keyboard switch.

The IME hosts its own `LifecycleOwner` + `SavedStateRegistryOwner` and wires both onto the
ComposeView via `setViewTreeLifecycleOwner` / `setViewTreeSavedStateRegistryOwner` -- required
for Compose to run inside an `InputMethodService`. Works in apps that don't support autofill
(legacy apps, terminal emulators).

It goes through the shared `VaultBridge` singleton, so it sees the same
`BitwardenVaultRepository` the main activity does.

### 4e. Autofill API integration (cold-dataset ceremony)

`ragewarden.ragedroid.autofill.RagewardenAutofillService` subclasses
`android.service.autofill.AutofillService`. The flow:

1. `onFillRequest` walks the latest `AssistStructure` via
   `AssistStructureWalker.walk(structure, packageName)`, harvesting an `AutofillFieldView` per
   node and classifying with `AutofillHeuristics.classify`. Heuristics check, in order:
   explicit `View.AUTOFILL_HINT_*`, HTML `type=password` / `autocomplete` / `name` / `id`
   tokens (for WebView nodes), `InputType.TYPE_TEXT_VARIATION_{PASSWORD, VISIBLE_PASSWORD,
   WEB_PASSWORD, EMAIL_ADDRESS}`, then view-id / hint substrings (`user`, `email`, `pass`,
   etc.). The walker also extracts the requesting web domain (when present) and the
   activity's package name.
2. `HostMatcher.matchVaultItems` compares registrable domains (public-suffix aware, so
   `alice.github.io` never sees `bob.github.io`), maps a package to the registrable domain of
   its reversed name, and honours explicit `androidapp://<package>` sites; no signal, no match.
3. Each match is rendered as a **cold dataset**: the dataset's autofill values are placeholder
   empty strings, and `setAuthentication(intentSender)` points the system at
   `AutofillAuthActivity`. The remote view names the action explicitly
   ("Autofill GitHub into github.com").
4. When the user picks a dataset, Android launches `AutofillAuthActivity`. That activity
   renders the same `InlineTapReveal` ceremony used in `ItemDetailScreen` with
   `TapAction.Autofill` pre-bound and the destination domain visible. **No plaintext exists
   anywhere yet.**
5. Only after the user confirms the tap does the activity decrypt through
   `BitwardenVaultRepository`, build a fresh `Dataset` carrying the real `AutofillValue.forText(...)`
   for username + password, attach it via `Intent.putExtra(EXTRA_AUTHENTICATION_RESULT, ...)`,
   `setResult(RESULT_OK)`, and finish. The dataset is what authenticated, so Android fills it
   at once (a `FillResponse` would be offered in the dropdown again). The activity runs in the
   caller's task -- standard launch mode, no `NEW_TASK` -- because a result cannot cross tasks:
   launched `singleInstance`, the caller got `RESULT_CANCELED` the moment the sheet opened. The
   activity zeroizes the `ByteArray` plaintext in the same `try/finally` that built the result.

This honors §0a (action chosen before tap -- the Android system credential picker is the
action choice, the activity confirmation is the tap) and §0c (plaintext lifetime is bounded
by the activity callback). A hostile autofill prompt cannot release plaintext because the
dataset itself is empty until the authentication intent succeeds.

When the vault is locked, the autofill dataset offers "Unlock Ragewarden to fill"
(`AutofillUnlockActivity`), and the fill proceeds after the unlock.

Further details:

- **Inline suggestions.** Datasets are built with `Presentations` and `Field` on API 33+ and
  the `setValue` overload below that. When the keyboard sends an `InlineSuggestionsRequest`,
  each matching item (up to the keyboard's slot count) and the locked "Unlock Ragewarden to
  fill" chip also carry an `InlinePresentation` built with androidx `InlineSuggestionUi`, so
  they show in the keyboard strip; every dataset still authenticates through
  `AutofillAuthActivity` before anything is filled (`AutofillDatasetsTest`, API 31/33/34).
- **Build flavors.** `app/build.gradle.kts` declares two product flavors on the
  `distribution` dimension: `standard` (Play-Store-friendly, pulls in
  `androidx.credentials:credentials` + `credentials-play-services-auth`) and `fdroid`
  (no Play Services dependencies, applicationIdSuffix `.fdroid`). The flavor-specific source
  sets at `app/src/{standard,fdroid}/kotlin/.../distribution/Distribution.kt` expose
  `LABEL` / `INCLUDES_PLAY_SERVICES`; passkey availability per flavour goes through
  `PasskeyAvailability`.
- **Saving from other apps.** Every fill response with a password field carries a
  `SaveInfo` (username optional), the locked one and the no-match one included, so Android
  offers a save when the form is submitted. `onSaveRequest` reads what was typed
  (`AssistStructureWalker.textValues`), keeps the password in process memory
  (`PendingSaves`, zeroed if not taken within two minutes) and hands `AutofillSaveActivity`
  only a token. That activity unlocks a locked vault with the lock screen, then shows what
  saving will do -- a new protected login for the site (`https://<domain>` or
  `androidapp://<package>`), or a new password for the login already saved under that site
  and username -- and writes nothing until the user presses Save: a new login through
  `VaultBackend.create` (core's `build_cipher`), a new password through `VaultBackend.edit`
  (core's `update_cipher_preserving`, which keeps the item's other protected fields or
  refuses with "Open “<item>” first"). A passkey or FIDO2 recipient's PRF tap is asked for
  by the activity itself while the write runs (`AutofillSaveTest`).

### 4f. First run

`FirstRunScreen` runs Welcome -> Sign in -> Enroll -> Backup -> Done. Sign-in (or register)
pins the account's KDF parameters, offers the upgrade of a legacy-KDF account, and installs
the `BitwardenVaultRepository`. Enroll adds a platform passkey, a security key or a YubiKey
PIV slot; Backup leads with the paper recovery phrase, which is saved only after the user
confirms words from it; Done lists anything still unprotected.

### 4g. Add and edit

`AddItemScreen` and `EditItemScreen` cover logins, notes, cards, identities and SSH keys,
each field with a Protect toggle (a login's password, TOTP seed and notes; a card's number
and code; and so on). Saves go through `BitwardenVaultRepository.create` / `createTyped` /
`edit(item, ItemEdit)`, which use core's cipher builders, so every field the server holds
survives. The TOTP seed field takes a QR scan. Plaintext is held in a `ByteArray` and zeroed
on dispose.

---

## 5. Persistence & state

- The ragewarden-core decrypt path is stateless; outputs zeroized buffers.
- The vault is held in memory on `BitwardenVaultRepository` and cached on disk encrypted
  (`VaultCache`, `vaultcache.v1.bin` under an AndroidKeyStore AEAD key, excluded from
  backup), so an unlock needs no network. Nothing in either is plaintext for a protected
  secret.
- The cross-device recipient registry is a cipher named `__ragedroid_recipients_v1__`,
  merged with the other clients' entries; `RecipientStore` keeps this device's own
  recipients per account.
- ViewModel state holds plaintext only inside the tap sheet's lifecycle.
- The stored session holds tokens only; the user keys are kept as a protected copy that
  the master password (offline unlock) or an auth-bound biometric key opens, and locking
  drops them and the decrypted vault from memory. See `docs/THREAT-MODEL.md` §5.1.
- The KDF pin is stored per (server, email) apart from the session, so it survives
  sign-out.

---

## 6. Test plan

- **Unit tests** on ViewModels: action-bound-to-tap correctness (the destination shown to the
  user matches the destination the consumer receives).
- **JNI tests** on the ragewarden-core bridge with mock `KotlinIdentity` returning a fixed key.
- **Robolectric tests** on the YubiKey sheet state machine, the autofill heuristics, host
  matcher and datasets, the UI's roles, wording and string resources (`app/src/test/kotlin/`).
- **Instrumentation tests** under `app/src/androidTest/kotlin/ragewarden/ragedroid/`:
  - `jni/RageNativeShapeTest` -- the packaged `libragedroid_jni.so` error surface:
    malformed recipients / PRF-inputs JSON, an unknown recipient kind, and garbage age
    secrets each throw `RageNativeException.MalformedStanza`; a panicking export throws
    `RageNativeException.Internal` and the process keeps running.
  - `data/RecipientStoreInstrumentedTest` -- `RecipientStore` against real
    SharedPreferences: round-trip fidelity, per-account isolation, removal,
    `defaultEncrypt` persistence, no plaintext in the raw prefs payload.
  - `journey/JourneyTest` -- the end-to-end journey through the shipped debug APK:
    sign in, recover a rageterm-written secret from the 24-word paper phrase (after a
    decoy phrase is refused), fail-closed composer for foreign-only recipient sets.
    Driven only by `tests/journey/run.sh`, which builds its fixtures.
  - `registry/RegistryPushInstrumentedTest` -- cold-cache `pushRecipientRegistry`
    against a browser-seeded vault: exactly one registry marker afterwards, browser
    entries survive, mocks never published. Also run.sh-driven; self-skips bare.
  - `journey/DeliveryFlowsTest` -- the three ways a secret leaves the app, against a
    foreign login form (`journey/LoginFixtureActivity`, which runs in the test APK's own
    process): autofill through the Authorize sheet, the keyboard typing an unprotected
    password, the keyboard handing a protected item to `ImeAuthActivity` and typing
    nothing when the tap is declined, and the detail screen's TOTP code checked against an
    independent RFC 6238 computation. run.sh-driven; it asserts the run had no skips.
  The first two run via `./gradlew :app:pixel6Api34StandardDebugAndroidTest` on a
  Pixel 6 API 34 [Gradle Managed Device][gmd], wired into the `e2e-android` GitHub
  Actions job. See `../E2E.md` Tier 3.
- **Real-hardware instrumentation** with a USB-OTG YubiKey -- release-gate, manual.
- **Manual matrix**: NFC tap on Android 12 / 14 / 15, USB-OTG with USB-A and USB-C YubiKeys,
  Keystore on StrongBox-having and StrongBox-lacking devices.

[gmd]: https://developer.android.com/studio/test/gradle-managed-devices

---

## 7. Build & distribution

- `:app:assembleStandardRelease` -> Play Store APK.
- `:app:assembleFdroidRelease` -> F-Droid; no Play services.
- `:app:assembleStandardDebug` -> dev.
- Native lib via `cargo-ndk` for `arm64-v8a` and `x86_64`.
- Reproducible builds: pinned Rust toolchain (`rust-toolchain.toml`),
  `-C codegen-units=16 -C target-cpu=generic` for the JNI crate. Verify
  byte-for-byte with `scripts/repro/verify-ragedroid.sh` (see `SECURITY.md`).
- **Baseline profile** at `ragedroid/baselineprofile/` (own gradle module). The producer
  module exercises the cold-start -> unlock -> vault list -> reveal flow with
  `BaselineProfileRule` on a connected device, signed in to the journey's account
  (`BenchVault.kt`); the `androidx.baselineprofile` plugin on `:app` merges the resulting
  `baseline-prof.txt` into `app/src/main/generated/baselineProfiles/`. ProGuard keeps the
  `profileinstaller` reflection surface so R8 doesn't drop it. (Re)generate with
  `JOURNEY_BENCH=1 tests/journey/run.sh`, which also runs the macrobenchmark. The committed
  `baseline-prof.txt` and `startup-prof.txt` (20,544 rules each) come from that run on a build host's
  API 37 emulator, 2026-10-03; every release build merges them (`merge*ReleaseArtProfile`).

---

## 8. Platform decisions

1. **Min SDK 31** (hardware-backed Keystore ECDH). Passkeys need Play services' Credential
   Manager on the standard build, or Android 14's built-in one on the F-Droid build.
2. **TOTP** lives in RageDroid; no separate authenticator app.
3. **No Bitwarden SDK.** KDF, Type-2 and sync come from ragewarden-core over JNI, one native
   library.
