# RageDroid -- Android frontend

Android client for the [Ragewarden](../DESIGN.md) ecosystem. Read the ecosystem design first
for threat model, crypto layering, and shared decisions. This file is Android-specific.

---

## 1. Modules

```
ragedroid/
+-- settings.gradle.kts
+-- build.gradle.kts
+-- gradle/libs.versions.toml
+-- jni/                    # Cargo crate; cargo-ndk builds librage_jni.so for arm64/x86_64
|   +-- Cargo.toml
|   +-- src/lib.rs          # JNI surface over rage-core
+-- app/                    # main Android app (Compose, Hilt, autofill service)
+-- core/                   # ScreenState, DataState mirror, util -- small
+-- data/                   # repositories, sync layer, Room cache
+-- recipients/             # Kotlin Identity impls for YubiKey, FIDO2, Keystore
+-- ui/                     # theme, BaseViewModel, shared Compose components
+-- network/                # Retrofit talking to the Bitwarden API
```

Reuses the Bitwarden SDK (`com.bitwarden:sdk-android`) for its outer-layer crypto. Reuses
`rage-core` (this project's Rust crate) via the `jni/` bridge for the inner layer.

---

## 2. JNI bridge

Three calls into Rust, one callback shape from Rust into Kotlin. We use [UniFFI](https://mozilla.github.io/uniffi-rs/)
to generate the binding so it stays in sync with the Rust source (Bitwarden's Rust SDK does
the same).

```kotlin
// Generated from rage-core's UniFFI definition
object Rage {
    fun encrypt(plaintext: ByteArray, recipients: List<Recipient>): ByteArray
    fun decrypt(blob: ByteArray, identities: List<KotlinIdentity>): ByteArray
}

interface KotlinIdentity {
    /** Try to unwrap the given age stanza. Return null if this identity does not match,
     *  throw IdentityError if hardware error / user cancellation. */
    fun tryUnwrap(stanza: AgeStanza): ByteArray?
}
```

The identity callback is the tricky bit: when rage-core needs the X25519 scalar product from
a YubiKey, it calls back into Kotlin (which calls yubikit-android). Kotlin blocks the JNI
thread on the YubiKey ceremony coroutine via a dedicated dispatcher; never the main thread.

Build: `./gradlew :app:assembleStandardRelease` triggers a `cargo-ndk` task that compiles
`jni/` for `arm64-v8a`, `armeabi-v7a`, `x86_64`, deposits `libragejni.so` into
`app/src/main/jniLibs/<abi>/`. Standard NDK pipeline.

---

## 3. Identity implementations

### 3a. YubiKeyPivIdentity

```
yubikit-android NfcYubiKeyManager / UsbYubiKeyManager
     |
     ▼
YubiKitConnection
     |
     |  open PivSession; verify PIN if needed; calculate_secret(slot, public_key)
     ▼
32-byte ECDH shared secret -> HKDF -> file key
```

Uses `com.yubico.yubikit:piv` and `com.yubico.yubikit:android`. Discovery via NFC
(foreground dispatch in the activity) and USB-OTG (intent filter on `USB_DEVICE_ATTACHED`).
A `YubiKeyPivIdentity` is parameterized by `(serial, slot, expected_public_key)`; matches
an age stanza when the stanza's pubkey equals the expected key.

PIN handling: yubikit-android caches PIN within a YubiKey session. We do not cache PIN
across sessions. PIN is entered once per tap if the slot requires it.

### 3b. Fido2HmacIdentity (raw CTAP2 path; works back to API 19)

`com.yubico.yubikit:fido` for direct CTAP2 over NFC + USB. Used to unlock `fido2-hmac`
stanzas -- the format produced by frontends that talk to authenticators directly.

The age stanza stores `(credential_id, salt)`. Identity calls `getAssertion` with
`hmac-secret` extension and the salt; the assertion's HMAC output is HKDF-expanded to a
file key.

### 3c. PasskeyIdentity (Credential Manager API, API 34+)

`androidx.credentials:credentials` -- the modern path. Unlocks `webauthn-prf-v1` stanzas, the
format produced by ragemanifest. This is what makes a passkey enrolled in the browser
roundtrip cleanly to the Android app: same RP ID, same credential ID, same PRF salt -> same
file key.

The user-visible flow on Android 14+: system Credential Manager picker shows whatever
passkeys the user has (Google Password Manager, third-party PMs that vend passkeys, security
keys via NFC/USB, paired devices via cross-device flow). User picks one, performs biometric
or tap, PRF result derives file key. Same UX shape as the browser.

Below API 34: this identity is unavailable. The user falls back to direct YubiKey paths
(3a/3b) or the AndroidKeystoreIdentity (3d).

### 3d. AndroidKeystoreIdentity

Local-only convenience identity. P-256 EC keypair generated in StrongBox-backed Keystore
(falls back to TEE if StrongBox unavailable). Stanza stores the X25519-converted public key
+ ephemeral ECDH share encrypted with the Keystore key.

User authentication: tied to BiometricPrompt -- Keystore `setUserAuthenticationRequired(true)`.
The "tap" for this identity is a biometric prompt or device PIN fallback.

Wire format: defined in `../core/DESIGN.md` under the `ragedroid-keystore-v1` stanza header.

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

1. rage-core decrypts the blob.
2. Frontend hands the plaintext directly to the bound destination -- clipboard set,
   `FillResponse` returned, IME `commitText`'d, or reveal text shown.
3. Buffer zeroized.
4. Sheet dismisses with success animation.

On cancel / timeout / hardware error: plaintext was never produced. Sheet dismisses with the
error reason.

The plaintext never lives in a "decrypted but undelivered" state. Bait-and-switch from a
hostile screen overlay would have to convince the user to tap with the *correct destination
already named in the prompt*; the prompt cannot be tampered with post-tap.

### 4d. IME injection (`Send to keyboard`)

Ragedroid ships an `InputMethodService` that the user can switch to per-text-field via the
system input picker. When invoked, the IME shows a minimal "pick credential -> tap" UI; on
success it `commitText()`s the plaintext to the focused field and switches back to the user's
default IME. Works in apps that don't support autofill (legacy apps, terminal emulators).

The IME process is short-lived per use; plaintext lives only between decrypt and `commitText`.

### 4e. Autofill API integration

Adapts Bitwarden's existing `BitwardenAutofillService` to the rage layer. When the user picks
a credential to fill:

1. Autofill picker shows ragewarden as a fill option.
2. Tapping the option does **not** yet release a value -- instead pops the YubiKey sheet bound
   to that fill request.
3. Tap completes -> rage-core decrypts -> `FillResponse` built with plaintext -> handed to
   system -> form filled.

The action ("autofill into github.com") is named in the sheet so a hostile autofill prompt
can be cancelled before tapping.

### 4f. Onboarding

1. Sign in to Bitwarden / Vaultwarden (existing flow, Bitwarden SDK).
2. Banner: "Set up Ragewarden protection." Tapping enters the wizard.
3. Wizard step 1: enroll first identity. YubiKey (NFC tap), FIDO2 hmac-secret (NFC tap), or
   Android Keystore (biometric).
4. Wizard step 2 (skippable): paper recovery identity. Generated software age identity
   displayed as 24 BIP39 words; ask user to confirm they wrote it down.
5. Wizard step 3 (post-MVP): bulk-protect existing ciphers. Per-item confirm.

---

## 5. Persistence & state

- The rage-core decrypt path is stateless; outputs zeroized buffers.
- Bitwarden vault cached in Room (same as Bitwarden Android). Cached ciphers contain the
  `rage:v1` field as opaque bytes. Nothing in cache is plaintext for any rage-protected
  secret.
- Recipient list lives in a single secure note in the vault named
  `Ragewarden Recipients (do not edit)`. Standard Bitwarden sync. New device first-run: sign
  in, sees the note, prompts to enroll its own Keystore identity and adds it to recipient
  list of existing ciphers.
- ViewModel state holds plaintext only inside the YubiKey sheet's lifecycle. `state.copy(...)`
  with the plaintext nulled on dismiss / completion.

---

## 6. Test plan

- **Unit tests** on ViewModels: action-bound-to-tap correctness (the destination shown to the
  user matches the destination the consumer receives).
- **JNI tests** on the rage-core bridge with mock `KotlinIdentity` returning a fixed key.
- **Robolectric tests** on the YubiKey sheet state machine.
- **Instrumentation tests** with a real YubiKey USB-OTG.
- **Manual matrix**: NFC tap on Android 9 / 12 / 14, USB-OTG with USB-A and USB-C YubiKeys,
  Keystore on StrongBox-having and StrongBox-lacking devices.

---

## 7. Build & distribution

- `:app:assembleStandardRelease` -> Play Store APK.
- `:app:assembleFdroidRelease` -> F-Droid; no Play services.
- `:app:assembleStandardDebug` -> dev.
- Native lib via `cargo-ndk`; CI matrix covers all 3 ABIs.
- Reproducible builds: pinned Rust toolchain (`rust-toolchain.toml`),
  `-C codegen-units=1 -C target-cpu=generic` for the JNI crate.

---

## 8. Open Android-specific questions

1. **Min SDK.** Bitwarden Android targets API 28 (Android 9). Platform Credential Manager
   FIDO2 hmac-secret is API 34 (Android 14). yubikit-direct path works back to API 19.
   **Default min SDK 28**, platform Credential Manager available only on 34+.

2. **TOTP integration.** v2; ragedroid handles passwords + TOTP, no separate Authenticator
   app.

3. **Bitwarden SDK reuse vs Rust port.** rage-core does not currently include Bitwarden's
   Rust SDK functionality (KDF, sync). Two options: (a) depend on the official
   `com.bitwarden:sdk-android` artifact alongside our `librage_jni.so`, two native libs; (b)
   port the bits we need into rage-core. **Default (a)**: smaller surface, lets Bitwarden
   own their crypto. Revisit if APK size matters.
