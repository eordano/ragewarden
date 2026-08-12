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
+-- jni/                    # Cargo crate; cargo-ndk builds libragedroid_jni.so for arm64/x86_64
|   +-- Cargo.toml
|   +-- src/lib.rs          # JNI surface over ragewarden-core
+-- app/                    # main Android app (Compose, Hilt, autofill service)
+-- core/                   # ScreenState, DataState mirror, util -- small
+-- data/                   # repositories, sync layer, Room cache
+-- recipients/             # Kotlin Identity impls for YubiKey, FIDO2, Keystore
+-- ui/                     # theme, BaseViewModel, shared Compose components
+-- network/                # Retrofit talking to the Bitwarden API
```

Reuses the Bitwarden SDK (`com.bitwarden:sdk-android`) for its outer-layer crypto. Reuses
`ragewarden-core` (this project's Rust crate) via the `jni/` bridge for the inner layer.

---

## 2. JNI bridge

Hand-written `extern "system"` JNI exports in `jni/src/lib.rs`, paired with `external fun`
declarations on the Kotlin side (`app/.../jni/RageNative.kt`). We considered UniFFI early on
but kept it hand-written because the surface is small (5 functions in phase 1, ~10 in
phase 3) and the JNI byte-array lifetime semantics matter enough that we'd rather audit
them ourselves than read generated code.

The Kotlin surface looks like:

```kotlin
package ragewarden.ragedroid.jni

object RageNative {
    init { System.loadLibrary("ragedroid_jni") }
    external fun encrypt(plaintext: ByteArray, recipientPubkey: ByteArray): ByteArray
    external fun decryptWithSoftwareSecret(blob: ByteArray, armoredSecret: String): ByteArray
    external fun generateSoftwareIdentity(): String
    external fun pubkeyFromArmoredSecret(armoredSecret: String): ByteArray
    external fun smoke(): String
}
```

Phase 3 widens this to take a `List<KotlinIdentity>` callback so hardware operations call
back into Kotlin (which calls yubikit-android). Kotlin blocks the JNI thread on the
YubiKey ceremony coroutine via a dedicated dispatcher; never the main thread.

Build: `./gradlew :app:assembleStandardRelease` triggers a `cargo-ndk` task that compiles
`jni/` for `arm64-v8a`, `armeabi-v7a`, `x86_64`, deposits `libragedroid_jni.so` into
`app/src/main/jniLibs/<abi>/`. Standard NDK pipeline.

---

## 3. Identity implementations

Phase-3 status (this pass):

| identity | Kotlin class | mock-mode | live hardware |
|---|---|---|---|
| YubiKey PIV | `YubiKeyPivIdentity` | ✅ | 🟡 stubbed (yubikit-android NFC/USB plumbing pending hardware test) |
| FIDO2 hmac-secret | `Fido2HmacIdentity` | ✅ | 🟡 stubbed (yubikit-fido pending hardware test) |
| Passkey (Credential Manager) | `PasskeyIdentity` (standard flavor) | ✅ | 🟡 stubbed (Credential Manager wiring needs activity-bound context) |
| F-Droid passkey stub | `PasskeyIdentity` (fdroid flavor) | n/a | n/a -- errors with a clear message |
| Android Keystore | `AndroidKeystoreIdentity` | ✅ | 🟡 stubbed (StrongBox / TEE keypair gen pending hardware test) |
| Recovery (BIP39 -> X25519) | `RecoveryIdentity` | ✅ | ✅ -- software path is the live path |

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

Two caveats this section did not previously state. **Tapjacking is defended against at the
window level, not the composable level:** `MainActivity.onCreate` and
`AutofillAuthActivity.onCreate` set `window.decorView.filterTouchesWhenObscured = true`, and
the IME sets it on its input view, so Android discards touches delivered while the window is
obscured by an overlay. That covers the "Authorize" affordance without any per-composable
work. It does **not** cover a partially-obscuring overlay on API levels where the flag is
window-scoped only, and it is not verified here -- there is no instrumented test for it. And
for the `AndroidKeystore` recipient kind the gate is a
30-second `setUserAuthenticationParameters` window rather than a per-operation
authentication, because `KeyAgreement` is not a supported `BiometricPrompt.CryptoObject` --
the UI re-prompts per reveal so the observable behaviour is one prompt per use, but an
attacker holding the unlocked device inside that window does not have to re-authenticate.
See `docs/THREAT-MODEL.md` §3 footnote.

### 4d. IME injection (`Send to keyboard`) -- implemented, **unprotected items only**

Ragedroid ships an `InputMethodService` (`ragewarden.ragedroid.ime.RagewardenInputMethodService`)
that the user can switch to per-text-field via the system input picker. When invoked,
`onCreateInputView()` returns a `ComposeView` rendering a vault list scoped to the keyboard
area. On success the IME calls `currentInputConnection.commitText(plaintext, 1)` then
`switchToPreviousInputMethod()` to hand control back to the user's previous IME. Plaintext is
held in a `ByteArray`, copied into one `String` for the input-connection call, and the byte
buffer is zeroized on the same line as the deliver call.

**Correction -- this section previously described the IME as delivering rage-protected
plaintext behind an `InlineTapReveal` ceremony. It does the opposite, deliberately.** An
`InputMethodService` cannot host a `BiometricPrompt` and cannot flag the host application's
window, so there is no surface on which to run a real hardware ceremony. Accordingly:

- the picker lists only `filterNot { it.rage }` -- Ragewarden-protected items are excluded,
  and the count of excluded items is shown so the omission is not silent;
- `deliverPlaintext` refuses outright, with a log line, if the id is unknown or the item is
  `rage`, so a stale composition cannot commit a protected secret;
- the confirmation is a plain "Type it", not a tap ceremony. Running a hardware-tap animation
  over an item that needs no hardware would be a consent dialog for a decision already made.

**NOT YET IMPLEMENTED, and a real gap:** the IME does not consult the app lock. It shares the
process and the `VaultBridge` singleton with `MainActivity`, and reads no lock state, so an
*unprotected* Bitwarden password can be typed into a host field while the vault is locked.
See `docs/THREAT-MODEL.md` §5.3 and §10.

The IME hosts its own `LifecycleOwner` + `SavedStateRegistryOwner` and wires both onto the
ComposeView via `setViewTreeLifecycleOwner` / `setViewTreeSavedStateRegistryOwner` -- required
for Compose to run inside an `InputMethodService`. Works in apps that don't support autofill
(legacy apps, terminal emulators).

It goes through the shared `VaultBridge` singleton, so it sees the same
`BitwardenVaultRepository` the main activity does. (The `DemoVaultStore` this paragraph used
to describe no longer exists anywhere in the tree.)

### 4e. Autofill API integration -- implemented (phase 4, cold-dataset ceremony)

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
2. `HostMatcher.matchVaultItems` filters the vault snapshot by hostname (exact, subdomain
   match) or package-name token, falling back to nothing if neither signal matches.
3. Each match is rendered as a **cold dataset**: the dataset's autofill values are placeholder
   empty strings, and `setAuthentication(intentSender)` points the system at
   `AutofillAuthActivity`. The remote view names the action explicitly
   ("Autofill GitHub into github.com").
4. When the user picks a dataset, Android launches `AutofillAuthActivity`. That activity
   renders the same `InlineTapReveal` ceremony used in `ItemDetailScreen` with
   `TapAction.Autofill` pre-bound and the destination domain visible. **No plaintext exists
   anywhere yet.**
5. Only after the user confirms the tap does the activity call `DemoVaultStore.decryptPassword`,
   build a fresh `FillResponse` whose dataset carries the real `AutofillValue.forText(...)`
   for username + password, attach it via `Intent.putExtra(EXTRA_AUTHENTICATION_RESULT, ...)`,
   `setResult(RESULT_OK)`, and finish. Android delivers the values to the form. The activity
   zeroizes the `ByteArray` plaintext in the same `try/finally` that built the response.

This honors §0a (action chosen before tap -- the Android system credential picker is the
action choice, the activity confirmation is the tap) and §0c (plaintext lifetime is bounded
by the activity callback). A hostile autofill prompt cannot release plaintext because the
dataset itself is empty until the authentication intent succeeds.

Phase 4 talks to the `DemoVaultStore` via `VaultBridge`; phase 2 (already done in core +
rageterm) replaces the demo store with the real Bitwarden vault repository on the Android
side.

#### Stubbed in phase 4, lands in later phases

- **Hardware identity dispatch.** The tap ceremony today renders the YubiKey-shaped UI but
  resolves through `RageNative.decryptWithSoftwareSecret` (phase 1 software identity). Phase 3
  swaps in real `YubiKeyPivIdentity` / `Fido2HmacIdentity` / `PasskeyIdentity` /
  `AndroidKeystoreIdentity` callbacks so the ceremony can drive the actual hardware token.
- **Real vault.** `DemoVaultStore` is a fixture-driven, in-memory store. Phase 2 swaps it for
  a `BitwardenVaultRepository` that streams `DataState<List<DisplayItem>>` via the SDK + rage
  layer.
- **Save-on-fill.** `onSaveRequest` accepts a save callback but does nothing useful yet;
  cipher CRUD lands in phase 2.
- **Inline suggestions.** Pre-Q `setAuthentication` is supported; phase-5 inline-suggestion
  presentations (API 30+) and `Presentations` (API 33+) are not yet wired. The deprecated
  `Dataset.Builder.setValue(AutofillId, AutofillValue, RemoteViews)` overload is used and
  `@file:Suppress("DEPRECATION")`d.
- **Build flavors.** `app/build.gradle.kts` declares two product flavors on the
  `distribution` dimension: `standard` (Play-Store-friendly, pulls in
  `androidx.credentials:credentials` + `credentials-play-services-auth`) and `fdroid`
  (no Play Services dependencies, applicationIdSuffix `.fdroid`). The flavor-specific source
  sets at `app/src/{standard,fdroid}/kotlin/.../distribution/Distribution.kt` expose
  `LABEL` / `INCLUDES_PLAY_SERVICES` / `CREDENTIAL_MANAGER_AVAILABLE` constants. Phase 4
  intentionally keeps the differentiation thin -- the structure is in place for phase 3 /
  phase 5 to fork the Credential-Manager passkey path.

### 4f. Onboarding -- implemented (phase 2, sign-in only)

`app/.../ui/screens/OnboardingScreen.kt` mirrors `design/screens-misc.jsx`'s `FirstRun`
step 1 with a sign-in / register toggle plus a "Skip -- use demo data" affordance. On
success the session blob lands in `SessionStore` (AES-256-GCM through `KeystorePrefs`, under a
non-exportable AndroidKeyStore key -- there is no plain-prefs fallback; an undecryptable blob is
reported as "no session" and the user signs in again) and `VaultBridge.installRepository(...)`
swaps the demo backend for the real `BitwardenVaultRepository`. Wizard steps 2 (enroll
identities) and 3 (bulk-protect) are stubbed pending the per-identity enroll wizards
(`design/screens-misc.jsx` `AddRecipientScreen`).

### 4g. Edit-cipher screen -- implemented (phase 2)

`app/.../ui/screens/EditItemScreen.kt` mirrors `design/screens-misc.jsx`'s `AddItemScreen`
with current values pre-filled. Reveal-on-tap on the current password (decrypts via the
backend), new-password field with a generator, TOTP/notes/recipients editor, save button
that calls `BitwardenVaultRepository.update(item, plaintext)`. Plaintext is held in a
`ByteArray` and zeroized on screen dispose. The pencil icon next to `MoreVert` on the
item-detail app bar opens this screen.

---

## 5. Persistence & state

- The ragewarden-core decrypt path is stateless; outputs zeroized buffers.
- **There is no Room cache.** This bullet described one, "same as Bitwarden Android"; the
  app has no Room dependency and no Bitwarden SDK dependency. The vault lives in a
  `@Volatile` in-memory `CachedState` on `BitwardenVaultRepository`, populated by
  `ragewarden_core::sync` over the JNI bridge. Nothing cached is plaintext for any
  rage-protected secret -- that part holds -- but the cache is process memory, not a database,
  so it does not survive a process death and is not encrypted at rest because it is never at
  rest. A persistent offline cache is **NOT YET IMPLEMENTED**.
- Recipient list lives in a single secure note in the vault named
  `Ragewarden Recipients (do not edit)`. Standard Bitwarden sync. New device first-run: sign
  in, sees the note, prompts to enroll its own Keystore identity and adds it to recipient
  list of existing ciphers.
- ViewModel state holds plaintext only inside the tap sheet's lifecycle. `state.copy(...)`
  with the plaintext nulled on dismiss / completion.
- The Bitwarden session blob -- which carries `user_enc_key_b64` **and** `user_mac_key_b64`,
  not merely tokens -- is stored through `data/KeystorePrefs` (AES-256-GCM under a
  non-exportable AndroidKeyStore key). It was previously written to plain
  `MODE_PRIVATE` prefs in base64; see §4f and `docs/THREAT-MODEL.md` §5.1.

---

## 6. Test plan

- **Unit tests** on ViewModels: action-bound-to-tap correctness (the destination shown to the
  user matches the destination the consumer receives).
- **JNI tests** on the ragewarden-core bridge with mock `KotlinIdentity` returning a fixed key.
- **Robolectric tests** on the YubiKey sheet state machine. Phase 4 has Robolectric coverage
  for the autofill heuristics + host matcher (`app/src/test/kotlin/.../autofill/`).
- **Instrumentation tests** under `app/src/androidTest/kotlin/ragewarden/ragedroid/`:
  - `jni/RageNativeShapeTest` -- the packaged `libragedroid_jni.so` error surface:
    malformed recipients / PRF-inputs JSON, an unknown recipient kind, and garbage age
    secrets each throw `RageNativeException.MalformedStanza`.
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
  The first two run via `./gradlew :app:pixel6Api34StandardDebugAndroidTest` on a
  Pixel 6 API 34 [Gradle Managed Device][gmd], wired into the `e2e-android` GitHub
  Actions job. See `../E2E.md` Tier 3.
- **Real-hardware instrumentation** with a USB-OTG YubiKey -- release-gate, manual.
- **Manual matrix**: NFC tap on Android 9 / 12 / 14, USB-OTG with USB-A and USB-C YubiKeys,
  Keystore on StrongBox-having and StrongBox-lacking devices.

[gmd]: https://developer.android.com/studio/test/gradle-managed-devices

---

## 7. Build & distribution

- `:app:assembleStandardRelease` -> Play Store APK.
- `:app:assembleFdroidRelease` -> F-Droid; no Play services.
- `:app:assembleStandardDebug` -> dev.
- Native lib via `cargo-ndk`; CI matrix covers all 3 ABIs.
- Reproducible builds: pinned Rust toolchain (`rust-toolchain.toml`),
  `-C codegen-units=1 -C target-cpu=generic` for the JNI crate. Verify
  byte-for-byte with `scripts/repro/verify-ragedroid.sh` (see `SECURITY.md`).
- **Baseline profile** at `ragedroid/baselineprofile/` (own gradle module). The producer
  module exercises the cold-start -> vault list -> reveal flow on a Pixel 6 API 34 Gradle
  Managed Device using `BaselineProfileRule`; the `androidx.baselineprofile` plugin on
  `:app` consumes the resulting `baseline-prof.txt` and packages it under
  `app/src/main/baselineProfiles/`. ProGuard keeps the `profileinstaller` reflection
  surface so R8 doesn't drop it. (Re)generate with:
  ```
  ./gradlew :baselineprofile:pixel6Api34BaselineProfileAndroidTest
  ```
  CI runs that target on tagged releases and the resulting APK ships the AOT hints.

---

## 8. Open Android-specific questions

1. **Min SDK.** Bitwarden Android targets API 28 (Android 9). Platform Credential Manager
   FIDO2 hmac-secret is API 34 (Android 14). yubikit-direct path works back to API 19.
   **Default min SDK 28**, platform Credential Manager available only on 34+.

2. **TOTP integration.** v2; ragedroid handles passwords + TOTP, no separate Authenticator
   app.

3. **Bitwarden SDK reuse vs Rust port.** ragewarden-core does not currently include Bitwarden's
   Rust SDK functionality (KDF, sync). Two options: (a) depend on the official
   `com.bitwarden:sdk-android` artifact alongside our `libragedroid_jni.so`, two native libs; (b)
   port the bits we need into ragewarden-core. **Default (a)**: smaller surface, lets Bitwarden
   own their crypto. Revisit if APK size matters.
