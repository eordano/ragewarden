# Recipient enrollment (real hardware)

Plan to replace the `enrollMock` / `error("Real X not implemented")` paths with real hardware-backed enrollment for all five recipient kinds: Software (already works), Recovery (already works), Android Keystore, YubiKey PIV, and FIDO2/Passkey PRF.

## Status (as of 2026-05-05, ragedroid 0.0.x)

All six phases of this plan have shipped. The "What's fake today" section below is preserved as historical context -- every item in it has since been replaced with real hardware-backed code.

| Phase | Description                                          | Commit    |
|-------|------------------------------------------------------|-----------|
| 0     | Real-recipient enrollment foundation (store + JNI)   | `1f68dda` |
| 1     | Persist real recovery recipients to `RecipientStore` | `4d2a858` |
| 2     | Real Android Keystore X25519 enrollment + decrypt    | `6dcd664` |
| 3     | Real `yubikit-android` PIV X25519 enrollment + decrypt | `ffb631f` |
| 4     | Real Passkey/FIDO2 PRF enrollment via Credential Manager | `3738319` |
| 5     | Wire enrollment ceremonies into `AddRecipientScreen` | `052a832` |

Two follow-on commits hardened the path: `9e44eda` (production-ready encrypt path, P0/B1, P1/C10, P1/C11) and `74e1b0b` (Wave 2 production-readiness fixes). See `THREAT-MODEL.md` for the security model that the shipped code provides.

## Already in place

- **Rust core**: `encrypt_with_prf(plaintext, recipients, prf_table)` accepts a slice of `Recipient` enum variants and emits a multi-stanza age blob. All four hardware stanza tags are implemented and round-trip in `core::tests`.
- **Kotlin identities**: `YubiKeyPivIdentity`, `Fido2HmacIdentity`, `AndroidKeystoreIdentity`, `PasskeyIdentity` all have working `tryUnwrap` paths. Each currently has a `mockSecret` bypass + an `enrollMock` companion gated on `RAGEWARDEN_MOCK_HARDWARE=1`.
- **MultiIdentityPickerSheet**: wired in `ItemDetailScreen` (last commit).

## Pre-Phase-0 baseline (historical)

These items described the codebase before Phase 0 landed; all three have since been replaced.

1. Enrollment paths all `error("Real X not implemented")`-ed when `mockSecret == null`.
2. `RageNative.encrypt(plaintext, pubkey)` only accepted a single recipient; multi-stanza blobs were not reachable from Kotlin.
3. `Fixtures.recipients` was a hardcoded preview list -- there was no production recipient store.

---

## Phase 0 -- Foundation

### 0a. Persistent recipient store

`data/RecipientStore.kt` + encrypted-shared-prefs (`androidx.security:security-crypto`), keyed on `accountId`. JSON-serialised list of `StoredRecipient`. **No secret material** -- only public material + opaque hardware handles (PIV slot numbers, FIDO2 credential IDs, Keystore key handle strings). The hardware retains every secret.

```kotlin
@Serializable data class StoredRecipient(
    val id: String,
    val kind: RecipientKind,
    val displayName: String,
    val createdAt: Long,
    val lastUsedAt: Long,
    // kind-specific (one set is non-null):
    val pivPubkey: ByteArray? = null,           val pivSerial: Int? = null, val pivSlot: Byte? = null,
    val fido2CredentialId: ByteArray? = null,   val fido2RpId: String? = null, val fido2Salt: ByteArray? = null,
    val keystorePubkey: ByteArray? = null,      val keystoreHandle: String? = null,
    val passkeyCredentialId: ByteArray? = null, val passkeyRpId: String? = null, val passkeySalt: ByteArray? = null,
    val recoveryArmoredPubkey: String? = null,
)
```

`Fixtures.recipients` survives only as preview/demo; production reads from `RecipientStore` via a new `VaultBridge.recipients()` flow.

### 0b. Multi-recipient encrypt JNI

```rust
pub extern "system" fn Java_..._RageNative_encryptToRecipients(
    plaintext: jbyteArray,
    recipients_json: jbyteArray,    // [{ kind: "PivP256", pubkey: "<base64>" }, ...]
    prf_inputs_json: jbyteArray,    // [{ rpId: "...", salt: "<base64>", prfOutput: "<base64>" }]
) -> jbyteArray
```

`BitwardenVaultRepository.create / update` collects active recipients from `RecipientStore`, computes any required PRF outputs (FIDO2/passkey require a tap **at encrypt time** per recipient), and calls the new JNI.

### 0c. Per-save PRF tap

FIDO2/Passkey are unique -- their stanza requires `prf_output = hmacSha256(hmac_key, salt)` baked in at encrypt. So if a user's default-encrypt recipient list includes a FIDO2 token, every save requires a tap. Surface this in `AddRecipientScreen`; let users mark FIDO2 recipients as decrypt-only (omit from default-encrypt set, only used at decrypt). PIV/Keystore have no such cost -- they ECDH at decrypt only. Approved per-save tap is fine.

**Touch count:** ~250 LOC across `core::lib::Recipient` parsers, JNI, `RecipientStore`, `BitwardenVaultRepository`, `AddRecipientScreen`.

---

## Phase 1 -- Recovery (already done; just wire to store)

`recovery::generate()` already produces `(mnemonic, armoredPubkey, armoredSecret)`. `RecoveryIdentity` already does `decryptDirect`.

- After mnemonic is shown to the user, persist `armoredPubkey` to `RecipientStore` as `kind=Recovery`.
- `armoredSecret` is **not** stored on the device -- it's reconstructable from the mnemonic on demand (`recovery::from_phrase`).
- Decrypt path: when the user types the mnemonic to unlock, derive secret -> `RecoveryIdentity` -> JNI `decryptWithSoftwareSecret`.

Mostly UI plumbing in `PaperRecoveryWizardScreen`.

**Touch count:** ~50 LOC.

---

## Phase 2 -- Android Keystore (StrongBox / TEE)

### Constraint resolved: minSdk 28 -> 31

`KeyProperties.KEY_ALGORITHM_XDH` (X25519) lands in API 31. Bumping `minSdk` to 31 (approved). Devices below 31 don't get hardware-backed Keystore enrollment but still have YubiKey/recovery available.

### Enrollment

Shipped signature (returns the persisted `StoredRecipient` next to a ready-to-use `AndroidKeystoreIdentity`):

```kotlin
suspend fun enrollKeystoreIdentity(
    displayName: String,
    handle: String = "ragewarden-keystore-${UUID.randomUUID()}",
    useStrongBox: Boolean = true,
    requireBiometric: Boolean = true,
): Pair<StoredRecipient, AndroidKeystoreIdentity>
```

The implementation builds a `KeyGenParameterSpec` with `KeyProperties.PURPOSE_AGREE_KEY`, `NamedParameterSpec("X25519")`, optional `setIsStrongBoxBacked(true)` and (when `requireBiometric`) `setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`. The generated public key is converted to a 32-byte little-endian X25519 representation via `bigIntegerToLittleEndian32`.

### Tap ceremony at decrypt

Replace `error(...)` in `AndroidKeystoreIdentity.tryUnwrap`:

```kotlin
val priv = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(keyHandle, null) as XECPrivateKey
val ka = KeyAgreement.getInstance("XDH", "AndroidKeyStore").apply {
    init(priv); doPhase(buildEphemeralX25519PublicKey(stanzaArgs[1]), true)
}
RageNative.unwrapStanza(StanzaTags.RAGEDROID_KEYSTORE_V1, stanzaArgs, stanzaBody, ka.generateSecret())
```

User-authentication-required keys fire `BiometricPrompt` automatically when `KeyAgreement.doPhase` is invoked.

**Touch count:** ~120 LOC. **Risk:** emulators don't have StrongBox; detect via `PackageManager.FEATURE_STRONGBOX_KEYSTORE` and fall back to TEE.

---

## Phase 3 -- YubiKey (NFC + USB-C HID)

### Dependency

`com.yubico.yubikit:android:2.7.0` plus `com.yubico.yubikit:piv:2.7.0` (Apache 2, F-Droid-compatible). Versions are declared in `gradle/libs.versions.toml` (`yubikit = "2.7.0"`).

### Enrollment

Shipped signature:

```kotlin
suspend fun enrollYubiKeyPivX25519(
    activity: FragmentActivity,
    slot: Slot = Slot.AUTHENTICATION,    // 0x9a
    pin: CharArray,
    displayName: String? = null,
): Pair<StoredRecipient, YubiKeyPivIdentity>
```

Internals:
- `YubiKitTransport.awaitYubiKey(activity)` waits for an NFC tap or USB-C session, then `YubiKitTransport.withSmartCard(device) { ... }` opens a `SmartCardConnection`.
- `PivSession.verifyPin(pin)` -- caller supplies the `CharArray`; it is zeroed by the UI layer after enrollment finishes.
- `PivSession.generateKeyValues(slot, KeyType.X25519, PinPolicy.ONCE, TouchPolicy.ALWAYS)` -- throws `YubiKeyX25519UnsupportedException` on firmware < 5.7.
- `extractX25519Pub32FromValues(...)` returns the raw 32-byte X25519 public key (handles both `PublicKeyValues.Cv25519` and the generic `XECPublicKey` paths).
- The returned `YubiKeyPivIdentity` carries a `pinProvider` that re-prompts on each decrypt rather than caching the PIN.

YubiKey 5.7+ supports X25519 directly. Older keys (5.4-5.6) use P-256; the existing `TAG_PIV_P256` label wraps the 32-byte ECDH share regardless of curve (HKDF info string maps to the same age `piv-p256` plugin convention). Detect firmware version and gate at enrollment if the firmware lacks X25519.

### Tap at decrypt

Replace `error(...)` in `YubiKeyPivIdentity.tryUnwrap` with a coroutine that opens the NFC/USB connection, calls `piv.calculateSecret(slot, ephemeralPub)`, and feeds the share into `RageNative.unwrapStanza`. UI: existing `InlineTapReveal` sheet drives the prompt.

### USB OTG quirk

USB-C YubiKey on Pixel 10 needs `UsbManager.requestPermission`. yubikit-android handles this if we call `yubiKitManager.startUsbDiscovery(UsbConfiguration().apply { isHandlePermissions = true })` from `Application.onCreate`.

**Touch count:** ~250 LOC. **Risks:** AOSP emulator has no NFC -- testing requires a real device. Cert-less generation requires firmware >=5.7 + attestation slot; otherwise generate a self-signed cert in the slot to extract the pubkey.

---

## Phase 4 -- FIDO2 / Passkey (PRF extension)

Trickiest because:

1. WebAuthn `hmac-secret` is a CTAP2 extension -- not all authenticators support it. YubiKey 5C does; many built-in fingerprint readers don't.
2. Android's `androidx.credentials` exposes WebAuthn via `CredentialManager`; PRF support landed in 1.3+.
3. F-Droid flavor cannot use Google's PlayServicesAuth provider -- depends on installed credential providers (1Password, Bitwarden's own passkey provider, etc.).

### Standard flavor enrollment

Shipped signature (in `app/src/standard/kotlin/.../PasskeyEnrollmentReal.kt`; the F-Droid flavor has the same signature but throws):

```kotlin
suspend fun enrollPasskeyWithPrf(
    activity: FragmentActivity,
    accountId: String,
    rpId: String = "ragewarden.local",
    displayName: String = "Passkey on this device",
): Pair<StoredRecipient, PasskeyIdentity>
```

Internals:
- Generates a 32-byte `challenge` and a 32-byte `salt` from `SecureRandom`.
- Builds a WebAuthn-compliant JSON request (`buildEnrollmentJson`) with `userVerification = "required"` and the `prf.eval.first` extension set to the salt.
- Calls `CredentialManager.create(activity).createCredential(activity, request)`.
- Parses the credential ID out of `registrationResponseJson`.
- Stores `fido2CredentialId`, `fido2RpId`, and the **salt** (not the PRF output) into `StoredRecipient`. The PRF output is recomputed by the authenticator at every encrypt and every decrypt.
- `defaultEncrypt = false` by default -- passkey recipients are decrypt-only unless the user opts in, since the per-encrypt tap is intrusive.

### F-Droid flavor

Replaces enrollment body with `error("FIDO2 enrollment requires Google Play Services in this build; install the standard build or use a YubiKey.")`. Existing fdroid `PasskeyIdentity.kt` already has this stub structure.

### Tap at encrypt + decrypt

`invokeRealCredentialManager(salt)` returns `null` today. Replace with:

```kotlin
override suspend fun invokeRealCredentialManager(salt: ByteArray): ByteArray? {
    val request = GetCredentialRequest(listOf(GetPublicKeyCredentialOption(buildAssertionJson(rpId, salt, credentialId))))
    val response = CredentialManager.create(activity).getCredential(activity, request)
    val cred = response.credential as PublicKeyCredential
    return parseAssertionResponse(cred.authenticationResponseJson)
        .clientExtensionResults.getJSONObject("prf").getJSONObject("results").getString("first").base64()
}
```

Activity reference: thread `activity: FragmentActivity` through identity construction.

**Touch count:** ~200 LOC standard, ~30 fdroid. **Risk:** PRF support depends on the user's credential provider -- detect lack-of-support and surface "your passkey provider doesn't support the PRF extension; pick another identity kind."

---

## Phase 5 -- Wire UX & polish

- `AddRecipientScreen`: per-kind enrollment ceremony; replace fake animation with calls to real enrollment functions.
- `RecipientDetailScreen`: real revoke (delete from `RecipientStore`; future ciphers won't include this stanza; existing ciphers stay decryptable until rotated).
- `MultiIdentityPickerSheet`: pass real `KotlinIdentity[]` based on the cipher's stanza tags.
- `ItemDetailScreen` reveal flow: load the active identity list from `RecipientStore` (today empty -> falls through to recovery / software).
- **Default-recipient set**: at create/update, every default recipient gets a stanza. Removing from defaults doesn't revoke -- it stops *future* saves from including this stanza.

**Touch count:** ~150 LOC.

---

## Verification

- **Unit (JVM):** mock all four identities via `enrollMock`; round-trip encrypt -> decrypt with each individually + in 2-/3-way combinations.
- **Instrumentation (Pixel 6 GMD `:app:pixel6Api34`):** Keystore enrollment + decrypt; mocked FIDO2 PRF.
- **Manual on Pixel 10:** Keystore biometric prompt; YubiKey 5C NFC + USB-C; passkey via on-device fingerprint.
- **Existing 160 Rust tests** must stay green throughout.

---

## Commit plan

| # | Commit | Phases |
|---|---|---|
| 1 | feat(android): persistent recipient store + multi-recipient JNI encrypt | 0a, 0b, 0c |
| 2 | feat(android): persist real recovery recipients to store | 1 |
| 3 | feat(android): real Android Keystore (StrongBox) enrollment + decrypt (minSdk 28->31) | 2 |
| 4 | feat(android): yubikit-android PIV enrollment over NFC/USB | 3 |
| 5 | feat(android): FIDO2/Passkey enrollment via Credential Manager | 4 |
| 6 | feat(android): wire enrollment UX to recipient store + decrypt path | 5 |

Independent commits; #3-5 land in any order after #1-2.

---

## Tracked follow-ups

These are explicit non-goals of the enrollment work above and need their own design passes when they come up:

- **Cipher rotation when recipient set changes.** When a recipient is added/revoked, existing ciphers still carry the old stanza set. Re-encrypting all ciphers to the current set is its own design (when to trigger, server-side cost, how to preserve history). Out of scope here.
- **Recipient priority/preference.** Today `MultiIdentityPickerSheet` lets the user choose among an item's recipients. Auto-prefer-Keystore (fastest), or auto-prefer-USB-when-plugged, is a future UX/heuristics pass.
- **Cross-device passkey sync via Google Password Manager.** Passkeys created here intentionally aren't synced -- their `hmac-secret` PRF is per-device by design. If we want shared passkeys, we'd need either a multi-device PRF derivation scheme or to abandon hmac-secret in favour of a device-local AES key. Out of scope.
- **~~`security-crypto = "1.1.0-alpha06"` is alpha.~~ Resolved by removal.** The `androidx.security:security-crypto` dependency is gone from `gradle/libs.versions.toml` and `app/build.gradle.kts`; `EncryptedSharedPreferences` / `MasterKey` are no longer used anywhere. `RecipientStore` now writes through `data/KeystorePrefs`, a ~70-line AES-256-GCM wrapper over plain `MODE_PRIVATE` prefs keyed by a non-exportable `AndroidKeyStore` secret (alias `ragewarden.recipients.aead.v1`, file `ragewarden.recipients.v2`). Trade-off worth knowing: unlike `EncryptedSharedPreferences` it does **not** encrypt pref *keys*, so `recipients:$accountId` is readable in cleartext. See `docs/THREAT-MODEL.md` §4.2.
- **Revoke UX clarity.** `RecipientStore.remove(accountId, recipientId)` only stops *future* ciphers from including the recipient's stanza. Existing ciphers retain the old stanza set. The in-app revoke UI should make this explicit: "this recipient will no longer be added to new items; existing items remain decryptable by any other recipient already on them, and unchanged until you re-encrypt." Cipher rotation (the bullet above) is the long-term fix.

## Open questions remaining

- Implementation order -- recommended: Phase 0 -> Phase 2 (Keystore, least UX-intrusive, all-Pixel-10-testable) -> Phase 3 (YubiKey, real-device-only) -> Phase 4 (Passkey).

---

## Public API

This section documents the surface that landed at the end of Phase 5. Every symbol below is reachable from `app` code and considered stable for the next minor version. The Threat-Model document (`THREAT-MODEL.md`) covers what each call commits to, security-wise.

### `enrollKeystoreIdentity`

`suspend fun enrollKeystoreIdentity(displayName, handle = ..., useStrongBox = true, requireBiometric = true): Pair<StoredRecipient, AndroidKeystoreIdentity>`

Suspends; runs on `Dispatchers.IO`. Generates an X25519 keypair inside Android Keystore (StrongBox when `useStrongBox = true` and supported by the device), with biometric gating when `requireBiometric = true`. Returns the public material as a `StoredRecipient` plus a ready-to-use `AndroidKeystoreIdentity`. **Does not** persist the recipient itself -- the caller is expected to hand the `StoredRecipient` to `RecipientStore.add(accountId, recipient)`. The private key never leaves Keystore. Throws if `KeyPairGenerator` setup fails (e.g. StrongBox requested but unavailable, or X25519 unsupported on the device's API level).

### `enrollYubiKeyPivX25519`

`suspend fun enrollYubiKeyPivX25519(activity, slot = Slot.AUTHENTICATION, pin: CharArray, displayName = null): Pair<StoredRecipient, YubiKeyPivIdentity>`

Suspends; spans NFC/USB-C transport orchestration, then runs the `PivSession` work on `Dispatchers.IO`. Waits for a YubiKey tap, verifies the supplied PIN, and generates an X25519 key directly on the token (`PinPolicy.ONCE`, `TouchPolicy.ALWAYS`). Returns the public material as a `StoredRecipient` plus a `YubiKeyPivIdentity` whose `pinProvider` re-prompts on each decrypt. The caller owns the `pin` `CharArray` and is responsible for zeroing it. Throws `YubiKeyX25519UnsupportedException` on firmware below 5.7. Side effect: writes a key to the named PIV slot on the token; existing key in that slot is overwritten.

### `enrollPasskeyWithPrf`

`suspend fun enrollPasskeyWithPrf(activity, accountId, rpId = "ragewarden.local", displayName = "Passkey on this device"): Pair<StoredRecipient, PasskeyIdentity>`

Suspends; runs on `Dispatchers.Main` (Credential Manager requires the main thread for UI). Standard flavor only; F-Droid flavor throws by design. Drives `CredentialManager.createCredential` with a WebAuthn registration request that requires user verification and asks for the `prf.eval.first` extension. Returns the credential ID + RP ID + 32-byte salt as a `StoredRecipient` (with `defaultEncrypt = false`) and a `PasskeyIdentity` ready for decrypt. Throws if the platform / installed credential provider does not support the PRF extension, or if the user cancels.

### `RecipientStore.add`

`suspend fun add(accountId: String, recipient: StoredRecipient)`

Suspends; runs on `Dispatchers.IO` under a per-store mutex. Inserts or replaces (by `id`) the recipient in the per-account list and persists to `KeystorePrefs`. If `accountId == activeAccountId`, also updates the live `flow`. Persists the recipient's *public* material only -- `StoredRecipient` has no fields that can hold a private key.

### `RecipientStore.remove`

`suspend fun remove(accountId: String, recipientId: String)`

Suspends; runs on `Dispatchers.IO` under the mutex. Removes the recipient from the per-account list and persists. Does **not** rotate or re-encrypt existing ciphers -- see the tracked follow-up about cipher rotation. If the removed recipient was the only one capable of decrypting some old ciphers, those ciphers become unreadable from this device.

### `RecipientStore.setDefaultEncrypt`

`suspend fun setDefaultEncrypt(accountId: String, recipientId: String, defaultEncrypt: Boolean)`

Suspends; runs on `Dispatchers.IO` under the mutex. Toggles whether new encrypts include this recipient's stanza. Does not affect existing ciphers and does not affect this recipient's eligibility to decrypt -- a `defaultEncrypt = false` recipient can still decrypt ciphers that already carry its stanza.

### `RecipientStore.touch`

`suspend fun touch(accountId: String, recipientId: String, now: Long = System.currentTimeMillis())`

Suspends; updates `lastUsedAt` for the recipient. Used by the decrypt path to drive recency sorting in pickers. Inject a fixed `now` from a `Clock` in tests rather than relying on `System.currentTimeMillis()`.

### `RecipientStore.setActiveAccount`

`suspend fun setActiveAccount(accountId: String?)`

Suspends; runs on `Dispatchers.IO` under the mutex. Switches the in-memory active-account pointer and resets the `flow` to that account's recipients (or empty if `null`). Pass `null` to detach (e.g. on logout).

### `RecipientStore.clearAccount`

`suspend fun clearAccount(accountId: String)`

Suspends; runs on `Dispatchers.IO` under the mutex. Drops the per-account entry from `KeystorePrefs` entirely. Fired by `UserLogoutManager` on logout. If the account is currently active, also clears the live `flow`.

### `RecipientStore.forAccount`

`fun forAccount(accountId: String): List<StoredRecipient>`

**Blocking.** Reads from `KeystorePrefs` synchronously on the calling thread. Used by repository code that needs a one-shot snapshot rather than a flow. Avoid calling on the main thread -- the underlying AndroidKeyStore AES-GCM decrypt is fast but not free. Returns an empty list if `accountId` is blank or unknown.

### `RecipientStore.flow`

`val flow: StateFlow<List<StoredRecipient>>`

Cold-on-construction, hot-after-`setActiveAccount`. Emits the current active account's recipient list and re-emits on every `add` / `remove` / `setDefaultEncrypt` / `touch` / `clearAccount` for the active account. Safe to collect on the main thread. Empty list when no account is active.

### `RageNative.encryptToRecipients`

`@JvmStatic external fun encryptToRecipients(plaintext: ByteArray, recipientsJson: ByteArray, prfInputsJson: ByteArray): ByteArray`

**Blocking JNI**; safe to call from `Dispatchers.IO`. Single entry point for multi-recipient encryption. Both JSON byte arrays are UTF-8. `recipientsJson` is the `WireRecipientList` produced by `BitwardenVaultRepository.collectActiveRecipients`; `prfInputsJson` is the `WirePrfInputList` produced by tapping the FIDO2/passkey credential manager. Returns the armored age blob as bytes. Throws (across the JNI boundary as a `RuntimeException`) on malformed JSON, unknown recipient kind, missing PRF for a recipient that requires one, or any Rust panic. Callers should wrap in `runCatching` and surface failures as user-visible errors. The function is **not** main-safe; route through `BitwardenVaultRepository.encryptForActiveRecipients`, which already dispatches to IO and applies the fail-closed policies (`NoRecipientsConfiguredException`, `PrfTapperNotConfiguredException`).
