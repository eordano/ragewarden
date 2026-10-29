# Recipient enrollment

How RageDroid enrols each recipient kind and wraps items to them. `THREAT-MODEL.md` has the
security model; `../DESIGN.md` §3 has the identities at decrypt time.

## Store and encrypt path

- `data/RecipientStore.kt` keeps a JSON list of `StoredRecipient` per `accountId` through
  `KeystorePrefs` (AES-256-GCM under a non-exportable AndroidKeyStore key). It holds public
  material and hardware handles only -- PIV slot and serial, credential ids, Keystore
  aliases. The cross-device registry note publishes the same public entries for the other
  clients.
- `BitwardenVaultRepository` gathers the account's `defaultEncrypt` recipients through core's
  recipient policy and calls JNI `encryptToRecipients(plaintext, recipientsJson,
  prfInputsJson)`. A FIDO2 or passkey recipient costs one prompt per write: the app draws a
  fresh 32-byte salt, the authenticator evaluates it, and the stanza carries that salt.
  PIV and Keystore recipients cost nothing at encrypt; they do ECDH only at decrypt.

## Recovery

`recovery::generate()` produces the mnemonic and its age key pair. The wizard persists only
the armored public key (`kind = Recovery`) after the user confirms words from the phrase;
the secret is re-derived from the mnemonic when needed (`recovery::from_phrase`). Recovery
opens items only through Settings -> Recover from phrase
(`BitwardenVaultRepository.decryptWithRecoveryPhrase`); `IdentityResolver` skips Recovery
recipients during routine reveals, so the paper key never makes a hardware tap optional.

## Android Keystore (StrongBox / TEE)

A P-256 (`secp256r1`) `PURPOSE_AGREE_KEY` key; the recipient is its 33-byte SEC1-compressed
public key and new items use `ragedroid-keystore-v2`. With authentication, a biometric or
the device credential unlocks it: per use on API 35+ (the `KeyAgreement` is the
`BiometricPrompt.CryptoObject`), a 30-second window opened by a prompt just before the
decrypt below that. Without a screen lock the key cannot require authentication, and it is
generated only after the user agrees to an unbound key. Emulators have no StrongBox; the
fallback ladder records which backing each key got. minSdk is 31.

## YubiKey PIV (NFC + USB-C)

`com.yubico.yubikit:android` and `:piv` 3.2.1 (Apache 2, F-Droid-compatible).
`YubiKitTransport.startUsbDiscovery` runs from `RageApplication` with permission handling,
so a USB-C key is asked for permission once and a key already plugged in when a prompt
opens is used immediately.

`enrollYubiKeyPiv(activity, slot = Slot.AUTHENTICATION, pin, displayName, curve =
PivCurve.P256)` waits for the key, verifies the PIN, and generates the slot key with
`PinPolicy.ONCE, TouchPolicy.ALWAYS`: P-256 by default (every PIV-capable YubiKey,
age-plugin-yubikey's format, rageterm's default), whose registry entry also publishes the
SPKI as `attestationPublicKey`; X25519 on request (firmware 5.7+). It then reads the slot's
touch policy back (GET METADATA) and refuses the slot if the card reports anything but
`always`. The serial is recorded, and at decrypt a different YubiKey is named, and a slot
whose touch policy is not `always` refused, before its PIN is used. `YubiKeyPivIdentity`
reads `piv-p256` (P-256) and the X25519 `piv-p256` / `piv-x25519-v2` stanzas by shape and
never claims a stanza on the other curve. The PIN is re-prompted on each decrypt.

## Passkeys (Credential Manager with PRF)

`enrollPasskeyWithPrf(activity, accountId, rpId = PasskeyRp.ID, displayName)` creates a
discoverable, ES256, user-verified passkey for `ragewarden.decent.foundation` with the
`prf.eval.first` extension. Credential Manager allows that RP because
`https://ragewarden.decent.foundation/.well-known/assetlinks.json` names this app and its
signing certificate. The recipient is `RecipientKind.PasskeyPrf` (`webauthn-prf-v1`
stanzas) with the credential id, the RP id, the enrolment salt and the credential's public
key (SPKI, published as `attestationPublicKey`), which lets the browser use the same
passkey through its relay page. A passkey asserts only with the RP it was made for, so
each recipient keeps its own RP id; entries stored before the RP id was recorded read
back as `ragewarden.local`, and passkeys enrolled earlier as `RecipientKind.Fido2` keep
working and can be moved from their recipient screen. Passkey recipients default to
`defaultEncrypt = false`, since each write costs a prompt.

The standard flavour uses Play services' Credential Manager; the F-Droid flavour uses the
installed credential providers Android offers from 14 on, and below that the enrolment
option says why it is unavailable. A provider without PRF is refused at enrolment.

## Rotation and revoke

The vault's rotation banner counts protected items not wrapped to the current recipient
set, and the re-encrypt wizard opens each with one tap of a current key and writes it back
to the current set (`BitwardenVaultRepository.rewrap`). A revoke offers the same pass while
the revoked key still covers items. Turning `defaultEncrypt` off only stops future writes
from including a recipient; it can still open items that carry its stanza.

## Verification

- Unit (JVM): every identity against its mock (`RAGEWARDEN_MOCK_HARDWARE=1`), alone and in
  combination; enrolment wording and flows under Robolectric.
- Instrumented (emulator): a real Keystore key opening real stanzas, the recipient store
  against real SharedPreferences, the registry push.
- Manual, before a release: Keystore prompt on a device with StrongBox; a YubiKey over NFC
  and USB-C; a passkey on the device (`../SECURITY.md`).

## Public API

Every symbol below is reachable from `app` code and considered stable for the next minor version. `THREAT-MODEL.md` covers what each call commits to, security-wise.

### `enrollKeystoreIdentity`

`suspend fun enrollKeystoreIdentity(displayName, handle = ..., useStrongBox = true, requireBiometric = true): Pair<StoredRecipient, AndroidKeystoreIdentity>`

Suspends; runs on `Dispatchers.IO`. Generates a P-256 key agreement key inside Android Keystore, trying StrongBox with authentication, StrongBox without, then the TEE in the same order, and records the rung it landed on. Returns the public material as a `StoredRecipient` plus a ready-to-use `AndroidKeystoreIdentity`. **Does not** persist the recipient itself -- the caller hands the `StoredRecipient` to `RecipientStore.add(accountId, recipient)`. The private key never leaves Keystore. Throws only when every rung fails.

### `enrollYubiKeyPiv`

`suspend fun enrollYubiKeyPiv(activity, slot = Slot.AUTHENTICATION, pin: CharArray, displayName = null, curve = PivCurve.P256): Pair<StoredRecipient, YubiKeyPivIdentity>`

Suspends; spans NFC/USB-C transport orchestration, then runs the `PivSession` work on `Dispatchers.IO`. Waits for a YubiKey tap, verifies the supplied PIN, and generates a P-256 key (or, with `curve = PivCurve.X25519`, an X25519 key) directly on the token (`PinPolicy.ONCE`, `TouchPolicy.ALWAYS`). Returns the public material as a `StoredRecipient` plus a `YubiKeyPivIdentity` whose `pinProvider` re-prompts on each decrypt. The caller owns the `pin` `CharArray` and is responsible for zeroing it. Throws `YubiKeyX25519UnsupportedException` for an X25519 request on firmware below 5.7, and `PivTouchPolicyException` when the card reports a touch policy other than `always` for the new key (firmware before 5.3 cannot report one; that is logged and accepted). Side effect: writes a key to the named PIV slot on the token; existing key in that slot is overwritten.

### `enrollPasskeyWithPrf`

`suspend fun enrollPasskeyWithPrf(activity, accountId, rpId = PasskeyRp.ID, displayName = "Passkey on this device"): Pair<StoredRecipient, PasskeyIdentity>`

Suspends; runs on `Dispatchers.Main` (Credential Manager requires the main thread for UI). Both flavours; the F-Droid one needs Android 14+ for a Credential Manager without Play services. Drives `CredentialManager.createCredential` with a WebAuthn registration request that requires user verification and asks for the `prf.eval.first` extension. Returns the credential ID + RP ID + 32-byte salt as a `StoredRecipient` (with `defaultEncrypt = false`) and a `PasskeyIdentity` ready for decrypt. Throws if the platform / installed credential provider does not support the PRF extension, or if the user cancels.

### `RecipientStore.add`

`suspend fun add(accountId: String, recipient: StoredRecipient)`

Suspends; runs on `Dispatchers.IO` under a per-store mutex. Inserts or replaces (by `id`) the recipient in the per-account list and persists to `KeystorePrefs`. If `accountId == activeAccountId`, also updates the live `flow`. Persists the recipient's *public* material only -- `StoredRecipient` has no fields that can hold a private key.

### `RecipientStore.remove`

`suspend fun remove(accountId: String, recipientId: String)`

Suspends; runs on `Dispatchers.IO` under the mutex. Removes the recipient from the per-account list and persists. Existing ciphers are re-wrapped by the bulk re-encrypt pass the revoke flow offers (`BitwardenVaultRepository.rewrap`); until then the removed recipient can still open them, and a cipher no remaining recipient can open stays unreadable from this device.

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

Suspends; runs on `Dispatchers.IO` under the mutex. Drops the per-account entry from `KeystorePrefs` entirely. It has no caller yet: sign-out keeps enrolled keys. If the account is currently active, also clears the live `flow`.

### `RecipientStore.forAccount`

`fun forAccount(accountId: String): List<StoredRecipient>`

**Blocking.** Reads from `KeystorePrefs` synchronously on the calling thread. Used by repository code that needs a one-shot snapshot rather than a flow. Avoid calling on the main thread -- the underlying AndroidKeyStore AES-GCM decrypt is fast but not free. Returns an empty list if `accountId` is blank or unknown.

### `RecipientStore.flow`

`val flow: StateFlow<List<StoredRecipient>>`

Cold-on-construction, hot-after-`setActiveAccount`. Emits the current active account's recipient list and re-emits on every `add` / `remove` / `setDefaultEncrypt` / `touch` / `clearAccount` for the active account. Safe to collect on the main thread. Empty list when no account is active.

### `RageNative.encryptToRecipients`

`@JvmStatic external fun encryptToRecipients(plaintext: ByteArray, recipientsJson: ByteArray, prfInputsJson: ByteArray): ByteArray`

**Blocking JNI**; safe to call from `Dispatchers.IO`. Single entry point for multi-recipient encryption. Both JSON byte arrays are UTF-8. `recipientsJson` is the `WireRecipientList` produced by `BitwardenVaultRepository.collectActiveRecipients`; `prfInputsJson` is the `WirePrfInputList` produced by tapping the FIDO2/passkey credential manager. Returns the armored age blob as bytes. Throws a `RageNativeException` on malformed JSON, unknown recipient kind or missing PRF for a recipient that requires one; a Rust panic in any export throws `RageNativeException.Internal` instead of aborting the process. Callers should wrap in `runCatching` and surface failures as user-visible errors. The function is **not** main-safe; route through `BitwardenVaultRepository.encryptForActiveRecipients`, which already dispatches to IO and applies the fail-closed policies (`NoRecipientsConfiguredException`, `PrfTapperNotConfiguredException`).
