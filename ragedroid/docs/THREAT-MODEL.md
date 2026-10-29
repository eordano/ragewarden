# Ragedroid threat model

Scope: the Android client (`ragedroid/app`), the Rust core (`core/`), and the JNI shim (`ragedroid/jni/`). The server in question is a self-hosted Vaultwarden (Bitwarden-compatible). This document is written for an external auditor and for internal contributors who need to make security-relevant changes.

The model is intentionally narrow: it covers what ragedroid adds on top of the Bitwarden zero-knowledge model. It does not re-derive the underlying Bitwarden cryptography -- see the upstream Bitwarden security whitepaper for the master-key/KDF/protected-symmetric-key derivation. What ragedroid layers on top is a multi-recipient `age`-style stanza wrapping that runs entirely client-side and produces an opaque ASCII blob the server treats as Type-2 ciphertext.

## 1. Zero-knowledge guarantees

The server (Vaultwarden) sees only what a stock Bitwarden server sees:

- Account email and KDF parameters (visible at login).
- Type-2 `EncString` blobs for cipher fields (name, login, notes, secure-note body, etc.).
- Cipher metadata: ID, folder ID, `revisionDate`, `creationDate`, organization ID.
- Sync deltas, history entries, share invitations -- same wire format as upstream Bitwarden.

The server does not see, and cannot derive without out-of-band keys:

- The user's master password.
- The user's master key, stretched master key, or protected symmetric key.
- The plaintext of any cipher field.
- Any rage stanza body or rage public key, except as enclosed inside an opaque ASCII payload that the server treats as a Type-2 EncString. The server cannot decrypt the EncString (that requires the user's symmetric key), and even if it could, the inner age blob is independently encrypted to the recipient set.
- Any private key material for any recipient kind (PIV, Keystore, FIDO2/Passkey, recovery).

Two layers of isolation apply, in order:

1. Outer layer (Bitwarden). Each cipher field is wrapped in a Type-2 EncString using the user's symmetric key. This is the standard Bitwarden encoding; the server holds only ciphertext.
2. Inner layer (rage). The cipher payload is itself a multi-stanza age blob. Each stanza wraps the same content-encryption key (CEK) to a different recipient. Decrypting any one stanza yields the CEK and unlocks the body.

The server therefore sees a Type-2 EncString of an age blob. Compromising the server gives the attacker neither key -- they would still need the user's master password (to peel off the outer layer) and at least one recipient's private material (to peel off the inner layer).

### 1.1 What a compromised server can do

Even though plaintext stays inaccessible, a malicious server is not a no-op. It can:

- Withhold ciphers (denial-of-service), or selectively serve stale revisions to roll back the user's view.
- Refuse to deliver new ciphers entirely, or modify the `revisionDate` ordering.
- Tamper with the outer Type-2 EncString. The user's symmetric key validates the GCM tag; tampering surfaces as "decrypt failed" on the client. There is no silent corruption.
- Truncate or replace a stanza-set inside an inner age blob. Modified blobs fail to decrypt (age uses authenticated encryption end-to-end inside its own framing).
- Observe access patterns -- which cipher IDs the user fetches, when, and how often.

The server cannot swap one user's recipient set for another (the recipient material is inside the inner age blob, which is itself inside the outer EncString -- both layers must be peeled to alter the recipient list). It cannot add a stanza that decrypts to a server-controlled key without first holding the user's symmetric key.

### 1.2 What ragedroid does not protect

Out of zero-knowledge scope:

- Account existence and metadata. The server knows the user's email address, KDF parameters, organization memberships, and cipher counts.
- Folder structure. Folder names live in Type-2 EncStrings, but folder count and cipher-to-folder mapping are visible (the mapping is a metadata field).
- Sync timestamps. `revisionDate` is plaintext. The server learns when each cipher last changed.
- Bitwarden upstream features ragedroid does not modify. Sends, password history, attachments -- these inherit upstream Bitwarden's exact zero-knowledge guarantees, no more and no less.

## 2. Trust boundaries per recipient kind

Each recipient kind has a different trust anchor. The relevant question for an attacker is: given capability class C, can I extract the secret needed to decrypt a stanza of kind K? The columns below answer that.

### 2.1 Software (master-key derived)

- Where the secret lives. ragedroid never creates Software recipients; `IdentityResolver` skips any it meets, so they protect items only on the clients that hold them.
- Persistent storage. None on the device. The recipient's public key is part of the cipher's stanza set and travels through the server like any other stanza.
- Adversarial model. Compromising this stanza requires either (a) the master password, (b) a memory dump of the unlocked process, or (c) extraction of derived key material before the user locks the vault.
- Server trust. None. The server never sees the master key.

### 2.2 Recovery (BIP-39 mnemonic)

- Where the secret lives. The mnemonic is shown to the user once during enrollment and is the only persistent representation of the private key. The armored age secret is reconstructable from the mnemonic on demand via `recovery::from_phrase` in the Rust core.
- Persistent storage on device. Only the armored public key (`recoveryArmoredPubkey`). The mnemonic is never written to disk by ragedroid.
- Adversarial model. Compromise requires possession of the mnemonic. Anyone with the 24-word phrase can decrypt every cipher whose recipient set includes this recovery recipient. The mnemonic is a backup factor: assume it is written down on paper and stored physically; the device is not the attack surface for this kind.
- Server trust. None.

### 2.3 Android Keystore P-256 (StrongBox or TEE)

- Where the secret lives. Inside the Android Keystore HAL, backed by StrongBox where available (Pixel 6+, Pixel 10) or TEE where not. The private key never leaves the secure element; `KeyAgreement.doPhase` returns only the ECDH shared secret.
- Persistent storage on device. The 33-byte SEC1-compressed P-256 public key (`keystorePubkey`) and an opaque alias string (`keystoreHandle`) used to look up the key in Keystore. The handle is not a secret -- losing it only loses the ability to use the key.
- Adversarial model. Extracting the private key requires defeating StrongBox/TEE itself, which is the device's hardware root of trust. The key spec sets `setUserAuthenticationRequired(true)` with `AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL`, so a device PIN/pattern also satisfies it. Precisely: on Android 15 (API 35) and later the key is generated with validity 0 -- every ECDH needs its own authentication, run with the `KeyAgreement` as the `BiometricPrompt.CryptoObject` (`AndroidKeystoreIdentity.perUseEcdh`), so an attacker with full app-process compromise cannot use the key without a fresh prompt. Below API 35 a `KeyAgreement` cannot be a CryptoObject, so the key falls back to a 30-second window (`KEY_VALIDITY_SECONDS`): it cannot be invoked cold, but can be invoked freely for 30 s after any legitimate unlock. Keys enrolled before this change keep the window they were generated with (`StoredRecipient.keystorePerUse`). StrongBox is requested first (`setIsStrongBoxBacked(true)`) with a documented fallback ladder down to TEE and to no-biometric, so the enrolled recipient records which rung it landed on.
- Server trust. None.

### 2.4 YubiKey PIV (NFC / USB-C)

- Where the secret lives. Inside the YubiKey's PIV applet. Generated in place by `PivSession.generateKey(slot, KeyType.ECCP256, PinPolicy.ONCE, TouchPolicy.ALWAYS)` (X25519 for slots on firmware 5.7+ when chosen); the private key never leaves the token.
- Persistent storage on device. The public key (`pivPubkey`: 33-byte SEC1 P-256 or 32-byte X25519), the YubiKey's serial number (`pivSerial`), and the slot byte (`pivSlot`). None are secret. The serial is checked before the PIN is sent, so a different YubiKey is named instead of spending a PIN attempt.
- Adversarial model.
  - `PinPolicy.ONCE`: PIN required once per power cycle.
  - `TouchPolicy.ALWAYS`: every decrypt requires a physical tap on the token. The policy is read back off the card (GET METADATA, INS 0xF7, yubikit's `getSlotMetadata`; `identities/PivTouch.kt`) right after generation and again before every unwrap, before the PIN is sent; a slot reporting `never`, `default` or `cached` is refused both times, whoever generated it. Firmware before 5.3 has no GET METADATA: such a slot is used on the policy it was generated with, and the read failure is logged.
  - PIN-block: 3 wrong PIN entries irreversibly block the slot until a PUK reset.
  - Physical possession of the token + knowledge of the PIN is needed to use it.
- Server trust. None.

### 2.5 FIDO2 / Passkey hmac-secret (PRF extension)

- Where the secret lives. Inside a WebAuthn authenticator that supports the `hmac-secret` CTAP2 extension (or `prf` at the WebAuthn layer). For built-in Android passkeys this is the device's TEE. For roaming authenticators this is the YubiKey 5C / 5 NFC.
- Persistent storage on device. The credential ID (`fido2CredentialId` or `passkeyCredentialId`), the relying-party ID (`fido2RpId` / `passkeyRpId`), the enrolment salt (`fido2Salt` / `passkeySalt`) and, for passkeys, the credential public key (`passkeyPublicKeySpki`). None is the PRF output, which is `HMAC-SHA256(authenticator_secret, salt)` computed inside the authenticator.
- Adversarial model. An attacker who reads the recipient store learns: which credential ID, which RP, and the 32-byte salt. They cannot derive the PRF output without the authenticator. If the authenticator is a roaming token, the attacker also needs physical possession; if it is a platform passkey, they need to defeat the TEE plus pass user verification.
- Salt per secret. Every write asks the authenticator for a PRF over a fresh 32-byte salt and stores that salt in the stanza, so one captured PRF output opens one secret. Stanzas written before this carry the enrolment salt and are replaced when the item is re-wrapped.
- Server trust. None. The server never sees the salt or the PRF output, only the resulting age stanza body.

### 2.6 Cross-kind invariants

Some properties hold across all hardware-rooted recipient kinds (Keystore, PIV, FIDO2/Passkey):

- Public-only persistence. `RecipientStore` carries only public keys (or, for FIDO2 and passkeys, the credential ID and salt -- neither of which is sufficient to derive the PRF output without the authenticator). A snapshot of the recipient store is not in itself a path to plaintext.
- Per-decrypt user presence. Every hardware-rooted decrypt requires either a biometric prompt (Keystore), a token tap (YubiKey), or a credential-manager assertion (FIDO2/Passkey). The Keystore key is the exception within its 30-second authentication window (§2.3); YubiKey and FIDO2/passkey assertions are per use.
- Per-account isolation. All `RecipientStore` operations are keyed on `accountId`. Switching active account swaps the visible recipient list; the inactive account's recipients are inaccessible to the active flow.
- Independence at decrypt. Each stanza is independently decryptable. Compromising one recipient (e.g. someone steals one of your YubiKeys) does not affect the secrecy of stanzas wrapped to other recipients on the same cipher; it only means that one stanza can now be unwrapped by the holder of the stolen key.

## 3. Attacker capability matrix

The columns are recipient kinds; the cells answer "can the attacker decrypt a cipher whose only listed recipient is this kind?". "No" means defeated; "Yes" means the kind does not stop this attacker (some other recipient may still stop them -- this matrix is per-kind).

| Capability | Software | Recovery | Keystore | YubiKey | FIDO2/Passkey |
|---|---|---|---|---|---|
| 1. Network-only (passive observer) | No | No | No | No | No |
| 2. Compromised server | No | No | No | No | No |
| 3. Lost device, locked | No* | No | No | No | No |
| 4. Lost device, unlocked vault | Yes | No | Yes** | No | Yes** |
| 5. Malicious app, same device | No | No | No | No | No |
| 6. Hardware token theft (no PIN) | n/a | n/a | n/a | No | No |
| 7. Rooted device | No* | No | No | No | No |

\* Software stanzas are bound to the master password via the Bitwarden symmetric key. A locked or rooted-but-locked device gives the attacker only the outer Type-2 EncString, which they cannot peel without the master password. Once the master password is brute-forced (KDF cost permitting), software stanzas fall.

\** "Yes" here means: the attacker can request decrypt and the OS will satisfy the user-presence check because the device is currently unlocked / the user is currently authenticated. Precisely:

- The Keystore key is gated by `AUTH_BIOMETRIC_STRONG` or `AUTH_DEVICE_CREDENTIAL` (`AndroidKeystoreEnrollment.kt`), so a device PIN/pattern satisfies it -- not only a biometric.
- On API 35+ that gate is per use: the key is generated with validity 0 and each ECDH runs its own prompt with the `KeyAgreement` as CryptoObject. Below API 35 it is time-bound, `setUserAuthenticationParameters(KEY_VALIDITY_SECONDS = 30, ...)`, because a `KeyAgreement` cannot be a CryptoObject there: the reveal flow prompts before each decrypt, but within 30 s of a passing auth the key is usable again with no further prompt.
- YubiKey stanzas require a fresh tap: `YubiKitPivEnrollment` generates the slot with `TouchPolicy.ALWAYS`, and before every unwrap ragedroid reads the slot's policy back with GET METADATA, as rageterm does, and refuses any other (§2.4). A slot generated elsewhere -- by rageterm or `ykman` -- gets the same check.

Passkey stanzas similarly require user verification at decrypt; whether that succeeds without user awareness depends on the platform UI.

### 3.1 Notes per capability

1. Network-only attacker. Sees Type-2 EncStrings on the wire. Defeats no recipient kind.
2. Compromised server. Same view as the network attacker plus access to the cipher database. Defeats no recipient kind.
3. Lost device, locked. Recipient store is encrypted-at-rest via `KeystorePrefs` (see §4.2 -- not `EncryptedSharedPreferences`, which this app does not depend on). Keystore handles can't be invoked without biometric. PIV/FIDO2 require their respective second factors and PINs.
4. Lost device, unlocked. This is the worst real-world case for software-only stanzas. Hardware-rooted recipients still gate decrypt on user presence (biometric tap, YubiKey tap). Best practice: enroll at least one hardware recipient and lock the vault aggressively.
5. Malicious app on device. Cannot read another app's private `SharedPreferences` file, and could not use it if it did (§4.2); cannot invoke another app's Keystore aliases; cannot drive `BiometricPrompt` for another app.
6. Hardware token theft. PIV requires PIN (3-strike block). FIDO2 requires user verification, which on a YubiKey is the same PIN.
7. Rooted device. `KeystorePrefs` values are bound to a non-exportable `AndroidKeyStore` AES-GCM key. Root can read the prefs file, but the wrapping key lives in Keystore. New keys are StrongBox-backed where the device has one and TEE-backed otherwise (§4.2). Software stanzas remain protected by the master password.

### 3.2 Layered defenses

A practical recipient policy combines kinds with disjoint failure modes:

- Software + Recovery + (Keystore or YubiKey). The minimum recommended set. Software gives you cheap unlock on each device. Recovery gives you the offline-paper escape hatch. Keystore or YubiKey gives you a phishing-resistant factor.
- Passkeys cost a tap per save. A passkey recipient that wraps new items needs one credential-manager prompt per write (a fresh PRF salt each time), so passkey enrolment defaults to `defaultEncrypt = false`; the user can turn it on per recipient.
- Avoid single-recipient ciphers. A cipher with exactly one recipient is recoverable only if that recipient survives. If the user loses their YubiKey and enrolled it as a single recipient on some sensitive cipher, that cipher is gone. First run and Settings push for a second key and a paper Recovery recipient, and first run says the vault is not protected while none is enrolled.

### 3.3 Race conditions and timing

Two notes on observable timing:

- `RecipientStore.flow` reads. `KeystorePrefs` decrypt is constant-overhead per access. We do not rely on the secrecy of recipient count or kind; an attacker who can time the reads learns at most "the user has N recipients of unknown kinds", which is not a meaningful leak.
- `encryptForActiveRecipients`. Encrypt time scales linearly with the number of stanzas, but each stanza derives from independent randomness; there is no cross-stanza key. An attacker who watches encrypt latency learns approximately how many recipients are active. Not a secret.

## 4. What is in `RecipientStore`

`StoredRecipient` is the single on-disk record per enrolled recipient. The full schema, field by field:

| Field | Type | Secret? | Notes |
|---|---|---|---|
| `id` | String (UUID) | No | Local identifier. |
| `kind`                  | enum           | No      | One of `YubiKey`, `Fido2`, `PasskeyPrf`, `StrongBox`, `Recovery`, `Software`. |
| `displayName` | String | No | User-supplied label. |
| `createdAt` | Long | No | Epoch millis. |
| `lastUsedAt`            | Long           | No      | Epoch millis; updated by `RecipientStore.touch`.                      |
| `defaultEncrypt` | Boolean | No | Whether new ciphers include a stanza for this recipient. |
| `pivPubkey` | ByteArray? | No | 33-byte SEC1 P-256 or 32-byte X25519 public key. |
| `pivSerial` | Int? | No | YubiKey serial. |
| `pivSlot`               | Byte?          | No      | PIV slot identifier (e.g. `0x9a` AUTHENTICATION).                     |
| `fido2CredentialId` | ByteArray? | No | Opaque WebAuthn credential ID. |
| `fido2RpId` | String? | No | Relying-party ID. |
| `fido2Salt` | ByteArray? | No | 32 bytes of random salt. Not the PRF output. |
| `keystorePubkey` | ByteArray? | No | 33-byte SEC1-compressed P-256 public key. |
| `keystoreHandle` | String? | No | Opaque Keystore alias. |
| `passkeyCredentialId`   | ByteArray?     | No      | Same shape as `fido2CredentialId`.                                    |
| `passkeyRpId`           | String?        | No      | Same shape as `fido2RpId`.                                            |
| `passkeySalt`           | ByteArray?     | No      | Same shape as `fido2Salt`. Not the PRF output.                    |
| `passkeyPublicKeySpki`  | ByteArray?     | No      | The passkey's public key, published as `attestationPublicKey` for the browser's relay. |
| `recoveryArmoredPubkey` | String? | No | Armored age public key for recovery; the secret never lives here. |
| `keystoreAuthBound`     | Boolean?       | No      | Whether the Keystore key requires user authentication. |
| `keystorePerUse`        | Boolean        | No      | Whether it prompts per use (API 35+) rather than a 30-second window. |

### 4.1 Never stored

The following secrets exist nowhere in `RecipientStore`, nowhere on disk, and nowhere in any ragedroid persistence layer:

- The recovery mnemonic itself.
- The armored age recovery secret.
- Any X25519 private scalar for any recipient kind.
- Any FIDO2 / passkey `hmac-secret` value or any `prf.results.first` output.
- The Bitwarden master password.
- The Bitwarden master key or stretched master key, and the user symmetric key in the clear (it lives in process memory while unlocked; the session blob holds it only encrypted, §4.2).
- The PIV PIN (collected ad-hoc as a `CharArray`, zeroed after use).

### 4.2 At-rest encryption

`RecipientStore` and `SessionStore` write through `data/KeystorePrefs`:

- Plain `getSharedPreferences(name, MODE_PRIVATE)` for the file.
- Values encrypted with `AES/GCM/NoPadding`, 256-bit, `setRandomizedEncryptionRequired(true)`, stored as `base64(IV‖ciphertext‖tag)` with a 12-byte IV and a 128-bit tag.
- Pref names are `h:` + HMAC-SHA256 of the logical key under a per-store Keystore HMAC key, so account ids never appear in the file; legacy cleartext names are migrated on first read.
- A value the key cannot open raises `StoreUnreadableException`; `RecipientStore` flags the account and refuses to overwrite it instead of reading it as an empty list. The vault screen and Settings, then Keys, show the unreadable list with a Reset key list action (`resetUnreadable`), and an enrolment that hits it says so instead of failing with a stack trace.
- Key material: one non-exportable `AndroidKeyStore` `SecretKey` per store, created on first use -- alias `ragewarden.recipients.aead.v1` for recipients, `ragewarden.session.aead.v1` for the session blob. Files: `ragewarden.recipients.v2` and `ragewarden.session.v2`.
- New keys request StrongBox (`setIsStrongBoxBacked(true)`) and fall back to the TEE on `StrongBoxUnavailableException`.
- The stored session blob never contains the user keys: it holds tokens plus `protectedUserKey`, the user key encrypted under the stretched master key (Bitwarden's own construction). Unlocking needs the master password, or biometrics through `SessionKeyWrap` (an auth-bound, per-use `CryptoObject` key invalidated by biometric re-enrolment).

A rooted attacker reading the raw XML gets ciphertext for every value; the wrapping key stays in Keystore.

### 4.3 Per-account separation

The store key inside `KeystorePrefs` is `recipients:$accountId` (see `RecipientStore.prefKey`). This means:

- Multi-account installs keep their recipients strictly separated; account A cannot see account B's recipients without explicitly switching `setActiveAccount`.
- `clearAccount(accountId)` removes only that account's pref entry; other accounts' entries survive a logout of one account.
- An attacker who can somehow read the file gets a separate ciphertext per account, but cannot tell from the prefs alone which account the user was logged into most recently.

## 5. On-device confidentiality

### 5.1 Session storage

`SessionStore` (`data/SessionStore.kt`) stores the Bitwarden session blob through `KeystorePrefs` -- AES-256-GCM under a non-exportable AndroidKeyStore key, the same primitive `RecipientStore` uses. Prefs file `ragewarden.session.v2`, key alias `ragewarden.session.aead.v1`.

The blob holds the access and refresh tokens and `protectedUserKey`, the user key encrypted under the stretched master key; it never holds the user key itself. Opening the vault needs the master password (which works offline) or biometrics through `SessionKeyWrap`, an auth-bound per-use key invalidated by biometric re-enrolment. An attacker who can run code as the app uid can ask Keystore to decrypt the blob and so obtain the tokens, which fetch the vault's ciphertext from the server but open nothing. `allowBackup="false"` and the `data_extraction_rules.xml` exclusions keep the file out of cloud backup and device transfer; sign-out (`SessionStore.clear()`) removes it.

### 5.2 Screen capture

Every Activity that can put a secret on screen sets `FLAG_SECURE` (`ui/SecureWindow.kt`): `MainActivity`, `AutofillAuthActivity`, `AutofillUnlockActivity`, `AutofillSaveActivity` and `ImeAuthActivity`. Revealed values, note/card/SSH bodies and the paper-recovery word grid are therefore not screenshot-able, screen-recordable, capturable through `MediaProjection`, or thumbnailed into Recents.

`FLAG_SECURE` is a window flag, so it is set for the whole Activity rather than toggled around each reveal: toggling would recreate the surface mid-interaction and would still leave the Recents snapshot -- taken when the Activity stops, not while the secret is visible -- unprotected. There is deliberately no debug-build escape hatch.

What it does not cover: `RagewardenInputMethodService` (an IME window, which never renders plaintext -- it commits the value into the host app's field and shows only item names, and only while the vault is unlocked -- see §5.3) and the host app's own window, which is not ours to flag. And per §8, a privileged screen-recorder can still defeat `FLAG_SECURE`; this stops ordinary apps and the system's own thumbnailing, not a rooted attacker.

### 5.3 The app lock

The lock is `data/LockState.kt`: a `@Singleton` (bound in `di/AppModule.kt`, reachable via `AppEntryPoint.lockState()`), not a navigation destination and not a value inside `RageApp`'s composition. `ui/RageApp.kt` observes it with `collectAsState`. While it is true the entire stage tree is not composed and `LockScreen` renders in its place; it is cleared only by a successful unlock (biometric/device credential, or a master password verified by `BitwardenVaultRepository.verifyMasterPassword`) or by sign-out. The global `BackHandler` short-circuits while locked, so back cannot walk out of it.

Initial value, fail-closed, evaluated once per process at first read:

1. no session on the device -> nothing to protect -> unlocked, and the stale persisted flag is dropped;
2. otherwise `LockPolicy.lockOnLaunch` is a floor, not a value -- when it is on (the default) a fresh process starts locked whatever was persisted;
3. otherwise the persisted `SharedPreferences` flag wins, defaulting to `true` when absent.

Writes go through `commit()`, not `apply()`, so a lock is on disk before the call returns. Tests: `app/src/test/kotlin/ragewarden/ragedroid/data/LockStateTest.kt`.

Back resolves the Activity through `LocalActivity.current` or `ui/ActivityContext.kt`'s `findActivity()` (which walks the `ContextWrapper` chain), so `moveTaskToBack` works from the locked screen; `FindActivityTest` pins it. If no Activity resolves, back is swallowed, which is fail-safe.

Locking drops the user keys and the decrypted snapshot from memory (`BitwardenVaultRepository.lock`, run from every `LockState.lock()`); only the encrypted sync response stays, sealed on disk by `VaultCache`, so unlocking works offline. It also locks after five idle minutes and when the screen turns off. The readers and what each does while locked:

- `ui/RageApp.kt` -- the stage tree is not composed; `LockScreen` renders instead. Every `snapshot()` / `decrypt()` call site under `ui/screens/` is inside that tree, and the post-unlock autosync `LaunchedEffect` is guarded by `!locked`.
- `ime/RagewardenInputMethodService` -- routes both the listing and the delivery through `ime/ImeDelivery.kt`, which consults `LockState` on every call. `offer()` returns an empty list while locked, so the keyboard does not even enumerate item names; `deliver()` checks the lock twice, once on entry and once after the decrypt resolves (the decrypt suspends and can wait on a network sync, so "Lock now" can land inside that window). `commitText` is reachable from exactly one lambda, the one `deliver()` invokes only on the success path. Tests: `ImeDeliveryTest`, `ImeSurfaceLockedTest`.
- `autofill/RagewardenAutofillService` -- `onFillRequest` answers only the "Unlock Ragewarden to fill" entry while locked (plus the `SaveInfo` that lets Android offer a save), so no dataset and no item name reaches the host app's picker.
- `autofill/AutofillSaveActivity` -- shows `LockScreen` until the vault is unlocked; the vault is not read, not even to see whether a login for the site exists, before that, and nothing is written before the user presses Save.
- `autofill/AutofillAuthActivity` -- refuses in `onCreate` before the item is looked up (a dataset's `PendingIntent` outlives the fill request that built it, so it can be entered after the vault has locked), and re-checks after the tap ceremony and decrypt resolve, throwing so `InlineTapReveal` can explain rather than blinking away.

While locked, neither surface lists anything, but both offer the way back: the autofill response is a single "Unlock Ragewarden to fill" entry whose authentication opens `AutofillUnlockActivity`, and the keyboard shows an "Unlock Ragewarden" button. Locking also drops the keys: the repository strips the user key out of the session blob and clears the decrypted vault cache; unlock re-derives the key and decrypts the sealed offline copy.

### 5.4 Plaintext lifetime in the app process

A decrypted secret is a `ByteArray` from the JNI call until the Android API that delivers it, and is zeroed in a `finally` once that API returns:

- Clipboard: `Clipboard.copySensitive` decodes the bytes into a `CharArray` (`SecretText`), hands `ClipData` a `CharBuffer` over it, and zeroes it when `setPrimaryClip` returns. The 30-second clearer recognises its own clip by a nonce in the clip description, so it never reads the secret back into the process.
- Autofill: `AutofillValue.forText` gets a `CharBuffer`; the characters are zeroed after `finish()` has handed the result to the system.
- Keyboard: `commitText` gets a `CharBuffer`, zeroed when the call returns.
- Saving from another app: the typed password arrives as the host's `CharSequence` in the `AssistStructure`; it is copied into a `CharArray` held by `PendingSaves` -- zeroed when not taken within two minutes, and when `AutofillSaveActivity` is destroyed -- and encoded to UTF-8 bytes only for the write, which are zeroed when it returns. The intent that opens the activity carries a token, not the password.
- Re-sealing protected fields builds the v2 field-map JSON from byte arrays (`SecretText.fieldsJson`); every buffer is zeroed after `sealProtectedFields` and the encrypt.

What Android requires, and is therefore not avoidable in this process:

- Each of those three APIs parcels its `CharSequence` for the binder call, and parcelling text creates a `String` (`TextUtils.writeToParcel`). It lives only for the duration of the call, but it is a `String`, so it is not zeroed; it is reclaimed by the garbage collector.
- A secret shown on screen is rendered by a Compose `Text`, which takes a `String`. One `String` is made per reveal (not per frame), and the reveal auto-clears.
- Text the user types into a field (a new password, a card number on the add form) is held by the text field's state as a `String`.

## 6. PIN / biometric model

### 6.1 Keystore (Android)

Keys generated by `enrollKeystoreIdentity` with biometric protection use:

```
.setUserAuthenticationRequired(true)
.setUserAuthenticationParameters(
    if (SDK_INT >= 35) 0 else 30,
    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
)
```

A class-3 biometric or the device credential satisfies the gate. On API 35+ the validity is 0: each `KeyAgreement.doPhase` runs its own `BiometricPrompt` with the `KeyAgreement` as the `CryptoObject`. Below 35 a `KeyAgreement` cannot be a `CryptoObject`, so the key is usable for 30 seconds after a prompt the reveal flow runs just before each decrypt. A key without user authentication is generated only after the user agrees to it (no screen lock set).

Failure modes:

- New biometric enrolment: a validity-0 key (API 35+) is invalidated (`KeyPermanentlyInvalidatedException`) and the recipient must be re-enrolled; a 30-second-window key is not, because Android applies that invalidation only to per-use keys.
- StrongBox unavailability: detected via `isStrongBoxAvailable(context)`; enrolment falls back to the TEE.

### 6.2 PIV PIN handling

The YubiKey PIV PIN is collected via `SecurePinField` (`ragedroid/app/src/main/kotlin/ragewarden/ragedroid/ui/components/SecurePinField.kt`). The contract:

- Storage during entry: `CharArray` only -- never a Kotlin `String`. Strings are interned and immutable; a `CharArray` can be zeroed.
- Lifetime: the buffer is wiped (filled with `0.toChar()`) immediately after `PivSession.verifyPin(pin)` returns, regardless of success.
- The PIN never reaches `RecipientStore` and is never logged.
- `pinProvider` callbacks in `YubiKeyPivIdentity` request a fresh PIN entry on each decrypt; old buffers are not retained.

### 6.3 FIDO2 / passkey user verification

`buildAssertionJson` and `buildEnrollmentJson` set `userVerification = "required"`. The platform credential manager enforces this; ragedroid does not collect the PIN or biometric itself.

## 7. Multi-recipient encryption

### 7.1 Per-encrypt behaviour

`BitwardenVaultRepository.encryptForActiveRecipients` runs at every write of a protected value. It:

1. Gathers `WireRecipient` entries from `RecipientStore.forAccount(accountId).filter { it.defaultEncrypt }`.
2. For each FIDO2 / passkey recipient, draws a fresh 32-byte salt and asks the installed `PrfTapper` to evaluate it (one credential-manager prompt per recipient, matched by credential id).
3. JSON-encodes the recipient list and the PRF results, hands them to `RageNative.encryptToRecipients`.
4. The Rust core builds one age stanza per recipient and concatenates them; every stanza encapsulates the same 16-byte CEK that wraps the body.

Consequence: any single enrolled `defaultEncrypt = true` recipient is sufficient to decrypt the resulting blob. The user can choose at decrypt-time which recipient to use (via `MultiIdentityPickerSheet`).

### 7.2 Adding a recipient

- New ciphers, and updates that change a protected value, include the new recipient.
- Existing ciphers keep their stanza set until re-encrypted: the rotation banner reports items not yet wrapped to the current set, and the bulk re-encrypt pass (§7.3) brings them up to date.

### 7.3 Removing a recipient

`RecipientStore.remove(accountId, recipientId)` deletes the entry. Effects:

- Future encrypts skip this recipient -- its stanza will not appear in newly written ciphers.
- Existing ciphers still carry the old stanza, including ciphers that cannot otherwise be decrypted by the user's current recipient set. If the removed recipient was the only one capable of decrypting some old cipher, that cipher is now permanently unreadable from this device.
- The recipient's public material is gone from the device, but the same public key already lives inside every old cipher's stanza on the server. Removing a recipient does not delete it from history.

After a revoke the app offers the re-encrypt pass (the backfill wizard, also reachable from the vault's rotation banner): every protected item still wrapped to the old set is opened with one tap of a current key and written back unchanged to the current recipients (`BitwardenVaultRepository.rewrap`), and the vault is marked current once every item is done. Until an item has been re-encrypted, the revoked recipient can still open it; an item no current key can open stays as it is and is listed as failed.

### 7.4 Fail-closed posture

`encryptForActiveRecipients` throws `NoRecipientsConfiguredException` if the active set is empty. The repository surfaces this as a hard error; nothing is sent to the server. There is no fallback to "encrypt to nobody" or "encrypt to a default key".

If a FIDO2 / passkey recipient is in the active set and no `PrfTapper` is installed, the encrypt throws `PrfTapperNotConfiguredException`. Same fail-closed posture.

### 7.5 What a stanza commits to

For each kind, the stanza on disk binds:

- Software: the `age` X25519 ephemeral pubkey; the recipient's static X25519 pubkey; an HKDF-derived wrapping key over the CEK.
- Recovery: identical structure to Software (recovery keys are X25519 keys derived from BIP-39, with a distinct armored prefix to make decrypt UX clearer).
- Keystore / PIV: an ephemeral public key, a recipient tag, and an HKDF-derived wrapping key whose IKM is the ECDH share (P-256 for Keystore and P-256 PIV slots, X25519 for X25519 slots); the v2 tags also put the recipient's public key in the HKDF salt.
- FIDO2 / Passkey: the credential ID, the salt, and an HKDF-derived wrapping key whose IKM is the PRF output. Decryption requires re-deriving the PRF output from the same salt + same authenticator; a different authenticator with the same credential ID would yield a different PRF output and fail the wrap.

There is no recipient-kind ambiguity at decrypt time: each stanza tag (`X25519` for software and recovery identities, `ragedroid-keystore-v1`/`-v2`, `piv-p256`, `piv-x25519-v2`, `fido2-hmac`, `webauthn-prf-v1`) selects a distinct unwrap path. An attacker cannot present a stanza of the wrong kind to trick the client into using the wrong key.

## 8. Out-of-scope attacks

The following are explicitly out of scope. We do not claim defense against them; users with these threats in their model need defenses outside ragedroid.

- Physical tampering with a running, unlocked device. If the device is in the user's hand and unlocked, every secret the device can compute, the attacker can compute. Recovery and Software stanzas can both be unwrapped at will. Hardware-tap recipients (YubiKey `TouchPolicy.ALWAYS`, the Keystore's biometric or device-credential gate) still gate user presence, but a device in the attacker's possession defeats most other defenses.
- Targeted malware that captures user input system-wide. A keylogger or screen-recorder running with elevated privileges can steal the master password as it is typed, the PIV PIN, the recovery mnemonic during reveal, and any data the user views in the unlocked vault. Defeating this requires OS-level isolation that ragedroid cannot provide.
- Quantum computing. X25519 and Ed25519 are not post-quantum. A future cryptographically-relevant quantum computer can break every recipient stanza we issue today. This is an industry-wide problem; PQC migration is a separate, multi-year design effort.
- Side channels in StrongBox / TEE. We rely on the secure element's resistance to fault injection, power analysis, and timing attacks. We do not add software-side mitigations.
- Loss of the recovery mnemonic. If the user loses the mnemonic and every other recipient becomes unavailable (lost YubiKey, wiped device, etc.), the vault is gone. We do not (and cannot) escrow.
- Compromise of the user's master password. The outer Bitwarden layer falls; rage stanzas of `Software` kind fall. Hardware-rooted stanzas (PIV, Keystore, FIDO2) still hold.
- Supply-chain compromise of build tools. A malicious AGP, Gradle plugin, NDK toolchain, or Rust toolchain can inject code into the shipped APK. Defenses against this live in CI infrastructure (reproducible builds, signed releases, dependency pinning) and are out of scope for this document. We pin major versions in `gradle/libs.versions.toml` and the Rust core has a `Cargo.lock`.
- Compromised PRNG. We trust `SecureRandom` (Android) and `OsRng` (Rust) for all secret generation. A backdoored device PRNG leaks every freshly generated key; we have no defense against this and no way to detect it.
- Authenticator firmware compromise. A malicious YubiKey or platform passkey implementation can leak keys. We trust the authenticator manufacturer and the WebAuthn attestation chain (where present).

## 9. Audit checklist

An external auditor reviewing the rage layer should focus on the following files. Path entries are all relative to the repository root.

### Rust core

- `core/src/lib.rs` -- `Recipient` enum, stanza construction, the `encrypt_with_prf` entry point, the per-stanza HKDF info strings, and the test suite that round-trips each kind; `core/tests/vectors/` pins every stanza writer's output.
- `core/src/recovery.rs` -- BIP-39 generation, mnemonic->secret derivation, armored output format.
- `core/src/stanza.rs`, `core/src/stanza_format.rs` -- per-kind stanza encoding and HKDF salt/info bindings for all identity kinds (Keystore, PIV, FIDO2, passkey-PRF).

### JNI shim

- `ragedroid/jni/src/lib.rs` -- only thin marshalling, but the place where untrusted Kotlin-supplied JSON is parsed and where the PRF output bytes cross from Java land into Rust land.

### Kotlin

- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/data/RecipientStore.kt` -- at-rest encryption configuration, the `StoredRecipient` schema, and the per-account isolation logic (`forAccount`, `setActiveAccount`, `clearAccount`).
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/AndroidKeystoreIdentity.kt` -- Keystore decrypt flow, `KeyAgreement.doPhase`, biometric prompt invocation.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/AndroidKeystoreEnrollment.kt` -- `KeyGenParameterSpec` settings for the P-256 key (StrongBox flag, authentication parameters, the consent before an unbound key).
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/YubiKeyPivIdentity.kt` -- PIV decrypt path, PIN prompt re-entry on each decrypt, PIN buffer zeroing.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/YubiKitPivEnrollment.kt` -- `PivSession.generateKey` parameters (P-256 or X25519, `PinPolicy.ONCE`, `TouchPolicy.ALWAYS`), the policy read-back, pubkey extraction.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/PivTouch.kt` -- `SlotTouch.read` (GET METADATA) and the refusal, used at enrolment and in `YubiKeyPivIdentity.agreeOnCard` before the PIN; `PivTouchPolicyTest` drives both against a scripted card.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/Fido2HmacIdentity.kt` -- assertion request shape, PRF extension JSON, response parsing, fail-closed on missing PRF.
- `ragedroid/app/src/standard/kotlin/ragewarden/ragedroid/identities/PasskeyEnrollmentReal.kt` -- enrollment request shape, PRF eval with random 32-byte salt, credential-ID parsing.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/RecoveryEnrollment.kt` -- mnemonic generation entry point and the contract that the mnemonic does not flow to disk.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/data/BitwardenVaultRepository.kt`, function `encryptForActiveRecipients` -- the active recipient gather -> PRF tap -> JSON marshal -> JNI handoff. This is the single entry point for "is this cipher actually encrypted to the right people?".
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/data/SessionStore.kt` and `data/SessionKeyWrap.kt` -- the session blob and the biometric unlock key (§5.1).
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/ui/components/SecurePinField.kt` -- PIN handling at the UI layer (CharArray buffer, zeroing).

### Recommended review order

For an external audit pass, work outside-in:

1. Start at `BitwardenVaultRepository.encryptForActiveRecipients`. This is the chokepoint. Verify that every encrypt path in the app routes through it (`grep -rn 'encryptToRecipients' ragedroid/`) and that no code path constructs ciphers via the legacy single-recipient `RageNative.encrypt`. If the chokepoint is sound, every cipher written by the app has the documented multi-recipient property.
2. Walk down to the JNI boundary. `RageNative.encryptToRecipients` takes JSON; confirm the deserializer rejects unknown variants and that no field reuse can let a "PivP256" recipient be processed by the FIDO2 stanza writer (or vice versa).
3. Walk down to the Rust core. Verify each `Recipient` variant produces a stanza with the correct tag and HKDF info. Verify the test suite includes round-trips for each kind individually and at least one combination test.
4. Walk back up to enrollment. For each kind, confirm the public material in `StoredRecipient` matches the curve and length the encrypt path expects (32 bytes for X25519; opaque blob for FIDO2 credential ID; ASCII for recovery armor).
5. Walk through `RecipientStore` once more, this time as an attacker. What if a corrupted JSON entry mixes fields across kinds -- say, a "Software" recipient with a `pivPubkey` set? The encrypt path keys off `kind`; mixed-field rows are tolerable but unused fields are ignored. Confirm that.

### Suggested review questions

- Is every key path that holds a private key bounded such that the buffer is overwritten before it leaves the function?
- Is every JSON parser between JNI boundaries strict about extra fields? (We use `kotlinx.serialization` with `ignoreUnknownKeys = true` for forward compatibility -- confirm that no unknown field can up-promote a recipient to a more-trusted kind.)
- Does any code path log a `ByteArray` that contains a private key, salt, PRF output, or PIN?
- Does the FIDO2 / passkey path re-randomize the assertion `challenge` on every call? (It does -- see `buildAssertionJson`.)
- Does the Keystore enrollment ever generate a key without `setUserAuthenticationRequired(true)` when the user asks for biometric protection?
- Does the YubiKey enrollment ever generate a key with `TouchPolicy.NEVER` or `PinPolicy.NEVER`? (It does not -- see `enrollYubiKeyPiv` -- and a card that reports a weaker touch policy after generation is refused.)

## 10. Provider limits

Some installed credential providers do not implement the PRF extension; enrolment and reveal report it, and such a provider cannot hold a Ragewarden passkey.

## 11. Summary

Ragedroid stacks an `age`-style multi-recipient inner encryption layer on top of Bitwarden's existing zero-knowledge model. The server's view is unchanged: opaque Type-2 EncStrings. The recipient store keeps only public material plus opaque hardware handles; every secret stays in its trust anchor (master password, BIP-39 paper backup, StrongBox/TEE, YubiKey PIV applet, FIDO2 authenticator). Multi-recipient encrypt is fail-closed; if no recipient is configured, no cipher gets written. The session blob holds tokens and the protected user key, never the key itself (§5.1); the lock drops keys and covers the IME and autofill (§5.3); re-encrypting existing ciphers after the recipient set changes is the bulk pass in §7.3.

Auditing this layer reduces to four questions:

1. Does private key material ever land in `RecipientStore` or any other on-disk artifact? (No -- see §4.)
2. Does the encrypt path ever skip the multi-recipient stanza set or fall back to a default key? (No -- see §7.4.)
3. Does the decrypt path require fresh user presence for hardware-rooted recipients? (YubiKey PIV: yes, the slot's `ALWAYS` policy is read back before every unwrap and any other is refused; firmware before 5.3 cannot report it. Keystore: per use on API 35+; below that a 30-second window, see §3. Passkey: yes, platform UV. See §6.)
4. Does the JNI boundary parse untrusted input strictly enough that a malformed `recipientsJson` cannot up-cast a recipient to a more-trusted kind? (Yes -- see §9 audit checklist.)

If the answer to all four is what the documentation says, the threat model holds.
