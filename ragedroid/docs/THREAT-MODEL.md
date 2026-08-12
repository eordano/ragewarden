# Ragedroid threat model

Scope: the Android client (`ragedroid/app`), the Rust core (`core/`), and the JNI shim (`ragedroid/jni/`). The server in question is a self-hosted Vaultwarden (Bitwarden-compatible). This document is written for an external auditor and for internal contributors who need to make security-relevant changes.

The model is intentionally narrow: it covers what *ragedroid adds on top of* the Bitwarden zero-knowledge model. It does not re-derive the underlying Bitwarden cryptography -- see the upstream Bitwarden security whitepaper for the master-key/KDF/protected-symmetric-key derivation. What ragedroid layers on top is a multi-recipient `age`-style stanza wrapping that runs entirely client-side and produces an opaque ASCII blob the server treats as Type-2 ciphertext.

---

## 1. Zero-knowledge guarantees

The server (Vaultwarden) sees **only** what a stock Bitwarden server sees:

- Account email and KDF parameters (visible at login).
- Type-2 `EncString` blobs for cipher fields (name, login, notes, secure-note body, etc.).
- Cipher metadata: ID, folder ID, `revisionDate`, `creationDate`, organization ID.
- Sync deltas, history entries, share invitations -- same wire format as upstream Bitwarden.

The server does **not** see, and cannot derive without out-of-band keys:

- The user's master password.
- The user's master key, stretched master key, or protected symmetric key.
- The plaintext of any cipher field.
- Any rage stanza body or rage public key, except as enclosed inside an opaque ASCII payload that the server treats as a Type-2 EncString. The server cannot decrypt the EncString (that requires the user's symmetric key), and even if it could, the inner age blob is independently encrypted to the recipient set.
- Any private key material for any recipient kind (PIV, Keystore, FIDO2/Passkey, recovery).

Two layers of isolation apply, in order:

1. **Outer layer (Bitwarden).** Each cipher field is wrapped in a Type-2 EncString using the user's symmetric key. This is the standard Bitwarden encoding; the server holds only ciphertext.
2. **Inner layer (rage).** The cipher payload is itself a multi-stanza age blob. Each stanza wraps the same content-encryption key (CEK) to a different recipient. Decrypting any one stanza yields the CEK and unlocks the body.

The server therefore sees a Type-2 EncString of an age blob. Compromising the server gives the attacker neither key -- they would still need the user's master password (to peel off the outer layer) **and** at least one recipient's private material (to peel off the inner layer).

### 1.1 What a compromised server *can* do

Even though plaintext stays inaccessible, a malicious server is not a no-op. It can:

- Withhold ciphers (denial-of-service), or selectively serve stale revisions to roll back the user's view.
- Refuse to deliver new ciphers entirely, or modify the `revisionDate` ordering.
- Tamper with the outer Type-2 EncString. The user's symmetric key validates the GCM tag; tampering surfaces as "decrypt failed" on the client. There is no silent corruption.
- Truncate or replace a stanza-set inside an inner age blob. Modified blobs fail to decrypt (age uses authenticated encryption end-to-end inside its own framing).
- Observe access patterns -- which cipher IDs the user fetches, when, and how often.

The server **cannot** swap one user's recipient set for another (the recipient material is inside the inner age blob, which is itself inside the outer EncString -- both layers must be peeled to alter the recipient list). It **cannot** add a stanza that decrypts to a server-controlled key without first holding the user's symmetric key.

### 1.2 What ragedroid does *not* protect

Out of zero-knowledge scope:

- **Account existence and metadata.** The server knows the user's email address, KDF parameters, organization memberships, and cipher counts.
- **Folder structure.** Folder names live in Type-2 EncStrings, but folder *count* and *cipher-to-folder mapping* are visible (the mapping is a metadata field).
- **Sync timestamps.** `revisionDate` is plaintext. The server learns when each cipher last changed.
- **Bitwarden upstream features ragedroid does not modify.** Sends, password history, attachments -- these inherit upstream Bitwarden's exact zero-knowledge guarantees, no more and no less.

---

## 2. Trust boundaries per recipient kind

Each recipient kind has a different trust anchor. The relevant question for an attacker is: *given capability class C, can I extract the secret needed to decrypt a stanza of kind K?* The columns below answer that.

### 2.1 Software (master-key derived)

- **Where the secret lives.** The age private key is derived from the Bitwarden master key on each unlock; it lives in process memory only while the vault is unlocked.
- **Persistent storage.** None on the device. The recipient's *public* key is part of the cipher's stanza set and travels through the server like any other stanza.
- **Adversarial model.** Compromising this stanza requires either (a) the master password, (b) a memory dump of the unlocked process, or (c) extraction of derived key material before the user locks the vault.
- **Server trust.** None. The server never sees the master key.

### 2.2 Recovery (BIP-39 mnemonic)

- **Where the secret lives.** The mnemonic is shown to the user once during enrollment and is the only persistent representation of the private key. The armored age secret is reconstructable from the mnemonic on demand via `recovery::from_phrase` in the Rust core.
- **Persistent storage on device.** Only the armored *public* key (`recoveryArmoredPubkey`). The mnemonic is **never** written to disk by ragedroid.
- **Adversarial model.** Compromise requires possession of the mnemonic. Anyone with the 24-word phrase can decrypt every cipher whose recipient set includes this recovery recipient. The mnemonic is a backup factor: assume it is written down on paper and stored physically; the device is not the attack surface for this kind.
- **Server trust.** None.

### 2.3 Android Keystore X25519 (StrongBox or TEE)

- **Where the secret lives.** Inside the Android Keystore HAL, backed by StrongBox where available (Pixel 6+, Pixel 10) or TEE where not. The private key never leaves the secure element; `KeyAgreement.doPhase` returns only the ECDH shared secret.
- **Persistent storage on device.** The 32-byte X25519 public key (`keystorePubkey`) and an opaque alias string (`keystoreHandle`) used to look up the key in Keystore. The handle is not a secret -- losing it only loses the ability to *use* the key.
- **Adversarial model.** Extracting the private key requires defeating StrongBox/TEE itself, which is the device's hardware root of trust. The key spec sets `setUserAuthenticationRequired(true)` with `AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL`, so a device PIN/pattern also satisfies it. Precisely: `setUserAuthenticationParameters(KEY_VALIDITY_SECONDS = 30, ...)` makes this a **30-second time window, not a per-operation gate** -- `KeyAgreement` is not a supported `BiometricPrompt.CryptoObject`, so the auth cannot be bound to the individual ECDH. An attacker with full app-process compromise cannot invoke the key cold, but *can* invoke it freely for 30 s after any legitimate unlock. StrongBox is requested first (`setIsStrongBoxBacked(true)`) with a documented fallback ladder down to TEE and to no-biometric, so the enrolled recipient records which rung it landed on.
- **Server trust.** None.

### 2.4 YubiKey PIV X25519 (NFC / USB-C)

- **Where the secret lives.** Inside the YubiKey's PIV applet. Generated in-place via `PivSession.generateKeyValues(slot, KeyType.X25519, ...)`; private key never leaves the token.
- **Persistent storage on device.** The 32-byte X25519 public key (`pivPubkey`), the YubiKey's serial number (`pivSerial`), and the slot byte (`pivSlot`). None are secret.
- **Adversarial model.**
  - `PinPolicy.ONCE`: PIN required once per power cycle.
  - `TouchPolicy.ALWAYS`: every decrypt requires a physical tap on the token.
  - PIN-block: 3 wrong PIN entries irreversibly block the slot until a PUK reset.
  - Physical possession of the token + knowledge of the PIN is needed to use it.
- **Server trust.** None.

### 2.5 FIDO2 / Passkey hmac-secret (PRF extension)

- **Where the secret lives.** Inside a WebAuthn authenticator that supports the `hmac-secret` CTAP2 extension (or `prf` at the WebAuthn layer). For built-in Android passkeys this is the device's TEE. For roaming authenticators this is the YubiKey 5C / 5 NFC.
- **Persistent storage on device.** The credential ID (`fido2CredentialId` or `passkeyCredentialId`), the relying-party ID (`fido2RpId` / `passkeyRpId`), and a 32-byte salt (`fido2Salt` / `passkeySalt`) generated by ragedroid at enrollment. **The salt is *not* the PRF output**. The PRF output is `HMAC-SHA256(authenticator_secret, salt)`; the authenticator never reveals `authenticator_secret`, and the PRF output is recomputed inside the authenticator on every encrypt and every decrypt.
- **Adversarial model.** An attacker who reads the recipient store learns: which credential ID, which RP, and the 32-byte salt. They cannot derive the PRF output without the authenticator. If the authenticator is a roaming token, the attacker also needs physical possession; if it is a platform passkey, they need to defeat the TEE plus pass user verification.
- **Salt rotation.** The salt is fixed per recipient at enrollment time and never changes. Rotating it would invalidate every cipher already encrypted to this recipient. If a user wants a fresh salt, they enroll a new recipient (which gets a new credential ID *and* a new salt) and can optionally remove the old one -- see §7.3 for what removal does and does not do.
- **Server trust.** None. The server never sees the salt or the PRF output, only the resulting age stanza body.

### 2.6 Cross-kind invariants

Some properties hold across all hardware-rooted recipient kinds (Keystore, PIV, FIDO2/Passkey):

- **Public-only persistence.** `RecipientStore` carries only the public X25519 key (or, for FIDO2, the credential ID and salt -- neither of which is sufficient to derive the PRF output without the authenticator). A snapshot of the recipient store is not in itself a path to plaintext.
- **Per-decrypt user presence.** Every hardware-rooted decrypt requires either a biometric prompt (Keystore), a token tap (YubiKey), or a credential-manager assertion (FIDO2/Passkey). There is no "remember this for 5 minutes" cache.
- **Per-account isolation.** All `RecipientStore` operations are keyed on `accountId`. Switching active account swaps the visible recipient list; the inactive account's recipients are inaccessible to the active flow.
- **Independence at decrypt.** Each stanza is independently decryptable. Compromising one recipient (e.g. someone steals one of your YubiKeys) does not affect the secrecy of stanzas wrapped to other recipients on the same cipher; it only means *that one stanza* can now be unwrapped by the holder of the stolen key.

---

## 3. Attacker capability matrix

The columns are recipient kinds; the cells answer "can the attacker decrypt a cipher whose only listed recipient is this kind?". "No" means defeated; "Yes" means the kind does not stop this attacker (some other recipient may still stop them -- this matrix is per-kind).

| Capability                          | Software | Recovery | Keystore | YubiKey | FIDO2/Passkey |
|-------------------------------------|----------|----------|----------|---------|---------------|
| 1. Network-only (passive observer)  | No       | No       | No       | No      | No            |
| 2. Compromised server               | No       | No       | No       | No      | No            |
| 3. Lost device, locked              | No*      | No       | No       | No      | No            |
| 4. Lost device, unlocked vault      | Yes      | No       | Yes**    | No      | Yes**         |
| 5. Malicious app, same device       | No       | No       | No       | No      | No            |
| 6. Hardware token theft (no PIN)    | n/a      | n/a      | n/a      | No      | No            |
| 7. Rooted device                    | No*      | No       | No       | No      | No            |

\* Software stanzas are bound to the master password via the Bitwarden symmetric key. A locked or rooted-but-locked device gives the attacker only the outer Type-2 EncString, which they cannot peel without the master password. Once the master password is brute-forced (KDF cost permitting), software stanzas fall.

\** "Yes" here means: the attacker can request decrypt and the OS will satisfy the user-presence check because the device is currently unlocked / the user is currently authenticated. Three precisions the earlier wording glossed over:

- The Keystore key is gated by `AUTH_BIOMETRIC_STRONG` **or `AUTH_DEVICE_CREDENTIAL`** (`AndroidKeystoreEnrollment.kt`), so a device PIN/pattern satisfies it -- not only a biometric.
- That gate is **time-bound, not per-use**: `setUserAuthenticationParameters(KEY_VALIDITY_SECONDS = 30, ...)`. Within 30 s of a passing auth the key is usable again with no further prompt. This is a documented departure from the ecosystem `DESIGN.md` §0b "strict tap per use" for the Keystore recipient kind; it exists because `KeyAgreement` is not a supported `BiometricPrompt.CryptoObject`, so the auth cannot be bound to the individual operation. The reveal flow re-prompts before each decrypt to keep the observable behaviour one-prompt-per-use, but an attacker with the unlocked device inside that window does not have to.
- YubiKey stanzas require a fresh tap because `YubiKitPivEnrollment` generates the slot with `TouchPolicy.ALWAYS` (`piv.generateKeyValues(slot, KeyType.X25519, PinPolicy.ONCE, TouchPolicy.ALWAYS)`). That holds for slots ragedroid generated. ragedroid has no way to read a policy back off a slot it did not generate, so it is a property of the enrollment path, not a verified property of the card.

Passkey stanzas similarly require user verification at decrypt; whether that succeeds without user awareness depends on the platform UI.

### 3.1 Notes per capability

1. **Network-only attacker.** Sees Type-2 EncStrings on the wire. Defeats no recipient kind.
2. **Compromised server.** Same view as the network attacker plus access to the cipher database. Defeats no recipient kind.
3. **Lost device, locked.** Recipient store is encrypted-at-rest via `KeystorePrefs` (see §4.2 -- not `EncryptedSharedPreferences`, which this app does not depend on). Keystore handles can't be invoked without biometric. PIV/FIDO2 require their respective second factors and PINs.
4. **Lost device, unlocked.** This is the worst real-world case for software-only stanzas. Hardware-rooted recipients still gate decrypt on user presence (biometric tap, YubiKey tap). Best practice: enroll at least one hardware recipient and lock the vault aggressively.
5. **Malicious app on device.** Cannot read another app's private `SharedPreferences` file, and could not use it if it did (§4.2); cannot invoke another app's Keystore aliases; cannot drive `BiometricPrompt` for another app.
6. **Hardware token theft.** PIV requires PIN (3-strike block). FIDO2 requires user verification, which on a YubiKey is the same PIN.
7. **Rooted device.** `KeystorePrefs` values are bound to a non-exportable `AndroidKeyStore` AES-GCM key. Root *can* read the prefs file, but the wrapping key lives in Keystore. Note the key is **not** StrongBox-backed (§4.2 -- `setIsStrongBoxBacked` is never called), so on a device without a TEE it is software-backed; TEE keys remain unrecoverable barring a TEE break. Software stanzas remain protected by the master password.

### 3.2 Layered defenses

A practical recipient policy combines kinds with disjoint failure modes:

- **Software + Recovery + (Keystore or YubiKey).** The minimum recommended set. Software gives you cheap unlock on each device. Recovery gives you the offline-paper escape hatch. Keystore or YubiKey gives you a phishing-resistant factor.
- **Mark FIDO2/Passkey as decrypt-only (`defaultEncrypt = false`).** Encrypt-time taps for passkey are intrusive -- every cipher save would need a credential-manager prompt. The shipped enrollment defaults `defaultEncrypt = false` for passkey recipients precisely so the user sees them only when explicitly choosing them at decrypt time.
- **Avoid single-recipient ciphers.** A cipher with exactly one recipient is recoverable only if that recipient survives. If the user loses their YubiKey and enrolled it as a single recipient on some sensitive cipher, that cipher is gone. The default UX always includes Software (and Recovery, where available) so single-point-of-failure ciphers are hard to create accidentally.

### 3.3 Race conditions and timing

Two notes on observable timing:

- **`RecipientStore.flow` reads.** `KeystorePrefs` decrypt is constant-overhead per access. We do not rely on the secrecy of recipient *count* or *kind*; an attacker who can time the reads learns at most "the user has N recipients of unknown kinds", which is not a meaningful leak.
- **`encryptForActiveRecipients`.** Encrypt time scales linearly with the number of stanzas, but each stanza derives from independent randomness; there is no cross-stanza key. An attacker who watches encrypt latency learns approximately how many recipients are active. Not a secret.

---

## 4. What is in `RecipientStore`

`StoredRecipient` is the single on-disk record per enrolled recipient. The full schema, field by field:

| Field                   | Type           | Secret? | Notes                                                                 |
|-------------------------|----------------|---------|-----------------------------------------------------------------------|
| `id`                    | String (UUID)  | No      | Local identifier.                                                     |
| `kind`                  | enum           | No      | One of `Software`, `Recovery`, `StrongBox`, `YubiKey`, `Fido2`.       |
| `displayName`           | String         | No      | User-supplied label.                                                  |
| `createdAt`             | Long           | No      | Epoch millis.                                                         |
| `lastUsedAt`            | Long           | No      | Epoch millis; updated by `RecipientStore.touch`.                      |
| `defaultEncrypt`        | Boolean        | No      | Whether new ciphers include a stanza for this recipient.              |
| `pivPubkey`             | ByteArray?     | No      | 32-byte X25519 public key.                                            |
| `pivSerial`             | Int?           | No      | YubiKey serial.                                                       |
| `pivSlot`               | Byte?          | No      | PIV slot identifier (e.g. `0x9a` AUTHENTICATION).                     |
| `fido2CredentialId`     | ByteArray?     | No      | Opaque WebAuthn credential ID.                                        |
| `fido2RpId`             | String?        | No      | Relying-party ID.                                                     |
| `fido2Salt`             | ByteArray?     | No      | 32 bytes of random salt. **Not the PRF output.**                      |
| `keystorePubkey`        | ByteArray?     | No      | 32-byte X25519 public key.                                            |
| `keystoreHandle`        | String?        | No      | Opaque Keystore alias.                                                |
| `passkeyCredentialId`   | ByteArray?     | No      | Same shape as `fido2CredentialId`.                                    |
| `passkeyRpId`           | String?        | No      | Same shape as `fido2RpId`.                                            |
| `passkeySalt`           | ByteArray?     | No      | Same shape as `fido2Salt`. **Not the PRF output.**                    |
| `recoveryArmoredPubkey` | String?        | No      | Armored age public key for recovery; the *secret* never lives here.   |

### 4.1 Never stored

The following secrets exist nowhere in `RecipientStore`, nowhere on disk, and nowhere in any ragedroid persistence layer:

- The recovery mnemonic itself.
- The armored age recovery secret.
- Any X25519 private scalar for any recipient kind.
- Any FIDO2 / passkey `hmac-secret` value or any `prf.results.first` output.
- The Bitwarden master password.
- The Bitwarden master key, stretched master key, or protected symmetric key (these live in the Bitwarden SDK's process memory only).
- The PIV PIN (collected ad-hoc as a `CharArray`, zeroed after use).

### 4.2 At-rest encryption

**Correction:** this section used to describe `androidx.security.crypto.EncryptedSharedPreferences` (`AES256_SIV` keys, `AES256_GCM` values, file `ragewarden.recipients.v1`, "StrongBox if available"). None of that is what ships. There is no `androidx.security:security-crypto` dependency in `gradle/libs.versions.toml` or `app/build.gradle.kts` at all -- that alpha dependency was dropped in favour of a hand-rolled wrapper, and this text was not updated with it.

What `RecipientStore` and `SessionStore` actually write through is `data/KeystorePrefs`:

- Plain `getSharedPreferences(name, MODE_PRIVATE)` for the file.
- **Values** encrypted with `AES/GCM/NoPadding`, 256-bit, `setRandomizedEncryptionRequired(true)`, stored as `base64(IV‖ciphertext‖tag)` with a 12-byte IV and a 128-bit tag.
- **Keys are not encrypted.** There is no `AES256_SIV` equivalent, so the pref key `recipients:$accountId` is readable in cleartext by anything that can read the file. It leaks the account id and the number of accounts; it does not leak recipient material.
- Key material: one non-exportable `AndroidKeyStore` `SecretKey` per store, created on first use -- alias `ragewarden.recipients.aead.v1` for recipients, `ragewarden.session.aead.v1` for the session blob. Files: `ragewarden.recipients.v2` and `ragewarden.session.v2`.
- **StrongBox is not requested.** `KeyGenParameterSpec.Builder` never calls `setIsStrongBoxBacked(true)`, so the key is TEE-backed on devices with a TEE and software-backed otherwise. Requesting StrongBox with a graceful fallback is **NOT YET IMPLEMENTED**.
- The key is **not** `setUserAuthenticationRequired`, so it is usable whenever the app process runs. The in-app lock does not revoke it -- see §5.3 and §10.

A rooted attacker reading the raw XML gets ciphertext for every value; the wrapping key stays in Keystore.

### 4.3 Per-account separation

The store key inside `KeystorePrefs` is `recipients:$accountId` (see `RecipientStore.prefKey`). This means:

- Multi-account installs keep their recipients strictly separated; account A cannot see account B's recipients without explicitly switching `setActiveAccount`.
- `clearAccount(accountId)` removes only that account's pref entry; other accounts' entries survive a logout of one account.
- An attacker who can somehow read the file gets a separate ciphertext per account, but cannot tell from the prefs alone which account the user was logged into most recently.

---

## 5. On-device confidentiality

### 5.1 Session storage

`SessionStore` (`ragedroid/app/src/main/kotlin/ragewarden/ragedroid/data/SessionStore.kt`) stores the Bitwarden session blob through `KeystorePrefs` -- AES-256-GCM under a non-exportable AndroidKeyStore key, the same primitive `RecipientStore` uses. Prefs file `ragewarden.session.v2`, key alias `ragewarden.session.aead.v1`.

**This was previously wrong and the correction matters.** Until this pass the blob went into a *plain* `getSharedPreferences(MODE_PRIVATE)` file (`ragedroid_session`), base64-encoded, not encrypted. Worse, the earlier text on this page claimed the exposure was limited to bearer tokens. It was not: `SessionDto` (`jni/src/sync_jni.rs:12-25`) carries `user_enc_key_b64` **and** `user_mac_key_b64` -- the user symmetric key pair derived from the master password. An attacker with file-system read access could therefore decrypt every non-Ragewarden-protected cipher in the vault offline, not merely replay a short-lived token. The zero-knowledge claim in the old wording was false for that file.

On first construction, `SessionStore.migrateLegacyCleartext` rewrites any surviving `ragedroid_session` blob into the encrypted store and then deletes the cleartext file (`edit().clear().commit()` + `deleteSharedPreferences`). The delete is unconditional: if the re-encrypt fails the user is signed out and signs in again, which is recoverable, whereas leaving the key material readable is the defect being closed.

Residual exposure:

- Ragewarden-protected items are unaffected either way -- their plaintext is inside an age blob whose recipients are hardware keys, so the user symmetric key never opens them. That property was always the reason the leak was survivable, not the (incorrect) claim that no key material was on disk.
- The Keystore key is not `setUserAuthenticationRequired`, so an attacker with *live code execution* as the app uid can still ask Keystore to decrypt. This raises the bar from "read the file" to "run as the app", which is the bar every other store in the app sits at.
- `allowBackup="false"` plus the blanket `sharedpref` exclusions in `data_extraction_rules.xml` keep the file out of cloud backup and device transfer regardless.
- Sign-out (`SessionStore.clear()`) removes the entry.

### 5.2 Screen capture

Both Activities that can put a decrypted secret on screen set `FLAG_SECURE` (`ui/SecureWindow.kt`, applied in `MainActivity.onCreate` and `AutofillAuthActivity.onCreate`). Before this the module contained no `FLAG_SECURE` at all, so `ItemDetailScreen`'s `RevealedPasswordCard` -- plaintext held for `REVEAL_AUTO_CLEAR_SECS` = 8 seconds -- along with the note/card/SSH bodies and the paper-recovery word grid were screenshot-able, screen-recordable, capturable by any app holding `MediaProjection`, and thumbnailed into the Recents switcher, where the thumbnail outlives the reveal.

`FLAG_SECURE` is a window flag, so it is set for the whole Activity rather than toggled around each reveal: toggling would recreate the surface mid-interaction and would still leave the Recents snapshot -- taken when the Activity stops, not while the secret is visible -- unprotected. There is deliberately no debug-build escape hatch.

What it does not cover: `RagewardenInputMethodService` (an IME window, which never renders plaintext -- it commits the value into the host app's field and shows only item names, and only while the vault is unlocked -- see §5.3) and the host app's own window, which is not ours to flag. And per §8, a privileged screen-recorder can still defeat `FLAG_SECURE`; this stops ordinary apps and the system's own thumbnailing, not a rooted attacker.

### 5.3 The app lock

The lock is `data/LockState.kt`: a `@Singleton` (bound in `di/AppModule.kt`, reachable via `AppEntryPoint.lockState()`), not a navigation destination and -- since 2026-08-04 -- no longer a value inside `RageApp`'s composition. `ui/RageApp.kt` observes it with `collectAsState`. While it is true the entire stage tree is not composed and `LockScreen` renders in its place; it is cleared only by a successful unlock (biometric/device credential, or a master password verified by `BitwardenVaultRepository.verifyMasterPassword`) or by sign-out. The global `BackHandler` short-circuits while locked, so back cannot walk out of it.

Initial value, fail-closed, evaluated once per process at first read:

1. no session on the device -> nothing to protect -> unlocked, and the stale persisted flag is dropped;
2. otherwise `LockPolicy.lockOnLaunch` is a **floor**, not a value -- when it is on (the default) a fresh process starts locked whatever was persisted;
3. otherwise the persisted `SharedPreferences` flag wins, defaulting to `true` when absent.

Writes go through `commit()`, not `apply()`, so a lock is on disk before the call returns. Tests: `app/src/test/kotlin/ragewarden/ragedroid/data/LockStateTest.kt`.

**Correction to two earlier versions of this paragraph.** One said back "short-circuits to `moveTaskToBack`"; it did not, because `RageApp` bound `val context = LocalContext.current.applicationContext`, so every `(context as? android.app.Activity)?.moveTaskToBack(true)` in that file -- the locked branch and the two pre-existing ones -- was `null?....`. A later revision correctly recorded that as dead code. It is now **fixed**: `RageApp` captures the Activity separately as `LocalActivity.current ?: localContext.findActivity()` and the three call sites use it. `ui/ActivityContext.kt` holds the fallback, which walks the `ContextWrapper` chain because a Compose `LocalContext` is often a `ContextThemeWrapper` around the Activity rather than the Activity itself; `app/src/test/kotlin/ragewarden/ragedroid/ui/FindActivityTest.kt` pins both halves (an application context still resolves to `null`; a doubly-wrapped Activity resolves). The same helper now backs the `as? FragmentActivity` casts in `LockScreen`, `FirstRunScreen`, `AddRecipientScreen` and `RageApp.VaultStage`, which had the same latent shape. If no Activity resolves at all, back is swallowed -- which is where the locked branch already was, and is fail-safe either way.

The lock was previously `Stage.Lock`, a peer of every other stage, and that was bypassable in two taps: `LockScreen`'s "Settings" affordance set `stage = Stage.Settings`, and `SettingsScreen`'s `onBack` set `stage = Stage.Vault`. The system back gesture was a second, independent route to the same place, because the global `BackHandler` mapped `Stage.Settings -> Stage.Vault` on its own. The lock screen's password path also accepted any non-empty string when `VaultBridge.repository()` was null -- which is exactly the state a cold launch into the lock is in, since nothing had called `ensureBackend` yet. All three are closed.

Scope of the lock, stated precisely: it is a **gate on every reader of vault material in the process, not a key-zeroisation boundary**. The readers and what each does while locked:

- **`ui/RageApp.kt`** -- the stage tree is not composed; `LockScreen` renders instead. Every `snapshot()` / `decrypt()` call site under `ui/screens/` is inside that tree, and the post-unlock autosync `LaunchedEffect` is guarded by `!locked`.
- **`ime/RagewardenInputMethodService`** -- routes both the listing and the delivery through `ime/ImeDelivery.kt`, which consults `LockState` on every call. `offer()` returns an empty list while locked, so the keyboard does not even enumerate item names; `deliver()` checks the lock twice, once on entry and once after the decrypt resolves (the decrypt suspends and can wait on a network sync, so "Lock now" can land inside that window). `commitText` is reachable from exactly one lambda, the one `deliver()` invokes only on the success path. Tests: `ImeDeliveryTest`, `ImeSurfaceLockedTest`.
- **`autofill/RagewardenAutofillService`** -- `onFillRequest` returns `callback.onSuccess(null)` while locked, so no dataset and no item name reaches the host app's picker.
- **`autofill/AutofillAuthActivity`** -- refuses in `onCreate` before the item is looked up (a dataset's `PendingIntent` outlives the fill request that built it, so it can be entered after the vault has locked), and re-checks after the tap ceremony and decrypt resolve, throwing so `InlineTapReveal` can explain rather than blinking away.

What it still does **not** do:

- **`BitwardenVaultRepository.cached` and the decrypted session blob stay resident** in the process while locked. An attacker who can read the app's memory is unaffected by locking. Making the lock drop key material would require a re-sync on unlock and would break offline use; that trade has not been made. This is why the gates above are on the *readers* -- the material itself is still there.
- **The autofill and IME surfaces cannot offer an unlock.** An `AutofillService` and an `InputMethodService` can host neither `BiometricPrompt` nor the master-password field, so while locked they refuse and say so rather than routing to an unlock flow. The user has to open the app.

---

## 6. PIN / biometric model

### 6.1 Keystore (Android)

Keys generated by `enrollKeystoreIdentity` use:

```
.setUserAuthenticationRequired(true)
.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
```

`AUTH_BIOMETRIC_STRONG` means class-3 biometric only -- fingerprint or face-unlock that meets Android's strong-biometric SAR/IAR thresholds. Pattern, PIN, and password unlocks alone do **not** satisfy this. The `0` validity duration means each `KeyAgreement.doPhase` call triggers a fresh `BiometricPrompt`; there is no auth-window sliding.

Failure modes:

- New biometric enrollment on the device: Keystore invalidates the key (`KeyPermanentlyInvalidatedException`). The user must re-enroll the recipient. This is intentional -- it limits the blast radius of a hostile take-over of the lock screen.
- StrongBox unavailability: detected via `isStrongBoxAvailable(context)`; enrollment falls back to TEE if requested.

### 6.2 PIV PIN handling

The YubiKey PIV PIN is collected via `SecurePinField` (`ragedroid/app/src/main/kotlin/ragewarden/ragedroid/ui/components/SecurePinField.kt`). The contract:

- Storage during entry: `CharArray` only -- never a Kotlin `String`. Strings are interned and immutable; a `CharArray` can be zeroed.
- Lifetime: the buffer is wiped (filled with `0.toChar()`) immediately after `PivSession.verifyPin(pin)` returns, regardless of success.
- The PIN never reaches `RecipientStore` and is never logged.
- `pinProvider` callbacks in `YubiKeyPivIdentity` request a fresh PIN entry on each decrypt; old buffers are not retained.

### 6.3 FIDO2 / passkey user verification

`buildAssertionJson` and `buildEnrollmentJson` set `userVerification = "required"`. The platform credential manager enforces this; ragedroid does not collect the PIN or biometric itself.

---

## 7. Multi-recipient encryption

### 7.1 Per-encrypt behaviour

`BitwardenVaultRepository.encryptForActiveRecipients` (lines 177-203) runs at every cipher create / update with a non-null plaintext. It:

1. Gathers `WireRecipient` entries from `RecipientStore.forAccount(accountId).filter { it.defaultEncrypt }`.
2. For each FIDO2 / passkey recipient, computes a `PrfRequest` (rpId, 32-byte salt) and asks the installed `PrfTapper` to drive the credential manager once per request.
3. JSON-encodes the recipient list and the PRF results, hands them to `RageNative.encryptToRecipients`.
4. The Rust core builds one age stanza per recipient and concatenates them; every stanza encapsulates the same 16-byte CEK that wraps the body.

Consequence: any single enrolled `defaultEncrypt = true` recipient is sufficient to decrypt the resulting blob. The user can choose at decrypt-time which recipient to use (via `MultiIdentityPickerSheet`).

### 7.2 Adding a recipient

- Existing ciphers are **not** re-encrypted. They retain their original stanza set.
- New ciphers (and updates that change plaintext) include the new recipient.

### 7.3 Removing a recipient

`RecipientStore.remove(accountId, recipientId)` deletes the entry. Effects:

- Future encrypts skip this recipient -- its stanza will not appear in newly written ciphers.
- Existing ciphers still carry the old stanza, **including ciphers that cannot otherwise be decrypted by the user's current recipient set**. If the removed recipient was the only one capable of decrypting some old cipher, that cipher is now permanently unreadable from this device.
- The recipient's *public* material is gone from the device, but the same public key already lives inside every old cipher's stanza on the server. Removing a recipient does not delete it from history.

This is a known UX gap. Tracked follow-up: cipher rotation pass that re-encrypts all ciphers to the current recipient set on demand. Until then, the in-app revoke UX should warn the user that removal does not re-encrypt.

### 7.4 Fail-closed posture

`encryptForActiveRecipients` throws `NoRecipientsConfiguredException` if the active set is empty. The repository surfaces this as a hard error; nothing is sent to the server. There is no fallback to "encrypt to nobody" or "encrypt to a default key".

If a FIDO2 / passkey recipient is in the active set and no `PrfTapper` is installed, the encrypt throws `PrfTapperNotConfiguredException`. Same fail-closed posture.

### 7.5 What a stanza commits to

For each kind, the stanza on disk binds:

- **Software:** the `age` X25519 ephemeral pubkey; the recipient's static X25519 pubkey; an HKDF-derived wrapping key over the CEK.
- **Recovery:** identical structure to Software (recovery keys are X25519 keys derived from BIP-39, with a distinct armored prefix to make decrypt UX clearer).
- **Keystore / PIV:** the `age` ephemeral pubkey, the recipient's X25519 pubkey, and an HKDF-derived wrapping key whose IKM is the X25519 ECDH share. The recipient pubkey acts as both target identifier and binding salt.
- **FIDO2 / Passkey:** the credential ID, the salt, and an HKDF-derived wrapping key whose IKM is the PRF output. Decryption requires re-deriving the PRF output from the same salt + same authenticator; a different authenticator with the same credential ID would yield a different PRF output and fail the wrap.

There is no recipient-kind ambiguity at decrypt time: each stanza tag (`X25519`, `recovery-v1`, `ragedroid-keystore-v1`, `piv-p256`, `fido2-hmac`, `passkey-prf`) selects a distinct unwrap path. An attacker cannot present a stanza of the wrong kind to trick the client into using the wrong key.

---

## 8. Out-of-scope attacks

The following are explicitly out of scope. We do not claim defense against them; users with these threats in their model need defenses outside ragedroid.

- **Physical tampering with a running, unlocked device.** If the device is in the user's hand and unlocked, every secret the device can compute, the attacker can compute. Recovery and Software stanzas can both be unwrapped at will. Hardware-tap recipients (YubiKey `TouchPolicy.ALWAYS`, Keystore `AUTH_BIOMETRIC_STRONG`) still gate per-decrypt user presence, but a device in the attacker's possession defeats most other defenses.
- **Targeted malware that captures user input system-wide.** A keylogger or screen-recorder running with elevated privileges can steal the master password as it is typed, the PIV PIN, the recovery mnemonic during reveal, and any data the user views in the unlocked vault. Defeating this requires OS-level isolation that ragedroid cannot provide.
- **Quantum computing.** X25519 and Ed25519 are not post-quantum. A future cryptographically-relevant quantum computer can break every recipient stanza we issue today. This is an industry-wide problem; PQC migration is a separate, multi-year design effort.
- **Side channels in StrongBox / TEE.** We rely on the secure element's resistance to fault injection, power analysis, and timing attacks. We do not add software-side mitigations.
- **Loss of the recovery mnemonic.** If the user loses the mnemonic and every other recipient becomes unavailable (lost YubiKey, wiped device, etc.), the vault is gone. We do not (and cannot) escrow.
- **Compromise of the user's master password.** The outer Bitwarden layer falls; rage stanzas of `Software` kind fall. Hardware-rooted stanzas (PIV, Keystore, FIDO2) still hold.
- **Supply-chain compromise of build tools.** A malicious AGP, Gradle plugin, NDK toolchain, or Rust toolchain can inject code into the shipped APK. Defenses against this live in CI infrastructure (reproducible builds, signed releases, dependency pinning) and are out of scope for this document. We pin major versions in `gradle/libs.versions.toml` and the Rust core has a `Cargo.lock`.
- **Compromised PRNG.** We trust `SecureRandom` (Android) and `OsRng` (Rust) for all secret generation. A backdoored device PRNG leaks every freshly generated key; we have no defense against this and no way to detect it.
- **Authenticator firmware compromise.** A malicious YubiKey or platform passkey implementation can leak keys. We trust the authenticator manufacturer and the WebAuthn attestation chain (where present).

---

## 9. Audit checklist

An external auditor reviewing the rage layer should focus on the following files. Path entries are all relative to the repository root.

### Rust core

- `core/src/lib.rs` -- `Recipient` enum, stanza construction, the `encrypt_with_prf` entry point, the per-stanza HKDF info strings, and the test suite that round-trips each kind. The 160-test suite is the canonical specification of stanza shape.
- `core/src/recovery.rs` -- BIP-39 generation, mnemonic->secret derivation, armored output format.
- `core/src/keystore.rs`, `core/src/piv.rs`, `core/src/fido2.rs`, `core/src/passkey.rs` -- per-kind stanza encoding and HKDF salt/info bindings.

### JNI shim

- `ragedroid/jni/src/lib.rs` -- only thin marshalling, but the place where untrusted Kotlin-supplied JSON is parsed and where the PRF output bytes cross from Java land into Rust land.

### Kotlin

- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/data/RecipientStore.kt` -- at-rest encryption configuration, the `StoredRecipient` schema, and the per-account isolation logic (`forAccount`, `setActiveAccount`, `clearAccount`).
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/AndroidKeystoreIdentity.kt` -- Keystore decrypt flow, `KeyAgreement.doPhase`, biometric prompt invocation.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/AndroidKeystoreEnrollment.kt` -- `KeyGenParameterSpec` settings for the X25519 key (StrongBox flag, biometric flag, X25519 algorithm parameter spec).
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/YubiKeyPivIdentity.kt` -- PIV decrypt path, PIN prompt re-entry on each decrypt, PIN buffer zeroing.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/YubiKitPivEnrollment.kt` -- `PivSession.generateKeyValues` parameters (X25519, `PinPolicy.ONCE`, `TouchPolicy.ALWAYS`), pubkey extraction, X25519-vs-other-curve gating.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/Fido2HmacIdentity.kt` -- assertion request shape, PRF extension JSON, response parsing, fail-closed on missing PRF.
- `ragedroid/app/src/standard/kotlin/ragewarden/ragedroid/identities/PasskeyEnrollmentReal.kt` -- enrollment request shape, PRF eval with random 32-byte salt, credential-ID parsing.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/identities/RecoveryEnrollment.kt` -- mnemonic generation entry point and the contract that the mnemonic does not flow to disk.
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/data/BitwardenVaultRepository.kt`, function `encryptForActiveRecipients` (lines 177-203) -- the active recipient gather -> PRF tap -> JSON marshal -> JNI handoff. This is the single entry point for "is this cipher actually encrypted to the right people?".
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/data/SessionStore.kt` -- known plaintext-storage issue (see §5).
- `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/ui/components/SecurePinField.kt` -- PIN handling at the UI layer (CharArray buffer, zeroing).

### Recommended review order

For an external audit pass, work outside-in:

1. **Start at `BitwardenVaultRepository.encryptForActiveRecipients`.** This is the chokepoint. Verify that every encrypt path in the app routes through it (`grep -rn 'encryptToRecipients' ragedroid/`) and that no code path constructs ciphers via the legacy single-recipient `RageNative.encrypt`. If the chokepoint is sound, every cipher written by the app has the documented multi-recipient property.
2. **Walk down to the JNI boundary.** `RageNative.encryptToRecipients` takes JSON; confirm the deserializer rejects unknown variants and that no field reuse can let a "PivP256" recipient be processed by the FIDO2 stanza writer (or vice versa).
3. **Walk down to the Rust core.** Verify each `Recipient` variant produces a stanza with the correct tag and HKDF info. Verify the test suite includes round-trips for each kind individually and at least one combination test.
4. **Walk back up to enrollment.** For each kind, confirm the public material in `StoredRecipient` matches the curve and length the encrypt path expects (32 bytes for X25519; opaque blob for FIDO2 credential ID; ASCII for recovery armor).
5. **Walk through `RecipientStore` once more, this time as an attacker.** What if a corrupted JSON entry mixes fields across kinds -- say, a "Software" recipient with a `pivPubkey` set? The encrypt path keys off `kind`; mixed-field rows are tolerable but unused fields are ignored. Confirm that.

### Suggested review questions

- Is every key path that holds a private key bounded such that the buffer is overwritten before it leaves the function?
- Is every JSON parser between JNI boundaries strict about extra fields? (We use `kotlinx.serialization` with `ignoreUnknownKeys = true` for forward compatibility -- confirm that no unknown field can up-promote a recipient to a more-trusted kind.)
- Does any code path log a `ByteArray` that contains a private key, salt, PRF output, or PIN?
- Does the FIDO2 / passkey path re-randomize the assertion `challenge` on every call? (It does -- see `buildAssertionJson`.)
- Does the Keystore enrollment ever generate a key without `setUserAuthenticationRequired(true)` when the user asks for biometric protection?
- Does the YubiKey enrollment ever generate a key with `TouchPolicy.NEVER` or `PinPolicy.NEVER`? (It does not -- see `enrollYubiKeyPivX25519`.)

---

## 10. Known issues and follow-ups

The following are explicitly tracked items that an auditor will see in code today:

- **§5.3: locking does not zeroise.** The app lock disposes the UI but leaves `BitwardenVaultRepository.cached` and the session blob in memory. Closing this means re-syncing on unlock; the offline-use cost has not been paid.
- **§5.1: no `setUserAuthenticationRequired` on the session key.** The session blob's Keystore key decrypts without a user-presence check, so the lock screen does not gate it.
- **§7.3: No cipher rotation on revoke.** `RecipientStore.remove` does not rewrite existing ciphers. Tracked in `RECIPIENT-ENROLLMENT.md` follow-ups.
- **§4.2: no StrongBox request.** `KeystorePrefs` never calls `setIsStrongBoxBacked(true)`, so its AES key is TEE-backed at best and software-backed on devices without a TEE.
- **§4.2: pref keys are not encrypted.** `KeystorePrefs` encrypts values only, so `recipients:$accountId` is readable in cleartext by anything that can read the file. It leaks account ids, not recipient material.
- **~~`security-crypto = "1.1.0-alpha06"`.~~ Resolved.** The dependency was removed; `RecipientStore` and `SessionStore` now use the in-tree `data/KeystorePrefs` instead of `EncryptedSharedPreferences`. See §4.2 for the trade-offs that came with it.
- **PRF support detection.** Some installed credential providers do not implement the PRF extension; we surface the error but cannot work around it without changing the stanza format.
- **F-Droid passkey path.** F-Droid builds cannot enroll passkeys (no Google Play Services). Users on F-Droid have Software, Recovery, Keystore, and YubiKey available. This is a deliberate flavor split.

## 11. Summary

Ragedroid stacks an `age`-style multi-recipient inner encryption layer on top of Bitwarden's existing zero-knowledge model. The server's view is unchanged: opaque Type-2 EncStrings. The recipient store keeps **only public material** plus opaque hardware handles; every secret stays in its trust anchor (master password, BIP-39 paper backup, StrongBox/TEE, YubiKey PIV applet, FIDO2 authenticator). Multi-recipient encrypt is fail-closed; if no recipient is configured, no cipher gets written. `SessionStore` plaintext-at-rest -- listed here as an open issue in earlier revisions -- is **fixed** (§5.1, AES-256-GCM through `KeystorePrefs`, with an unconditional delete of the legacy cleartext file). The open items are now the ones enumerated in §10: no key zeroisation on lock, no `setUserAuthenticationRequired` on the session key, and the absence of cipher rotation when the recipient set changes (§7.3). The IME/autofill lock gap and the composition-scoped lock flag, listed here in earlier revisions, are **fixed** (§5.3, `data/LockState.kt`).

Auditing this layer reduces to four questions:

1. Does private key material ever land in `RecipientStore` or any other on-disk artifact? (No -- see §4.)
2. Does the encrypt path ever skip the multi-recipient stanza set or fall back to a default key? (No -- see §7.4.)
3. Does the decrypt path require fresh user presence for hardware-rooted recipients? (YubiKey PIV: yes, `TouchPolicy.ALWAYS` on slots ragedroid generated. Keystore: **not per-use** -- the auth is time-bound to a 30-second window, see the footnote under §3. Passkey: yes, platform UV. See §6.)
4. Does the JNI boundary parse untrusted input strictly enough that a malformed `recipientsJson` cannot up-cast a recipient to a more-trusted kind? (Yes -- see §9 audit checklist.)

If the answer to all four is what the documentation says, the threat model holds.
