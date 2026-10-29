# Changelog

All notable changes to RageDroid (the Android client) are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Cards, identities and SSH keys as typed Bitwarden items, with a Protect toggle per
  field (several protected fields sealed in one blob); a login's TOTP seed and notes can
  be protected too.
- Offline unlock: the vault is cached encrypted on disk and the master password unlocks
  without the network; biometric unlock through a per-use, auth-bound Keystore key.
- Idle lock after five minutes and on screen off; the lock drops the keys and the
  decrypted vault from memory.
- Autofill and the keyboard offer an unlock while locked; the keyboard types protected
  items after a hardware tap; inline keyboard-strip suggestions on Android 11+.
- Saving from other apps: a login submitted in another app or site is saved as a new
  protected login, or as the new password of the matching one, after the unlock and a
  confirmation that says which.
- YubiKey P-256 PIV slots (the default for new enrolments, age-plugin-yubikey's format);
  a different YubiKey is named before its PIN is used; a key already plugged in is used.
  The slot's touch policy is read back (GET METADATA) at enrolment and before every
  unwrap, and a slot that does not wait for a touch on every use is refused.
- Passkeys for `ragewarden.decent.foundation`, discoverable and published with their public
  key so the browser can use them through its relay page; the F-Droid build supports
  passkeys on Android 14+.
- Token refresh on a 401; legacy-KDF accounts are offered an upgrade to 600 000
  iterations; the KDF pin is kept per server and email across sign-out.
- Bulk re-encrypt of stale items, offered after a revoke; "Move to folder"; a TOTP field
  with QR scan on new logins; "Test it now" for the paper backup.
- Shared revision history and audit vocabulary with the other clients; the audit log
  records outcomes.
- Instrumented delivery-flow tests and a macrobenchmark against a real signed-in vault.

### Changed
- Writes go through core's field-preserving cipher builders, so every field of the
  server copy survives an edit, rotation or protect.
- New writes use a fresh PRF salt per secret, and passkeys wrap as `webauthn-prf-v1`
  (`PasskeyPrf`); older passkey entries move on request.
- Keystore keys prompt on every use from API 35 and are generated without
  authentication only after the user agrees.
- UI text comes from string resources, in user vocabulary, with plurals for counts; a unit
  test fails on any human-text literal in `ui/`, `ime/` or `autofill/`. The vault's errors
  reach toasts as plain sentences ("You're signed out. Sign in and try again."). The lock
  and account screens name the account's real KDF.
- AGP 9.4.1 on Gradle 9.7.1, compileSdk 37, Kotlin 2.4.20, yubikit 3.2.1; R8 on release.

### Fixed
- Edits, rotations and protect no longer drop login fields, TOTP, notes or favourites.
- Card and Identity saves no longer report success without saving.
- Rotating the phone no longer regenerates the paper recovery phrase.
- Autofill host matching uses the public-suffix list (`com` no longer matches every
  `.com` item).
- A Rust panic in a JNI call throws instead of killing the app.
- An unreadable key list is shown with a reset instead of reading as "no keys".

### Security
- The stored session holds tokens only; the user key is kept encrypted.
- Store keys prefer StrongBox; pref names are hashed so account ids are not in the file.
- Overlay-obscured touches are refused on every control that releases a secret or removes
  a key.
- Secrets reach the clipboard, autofill and keyboard as zeroed char buffers.

## [0.1.0] - 2026-05-05

The first publishable build. Vault items can be encrypted to multiple
recipients (Android Keystore P-256, YubiKey PIV, FIDO2 PRF, paper recovery
phrase) on top of Bitwarden Type-2 ciphertext, decrypted on demand, and synced
through any Vaultwarden / Bitwarden instance.

### Added
- Real recipient enrollment ceremonies for Android Keystore (StrongBox or TEE,
  with biometric gate when available), YubiKey PIV (yubikit-android 3.2.1),
  FIDO2 / passkey PRF via `androidx.credentials`, and paper recovery phrase.
- `RecipientStore` and `HistoryStore` backed by `KeystorePrefs` (AES/GCM
  under an AndroidKeyStore key), scoped per Bitwarden account id.
- Multi-recipient `encryptToRecipients` JNI path with PRF input collection.
- Backfill wizard that re-encrypts unprotected vault items in place. When
  no items need first-time protection but the recipient set is stale, the
  wizard offers an explicit "Mark all rotated" dismiss path.
- Organic auto-rotation: decrypting a rage item while the recipient set is
  stale automatically re-encrypts it with the current set in the background
  -- no extra biometric prompt; the rotation banner clears once every protected
  item has been re-encrypted to the current keys.
- Per-item history surface backed by `HistoryStore`: Created / Rotated /
  Modified events tagged with `Build.MODEL · backing`, capped at 50 per item.
- Activity log backed by `AuditFeed`: enroll / reveal / copy / rotate events
  with bucketed timestamps, capped at 500 entries, clearable from the screen.
- Lock-on-launch and re-lock-on-resume controlled by `LockPolicy`.
- Auto-sync on entering the vault stage when the cached snapshot is empty.
- Release signing config wired to `RAGEDROID_KEYSTORE*` env vars.

### Changed
- Hilt + ViewModel migration across enrollment, vault, and settings flows.
- Visible enrollment failure card with retry / dismiss; full stack traces logged.
- Fingerprint card is the sole tap target on the Enroll step; "Skip" moved
  below.
- Empty-vault and empty-history screens render true zero-state copy (no
  fixture leakage).
- Vault list AppBar drops the search icon (Add -> Settings only); search lives
  in the tap-through filter row.

### Security
- All vault item ciphertext stays opaque to the server; rage-protected items
  never decrypt outside on-device identity material.
- Cipher rotation: when the recipient set changes, existing rage-protected
  items can be re-encrypted via the backfill wizard.
- Replaced the deprecated `androidx.security:security-crypto:1.1.0-alpha06`
  dependency with an in-tree `KeystorePrefs` helper that AES/GCM-encrypts
  values under a per-app AndroidKeyStore key.

