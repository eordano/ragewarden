# Changelog

All notable changes to RageDroid (the Android client) are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-05

The first publishable build. Vault items can be encrypted to multiple
recipients (Android Keystore X25519, YubiKey PIV, FIDO2 PRF, paper recovery
phrase) on top of Bitwarden Type-2 ciphertext, decrypted on demand, and synced
through any Vaultwarden / Bitwarden instance.

### Added
- Real recipient enrollment ceremonies for Android Keystore (StrongBox or TEE,
  with biometric gate when available), YubiKey PIV (yubikit-android 2.7.0),
  FIDO2 / passkey PRF via `androidx.credentials`, and paper recovery phrase.
- `RecipientStore` and `HistoryStore` backed by `KeystorePrefs` (AES/GCM
  under an AndroidKeyStore key), scoped per Bitwarden account id.
- Multi-recipient `encryptToRecipients` JNI path with PRF input collection.
- Backfill wizard that re-encrypts unprotected vault items in place. When
  no items need first-time protection but the recipient set is stale, the
  wizard offers an explicit "Mark all rotated" dismiss path.
- Organic auto-rotation: decrypting a rage item while the recipient set is
  stale automatically re-encrypts it with the current set in the background
  -- no extra biometric prompt; the rotation banner clears itself once every
  rage item has been touched.
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

### Known issues
- Strings are inline (English only); localization to
  `res/values/strings.xml` is pending and tracked for a future release.
- Two flow tests (`AutofillFlowTest`, `ImeFlowTest`) need a process-isolation
  fix to launch `TestActivity` from the autofill / IME service path on
  newer Android. Tracked separately; does not affect runtime behavior.
