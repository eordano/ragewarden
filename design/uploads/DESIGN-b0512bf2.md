# ragewarden-core -- design notes

Read [`../DESIGN.md`](../DESIGN.md) for the ecosystem context. This file documents
crate-level decisions and the wire format of non-stock recipient stanzas.

---

## 1. Public API surface (current)

```rust
pub fn encrypt(plaintext: &[u8], recipients: &[Recipient]) -> Result<AgeBlob, EncryptError>;
pub fn decrypt(blob: &AgeBlob, identities: &[Box<dyn Identity>]) -> Result<Plaintext, _>;

pub trait Identity: Send + Sync { ... }
pub enum Recipient { X25519, YubiKeyPiv, Fido2HmacSecret, AndroidKeystore, SoftwarePassphrase }
pub struct Stanza { tag, args, body }
pub mod bitwarden { derive_master_key, master_password_hash, stretch_master_key, encrypt_type2, decrypt_type2 }
```

Stable -- frontends depend on this surface. Changes will require coordinated frontend updates.

---

## 2. Wire formats

### 2a. Stock age stanzas

Used as-is, no custom code:

- **`X25519`** -- stock age X25519 recipient. Used for software/recovery identities.
- **`scrypt`** -- stock age scrypt recipient. Used for paper passphrase identities.

### 2b. `piv-p256` / `piv-p384`

Wire-compatible with `age-plugin-yubikey`. Identity matches when the stanza's pubkey equals
the slot's pubkey. Body is HKDF-derived and AEAD-wrapped exactly per the upstream plugin
spec: <https://github.com/str4d/age-plugin-yubikey>.

We do not re-spec it; we implement against the upstream test vectors.

### 2c. `fido2-hmac`

Wire-compatible with `age-plugin-fido2-hmac`:
<https://github.com/sneakers-the-rat/age-plugin-fido2-hmac>. Stanza body wraps the file key
with a key derived from the FIDO2 hmac-secret extension output. Used by frontends that talk
to authenticators directly (rageterm via libfido2; ragedroid via yubikit-android).

### 2d. `webauthn-prf-v1` (custom, browser-friendly variant of `fido2-hmac`)

Used by ragemanifest and by ragedroid on API 34+ (Credential Manager). Same primitive as
`fido2-hmac` (HMAC-SHA-256 keyed by an authenticator-resident secret), but the salt framing
matches the WebAuthn PRF extension's `eval.first` semantics rather than the raw CTAP2
`hmac-secret` salt. We don't reuse `fido2-hmac` directly because:

1. WebAuthn PRF prepends a 4-byte tag (`"WebAuthn PRF\x00"`) to the salt before HMAC, per
   the W3C spec; raw CTAP2 hmac-secret doesn't.
2. The output is 32 bytes (single salt) vs 64 bytes (paired salt) -- we use the single form.

```
-> webauthn-prf-v1 <credential_id_b64> <rp_id> <salt_b64>
<base64 wrapped file key>
```

Where:
- `<credential_id_b64>` -- base64(no padding) of the WebAuthn credential ID.
- `<rp_id>` -- relying-party ID the credential was created under (e.g., `ragewarden`).
- `<salt_b64>` -- base64 of the 32-byte per-secret salt, fed verbatim into PRF's `eval.first`.
- Body -- base64 of `ChaCha20-Poly1305(key=hkdf(prf_output, info="webauthn-prf-v1"), nonce=0, ad="webauthn-prf-v1", ct=file_key)`.

This stanza is interoperable across ragemanifest and ragedroid (API 34+). Frontends without
WebAuthn-PRF support fall through to the next stanza in the header -- typically a `fido2-hmac`
or `piv-p256` stanza for the same authenticator if it's a security key, or just nothing if
it's a platform-only passkey (Touch ID etc.).

### 2e. `ragedroid-keystore-v1` (custom)

Local-device identity for Android StrongBox / TEE keys. Not portable across devices
(the underlying Keystore key isn't extractable; only this device can unwrap).

```
-> ragedroid-keystore-v1 <key_handle> <ephemeral_pub>
<base64 wrapped file key>
```

Where:

- `<key_handle>` -- opaque base32(no padding) identifier the Android frontend uses to look up
  the local Keystore alias. Doesn't leak globally identifying info.
- `<ephemeral_pub>` -- base64 of an ephemeral X25519 pubkey used in ECDH.
- Body -- base64 of `ChaCha20-Poly1305(key=hkdf(ECDH(ephemeral, keystore_pub)), nonce=0, ad="ragedroid-keystore-v1", ct=file_key)`.

Conversion of the Keystore P-256 key to an X25519 key uses the standard "convert P-256 to
Montgomery" approach used by libsignal and others. The Android frontend does the conversion
at recipient-enrollment time so the public key recorded in the recipient list is the
post-conversion X25519 pubkey, ready for direct ECDH.

This stanza is opaque to non-Android frontends (no implementation = no match = falls through
to next stanza). The recipient list in the vault tells other frontends "this cipher is also
unlockable on Android device X" so they can prompt the user to fall back to ragedroid if
they're stuck.

---

## 3. Why we re-implement the Bitwarden helpers

Bitwarden's official Rust SDK exposes everything we need plus a lot we don't (vault sync,
cipher decryption, organization handling, send, etc.). We need only:

- PBKDF2 master key derivation.
- Master password hash.
- HKDF-expand for the stretched master key.
- AES-CBC + HMAC-SHA256 Type-2 encrypt/decrypt.

These are all stock primitives. Re-implementing means:

- ~200 lines of Rust we can audit independently.
- No churn from the official SDK's release cadence.
- Reuse across all three frontends without an `sdk-android` / `sdk-rs` / `sdk-wasm` matrix.

The frontends still depend on the official SDK *separately* for sync and cipher
serialization; that's a reasonable scope split (sync is fiddly, the primitives aren't).

---

## 4. Threading and async

`encrypt` and `decrypt` are sync functions. Hardware identity callbacks are sync from rage-core's
perspective; the frontend is responsible for blocking the calling thread on async hardware
operations (Android: `runBlocking` on a dedicated dispatcher; CLI: just sync; WASM: ...
complicated, see below).

WASM is special-cased because `WebAuthn`'s `navigator.credentials.get` is async-only. The WASM
build of rage-core exposes `decrypt_async` returning a `Promise`, with identity callbacks that
can themselves return promises. This is implemented in the ragemanifest crate via wasm-bindgen
adapters, not in the core crate.

---

## 5. Testing

- **Unit tests** on each primitive (KDF vectors against Bitwarden spec, age round-trip with
  software X25519 recipients, Type-2 vectors).
- **Property tests** (`proptest`) on encrypt/decrypt round-trips for software identities.
- **Conformance vectors** for `piv-p256`/`fido2-hmac` stanzas borrowed from upstream
  age-plugin-* test fixtures, executed without hardware via mock identity implementations.

Hardware-bound tests live in the per-frontend crates. Core remains hardware-free.

---

## 6. Phases

- **Phase 1**: implement encrypt / decrypt for `X25519` and `scrypt` recipients only;
  Bitwarden helpers; tests. Frontends can run end-to-end with software identities.
- **Phase 2**: wire `piv-p256`, `fido2-hmac`, `ragedroid-keystore-v1` stanzas in core
  (parsing + body wrapping; identity work happens in frontends).
- **Phase 3**: optimize / harden / audit prep.
