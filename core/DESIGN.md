# ragewarden-core -- design notes

Read [`../DESIGN.md`](../DESIGN.md) for the ecosystem context. This file documents
crate-level decisions and the wire format of non-stock recipient stanzas.

---

## 1. Public API surface (current)

```rust
pub fn encrypt(plaintext: &[u8], recipients: &[Recipient]) -> Result<AgeBlob, EncryptError>;
pub fn decrypt(blob: &AgeBlob, identities: &[Box<dyn Identity>]) -> Result<Plaintext, _>;

pub trait Identity: Send + Sync { ... }
pub enum Recipient { X25519, YubiKeyPiv, Fido2HmacSecret, PasskeyPrf, AndroidKeystore, SoftwarePassphrase }
pub struct Stanza { tag, args, body }
pub mod bitwarden { derive_master_key, master_password_hash, stretch_master_key, encrypt_type2, decrypt_type2 }
pub mod sync { Server, HttpClient, register, login, fetch_vault, create_cipher, update_cipher, ... }
```

Stable -- frontends depend on this surface. Changes will require coordinated frontend updates.

`is_secure_url()` accepts `https://` anywhere and `http://` only to a real loopback host.
The host is parsed properly -- lowercased, authority split at `/ ? #`, host taken after the
last `@` so `http://127.0.0.1@evil.example` is rejected, `[...]` unwrapped only when the
bracket closes the host, port stripped -- and then must be `localhost` or parse as a
loopback `Ipv4Addr`/`Ipv6Addr`. `http://[::1]` works; `http://127.1:8080` and
`http://[::ffff:127.0.0.1]` are rejected, a deliberate tightening from the old
`starts_with("127.")` test.

The check is no longer replicated per call site, which is what let `sync::set_folder` slip
through unguarded. `sync.rs` now reaches the network in exactly one private function,
`send()`, and that function takes a `&SecureUrl` -- a newtype in a sealed private module
whose only constructor, `SecureUrl::parse`, runs `is_secure_url`. A new endpoint therefore
cannot transmit anything without first producing a validated URL; forgetting the check is a
compile error rather than a review miss. `Server::api()` / `Server::identity()` are the
`&Server` builders and call `require_secure()` (both URLs) before handing back a
`SecureUrl`. `set_folder`, which takes a bare `server_url: &str` and has no `&Server`, goes
through `SecureUrl::parse` on the single URL it dials; `set_folder_on` is the `&Server`
variant that validates both. `require_secure()` remains public for fail-fast use, joined by
`Server::try_self_hosted` / `try_new` for validating at configuration time.

Because `Server` keeps public fields and a `Deserialize` impl, construction-time validation
alone cannot be sufficient -- a persisted config can rehydrate an insecure `Server`
regardless of which constructor was used. That is why the enforcement point is the wire,
not the constructor. `ReqwestClient` additionally refuses insecure URLs itself and uses a
custom redirect policy, so a 30x from `https://` to `http://` cannot replay the
`Authorization` header in cleartext.

`core/tests/sync_protocol.rs::every_network_entry_point_refuses_an_insecure_server`
enumerates all eleven `&Server` network functions plus `set_folder`, and
`every_http_call_in_sync_rs_goes_through_the_chokepoint` fails if a future endpoint calls
the `HttpClient` trait directly.

### KDF

`login` enforces a floor of `KDF_ITERATIONS_MIN` = 100 000 -- the Bitwarden client default
from 2018 until the 2023 bump, so the lowest count a legitimately-provisioned account is
likely to carry. The previous floor of 5 000 was the 2013-era default and roughly 120x
cheaper to crack than today's; refusing it is deliberate, and the remedy (raising the count
server-side) is available to the user without this client.
`register` uses the stricter `KDF_ITERATIONS_MIN_NEW_ACCOUNT` = 600 000, since nothing
legacy can exist at registration time.

A floor narrows but does not close the downgrade attack: a hostile server can answer
prelogin with 100 000 for an account that really uses 600 000 and stay above it. Only
pinning catches that, so `login_pinned()` takes the count recorded by the previous
successful login and raises `SyncError::KdfIterationsDowngraded` on any decrease, before
the master-password hash is derived or transmitted. Plain `login()` is `login_pinned(...,
None)` -- trust-on-first-use, which cannot detect anything.

The KDF *type* is checked (`SyncError::UnsupportedKdfType`) before any hash is computed, so
an Argon2id account fails loudly rather than silently misderiving. Two gaps remain: an
absent `Kdf` field in the prelogin response is treated as PBKDF2, and a prelogin that
errors skips the type check entirely (the fallback then uses the strongest parameters
known, so it is not itself a weakening). More importantly the type is **dropped** after the
check -- `Session` and `RegisterOutput` carry `kdf_iterations` but no `kdf`, so nothing
downstream can persist, pin or display it. Adding the field is a breaking change to struct
literals in `ragemanifest` and `ragedroid/jni` and has not been done.

---

## 2. Wire formats

### 2a. Stock age stanzas

Used as-is, no custom code:

- **`X25519`** -- stock age X25519 recipient. Used for software/recovery identities.
- **`scrypt`** -- stock age scrypt recipient. Used for paper passphrase identities.

### 2b. `piv-p256`

**The tag is a misnomer and the format is ours, not upstream's.** An earlier draft of this
file claimed wire compatibility with `age-plugin-yubikey`
(<https://github.com/str4d/age-plugin-yubikey>) and implementation against its test
vectors. Neither is true of the shipped code, and no `piv-p384` exists anywhere in the
tree. What `encrypt_piv_p256_stanza` / `decrypt_piv_p256_with_ecdh_share` actually
implement:

```
-> piv-p256 <ephemeral_x25519_pub_b64> <recipient_tag_b64>
<base64 wrapped file key>
```

- **X25519**, not P-256. `X25519Secret` / `X25519Public`, 32-byte keys, a fresh ephemeral
  scalar per stanza. rageterm enrolls a YubiKey 5.7.0+ PIV slot generated with
  `ykman piv keys generate --algorithm X25519`; pre-5.7.0 cards cannot be enrolled.
- `<recipient_tag_b64>` is the first four bytes of `SHA-256(recipient_pubkey)` -- a
  matching hint, not a key.
- Body key is `HKDF-SHA256(salt = ephemeral_pub, ikm = ECDH(ephemeral, slot_pub),
  info = "piv-p256")`, AEAD `ChaCha20-Poly1305` with `nonce = 0` and
  `ad = "piv-p256"`. The zero nonce is safe here for the same reason as §2d: the
  ephemeral public key makes the body key fresh per stanza.

Because each stanza carries its own ephemeral key, unwrapping each secret needs its own
ECDH on the card -- this stanza does *not* have the bulk-siphon exposure §2d describes for
the PRF stanzas.

Renaming the tag to something honest (`piv-x25519`) is a wire-format break for anything
already written, so it has not been done. **Deciding that compatibility question, and
implementing a genuinely `age-plugin-yubikey`-compatible P-256 stanza alongside it, is NOT
YET IMPLEMENTED.**

### 2c. `fido2-hmac`

Modelled on `age-plugin-fido2-hmac`:
<https://github.com/sneakers-the-rat/age-plugin-fido2-hmac>. Stanza body wraps the file key
with a key derived from the FIDO2 hmac-secret extension output. Used by frontends that talk
to authenticators directly (rageterm via ctap-hid-fido2; ragedroid via yubikit-android).

```
-> fido2-hmac <credential_id_b64url> <prf_salt_b64> <rp_id> <wrap_salt_b64>
<base64 wrapped file key>
```

Body key and per-secret uniqueness follow §2d -- the two stanzas differ only in the HKDF
`info` / AEAD associated-data string and in argument order. The trailing `<wrap_salt_b64>`
makes this a superset of the upstream stanza, so we do not claim byte-for-byte wire
compatibility with the upstream plugin.

### 2d. `webauthn-prf-v1` (custom, browser-friendly variant of `fido2-hmac`)

Used by ragemanifest and by ragedroid on API 34+ (Credential Manager). Same primitive as
`fido2-hmac` (HMAC-SHA-256 keyed by an authenticator-resident secret), but the salt framing
matches the WebAuthn PRF extension's `eval.first` semantics rather than the raw CTAP2
`hmac-secret` salt. We don't reuse `fido2-hmac` directly because:

1. WebAuthn PRF prepends a 4-byte tag (`"WebAuthn PRF\x00"`) to the salt before HMAC, per
   the W3C spec; raw CTAP2 hmac-secret doesn't.
2. The output is 32 bytes (single salt) vs 64 bytes (paired salt) -- we use the single form.

```
-> webauthn-prf-v1 <credential_id_b64> <rp_id> <prf_salt_b64> <wrap_salt_b64>
<base64 wrapped file key>
```

Where:
- `<credential_id_b64>` -- base64(no padding) of the WebAuthn credential ID.
- `<rp_id>` -- relying-party ID the credential was created under (e.g., `ragewarden`).
- `<prf_salt_b64>` -- base64 of the 32-byte salt fed verbatim into PRF's `eval.first`.
- `<wrap_salt_b64>` -- base64 of a 32-byte salt drawn from the CSPRNG **once per stanza**.
- Body -- base64 of
  `ChaCha20-Poly1305(key=HKDF-SHA256(salt=prf_salt||wrap_salt, ikm=prf_output, info="webauthn-prf-v1"), nonce=0, ad="webauthn-prf-v1", ct=file_key)`.

#### Per-secret uniqueness

The wrap must be unique per secret: the PRF output is deterministic for a fixed
(authenticator, credential, prf_salt), so if that were the only key input, every secret
wrapped to one authenticator would share a ChaCha20 keystream and a Poly1305 one-time key.
That is a plaintext-recovery and forgery break, and it also defeats §0b "strict tap per
use" in the ecosystem `DESIGN.md`: one captured PRF output would unwrap the whole vault.

Uniqueness comes from `wrap_salt`, not from `prf_salt`. `prf_salt` is an *input to the
authenticator* -- core cannot mint a fresh one, because `encrypt_with_prf` is synchronous
and hardware-free and receives an already-evaluated `prf_output` bound to a specific salt.
Minting a per-secret `prf_salt` would require an authenticator round trip inside core.
`wrap_salt` is pure CSPRNG output and needs no hardware, so core can always draw it.
Frontends that *do* rotate `prf_salt` per secret still work and simply add entropy: both
salts are concatenated into the HKDF salt.

The nonce stays `0`. With a 32-byte CSPRNG salt per stanza the body key is fresh with
overwhelming probability, which is exactly the condition under which age's own `X25519`
and `scrypt` stanzas -- and the `piv-p256` / `ragedroid-keystore-v1` stanzas below, where
the per-encryption ephemeral public key plays the role of `wrap_salt` -- use a zero nonce.
A random nonce would add wire bytes without adding entropy: it would come from the same
CSPRNG whose failure is the only way the salt repeats.

#### Compatibility with pre-`wrap_salt` stanzas

A three-argument `webauthn-prf-v1` / `fido2-hmac` stanza is the pre-`wrap_salt` format.
Core **decrypts** those with the old `HKDF(salt=prf_salt, ...)` derivation and **never
writes** them. The formats are distinguished by argument count, which the parser already
validated, so the wire format stays self-describing and existing argument positions are
unchanged.

Rejecting old stanzas was considered and rejected: the flaw is a confidentiality break of
data already written, so refusing to read it does not undo the exposure -- it only strands
the vault with no migration path. There is no downgrade attack, because forging a
three-argument stanza still requires `prf_output`, and replaying a captured one gives an
attacker nothing they did not already hold. `webauthn_prf_is_legacy_wrap` /
`fido2_hmac_is_legacy_wrap` let frontends flag affected ciphers and prompt a re-wrap; any
secret ever wrapped under the old format should be treated as compromised and rotated.

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
- `<ephemeral_pub>` -- base64 of a **33-byte SEC1-compressed P-256** ephemeral public key.
- Body -- base64 of
  `ChaCha20-Poly1305(key=HKDF-SHA256(salt=ephemeral_pub, ikm=ECDH_P256(ephemeral, keystore_pub), info="ragedroid-keystore-v1"), nonce=0, ad="ragedroid-keystore-v1", ct=file_key)`.

**This is P-256 throughout -- there is no curve conversion.** An earlier draft of this file
described converting the Keystore P-256 key to X25519 via the libsignal-style
"P-256 -> Montgomery" trick at enrollment time. That is not what the code does.
`encrypt_ragedroid_keystore_stanza` takes the raw 33-byte SEC1-compressed P-256 point,
validates it with `P256PublicKey::from_sec1_bytes` (`is_valid_p256_sec1_compressed`, also
enforced at the `Recipient::AndroidKeystore` boundary in `lib.rs` and on registry entries),
and runs a P-256 ECDH against a fresh `P256EphemeralSecret`. The Kotlin side matches:
`AndroidKeystoreEnrollment` generates a `secp256r1` Keystore key and
`AndroidKeystoreIdentity` decompresses the SEC1 point and runs
`KeyAgreement.getInstance("ECDH", "AndroidKeyStore")`.

As with §2b, the per-stanza ephemeral key means each unwrap needs its own Keystore
operation, so this stanza has no bulk-siphon exposure.

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

## 6. TOTP

`totp` module exports `TotpConfig::from_base32_secret` / `from_otpauth_uri`,
`generate(cfg) -> TotpCode`, and the convenience `generate_for_uri_or_secret(input)`
that handles either shape Bitwarden may store in the cipher `totp` field. Algorithms:
SHA1 (RFC 6238 default), SHA256, SHA512. Periods and digit counts come from the
`otpauth://` parameters; defaults are 30 seconds / 6 digits.

`generate_at(cfg, unix_ts)` is the deterministic version used by tests; the production
`generate` reads `SystemTime::now()`. Conformance is verified against the RFC 6238
appendix-B vectors for all three algorithms.

The frontends consume `generate_for_uri_or_secret` directly: rageterm has a `totp`
subcommand, ragedroid surfaces TOTP codes inline on the item-detail screen with a
30-second countdown ring, ragemanifest exposes the same via a `wasm_totp_generate`
WASM binding.

---

## 7. Phases (per the canonical 5-phase roadmap in [`../DESIGN.md`](../DESIGN.md#7-sequencing))

- **Phase 1** -- encrypt / decrypt for `X25519` and `scrypt`; Bitwarden helpers; tests.
- **Phase 2** -- `sync` module: HTTP-injected Bitwarden / Vaultwarden client (register,
  login, fetch_vault, cipher CRUD), with the rage blob stored in the cipher's `rage:v1`
  custom field.
- **Phase 3** -- wire `piv-p256`, `fido2-hmac`, `webauthn-prf-v1`, `ragedroid-keystore-v1`
  stanzas (parsing + body wrapping); the actual hardware operations live in the
  frontends.
- **Phase 4** -- feature-gating and optional sibling crates so a non-Bitwarden frontend
  can drop the `bitwarden` and `sync` modules.
- **Phase 5** -- optimize, harden, audit prep, reproducible-build verification.
