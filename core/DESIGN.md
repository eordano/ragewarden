# ragewarden-core -- design notes

Read [`../DESIGN.md`](../DESIGN.md) for the ecosystem context. This file documents
crate-level decisions and the wire format of non-stock recipient stanzas.

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
through `SecureUrl::parse` on the two URLs it dials (it reads the cipher's favourite, then
`PUT /ciphers/{id}/partial`, the folder/favourite endpoint Bitwarden and Vaultwarden serve); `set_folder_on` is the `&Server`
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

`kdf::KdfParams` carries the account's derivation: PBKDF2-SHA256 with an iteration count,
or Argon2id with iterations, memory (MiB) and parallelism, salted with SHA-256 of the
lowercased email as the Bitwarden clients do (a known-answer test checks it against
libargon2). `Session` and `RegisterOutput` carry the full `KdfParams`.

`check_server_kdf` vets what prelogin reports before any hash is derived or sent:

- PBKDF2 below `KDF_ITERATIONS_MIN` = 100 000 (the 2018-2023 Bitwarden default) is a
  legacy account. Login fails with `SyncError::LegacyKdfNeedsConsent` unless
  `LoginOptions::allow_legacy_kdf` says the user confirmed it, and never goes below the
  2013-era 5 000. After such a login the client calls `upgrade_kdf`, which re-wraps the
  user key under the new master key (`POST /api/accounts/kdf`), logs in again with the
  new parameters and returns that session; ciphers are untouched.
- Argon2id must stay within 2..=10 passes, 16..=1024 MiB and 1..=16 lanes, and PBKDF2 at
  or below 2 000 000, so a hostile server cannot stall the client either.
- `LoginOptions::kdf_pin` is the `Session::kdf` of the account's last successful login.
  Anything weaker -- fewer iterations, less Argon2id memory, Argon2id back to PBKDF2 --
  fails with `SyncError::KdfDowngraded`. Without a pin the check is trust-on-first-use.

`register` / `register_with_kdf` and `upgrade_kdf` refuse anything below the current
recommendation (600 000 PBKDF2 iterations, or Argon2id 3 passes / 64 MiB).

A prelogin that errors falls back to the pinned parameters, or the PBKDF2 default.

## 2. Wire formats

### 2a. Stock age stanzas

Used as-is, no custom code:

- `X25519` -- stock age X25519 recipient. Used for software/recovery identities.
- `scrypt` -- stock age scrypt recipient. Used for paper passphrase identities.

### 2b. PIV: `piv-x25519-v2` and `piv-p256`

Three wire shapes, told apart by tag and argument lengths (`piv_stanza_kind`):

```
-> piv-x25519-v2 <ephemeral_x25519_pub_b64> <recipient_tag_b64>     (X25519 slot, written now)
-> piv-p256 <ephemeral_x25519_pub_b64> <recipient_tag_b64>          (X25519 slot, v1, read only)
-> piv-p256 <recipient_tag_b64> <ephemeral_p256_pub_compressed_b64> (P-256 slot, age-plugin-yubikey)
```

- `<recipient_tag_b64>` is the first four bytes of `SHA-256(recipient_pubkey)` -- a
  matching hint, not a key (32 raw bytes for X25519, 33 compressed SEC1 bytes for P-256).
- X25519 slots (YubiKey 5.7.0+, `ykman piv keys generate --algorithm X25519`): body key
  `HKDF-SHA256(salt = ephemeral_pub || recipient_pub, ikm = ECDH, info = "piv-x25519-v2")`,
  AEAD `ChaCha20-Poly1305`, `nonce = 0`, `ad = "piv-x25519-v2"`. The v1 `piv-p256` X25519
  shape salted HKDF with the ephemeral key alone (no recipient binding) and used
  `info = ad = "piv-p256"`; it stays readable forever and is written only to a recipient
  whose registry entry has not advertised `stanzaVersion: 2`.
- P-256 slots (every YubiKey 4/5; `Recipient::YubiKeyPivP256`, registry kind `YubiKey` with
  a 33-byte `pivPubkey`): `age-plugin-yubikey`'s format byte for byte -- salt
  `ephemeral_pub || recipient_pub`, `info = "piv-p256"`, no associated data. Tests check
  both directions against that plugin's `wrap_file_key` restated with age-core's own
  primitives.

Each stanza carries a fresh ephemeral key, so each unwrap needs its own ECDH on the card
-- no bulk-siphon exposure. The zero nonce is safe for the same reason as §2d.

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
- `<wrap_salt_b64>` -- base64 of a 32-byte salt drawn from the CSPRNG once per stanza.
- Body -- base64 of
  `ChaCha20-Poly1305(key=HKDF-SHA256(salt=prf_salt||wrap_salt, ikm=prf_output, info="webauthn-prf-v1"), nonce=0, ad="webauthn-prf-v1", ct=file_key)`.

#### Per-secret uniqueness

The wrap must be unique per secret: the PRF output is deterministic for a fixed
(authenticator, credential, prf_salt), so if that were the only key input, every secret
wrapped to one authenticator would share a ChaCha20 keystream and a Poly1305 one-time key.
That is a plaintext-recovery and forgery break, and it also defeats §0b "strict tap per
use" in the ecosystem `DESIGN.md`: one captured PRF output would unwrap the whole vault.

Two salts carry that uniqueness. `prf_salt` is the input the authenticator evaluated, and
it is per secret: `prf_requests_for(recipients)` draws a fresh one for each PRF recipient,
the client has the authenticator evaluate it, and `encrypt_with_prf` writes the evaluated
salt into the stanza (`PrfEntry` names the credential). Every decryptor evaluates the salt
the stanza carries, so one captured `prf_output` opens one secret, not every secret
wrapped to that authenticator. An entry with an empty `credential_id` still names its
recipient by enrolment salt -- the older per-recipient form, which is siphonable.
`wrap_salt` is pure CSPRNG output core draws itself, so the body key stays fresh even if a
caller repeats a `prf_salt`; both salts are concatenated into the HKDF salt.

The nonce stays `0`. With a 32-byte CSPRNG salt per stanza the body key is fresh with
overwhelming probability, which is exactly the condition under which age's own `X25519`
and `scrypt` stanzas -- and the PIV / keystore stanzas below, where
the per-encryption ephemeral public key plays the role of `wrap_salt` -- use a zero nonce.
A random nonce would add wire bytes without adding entropy: it would come from the same
CSPRNG whose failure is the only way the salt repeats.

#### Compatibility with pre-`wrap_salt` stanzas

A three-argument `webauthn-prf-v1` / `fido2-hmac` stanza is the pre-`wrap_salt` format.
Core decrypts those with the old `HKDF(salt=prf_salt, ...)` derivation and **never
writes** them. The formats are distinguished by argument count, which the parser already
validated, so the wire format stays self-describing and existing argument positions are
unchanged. A four-argument stanza whose `wrap_salt` is all zeros is refused: HMAC zero-pads
a 32-byte key to its block, so `prf_salt || 0^32` would select the legacy body key.

Rejecting old stanzas was considered and rejected: the flaw is a confidentiality break of
data already written, so refusing to read it does not undo the exposure -- it only strands
the vault with no migration path. There is no downgrade attack, because forging a
three-argument stanza still requires `prf_output`, and replaying a captured one gives an
attacker nothing they did not already hold. `legacy_prf_wraps(blob)` counts such stanzas
from the header alone so frontends can flag affected ciphers, and `rewrap` re-encrypts the
plaintext in the current format; any secret ever wrapped under the old format should be
treated as compromised and rotated.

A `webauthn-prf-v1` stanza opens wherever its passkey can be asked: the browser that created
it, ragedroid for its own passkeys (Credential Manager -- Play services, or Android 14+ on the
F-Droid build), and the browser for a phone passkey through the relay page. Frontends without
WebAuthn-PRF fall through to the next stanza in the header -- typically a `fido2-hmac` or PIV
stanza for the same security key, or nothing for a platform-only passkey.

### 2e. `ragedroid-keystore-v2` / `-v1` (custom)

Local-device identity for Android StrongBox / TEE keys. Not portable across devices
(the underlying Keystore key isn't extractable; only this device can unwrap).

```
-> ragedroid-keystore-v2 <key_handle> <ephemeral_pub>
<base64 wrapped file key>
```

Where:

- `<key_handle>` -- opaque base32(no padding) identifier the Android frontend uses to look up
  the local Keystore alias. Doesn't leak globally identifying info.
- `<ephemeral_pub>` -- base64 of a 33-byte SEC1-compressed P-256 ephemeral public key.
- Body -- base64 of
  `ChaCha20-Poly1305(key=HKDF-SHA256(salt=ephemeral_pub||keystore_pub, ikm=ECDH_P256(ephemeral, keystore_pub), info="ragedroid-keystore-v2"), nonce=0, ad="ragedroid-keystore-v2", ct=file_key)`.
- `ragedroid-keystore-v1` is the same with `salt=ephemeral_pub` alone and the v1 tag as
  info and associated data. It stays readable and is written only to an entry that has
  not advertised `stanzaVersion: 2`; the Android device publishes 2 once its build reads
  v2, since it is the only reader of its own key.

This is P-256 throughout -- there is no curve conversion. An earlier draft of this file
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

## 3. Why we re-implement the Bitwarden helpers

Bitwarden's official Rust SDK exposes everything we need plus a lot we don't (organization
handling, Send, and so on). Core implements the part Ragewarden uses -- PBKDF2 and Argon2id
master keys, the master-password hash, HKDF-expand of the stretched key, Type-2
AES-CBC + HMAC-SHA256 EncStrings, and the `sync` protocol (prelogin, token, refresh, sync,
cipher CRUD, KDF change) -- in auditable Rust shared by all three frontends, with no
`sdk-android` / `sdk-rs` / `sdk-wasm` matrix and no dependency on the SDK's release cadence.
No frontend links the official SDK.

## 4. Threading and async

`encrypt` and `decrypt` are sync functions. Hardware identity callbacks are sync from rage-core's
perspective; the frontend is responsible for blocking the calling thread on async hardware
operations (Android: `runBlocking` on a dedicated dispatcher; CLI: just sync; WASM: ...
complicated, see below).

WASM is special-cased because WebAuthn's `navigator.credentials.get` is async-only. The
ragemanifest crate's async exports (`wasm_decrypt_cipher_field*`) read the stanzas, await the
one ceremony they need through a JS callback, and then call core's synchronous `decrypt` with
identities that hold the answer; core stays synchronous.

## 5. Testing

- Unit tests on each primitive (KDF vectors against Bitwarden spec, age round-trip with
  software X25519 recipients, Type-2 vectors).
- Property tests (`tests/properties.rs`, `proptest`): round trips over arbitrary plaintexts
  and recipient sets, and every stanza, header, EncString and TOTP parser fed arbitrary
  input without panicking.
- Known answers: `tests/vectors/stanza_kat_v2.json` pins every stanza writer's output for
  fixed keys, ephemerals and salts (inputs included, so another language can reproduce
  them); `tests/vectors/stanza_formats_v1_frozen.json` holds ciphertexts the pre-v2 formats
  wrote, which every reader must keep opening.
- `age-plugin-yubikey` conformance: the P-256 `piv-p256` tests run that plugin's
  `wrap_file_key` (0.5.1, restated with age-core's own primitives) against our reader, and
  our writer against its unwrap.

Hardware-bound tests live in the per-frontend crates (and the CanoKey NixOS checks). Core
remains hardware-free.

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


## 6b. Password generator

`generator::password(&PasswordPolicy)` draws `length` (8..=128) characters uniformly from
the enabled classes (lower, upper, digits, `!@#$%^&*-_=+?.:`) with rejection sampling
against modulo bias, and redraws until every enabled class appears;
`generator::passphrase(words, separator)` joins 4..=24 BIP39 English words (11 bits
each). Both return zeroizing strings. ragemanifest exports them as
`wasm_generate_password` / `wasm_generate_passphrase`, ragedroid's JNI as
`generatePassword` / `generatePassphrase`.

## 7. Phases (per the canonical 5-phase roadmap in [`../DESIGN.md`](../DESIGN.md#7-sequencing))

- Phase 1 -- encrypt / decrypt for `X25519` and `scrypt`; Bitwarden helpers; tests.
- Phase 2 -- `sync` module: HTTP-injected Bitwarden / Vaultwarden client (register,
  login, fetch_vault, cipher CRUD), with the rage blob stored in the cipher's `rage:v1`
  custom field.
- Phase 3 -- wire `piv-p256`, `fido2-hmac`, `webauthn-prf-v1`, `ragedroid-keystore-v1`
  stanzas (parsing + body wrapping); the actual hardware operations live in the
  frontends.
- Phase 4 -- feature gates: `bitwarden` (KDFs, Type-2, account keys, tokens), `sync`
  (the HTTP protocol), `history`, `registry` and `policy`, all on by default. A
  non-Bitwarden frontend builds with `default-features = false` and keeps the age layer,
  stanzas, recovery, TOTP and the audit log; CI checks that build.
- Phase 5 -- optimize, harden, audit prep, reproducible-build verification.
