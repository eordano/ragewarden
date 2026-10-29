# RageTerm -- terminal client

Native CLI/TUI binary for the [Ragewarden](../DESIGN.md) ecosystem. Read the ecosystem
design first. This file is terminal-specific; [`README.md`](README.md) has the command
reference.

## 1. Targets

One Rust binary, built by `nix build <nixos-config>#rageterm` for Linux (x86_64,
aarch64). macOS builds with cargo (PC/SC from the OS, Keychain). Windows
(`x86_64-pc-windows-gnu`) cross-compiles from the `#ragewarden-windows` devshell: SCard,
Credential Manager, an owner-only ACL on config files, PowerShell `SendKeys` for `fill`, an
inherited pipe handle (`RAGEWARDEN_SECRET_HANDLE`) for `exec`, OpenSSH's named pipe for
`agent add`, and per-browser registry keys for the native host.

## 2. Module layout

`src/main.rs` parses arguments and dispatches; command implementations live in flat modules
(`commands.rs`, `native_host.rs`, `agent_add.rs`, `fill.rs`, ...). `tui.rs` is the ratatui
interface, `piv.rs` / `piv_apdu.rs` / `piv_pcsc.rs` the PIV path, `fido.rs` /
`fido_ctap.rs` FIDO2 over `ctap-hid-fido2`, `keyring_id.rs` the OS keyring, `pin.rs` where
device PINs come from, `lock.rs` the process-wide hardware lock, `output.rs` delivery.
`build.rs` sets `cfg(release_build)` so `hw.rs` can refuse `mock-hardware` in a release
build. Encryption, the Bitwarden protocol and the recipient policy are `ragewarden-core`.

## 3. Identity implementations

### 3a. PIV (PC/SC)

SELECT the PIV applet (AID `A0 00 00 03 08 00 00 10 00`), GET SERIAL to pick the card
holding the enrolled serial, read the slot's PIN and touch policy (GET METADATA,
`INS 0xF7`), VERIFY the PIN when the card asks for it, then GENERAL AUTHENTICATE with algorithm `0xE1`
(X25519) or `0x11` (P-256) on the stanza's ephemeral key. The shared secret unwraps the
`piv-p256` / `piv-x25519-v2` stanza (a P-256 slot's in age-plugin-yubikey's format).
Enrolment proves the card holds the key for the supplied public key and refuses a slot
whose touch policy is not `always` unless the operator passes the override. New slots are
P-256 (an X25519 key needs `--x25519`): for the native host a P-256 slot also signs the
request's challenge (GENERAL AUTHENTICATE with a `0x81` challenge) in the same card
session, so the PIN is entered once, and an X25519 slot cannot sign at all. `migrate-piv`
moves an X25519 slot's items to a P-256 slot and retires it.

### 3b. FIDO2 hmac-secret (`ctap-hid-fido2`)

getAssertion with the hmac-secret extension and the stanza's salt; the output unwraps the
`fido2-hmac` stanza. The assertion's UP flag must be set, and its UP/UV flags travel to the
native host's attestation. Whether the credential was enrolled with user verification is
recorded, and every later wrap and unwrap asks for that same seed. Enrolment keeps the
credential's ES256 public key; for the native host the assertion's client data is the
browser's proof message, so the same assertion that yields the hmac-secret signs it.
`attest-fido2` recovers the key of a credential enrolled before it was kept: ECDSA
public-key recovery over a touched and a silent assertion leaves one key.

### 3c. OS keyring

[`keyring`](https://crates.io/crates/keyring) (Keychain, Secret Service, Credential
Manager) stores a software X25519 identity. It is a software key: consent is the y/N prompt,
not an unlock dialog the keyring may or may not show.

### 3d. Software identity and paper recovery

`identity.age` is a software X25519 identity, passphrase-encrypted when enrolled at a
terminal. `enroll-recovery` prints 24 BIP39 words and keeps nothing on disk; `recover
--save` puts the derived key on a machine deliberately.

## 4. CLI -- the command names the action

There is no `decrypt`: each command consumes the plaintext and delivers it to one place.

- `get`/`pipe` write raw bytes to stdout (`--newline` adds one).
- `exec <name> -- cmd` passes the secret on FD 3 (or `$RAGEWARDEN_SECRET` with `--via-env`)
  so it is not in argv. rageterm's own `RAGEWARDEN_*` settings never reach the child;
  `--clean-env [--keep VAR]` passes only a minimal login environment.
- `agent add` parses the secret as an OpenSSH private key (`ssh-key`) and adds it over
  `$SSH_AUTH_SOCK` (`SSH_AGENTC_ADD_ID_CONSTRAINED` with `--lifetime`), never via
  `ssh-add`, so it is in no argv and on no disk.
- `fill --to pid:N|class:NAME|title:SUBSTR|focused` types through `xdotool`/`ydotool`
  (Linux) or PowerShell `SendKeys` (Windows) with the secret on stdin, and on macOS
  in-process: CoreGraphics keyboard events carrying the text as Unicode
  (`CGEventKeyboardSetUnicodeString`, at most 20 UTF-16 units per event, never splitting a
  surrogate pair), posted to the focused app or with `pid:N` to that process. Every
  character goes through, line breaks and trailing whitespace included, and the secret
  never leaves the process. Posting needs the terminal's Accessibility permission, which
  rageterm checks first; without it, an installed `cliclick -f -` (secret on stdin; its
  line-oriented command stream cannot carry a line break or trailing whitespace, which it
  refuses) is the fallback.
- `copy` hands the plaintext over a pipe to a detached `__clipboard-serve` child that owns
  the clipboard value (marked so clipboard managers skip it), clears it after the
  timeout if unchanged, and exits; `copy` returns once the value reads back.
- `reencrypt` (alias `rotate`) re-wraps items to the current recipient set; `restrict
  --to` narrows one item to named recipients.
- `set --offline` keeps an item in `store.json` without a session; `login` uploads it.
- `set --type card|identity|ssh-key` builds the typed block with core's `build_cipher`;
  `--protect` chooses the fields sealed in the blob and `--with` fills the rest, never a
  protected one (argv is readable by other processes). `set --field F` on an existing item
  decrypts the payload behind the consent gate when the item protects anything besides F,
  replaces F, re-seals the map with `core::protected::seal` and saves it with
  `update_preserving`. `get --field F` reads one field; `reencrypt` and `restrict` carry
  the whole payload.
- `delete` records the item's last revision in the account's history document (core
  `history`, under the user key) first and refuses to delete when it cannot; `audit` reads
  `audit.jsonl` with each event's outcome.

### Account

`login` passes core the KDF this (server, email) last used (`kdf-pins.json`, kept across
`logout`), so a server offering a weaker one is refused. An account still under PBKDF2
below 100 000 iterations logs in only after a confirmation (or `--allow-weak-kdf`) and is
then upgraded to the default KDF. Every request goes through `http.rs`, which on a 401
refreshes the session once, saves it, and retries.

### What the consent gate does

`consent::require` (or, from the TUI, `require_after_confirm` with a `UiConfirmed` value
only the overlay's Enter handler can build) produces the guard that `decrypt_named` needs.
With a real device enrolled, `decrypt_named` first offers the header to the device
identities only: if the item names a device, that device's answer is final and an error is
returned as an error; only an item naming no device reaches the software keys, and only
after the y/N confirmation. `--yes` is refused on such a vault and announces itself as
`SOFTWARE-ONLY` everywhere else.

## 5. TUI (`--tui`)

A searchable list (`/`) with each item marked `[device]` or `[software]` from its header.
`c` copy, `r` reveal, `a` ssh-agent, `x` exec (asks for the command line) open an overlay
that names the action and promises a tap only when the item names an enrolled device.
Enter runs the ceremony with the TUI suspended, so PIN prompts and device messages appear on
the normal screen; the status bar counts down the clipboard clear. Reveal is refused under
tmux/screen/ssh and clears the screen and scrollback afterwards.

## 6. Native messaging host

Browsers start `rageterm` with their own arguments (`chrome-extension://<id>/`,
`--parent-window=`, or Firefox's manifest path and add-on id); rageterm recognises them and
serves the length-prefixed protocol on stdio. `install-native-host` writes the manifest with
a profile path rather than a garbage-collectable store path. Safari has no manifest: the
Ragewarden Safari app relays to the rageterm it bundles or finds on a fixed list of paths,
and `install-native-host --browser safari` reports which one that is, or where to link it.

```
{ "method": "probe" }                    -> which backends exist and can attest a touch
{ "method": "unwrap_stanza", "stanza": {...},
  "context": { "action", "domain", "destination" }, "challenge": "<base64>" }
                                         -> { "ok": true, "file_key": "...", "tap": {...} }
```

With a challenge, an unwrap returns `tap.proof` over the message
`ragemanifest/ext/glue/native-proof.js` defines (challenge, stanza, action, destination):
from a P-256 PIV slot an ES256 signature of it, from a FIDO2 credential
`{kind: "fido2-assertion", authenticatorData, signature}` with clientDataHash =
SHA-256(message). Either carries the device's SPKI, which enrolment publishes as the
registry entry's `attestationPublicKey` (`sync` writes it back if an entry lost it). The
browser accepts a proof only from the key of the recipient the stanza names, and refuses
an unsigned reply for a recipient that publishes one.

The host never sees plaintext: it returns the file key and the browser's wasm core decrypts.
It refuses software-only stanzas (unless `RAGEWARDEN_NATIVE_HOST_ALLOW_SOFTWARE=1`), refuses
before asking the device when no touch can be attested (PIV policy other than `always`),
and refuses after when the device answered without one (FIDO2 UP unset). The desktop
notification says to touch only when a touch is coming. PINs come from `pinentry`, since
stdin is the browser pipe.

## 7. Build & distribution

`nix build <nixos-config>#rageterm`; `nix flake check` runs the NixOS checks
`ragewarden-e2e` (rageterm unit tests and the release binary against Vaultwarden),
`ragewarden-canokey` and `ragewarden-canokey-touch` (PIV and FIDO2 against a virtual
CanoKey). The `mock-hardware` stand-ins cannot be compiled into a release build.

## 8. Decisions

1. One-shot process; the clipboard timer lives in a detached child.
2. PINs: terminal prompt, else `pinentry`; the TUI suspends itself for the ceremony.
3. Concurrent invocations: a process-reentrant lock at `$XDG_RUNTIME_DIR/ragewarden.lock`
   is taken around every device conversation; `--no-wait` fails fast.
4. Local state: `vault.json` is the server-encrypted vault, readable only with the user key
   in `session.json`; when `identity.age` is passphrase-protected, `session.json` is
   age-encrypted to that identity, so one passphrase guards the identity, the session and
   through it the cache.
5. Scrollback: `get` to an interactive terminal and `reveal` refuse under tmux/screen/ssh;
   pipe `get`, or pass `reveal --force`.
