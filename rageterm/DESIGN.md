# RageTerm -- terminal client

Native CLI/TUI binary for the [Ragewarden](../DESIGN.md) ecosystem. Read the ecosystem
design first. This file is terminal-specific.

---

## 1. Targets

| platform | binary | hardware reachable |
|---|---|---|
| Linux x86_64 | `rageterm` | PCSC (YubiKey PIV), ctap-hid-fido2 (FIDO2 hmac-secret), gnome-keyring / kwallet (OS keyring) |
| Linux aarch64 | `rageterm` | same |
| macOS universal | `rageterm` (lipo `arm64 + x86_64`) | PCSC (built-in CCID stack), ctap-hid-fido2 (pure-Rust CTAP2), macOS Keychain |
| Windows x86_64 | `rageterm.exe` | Smart Card API (PIV), ctap-hid-fido2 (winhello), Credential Manager |

One Rust binary; cargo build per target. No interpreter, no runtime.

Distribution channels:

- GitHub releases (signed binaries per target).
- Homebrew tap (`brew install ragewarden/tap/rageterm`).
- `cargo install rageterm`.
- `apt`/`dnf` repos (post-MVP).

---

## 2. Module layout

```
rageterm/
+-- DESIGN.md
+-- README.md
+-- Cargo.toml               # binary + lib crates
+-- build.rs                 # bake version / git hash for `--version`
+-- src/
    +-- main.rs              # entry point; arg dispatch
    +-- cli/                 # CLI command implementations
    |   +-- mod.rs
    |   +-- login.rs
    |   +-- list.rs
    |   +-- get.rs
    |   +-- set.rs
    |   +-- enroll.rs
    |   +-- recipients.rs
    |   +-- lock.rs
    |   +-- agent.rs
    |   +-- native_host.rs    # for ragemanifest native messaging
    +-- tui/                 # ratatui interactive mode
    |   +-- mod.rs           # entry under `--tui`
    |   +-- app.rs           # state machine
    |   +-- views/           # list, detail, prompt, recipients
    |   +-- input.rs
    +-- pcsc.rs              # PIV via pcsc-lite / Windows SCard API
    +-- fido.rs              # FIDO2 via ctap-hid-fido2
    +-- keyring.rs           # OS keyring (gnome-keyring, Keychain, Win Cred)
    +-- output.rs            # action delivery: stdout, clipboard, agent, reveal
```

Depends on `rage-core` for the encryption layer and the Bitwarden helpers. Hardware
identity implementations live in this crate (they're platform-specific and don't fit in the
shared core).

---

## 3. Identity implementations

### 3a. PivIdentity (PCSC)

Uses the [`pcsc`](https://crates.io/crates/pcsc) crate (Linux: pcsc-lite, macOS: built-in,
Windows: Smart Card API). Each PIV slot operation:

```
SCardConnect -> select PIV applet (00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00 00)
             -> verify PIN if required (00 20 00 80 ... PIN ...)
             -> general authenticate ECDH (00 87 11 9X ... ephemeral pubkey ...)
             -> response = X25519 shared secret
             -> close
```

Touch-required slots prompt the user via the YubiKey's blink. Identity is parameterized by
`(serial, slot, expected_pubkey)`.

### 3b. Fido2Identity (ctap-hid-fido2 (pure-Rust CTAP2))

Uses [`ctap-hid-fido2`](https://crates.io/crates/ctap-hid-fido2). Calls `fido_dev_get_assert` with
`hmac-secret` extension and the stanza's salt; assertion's HMAC output -> HKDF -> file key.

### 3c. KeyringIdentity (OS keyring)

Uses [`keyring`](https://crates.io/crates/keyring). On macOS: Keychain Services; on Linux:
`secret-service` D-Bus (gnome-keyring, KeePassXC); on Windows: Credential Manager. Stores a
software age identity sealed by the OS-keyring lock; "tap" is the OS keyring's own
unlock prompt (Touch ID, password, etc.).

### 3d. Software passphrase identity (recovery only)

Same as elsewhere. `rageterm enroll-recovery` prints the 24 BIP39 words; user must save.

---

## 4. CLI command surface -- action chosen by command name

The entire CLI follows the principle: **the command names what the user wants done with the
plaintext**. There is no `decrypt` command that emits to stdout for the user to figure out
what to do with. Each command consumes the plaintext and returns to the user with the action
performed.

**Phase-4 leftovers status:** ✅ done -- `agent add`, `fill --to`, and the `pass`-style
aliases (`show`, `insert`, top-level `-c`) all ship in this phase. See `agent_add.rs`,
`fill.rs`, and the alias arms in `main.rs` / `commands.rs`.

```
rageterm login [server] [--email ...] [--password-stdin]
rageterm logout

rageterm list [--filter ...] [--json]
rageterm reveal <name>                         # ANSI-renders plaintext, holds until ENTER
rageterm show <name>                           # `pass`-style alias of `reveal`

# Use commands -- each runs the YubiKey ceremony and delivers plaintext to ONE consumer:
rageterm get <name>                            # writes plaintext to stdout, exits
rageterm copy <name>                           # to clipboard, auto-clears 30s
rageterm -c <name>                             # `pass`-style top-level shortcut for `copy`
rageterm fill <name> [--to pid:N|class:NAME|title:SUBSTR|focused]
                                                # injects via OS-specific autotype primitive
rageterm agent add <name> [--lifetime SECS]    # `ssh-add` equivalent: load into ssh-agent
rageterm exec <name> -- <command> [args...]      # spawns command with secret on FD 3 / env
rageterm pipe <name> | <consumer>              # alias of `get`; explicit for piping

# Write commands:
rageterm set <name> [--type login] [--from-stdin]
rageterm insert <name>                         # `pass`-style alias of `set`
rageterm rotate <name> --to <recipient-list>   # re-encrypt to new recipient list

# Recipient management:
rageterm enroll-yubikey [--slot 95]
rageterm enroll-fido2
rageterm enroll-keyring
rageterm enroll-recovery
rageterm recipients list
rageterm recipients remove <id>

# Native messaging host for ragemanifest (phase 4 delivered, hw tap stubbed):
rageterm native-host
rageterm install-native-host [--browser chromium|firefox|safari] [--user|--system]
                              --extension-id ID [--yes]
                              # --extension-id is required for chromium (the 32-char a-p id
                              # from chrome://extensions; prompted for at a terminal when
                              # omitted, validated, never defaulted); firefox/safari fall
                              # back to ragewarden@ragewarden / com.ragewarden.safari
rageterm uninstall-native-host [--browser ...] [--user|--system]

# `pass(1)` import (phase 4 delivered, real gpg invocation):
rageterm pass-import [--from PATH] [--folder NAME] [--default-recipient ID]
                     [--dry-run] [--also-export]

# Interactive mode:
rageterm --tui                                  # all of the above, mouse-and-keyboard UI
```

Notes on design:

- **`get` writes raw bytes to stdout, exits.** Useful for `rageterm get aws-prod-key | aws sts ...`.
  No prompt artifacts, no trailing newline unless the secret has one. `--newline` for the rare
  case where the consumer expects a trailing newline.
- **`exec` replaces `get | ...` for safety.** `rageterm exec aws-prod-key -- aws sts ...`
  passes the secret on FD 3 (or `$RAGEWARDEN_SECRET` if `--via-env`) so it doesn't appear
  in `ps`. Spawned process inherits no other state.
- **`agent add` for SSH.** Decrypts the secret as an OpenSSH-format private key (parsed
  via `ssh-key`), inserts it into `ssh-agent` over `$SSH_AUTH_SOCK` using
  `SSH_AGENTC_ADD_IDENTITY` (or `SSH_AGENTC_ADD_ID_CONSTRAINED` if `--lifetime` is set).
  The plaintext never touches disk and never appears in any process's argv (we don't
  shell out to `ssh-add`). Confirm prompt: `"Add <name> to ssh-agent for the next
  session? [y/N]"`. Lifetime bound by `ssh-agent`; `ssh-add -d` to remove early.
- **`fill --to <window-spec>` does autotype.** Uses `xdotool` on Linux X11, `ydotool` on
  Wayland (requires `ydotoold`), `cliclick` on macOS (one-time Accessibility grant),
  `SendInput` on Windows (stubbed pending real-platform test). `--to` accepts
  `pid:N`, `class:NAME` (X11 only), `title:SUBSTR`, or `focused` (default). The
  confirm prompt names the target window before tap. If the OS tool is missing,
  `fill` reports `"<tool> not found in PATH; install it via brew/apt"` rather than
  panicking.

  **The secret reaches every backend over a pipe, never over argv** -- the same rule
  `exec` and `agent add` follow above. `xdotool type --file -` and `ydotool type
  --file -` read it from stdin. macOS is the one that needed care: `cliclick t:<text>`
  as an argument put the plaintext in `ps`/`/proc/PID/cmdline` for the child's whole
  lifetime, so `fill` now uses `cliclick -f -`, which reads its command stream from
  stdin. That stream is line-oriented: `parseCommandsFile` splits on newlines, trims
  leading/trailing whitespace per line, drops blank and `#`-prefixed lines, and does
  *no* shell-style quote parsing, and `ActionExecutor` splits each line at the first
  colon and rejoins the rest with `:`. So `t:<secret>` carries spaces and colons
  verbatim, and rageterm refuses two inputs the format cannot carry losslessly rather
  than typing something other than the stored secret: a secret containing a line break,
  and a secret ending in whitespace. Both refusals point at `copy` / `exec` instead.
- **No `decrypt` command exists.** If you want plaintext in your hand, use `reveal`.
- **`copy` clears clipboard after 30s** by default (`--clear N` to override). Implementation
  via `arboard` crate, with a fork-and-detach to keep the timer running after rageterm exits.
  Two honest caveats. (1) `arboard::Clipboard::set_text` takes `impl Into<Cow<'_, str>>`, so
  passing the borrowed `&str` avoids minting an extra owned copy in rageterm -- but arboard
  still calls `.into_owned()` internally and holds a non-zeroizing `String` in its clipboard-
  owner thread for the life of the selection. rageterm cannot wipe that one. (2) The detached
  helper is spawned as `rageterm __clipboard-clear-helper <secs> <sha256hex>`, so an unsalted
  hex SHA-256 of the plaintext sits in the helper's argv -- readable in `/proc/<pid>/cmdline`
  for the whole clear window, and offline-guessable for a low-entropy secret. Moving that
  digest onto a pipe or an inherited fd is **NOT YET IMPLEMENTED**.

### What the consent gate actually does -- read this before trusting the tap

**There is no `--no-tap` flag, but "every action runs the YubiKey ceremony" is not true
today.** `consent::require` is the single gate in front of every plaintext delivery
(`get`, `copy`, `totp`, `reveal`, `pipe`, `rotate`, `agent add`, `fill`, `exec`). It
branches on `hardware_state()`, which is a property of the **vault**, not of the item:

- `HardwareState::Real` -- at least one non-mock PIV/FIDO2 identity is enrolled *anywhere*.
  The gate prints `"... -- this needs a hardware tap."` and **returns immediately with no
  gate of its own**, on the theory that the device prompt in the identity backend is the
  consent. `--yes` is structurally unable to touch this path, which is the property that
  was wanted. The hole is elsewhere: `core::decrypt` tries `as_software_age_identity()`
  entries *before* any hardware adapter, and `cmd_*` pushes the `identity.age` software
  identity first, so an item that also carries an X25519 stanza -- which is every item in a
  vault where `enroll-software-identity` was run, the CLI's own step one -- unwraps from
  disk with no device involved, under a message claiming a tap was required. Enrolling a
  YubiKey therefore currently makes `get` **less** gated than not enrolling one.
- `HardwareState::None` and `HardwareState::MockOnly` -- treated identically and honestly.
  A y/N confirmation read from `/dev/tty` (never stdin, so `printf 'y\n' | rageterm copy x`
  can no longer answer its own prompt) stands in for the tap; `--yes` skips it and says on
  stderr that no tap was performed; with neither a tty nor `--yes`, the command refuses.

**NOT YET IMPLEMENTED:** deriving the gate from the item's own stanza tags -- take the
"hardware" branch only when *every* stanza on that item is hardware-gated, and otherwise
fall through to the confirmation without claiming a tap. Also unimplemented: reading a PIV
slot's touch policy back (YubiKey metadata APDU `INS 0xF7`, absent from `piv_apdu.rs`), so
a slot generated without `--touch-policy always` completes ECDH silently while the prompt
says otherwise. `enroll-yubikey`'s guidance string now tells the user to pass
`--touch-policy always --pin-policy once` and states that rageterm cannot verify it.

See `../DESIGN.md` §0e and `../SECURITY.md` "Known gaps".

---

## 5. TUI mode (`--tui`)

Built on [ratatui](https://crates.io/crates/ratatui) + [crossterm](https://crates.io/crates/crossterm).
Same actions, just navigable.

```
+------------------------------------+
| ragewarden -- vault for foo@bar.com |
+------------------------------------+
| /search                            |
|                                    |
| ❯ github.com         (🔒)          |
|   gitlab.com         (🔒)          |
|   aws-prod-key       (🔒)          |
|   personal-blog                    |
|                                    |
+------------------------------------+
| enter: open  c: copy  r: reveal    |
| x: exec  a: agent-add  q: quit     |
+------------------------------------+
```

Selecting a cipher and pressing `c` (copy), `r` (reveal), `a` (agent-add), `x` (exec) opens
the prompt overlay:

```
+- Copy github.com password? --------+
|                                    |
|  Tap your YubiKey to authorize.    |
|                                    |
|  [ Cancel: Esc ]                   |
+------------------------------------+
```

Exact same action-named-before-tap semantics as the GUI frontends. The keypress chooses the
action; the tap consents to that specific action.

`x` (exec) prompts for a command: `Enter command: ...`, then on tap the command is spawned with
the secret on FD 3.

Status bar shows clipboard auto-clear countdown after a `c` action.

---

## 6. Native messaging host mode (`--native-host`)

Invoked by ragemanifest as a subprocess. Reads JSON-RPC-style messages from stdin (length-
prefixed per the WebExtensions native messaging spec), writes responses to stdout.

Protocol surface (small):

```
Request:  { "method": "unwrap_stanza",
            "stanza": { "tag": "piv-p256", "args": [...], "body": "..." },
            "context": { "action": "autofill", "domain": "github.com" } }
Response: { "ok": true, "file_key": "<base64 32 bytes>" }
```

Crucially: `rageterm --native-host` **does not see the plaintext**. It receives the stanza
and returns the file key (or an error). The browser extension's WASM core does the actual
age decrypt with that file key. This way, plaintext never leaves the browser process for
browser-initiated operations.

The `context` object lets rageterm display a prompt (via TUI overlay if running attached,
via a desktop notification if running detached) so the user sees `"Autofill into github.com?
Tap your YubiKey."` before tapping. Same action-named-before-tap principle.

Host manifest installation: `rageterm install-native-host [--browser chromium|firefox|safari]
[--user|--system] --extension-id ID [--yes]` writes the JSON manifest to the right path for
the OS+browser combo. For chromium the extension id is required and validated (32 characters,
each a-p -- the id chrome://extensions shows); when omitted at a terminal it is prompted for,
and an invalid id is refused before anything is written, since Chrome silently ignores a
manifest whose `allowed_origins` entry is not a real extension id. Firefox and Safari keep
their defaults (`ragewarden@ragewarden`, `com.ragewarden.safari`). `rageterm uninstall-native-host --browser ...` removes it. **Phase 4
status -- delivered**: the installer + uninstaller resolve paths per OS (macOS / Linux /
Windows registry), the native-host loop reads length-prefixed JSON-RPC frames per the
WebExtensions spec, and the `unwrap_stanza` method routes through the existing
`commands::build_identity_list` to dispatch to enrolled identities. Hardware tap is
**stubbed pending hardware test**: a desktop notification (`notify-rust`) is shown before
the unwrap; mock-mode identities answer in-process, while the real PIV/FIDO2 paths still
go through the §3a-3b stubs documented in `src/piv.rs` and `src/fido.rs`.

---

## 7. Output / delivery primitives

```rust
// src/output.rs (sketch)
pub enum Destination {
    Stdout,
    Clipboard { clear_after: Duration },
    Agent,                                // ssh-agent
    Exec { argv: Vec<String>, via_env: bool },
    Reveal,                               // print to terminal until ENTER
    Fill { window: WindowSpec },          // autotype
    NativeHostFileKey,                    // returned to browser; no plaintext
}

pub fn deliver(plaintext: Zeroizing<Vec<u8>>, dest: Destination) -> Result<(), Error>;
```

Each destination variant takes ownership of the plaintext, delivers, then drops (zeroize on
drop).

"No path leaves a plaintext value reachable after `deliver` returns" is true of the buffers
rageterm owns, and false of one it hands away: the `Clipboard` variant transfers the string
to `arboard`, which keeps its own non-zeroizing copy in the clipboard-owner thread until the
selection is replaced. `Agent` encodes into a `Zeroizing<Vec<u8>>` pre-sized to 8 KiB so the
buffer cannot reallocate mid-encode and strand an unwiped block (`ssh-key`'s own
`Ed25519PrivateKey` / `RsaPrivateKey` / `EcdsaPrivateKey` already zeroize on drop, so the
parsed `PrivateKey` was never the leak). `Fill` writes to the backend's stdin and never to
argv. See `../SECURITY.md` "Known gaps" for the full list.

---

## 8. Build & distribution

- `cargo build --release` produces a single binary per target.
- Cross-compilation matrix in CI (GitHub Actions). macOS universal via `lipo`.
- Code-signed on macOS (Apple Developer ID) and Windows (Authenticode); reproducible
  builds across all platforms.
- Homebrew tap auto-updated on tag push.
- `cargo install rageterm` works as a fallback (compiles from source; PCSC headers
  required, documented).
- Static linking where possible; ctap-hid-fido2 (pure-Rust CTAP2) and pcsc-lite are dynamic on Linux (linked at
  runtime, fail with a clear error if missing).

---

## 9. Open terminal-specific questions

1. **Daemon vs one-shot.** Some operations (clipboard auto-clear, ssh-agent integration)
   want a persistent process. `rageterm` is one-shot today, with detached background timers
   for clipboard. **Default: one-shot, fork-detach for clipboard**. Optional `rageterm
   daemon` mode for users who want a single long-running process.

2. **Pinentry / PIN UX.** YubiKey PIV PIN entry: terminal prompt (`rpassword`) is fine for
   CLI; TUI mode needs an in-screen modal. **Default: terminal prompt for CLI, TUI modal for
   `--tui`**. Pinentry-style external prompt deferred.

3. **Concurrent invocations.** Two `rageterm` processes calling YubiKey simultaneously will
   error from the smart-card layer. **Default: file lock at `$XDG_RUNTIME_DIR/ragewarden.lock`**
   serializing hardware access. Wait or fail-fast configurable.

4. **Vault cache.** Encrypted local cache (sqlite + sqlcipher, master-password-derived key) so
   `list` and metadata reads don't require a network round-trip every time. Sync in background
   on `login` and explicitly via `sync`. **Default: yes, encrypted SQLite cache at
   `~/.config/ragewarden/cache.db`.**

5. **Hostility detection.** Detect being run inside `tmux` / `screen` / over SSH and warn
   that `reveal` may write to scrollback. **Default: warn on TTY-share heuristics**;
   `--force` to override.
