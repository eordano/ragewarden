# RageManifest -- browser extension

Browser extension for the [Ragewarden](../DESIGN.md) ecosystem. See
[`DESIGN.md`](DESIGN.md) for the browser-specific design.

> **Status.** Chromium MV3 + Firefox MV3 builds at parity, both using the
> [`ragewarden/design/`](../design) folder as the popup UI directly, wired to
> the Rust -> WASM core for actual encrypt/decrypt and to a real WebAuthn-PRF
> ceremony per reveal/copy/autofill (DESIGN.md §3a). Safari remains post-MVP
> (host-app shell at `safari-host-app/`).

---

## Architecture

Three layers, kept strictly separate:

```
ragewarden/design/                    canonical UI source -- read-only
   |  (copied at build time)
   v
ragemanifest/dist/<browser>/popup/    UI bundle (.jsx pre-compiled to .js)
       ^                  ^
       | imports          | imports
       |                  |
ragemanifest/ext/glue/    ragemanifest/dist/<browser>/wasm/
   crypto.js                  ragemanifest.js (wasm-pack output)
   vault.js                   ragemanifest_bg.wasm
   init.js
       ^
       | thin bridge
       v
ragemanifest/src/lib.rs               Rust crate, wasm-bindgen exports
       |
       v
ragewarden/core/                      shared crypto core (age, recipients)
```

The design folder stays the canonical UI source. We re-import it at build
time; we do not modify it. WASM does the crypto. Glue is a ~250-line bridge
between the two.

### Layout choice: A (copy-at-build)

`build.mjs` copies `../design/` into `dist/<browser>/popup/` at build time
and pre-compiles every `.jsx` to `.js` (MV3 forbids `'unsafe-eval'`, so we
can't ship Babel-standalone and run JSX at runtime). The `<script>` tags in
`RageDroid.html` are rewritten to point at the compiled files and at
locally-vendored React UMDs.

We considered Layout B (symlinking `ext/popup/` -> `../../design/`) but
rejected it because:

- `wasm-pack`'s output and the JSX -> JS pre-compilation step both write
  into the popup directory; mixing those with a symlink to the canonical
  source risks accidental writes back into `design/`.
- Cross-platform packaging (Windows zips, Safari host-app builds) is
  fiddly with symlinks.
- The copy step is fast (~50 ms) and watch mode keeps it reactive.

### React vs Preact: bundle React

We ship React + ReactDOM (production UMD builds, ~140 KB combined gzipped)
vendored under `popup/vendor/`. No CDN at runtime -- required for MV3 CSP
`script-src 'self' 'wasm-unsafe-eval'`.

A future Preact swap (~3 KB, with `preact/compat` aliasing for the design's
`React.useState` etc. usage) is documented as a bundle-size win for v2.
The design's JSX is shallow enough that it should work with Preact's compat
layer; we ship React in v1 for fastest delivery.

---

## Layout

```
ragemanifest/
+-- Cargo.toml                # WASM crate manifest (cdylib + rlib)
+-- src/lib.rs                # wasm-bindgen exports over ragewarden-core
+-- ext/                      # Browser extension shell
|   +-- manifest.json         # Chromium MV3 base manifest
|   +-- manifests/
|   |   +-- firefox.json      # Firefox MV3 overlay (event-page background, gecko.id)
|   |   +-- safari.json       # Safari MV3 overlay (post-MVP)
|   +-- background.js         # MV3 service worker (Chromium) / event page (Firefox)
|   +-- content.js            # autofill content script (chip + prompt sheet)
|   +-- glue/                 # Bridge between design UI and WASM crypto
|       +-- crypto.js         # init(), softwareKeygen(), encrypt(), decrypt()
|       +-- vault.js          # session-aware popup state, per-action ceremony hook
|       +-- storage.js        # AES-GCM-wrapped session envelope
|       +-- onboarding.js     # sign-in + protection wizard overlays
|       +-- passkey.js        # WebAuthn-PRF enrol / unlock
|       +-- passkey-store.js  # local copy of enrolled passkey-PRF recipient
|       +-- prf-detect.js     # capability detection for the popup
|       +-- tap-counters.js   # test-only per-use counters for §0b
|       +-- native-host.js    # rageterm --native-host bridge (Chromium / Firefox)
|       +-- init.js           # popup-load entry; exposes window.RagewardenVault
+-- build.mjs                 # esbuild orchestrator -> dist/<target>/
+-- package.json              # npm scripts
+-- tsconfig.json
```

`ext/wasm/` is a build artifact (regenerated from `pkg/` by `wasm-pack`),
gitignored. `dist/` is gitignored.

---

## Build

You need:

- A working Rust toolchain (workspace pins `rust-toolchain.toml`).
- `wasm-pack` >= 0.13: <https://rustwasm.github.io/wasm-pack/installer/>
  (see "WASM build status on this nix-darwin" below for current
  status / fallback).
- Node.js >= 20.

### 1. Verify the Rust crate builds for the host target

```sh
cargo build -p ragemanifest
cargo test -p ragemanifest
```

This builds without WASM -- the `wasm-bindgen` exports are gated behind
`#[cfg(target_arch = "wasm32")]` so the workspace stays green on Linux/macOS
without extra toolchain.

### 2. Compile to WASM

```sh
cd ragemanifest
npm install                      # one-time: pulls esbuild, react, react-dom
npm run build:wasm               # invokes wasm-pack
```

Output: `ragemanifest/pkg/{ragemanifest.js,ragemanifest_bg.wasm}`.

### 3. Bundle the extension

```sh
npm run build:chromium           # produces dist/chromium/
```

This runs `node build.mjs chromium`, which:

1. Stages `pkg/` into `ext/wasm/` and into `dist/chromium/wasm/`.
2. Copies `../design/` -> `dist/chromium/popup/`.
3. Pre-compiles every `.jsx` in popup/ -> `.js` via esbuild (JSX classic
   runtime, `React.createElement` factory).
4. Patches `dist/chromium/popup/RageDroid.html`:
   - Rewrites the React + ReactDOM CDN URLs -> `vendor/*` local paths.
   - Strips the Babel-standalone `<script>` tag (no longer needed).
   - Rewrites `<script type="text/babel" src="*.jsx">` -> `<script src="*.js">`.
   - Compiles the inline `<script type="text/babel">` block (the App
     component + render) to plain JS.
   - Appends `<script type="module" src="../glue/init.js">`.
5. Vendors React + ReactDOM UMDs from `node_modules` -> `popup/vendor/`.
6. Copies `ext/glue/` -> `dist/chromium/glue/`.
7. Emits `dist/chromium/manifest.json` (popup repointed at
   `popup/RageDroid.html`).

### 4. Watch mode

```sh
npm run dev:chromium
```

Watches `../design/`, `ext/glue/`, and `ext/manifest.json` for changes and
rebuilds. Reload the extension in `chrome://extensions` to see changes.

---

## Loading the extension into Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked**.
4. Select `ragemanifest/dist/chromium/`.
5. Pin the toolbar button if you want easy access.

The popup loads the design's UI directly. A small status badge bottom-left
confirms WASM bridge readiness ("wasm ok · N items round-tripped"). Open
DevTools on the popup to inspect `window.RagewardenVault` -- calling
`RagewardenVault.revealPassword('github')` from the console will perform a
real WASM decrypt round-trip.

## Loading the extension into Firefox

Firefox MV3 is supported as a first-class target alongside Chromium. The
Firefox build differs in three load-bearing places -- `build.mjs` reconciles
all of them when you run `npm run build:firefox`:

- The background script runs as an event page, not a service worker
  (`background.scripts: ["background.js"]`, no `"type": "module"`).
- A stable `browser_specific_settings.gecko.id` is declared
  (`ragewarden@ragewarden`) with `strict_min_version: 132.0` (PRF requirement).
- `nativeMessaging` is dropped from `permissions` for now (cross-frontend PIV
  is out of scope this round).

**Build:**

```sh
cd ragemanifest
npm install
npm run build:wasm        # one-time per code change to the Rust crate
npm run build:firefox     # produces dist/firefox/
```

**Load via about:debugging (preferred for dev):**

1. Open Firefox 132 or newer.
2. Navigate to `about:debugging#/runtime/this-firefox`.
3. Click **Load Temporary Add-on...**
4. Select `ragemanifest/dist/firefox/manifest.json`.
5. The extension appears with **Inspect** buttons for the popup, content
   scripts, and the background event page.

**Load via `web-ext run` (preferred for fast iteration):**

```sh
cd ragemanifest
npx web-ext run --source-dir dist/firefox
```

Mozilla's `web-ext` tool launches a fresh Firefox profile with the extension
already installed. Add `--devtools` to auto-open the addon's DevTools, or
`--start-url moz-extension://<uuid>/popup/RageDroid.html` to land directly on
the popup (the extension's internal UUID prints in the `web-ext run` log).

**Smoke test:**

```sh
node tests/smoke-firefox.mjs              # static + lint + Chromium-proxy popup load
node tests/smoke-firefox.mjs --firefox    # additionally launch real Firefox (headed)
node tests/smoke-firefox.mjs --static-only  # CI mode (manifest + lint only)
```

The default mode validates the manifest, runs `web-ext lint --self-hosted`,
and loads the popup in a headless Chromium served from `dist/firefox/`. The
popup is browser-agnostic JS+WASM, so a Chromium proxy load is a strong CI
signal that Firefox will mount it. The `--firefox` flag adds a real (headed)
Firefox launch via `web-ext run` for human verification.

The CDP virtual authenticator with `hasPrf: true` that powers the Tier-2
Chromium spec is not available on Firefox; passkey ceremonies remain a
release-gate manual check -- see
[`tests/manual/firefox-checklist.md`](tests/manual/firefox-checklist.md) and
[`DESIGN.md`](DESIGN.md#6a-test-plan) §6a.

## Testing in a regular browser (no extension)

Because the extension's popup is the design folder unchanged, you can test
it without installing the extension at all:

```sh
cd ragemanifest/dist/chromium
python3 -m http.server
# then visit http://localhost:8000/popup/RageDroid.html
```

This is the fastest dev loop for design iteration. The crypto round-trip
runs the same way it does inside the extension.

---

## How the glue bridges design <-> WASM

The popup's reveal/copy/autofill UX is implemented entirely inside
`design/screens-vault.jsx` (the `InlineTapReveal` ceremony, the
`completeAction` handler that writes to clipboard, etc.). The principle is
**action-chosen-before-tap**: the user picks Reveal/Copy/Autofill *before*
the passkey tap, so the prompt names the exact action and destination.

What the glue does:

1. **At popup load**, `init.js` boots WASM, runs `vault.bootstrap()`, and
   exposes `window.RagewardenVault`.
2. **`vault.bootstrap()`** loads any persisted session envelope (AES-GCM
   wrapped under a `chrome.storage.session` key, see DESIGN.md §2a). On a
   fresh sign-in it routes the user through `onboarding.js`
   (server URL + email + password) and the protection wizard
   (`navigator.credentials.create` with the PRF extension), then calls
   `wasm_fetch_vault` for the first cipher list snapshot.
3. **Every reveal/copy/autofill** runs `unlockOnce(itemId, ctx)` --
   one fresh `navigator.credentials.get` per use (§0b), one
   `wasm_decrypt_cipher_field` per use, plaintext only owned by the
   resolving promise scope (§0c). The same call shape powers the
   content-script autofill chip via the background service worker.
4. **`window.RagewardenVault`** exposes:
   - `revealPassword(itemId, fieldName='password')` -- runs the ceremony,
     returns plaintext as a string.
   - `autofillPassword(itemId, destination?)` -- same shape; the caller is
     responsible for delivering the bytes to the autofill consumer.
   - `copyPassword(itemId)` -- same shape; clipboard writes happen in the
     design layer's `completeAction` handler.
   - `logout()` -- drops the in-memory session, clears the persisted
     envelope.
   - `status()` -- `{ wasmReady, signedIn, ciphers, email }`.

---

## WASM toolchain (nix dev shell)

The repo ships a `flake.nix` that pins `wasm-pack`, `wasm-bindgen-cli`,
`binaryen` (`wasm-opt`), and `nodejs_20` so the WASM build works on any
machine with Nix + flakes enabled -- including nix-darwin where
`rust-lld` isn't on the global PATH.

```sh
cd ragemanifest
nix develop                       # drops you into a shell with the toolchain
wasm-pack build --target web --out-dir pkg .
node build.mjs chromium           # or firefox / safari
```

Or one-shot:

```sh
nix develop --command bash -c 'wasm-pack build --target web --out-dir pkg .'
```

Without Nix, install `wasm-pack` (`cargo install wasm-pack`, the
upstream installer script, or your distro's package) and a working
`rust-lld`/clang linker. `pkg/` and `dist/` are gitignored.

Verification proxy without WASM build:

```sh
cargo build -p ragemanifest    # host target -- passes
cargo test -p ragemanifest     # smoke test -- passes
node tests/smoke-firefox.mjs   # validates the prebuilt pkg/ end-to-end
```

---

## What's next

The following are open follow-ups documented in [`DESIGN.md`](DESIGN.md):

1. **Safari host-app + Mac App Store submission.** Skeleton lives at
   `safari-host-app/`; full packaging is post-MVP (DESIGN.md §6).
2. **Side panel on Chromium.** Better than the popup since it persists past
   focus changes (DESIGN.md §8).
3. **Preact swap** (~140 KB -> ~3 KB bundle) (DESIGN.md §2a).
4. **Multi-passkey ciphers in `wasm_decrypt_with_passkey`.** Today's contract
   threads one PRF callback per call; multi-passkey ciphers will need an
   enriched callback shape (DESIGN.md §3a).

---

## Tests

Phase-1 host-target unit tests:

```sh
cargo test -p ragemanifest
```

The smoke test verifies workspace linkage. Phase 2 will add `wasm-bindgen-test` integration tests run via `wasm-pack test --headless --chrome`.

### Tier-2 (Playwright) without Docker

The Playwright harness under `tests/playwright/` needs a real Vaultwarden
instance -- the specs sign up a fresh user and exercise crypto round-trips
against the API, so a stub server isn't enough. CI brings one up via Docker;
locally `tests/playwright/global-setup.ts` does the same when `docker` is on
`PATH`.

When `docker` is missing, `global-setup.ts` walks the following list and uses
the first one that applies:

| Mechanism | How to opt in | Notes |
|-----------|---------------|-------|
| Pre-running Vaultwarden | `VAULTWARDEN_URL=http://...` | Highest priority; bypasses all spawning. Use this if you run Vaultwarden under colima/podman/orbstack/native and want full control. |
| Container runtime override | `RAGEWARDEN_CONTAINER_RUNTIME=podman` (or `docker`) | Forces a specific runtime even if the other one is also on PATH. |
| Auto-fallback to podman | (automatic if `docker` missing and `podman` present) | Same `pull` / `run --publish 0:80` / `port` flow as docker. |
| Cargo-built native binary | `RAGEWARDEN_USE_CARGO_VAULTWARDEN=1` | Builds Vaultwarden 1.32.7 from source via `cargo install --git ... --tag 1.32.7 --root tests/playwright/.vaultwarden-cache vaultwarden`. First run is slow (5-10 min); the resulting binary is cached at `tests/playwright/.vaultwarden-cache/bin/vaultwarden` and reused. |

Caveat: Vaultwarden does not publish prebuilt native binaries -- the only
official artifacts at v1.32.7 are Docker images and the source tarball, and
the `vaultwarden` crate on crates.io is a 2021 placeholder stub. There is no
"download a static darwin binary" path; the cargo route compiles from
upstream's git tag.

#### Example: drive Tier-2 against a Vaultwarden you started yourself

```sh
# 1. Run Vaultwarden however you like -- colima + docker, podman, or native.
#    The four LOGIN_/ADMIN_RATELIMIT_* envs relax Vaultwarden's per-IP login
#    limiter (default 10 / 60 s) -- without them, back-to-back register-flow
#    tests silently 429-fail. TEST-ONLY relaxation; never apply to a
#    production Vaultwarden:
podman run -d --rm --name vw \
  -p 127.0.0.1:8080:80 \
  -e SIGNUPS_ALLOWED=true \
  -e WEB_VAULT_ENABLED=false \
  -e ROCKET_PORT=80 \
  -e DOMAIN=http://localhost \
  -e LOGIN_RATELIMIT_MAX_BURST=1000 \
  -e LOGIN_RATELIMIT_SECONDS=1 \
  -e ADMIN_RATELIMIT_MAX_BURST=1000 \
  -e ADMIN_RATELIMIT_SECONDS=1 \
  vaultwarden/server:1.32.7

# 2. Point the harness at it and run tests:
cd ragemanifest/tests/playwright
VAULTWARDEN_URL=http://127.0.0.1:8080 npm test
```

You'll see `[global-setup] using pre-running Vaultwarden at ... (VAULTWARDEN_URL set)`
in the output, confirming the Docker path was bypassed. Teardown is a no-op
in env-url mode -- the server you started keeps running.

#### Example: cargo-built native binary

```sh
cd ragemanifest/tests/playwright
RAGEWARDEN_USE_CARGO_VAULTWARDEN=1 npm test
# first run: ~5-10 min cargo build, then `[global-setup] spawning native Vaultwarden on http://127.0.0.1:<port>`
# subsequent runs: ~5 sec -- cached binary is reused, fresh data dir per run.
```

The spawned process is tracked in `tests/playwright/.playwright-state.json`
and SIGTERM'd in `globalTeardown`. Its stdout+stderr stream to
`tests/playwright/.vaultwarden-cache/vaultwarden.log` (tailed automatically
on health-check failure).

#### Other env vars

- `RAGEWARDEN_SKIP_PULL=1` -- skip `docker pull` (handy on slow links if the
  image is already cached).
- `LOG_LEVEL=info` -- passed through to native Vaultwarden; defaults to `warn`
  to keep test output quiet.
