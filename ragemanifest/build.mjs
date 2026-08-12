#!/usr/bin/env node

import {
    cpSync,
    existsSync,
    mkdirSync,
    readdirSync,
    readFileSync,
    rmSync,
    statSync,
    watch,
    writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = __dirname;

const args = process.argv.slice(2);
const TARGET = args[0] ?? 'chromium';
const WATCH = args.includes('--watch');
const ZIP = args.includes('--zip');
const RUN_WASM_PACK = args.includes('--with-wasm');

/*
 * VM mode: one flag for "run the whole product in a box with no hardware".
 *
 * It is the composition the mock backend was always missing a caller for --
 * mock taps forced on (a VM has no authenticator to prefer), test hooks on, and
 * a loopback server baked in so onboarding does not need a human to type one.
 * It implies --allow-mock-tap, so it inherits that flag's env-var interlock and
 * its --zip refusal; there is no path to a distributable VM build.
 */
const VM_MODE = args.includes('--vm') || args.includes('--fake');
const ALLOW_MOCK_TAP = args.includes('--allow-mock-tap') || VM_MODE;
const FORCE_MOCK_TAP = args.includes('--force-mock-tap') || VM_MODE;
const TEST_HOOKS = args.includes('--test-hooks') || VM_MODE;

const VM_SERVER_URL = process.env.RAGEWARDEN_VM_SERVER_URL || 'http://127.0.0.1:8222';

if (VM_MODE) {
    let host;
    try {
        host = new URL(VM_SERVER_URL).hostname.toLowerCase();
    } catch {
        console.error(`--vm: RAGEWARDEN_VM_SERVER_URL is not a URL: ${VM_SERVER_URL}`);
        process.exit(1);
    }
    /*
     * Loopback is a speed bump, not a security property -- say so.
     *
     * This check used to be justified by "vault.js refuses to publish a stand-in
     * recipient to anything but loopback". That exemption is gone: a mock build
     * now publishes nothing at all, because `is_secure_url` (core/src/sync.rs)
     * deliberately treats `http://` to loopback as a *real* server and an
     * SSH-tunnelled Vaultwarden at 127.0.0.1 is the same database every other
     * client reaches.
     *
     * What survives is the weaker, still-worth-having claim: a VM build wraps
     * every item it writes to a stand-in key derived from constants in this
     * repository, so anything it saves is readable by anyone holding this
     * source. Pointing one at a URL somebody typed on purpose is the obvious way
     * to get that into a vault that matters, and the default is loopback, so
     * refusing anything else costs nothing. It does not make loopback safe.
     */
    if (!['localhost', '127.0.0.1', '[::1]', '::1'].includes(host)) {
        console.error(
            `--vm: RAGEWARDEN_VM_SERVER_URL must be a loopback server, got ${host}.\n`
            + 'A VM build wraps everything it writes to a stand-in key derived from\n'
            + 'constants in this repository; do not aim it at a vault you care about.',
        );
        process.exit(1);
    }
}

if (ALLOW_MOCK_TAP && process.env.RAGEWARDEN_UNSAFE_MOCK_TAP !== '1') {
    console.error(
        '--allow-mock-tap ships a build that can fabricate hardware taps.\n'
        + 'It is refused unless you also set RAGEWARDEN_UNSAFE_MOCK_TAP=1 in the environment.',
    );
    process.exit(1);
}
if (FORCE_MOCK_TAP && !ALLOW_MOCK_TAP) {
    console.error('--force-mock-tap requires --allow-mock-tap');
    process.exit(1);
}
if (ZIP && (ALLOW_MOCK_TAP || TEST_HOOKS)) {
    console.error(
        '--zip produces a distributable artifact and is refused together with '
        + '--allow-mock-tap / --test-hooks.',
    );
    process.exit(1);
}

const BUILD_FLAGS = Object.freeze({
    profile: (ALLOW_MOCK_TAP || TEST_HOOKS) ? 'development' : 'release',
    allowMockTap: ALLOW_MOCK_TAP,
    forceMockTap: FORCE_MOCK_TAP,
    testHooks: TEST_HOOKS,
    vmMode: VM_MODE,
    vmServerUrl: VM_MODE ? VM_SERVER_URL : null,
});

if (!['chromium', 'firefox', 'safari'].includes(TARGET)) {
    console.error(`unknown target: ${TARGET}`);
    process.exit(1);
}

const PKG_DIR = join(ROOT, 'pkg');
const EXT_DIR = join(ROOT, 'ext');
const GLUE_DIR = join(EXT_DIR, 'glue');
const POPUP_DIR = join(EXT_DIR, 'popup');
const WASM_STAGING = join(EXT_DIR, 'wasm');
const DESIGN_DIR = resolve(ROOT, '..', 'design');
const DIST_DIR = join(ROOT, 'dist', TARGET);
const DIST_POPUP = join(DIST_DIR, 'popup');
const DIST_GLUE = join(DIST_DIR, 'glue');
const DIST_WASM = join(DIST_DIR, 'wasm');

function logStep(msg) {
    console.log(`[build] ${msg}`);
}
function logWarn(msg) {
    console.warn(`[build] WARN ${msg}`);
}

function stageWasm() {
    if (!existsSync(PKG_DIR)) {
        logWarn(
            `${relative(ROOT, PKG_DIR)} missing -- run \`wasm-pack build --target web .\` first.`,
        );
        logWarn('Building extension without WASM. Popup will display an error badge.');
        return false;
    }
    rmSync(WASM_STAGING, { recursive: true, force: true });
    mkdirSync(WASM_STAGING, { recursive: true });
    let any = false;
    for (const file of [
        'ragemanifest.js',
        'ragemanifest_bg.wasm',
        'ragemanifest.d.ts',
        'ragemanifest_bg.wasm.d.ts',
        'package.json',
    ]) {
        const src = join(PKG_DIR, file);
        if (existsSync(src)) {
            cpSync(src, join(WASM_STAGING, file));
            any = true;
        }
    }
    if (!any) {
        logWarn('pkg/ exists but no expected files found');
        return false;
    }
    logStep(`staged WASM into ${relative(ROOT, WASM_STAGING)}`);
    return true;
}

/**
 * Stage the popup.
 *
 * This used to copy `design/` wholesale into `dist/<target>/popup` and then
 * Babel/esbuild the prototype's JSX into the shipped extension. `design/` is a
 * mockup: its ToastHost renders nothing, its lock screen accepts any password,
 * and `screens-extras.jsx` prints the *constant* word list from `data.jsx` on
 * the paper-recovery screen while the real generated phrase goes to
 * `console.warn` -- a user who wrote down what the popup showed lost their
 * vault. None of that belongs in a shipped product.
 *
 * The popup now lives in `ext/popup/` as plain ES modules against the real
 * `ext/glue/` bridge. `design/` contributes exactly two things: the design
 * tokens (`colors_and_type.css` -> `tokens.css`) and the webfonts. Nothing
 * executable from `design/` reaches `dist/`, and `assertDistIsSane()` fails the
 * build if it ever does again.
 */
function copyPopup() {
    if (!existsSync(POPUP_DIR)) {
        throw new Error(`popup source missing: ${POPUP_DIR}`);
    }
    rmSync(DIST_POPUP, { recursive: true, force: true });
    mkdirSync(DIST_POPUP, { recursive: true });
    cpSync(POPUP_DIR, DIST_POPUP, { recursive: true });

    const entry = join(DIST_POPUP, 'RageDroid.html');
    if (!existsSync(entry)) {
        throw new Error(
            'ext/popup/RageDroid.html is missing -- every manifest target points the browser '
            + 'at popup/RageDroid.html',
        );
    }
    const html = readFileSync(entry, 'utf8');
    if (!html.includes('../glue/init.js')) {
        throw new Error(
            'popup/RageDroid.html does not load ../glue/init.js -- without it the popup '
            + 'renders with no vault bridge at all',
        );
    }

    const tokens = join(DESIGN_DIR, 'colors_and_type.css');
    if (!existsSync(tokens)) {
        throw new Error(`design tokens missing: ${tokens}`);
    }
    cpSync(tokens, join(DIST_POPUP, 'tokens.css'));
    const fonts = join(DESIGN_DIR, 'fonts');
    if (existsSync(fonts)) {
        cpSync(fonts, join(DIST_POPUP, 'fonts'), { recursive: true });
    } else {
        logWarn('design/fonts/ missing -- the popup will fall back to system serif');
    }
    logStep(`staged ext/popup -> ${relative(ROOT, DIST_POPUP)} (+ design tokens & fonts)`);
}

const FLAG_BANNER = `// GENERATED by build.mjs -- do not edit in dist/.
// profile=${BUILD_FLAGS.profile} allowMockTap=${BUILD_FLAGS.allowMockTap} `
    + `forceMockTap=${BUILD_FLAGS.forceMockTap} testHooks=${BUILD_FLAGS.testHooks} `
    + `vmMode=${BUILD_FLAGS.vmMode}\n`;

function emitGlueBuildFlags() {
    const body = FLAG_BANNER
        + `const DEFAULTS = Object.freeze(${JSON.stringify(BUILD_FLAGS)});\n`
        + 'export const BUILD_FLAGS = DEFAULTS;\n'
        + 'export function buildProfile() { return BUILD_FLAGS.profile; }\n'
        + 'export function mockTapAllowed() { return BUILD_FLAGS.allowMockTap === true; }\n'
        + 'export function testHooksEnabled() { return BUILD_FLAGS.testHooks === true; }\n'
        + 'export function vmModeEnabled() { return BUILD_FLAGS.vmMode === true; }\n'
        + 'export function vmServerUrl() { return BUILD_FLAGS.vmServerUrl || null; }\n'
        + 'export function assertReleaseSafe() {\n'
        + "    if (BUILD_FLAGS.profile === 'release'\n"
        + '        && (BUILD_FLAGS.allowMockTap || BUILD_FLAGS.forceMockTap\n'
        + '            || BUILD_FLAGS.testHooks || BUILD_FLAGS.vmMode)) {\n'
        + "        throw new Error('build-flags.js: release profile must not enable "
        + "allowMockTap/forceMockTap/testHooks/vmMode');\n"
        + '    }\n'
        + '    if (BUILD_FLAGS.vmMode && !BUILD_FLAGS.allowMockTap) {\n'
        + "        throw new Error('build-flags.js: vmMode without allowMockTap is incoherent');\n"
        + '    }\n'
        + '}\n';
    writeFileSync(join(DIST_GLUE, 'build-flags.js'), body);
    logStep(`emitted glue/build-flags.js (${BUILD_FLAGS.profile})`);
}

const MOCK_BACKEND_FILE = 'mock-hardware-tap.js';

/**
 * The mock backend's exports, checked by importing the emitted module.
 *
 * Checking only that the *directory* exists was not enough: an empty
 * `dev-only/` satisfied `existsSync`, so the build reported success and
 * announced the mock was bundled, and the failure surfaced as a dynamic-import
 * error the first time a user pressed Reveal.
 *
 * Checking the *text* for `export function <name>` was not enough either -- a
 * commented-out export satisfies the regex, so exactly the edit most likely to
 * remove a ceremony by accident is the one it waves through. The build now
 * imports what it just wrote into dist/ and asks the module object, which is
 * the same question `hardware-tap.js` asks at the first tap: does calling this
 * binding work? A commented-out or renamed export is `undefined` here. Naming
 * the exports at all is what makes adding a ceremony to hardware-tap.js without
 * adding its stand-in a build failure rather than a runtime one.
 *
 * Importing is safe: this is our own file, its module scope only defines
 * constants and re-asserts the `mockTapAllowed()` fence, and we only reach this
 * branch in a build that has already declared itself unsafe. It resolves its
 * `../build-flags.js` against the *dist* copy `emitGlueBuildFlags()` wrote a
 * moment ago, so the fence sees the real flags of this build.
 */
const MOCK_BACKEND_EXPORTS = ['mockPrfTap', 'mockPresenceTap', 'mockEnroll'];

async function stripDevOnlyGlue() {
    const devOnly = join(DIST_GLUE, 'dev-only');
    if (BUILD_FLAGS.allowMockTap) {
        const backend = join(devOnly, MOCK_BACKEND_FILE);
        if (!existsSync(backend)) {
            throw new Error(
                `allowMockTap is set but glue/dev-only/${MOCK_BACKEND_FILE} is missing -- `
                + 'the mock backend would fail to load at the first tap',
            );
        }
        // --watch rebuilds into the same paths, and Node's ESM cache is keyed on
        // URL: without the query the second build would re-answer from the first
        // build's module, i.e. stop checking exactly when someone is editing.
        const url = `${pathToFileURL(backend).href}?build=${Date.now()}`;
        let mod;
        try {
            mod = await import(url);
        } catch (e) {
            throw new Error(
                `glue/dev-only/${MOCK_BACKEND_FILE} does not load: ${(e && e.message) || e} -- `
                + 'hardware-tap.js would hit the same failure at the first tap',
            );
        }
        const missing = MOCK_BACKEND_EXPORTS.filter(name => typeof mod[name] !== 'function');
        if (missing.length > 0) {
            throw new Error(
                `glue/dev-only/${MOCK_BACKEND_FILE} exports no callable ${missing.join(', ')} -- `
                + 'hardware-tap.js would throw at the ceremony that needs it',
            );
        }
        logWarn('*** MOCK HARDWARE TAP BACKEND IS BUNDLED -- THIS BUILD IS NOT SAFE ***');
        return;
    }
    rmSync(devOnly, { recursive: true, force: true });
    if (existsSync(devOnly)) {
        throw new Error(`failed to strip ${relative(ROOT, devOnly)} from a release build`);
    }
    logStep('stripped glue/dev-only/ (release build: no mock tap backend)');
}

async function copyGlue() {
    rmSync(DIST_GLUE, { recursive: true, force: true });
    mkdirSync(DIST_GLUE, { recursive: true });
    cpSync(GLUE_DIR, DIST_GLUE, { recursive: true });
    emitGlueBuildFlags();
    await stripDevOnlyGlue();
    logStep(`copied ext/glue -> ${relative(ROOT, DIST_GLUE)}`);
}

function copyWasm() {
    if (!existsSync(WASM_STAGING) || !statSync(WASM_STAGING).isDirectory()) {
        return;
    }
    rmSync(DIST_WASM, { recursive: true, force: true });
    mkdirSync(DIST_WASM, { recursive: true });
    cpSync(WASM_STAGING, DIST_WASM, { recursive: true });
    logStep(`copied wasm -> ${relative(ROOT, DIST_WASM)}`);
}

function emitManifest() {
    const baseManifest = JSON.parse(
        readFileSync(join(EXT_DIR, 'manifest.json'), 'utf8'),
    );
    baseManifest.action = baseManifest.action ?? {};
    baseManifest.action.default_popup = 'popup/RageDroid.html';

    // Chromium uses the normal action popup (default_popup, set above). WebAuthn
    // runs inline in a popup, so hardware taps happen in place with no separate
    // tap window. The side panel was tried but navigator.credentials does not run
    // reliably there (create()/get() hang), which is why this is a popup.

    if (TARGET === 'firefox') {
        const ff = JSON.parse(stripJsonComments(
            readFileSync(join(EXT_DIR, 'manifests', 'firefox.json'), 'utf8'),
        ));
        delete baseManifest.background;
        delete baseManifest.minimum_chrome_version;
        /*
         * `nativeMessaging` is DELIBERATELY KEPT for firefox.
         *
         * It used to be filtered out here, with no comment, since the original
         * vendoring commit. There is no platform reason for that: Firefox has
         * supported nativeMessaging since 50, in MV2 and MV3 alike, and
         * rageterm already serves this browser specifically --
         * install_native_host.rs models Browser::Firefox with its own
         * FirefoxManifest (Firefox keys on `allowed_extensions`, Chromium on
         * `allowed_origins`), per-OS install paths, and
         * DEFAULT_FIREFOX_EXTENSION_ID = "ragewarden@ragewarden", which is
         * byte-identical to the gecko id asserted a few lines below.
         *
         * The strip looks like it was justified by the fact that nothing dials
         * the host -- ext/glue/native-host.js has no importer -- but that made it
         * circular: the permission was removed because it was unused, and then
         * it could never be used. Wiring the bridge would have fixed Chromium
         * and silently done nothing here, because the port cannot be opened
         * without this permission, and that failure surfaces only to whoever
         * wonders why their YubiKey works in one browser and not the other.
         *
         * Safari still strips it below, where the argument is different: that
         * target emits only a manifest and an extension shell, and the host app
         * needs Xcode.
         */
        Object.assign(baseManifest, ff);
        baseManifest.action = baseManifest.action ?? {};
        baseManifest.action.default_popup = 'popup/RageDroid.html';
        const bg = baseManifest.background || {};
        if (!Array.isArray(bg.scripts) || bg.scripts.length === 0) {
            throw new Error(
                'firefox manifest must declare background.scripts (event-page model)',
            );
        }
        if (bg.service_worker || bg.type === 'module') {
            throw new Error(
                'firefox manifest must not retain background.service_worker or "type":"module"',
            );
        }
        const gecko = baseManifest.browser_specific_settings?.gecko;
        if (!gecko || !gecko.id || !gecko.strict_min_version) {
            throw new Error(
                'firefox manifest must declare browser_specific_settings.gecko.{id,strict_min_version}',
            );
        }
    } else if (TARGET === 'safari') {
        const sf = JSON.parse(stripJsonComments(
            readFileSync(join(EXT_DIR, 'manifests', 'safari.json'), 'utf8'),
        ));
        if (Array.isArray(baseManifest.permissions)) {
            baseManifest.permissions = baseManifest.permissions.filter(p => p !== 'nativeMessaging');
        }
        delete baseManifest.minimum_chrome_version;
        Object.assign(baseManifest, sf);
        baseManifest.action = baseManifest.action ?? {};
        baseManifest.action.default_popup = 'popup/RageDroid.html';
        logWarn(
            'safari target produces only the manifest + extension shell -- host app lives in safari-host-app/.',
        );
    }

    if (BUILD_FLAGS.allowMockTap) {
        baseManifest.name = BUILD_FLAGS.vmMode
            ? 'Ragewarden (VM MODE -- NOT SECURE)'
            : 'Ragewarden (MOCK TAP -- NOT SECURE)';
        baseManifest.short_name = 'Ragewarden MOCK';
        baseManifest.description =
            'DEVELOPMENT BUILD. This build can fabricate hardware taps in software. '
            + 'Do not use it with real secrets. ' + (baseManifest.description || '');
    } else if (BUILD_FLAGS.testHooks) {
        baseManifest.name = 'Ragewarden (test hooks)';
    }

    writeFileSync(
        join(DIST_DIR, 'manifest.json'),
        JSON.stringify(baseManifest, null, 2),
    );
    logStep(`emitted manifest.json (${TARGET})`);
}

function copyTopLevelExtFiles() {
    const prelude = FLAG_BANNER
        + `globalThis.__RAGEWARDEN_BUILD_FLAGS = Object.freeze(${JSON.stringify(BUILD_FLAGS)});\n`;
    for (const f of ['content.js', 'background.js']) {
        const src = join(EXT_DIR, f);
        if (existsSync(src)) {
            writeFileSync(join(DIST_DIR, f), prelude + readFileSync(src, 'utf8'));
        } else {
            throw new Error(
                `missing ext/${f} -- refusing to emit an extension without its `
                + 'content/background script',
            );
        }
    }
    for (const f of ['tap.html', 'tap.js']) {
        const src = join(EXT_DIR, f);
        if (!existsSync(src)) {
            throw new Error(
                `missing ext/${f} -- the hardware-tap ceremony window is mandatory; `
                + 'without it every content-script unlock would have to fall back to '
                + 'no ceremony at all',
            );
        }
        cpSync(src, join(DIST_DIR, f));
    }
    const iconsSrc = join(EXT_DIR, 'icons');
    if (existsSync(iconsSrc)) cpSync(iconsSrc, join(DIST_DIR, 'icons'), { recursive: true });
    logStep('copied content.js + background.js + tap.{html,js} + icons/ into dist');
}

/**
 * Refuse to emit a bundle that carries the design prototype.
 *
 * Each pattern below is a specific way the mockup used to reach users:
 * the sample vault (`data.jsx` -- fake passwords and a *constant* recovery
 * phrase), the `ToastHost = () => null` no-op error channel, and the
 * CDN/Babel script tags the prototype needs and the extension CSP forbids.
 */
function assertPopupIsNotThePrototype() {
    const banned = [
        [/RECOVERY_PHRASE/, 'the prototype\'s hardcoded recovery phrase (design/data.jsx)'],
        [/ToastHost\s*=\s*\(\s*\)\s*=>\s*null/, 'the no-op ToastHost from design/components.jsx'],
        [/unpkg\.com/, 'a CDN script tag (blocked by the extension CSP)'],
        [/type="text\/babel"/, 'an in-browser Babel script tag'],
        [/maya@feldspar\.fm/, 'the prototype\'s sample vault data'],
    ];
    const walk = (dir) => {
        for (const name of readdirSync(dir)) {
            const p = join(dir, name);
            if (statSync(p).isDirectory()) { walk(p); continue; }
            if (name.endsWith('.jsx')) {
                throw new Error(
                    `dist popup contains ${relative(DIST_DIR, p)} -- design/ is a mockup and `
                    + 'must not be bundled',
                );
            }
            if (!/\.(html|js|css)$/.test(name)) continue;
            const src = readFileSync(p, 'utf8');
            for (const [re, what] of banned) {
                if (re.test(src)) {
                    throw new Error(
                        `dist popup file ${relative(DIST_DIR, p)} contains ${what}`,
                    );
                }
            }
        }
    };
    walk(DIST_POPUP);
    logStep('asserted the shipped popup is the real implementation, not design/');
}

function assertDistIsSane() {
    const mustExist = ['tap.html', 'tap.js', 'glue/build-flags.js', 'glue/hardware-tap.js',
        'glue/unlock.js'];
    for (const rel of mustExist) {
        if (!existsSync(join(DIST_DIR, rel))) {
            throw new Error(`dist is missing ${rel}`);
        }
    }
    const bg = readFileSync(join(DIST_DIR, 'background.js'), 'utf8');
    if (!bg.includes('__RAGEWARDEN_BUILD_FLAGS')) {
        throw new Error('background.js in dist has no build-flag prelude');
    }
    if (bg.includes('prfOutputB64')) {
        throw new Error(
            'background.js accepts a caller-supplied PRF output again -- that lets any '
            + 'content script hand the worker key material it did not derive from a tap',
        );
    }
    if (!BUILD_FLAGS.allowMockTap) {
        if (existsSync(join(DIST_GLUE, 'dev-only'))) {
            throw new Error('release build still contains glue/dev-only/');
        }
        const flags = readFileSync(join(DIST_GLUE, 'build-flags.js'), 'utf8');
        if (!/allowMockTap":false/.test(flags.replace(/\s+/g, ''))) {
            throw new Error('release build-flags.js does not pin allowMockTap:false');
        }
        // vmMode implies allowMockTap, bakes a server URL into the bundle, and
        // is what makes vault.js wrap writes to a stand-in key anyone with this
        // source can open. It must never be live in a build that ships.
        if (!/"vmMode":false/.test(flags.replace(/\s+/g, ''))) {
            throw new Error('release build-flags.js does not pin vmMode:false');
        }
        if (!/"vmServerUrl":null/.test(flags.replace(/\s+/g, ''))) {
            throw new Error('release build-flags.js carries a baked-in vmServerUrl');
        }
    }
    if (!BUILD_FLAGS.testHooks) {
        const flags = readFileSync(join(DIST_GLUE, 'build-flags.js'), 'utf8');
        if (!/"testHooks":false/.test(flags.replace(/\s+/g, ''))) {
            throw new Error(
                'build-flags.js does not pin testHooks:false -- testHooksEnabled() is the only '
                + 'thing standing between a release build and window.__ragewardenSession, '
                + 'which carries access_token, refresh_token and the Bitwarden '
                + 'user_enc_key/user_mac_key',
            );
        }
        for (const f of ['content.js', 'background.js']) {
            const src = readFileSync(join(DIST_DIR, f), 'utf8');
            if (!/"testHooks":false/.test(src.replace(/\s+/g, ''))) {
                throw new Error(`${f} build-flag prelude does not pin testHooks:false`);
            }
        }
    }
    assertPopupIsNotThePrototype();
    const manifest = JSON.parse(readFileSync(join(DIST_DIR, 'manifest.json'), 'utf8'));
    if ((manifest.permissions || []).includes('scripting')) {
        throw new Error(
            'manifest declares the scripting permission, but nothing in the extension calls '
            + 'chrome.scripting -- it only widens the install-time warning',
        );
    }
    if ((manifest.web_accessible_resources || []).length > 0) {
        throw new Error(
            'manifest declares web_accessible_resources; wasm/ is loaded only from extension '
            + 'pages and the background worker, which never consult it, so every entry is a '
            + 'fingerprinting surface for any page that probes the resource URL',
        );
    }
    if (!BUILD_FLAGS.testHooks) {
        const flags = readFileSync(join(DIST_GLUE, 'build-flags.js'), 'utf8');
        if (!/"testHooks":false/.test(flags.replace(/\s+/g, ''))) {
            throw new Error(
                'build-flags.js does not pin testHooks:false -- testHooksEnabled() is the only '
                + 'thing standing between a release build and window.__ragewardenSession, '
                + 'which carries access_token, refresh_token and the Bitwarden '
                + 'user_enc_key/user_mac_key',
            );
        }
        for (const f of ['content.js', 'background.js']) {
            const src = readFileSync(join(DIST_DIR, f), 'utf8');
            if (!/"testHooks":false/.test(src.replace(/\s+/g, ''))) {
                throw new Error(`${f} build-flag prelude does not pin testHooks:false`);
            }
        }
    }
    logStep(`asserted dist shape (profile=${BUILD_FLAGS.profile})`);
}

function maybeRunWasmPack() {
    if (!RUN_WASM_PACK) return;
    const workspaceRoot = resolve(ROOT, '..');
    logStep('running wasm-pack build --target web ragemanifest');
    const r = spawnSync('wasm-pack', ['build', '--target', 'web', 'ragemanifest'], {
        cwd: workspaceRoot,
        stdio: 'inherit',
    });
    if (r.status !== 0) throw new Error(`wasm-pack failed with code ${r.status}`);
}

function maybeZipDist() {
    if (!ZIP) return;
    const zipPath = join(ROOT, 'dist', `ragemanifest-${TARGET}.zip`);
    rmSync(zipPath, { force: true });
    const r = spawnSync('zip', ['-r', '-X', '-q', zipPath, '.'], {
        cwd: DIST_DIR,
        stdio: 'inherit',
    });
    if (r.status !== 0) {
        logWarn(`zip failed (status ${r.status}); skipping zipped artifact`);
        return;
    }
    logStep(`emitted ${relative(ROOT, zipPath)}`);
}

function stripJsonComments(s) {
    return s
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

async function buildOnce() {
    console.log(`[build] target=${TARGET}`);

    rmSync(DIST_DIR, { recursive: true, force: true });
    mkdirSync(DIST_DIR, { recursive: true });

    maybeRunWasmPack();
    stageWasm();
    copyPopup();
    await copyGlue();
    copyWasm();
    copyTopLevelExtFiles();
    emitManifest();
    assertDistIsSane();
    maybeZipDist();

    console.log(`[build] done. Output at: ${DIST_DIR}`);
    console.log(`[build] load it via chrome://extensions -> "Load unpacked" -> ${DIST_DIR}`);
    console.log(
        `[build] or test in a regular browser:\n` +
        `        cd ${DIST_DIR} && python3 -m http.server\n` +
        `        then visit http://localhost:8000/popup/RageDroid.html`,
    );
}

await buildOnce();

if (WATCH) {
    console.log('[build] watching ext/popup/, ext/glue/ and design tokens for changes...');
    let pending = false;
    const trigger = () => {
        if (pending) return;
        pending = true;
        setTimeout(async () => {
            pending = false;
            try { await buildOnce(); } catch (e) { console.error('[build] rebuild failed:', e); }
        }, 100);
    };
    watch(POPUP_DIR, { recursive: true }, trigger);
    watch(GLUE_DIR, { recursive: true }, trigger);
    watch(DESIGN_DIR, { recursive: false }, (_eventType, fname) => {
        if (fname === 'colors_and_type.css') trigger();
    });
    watch(EXT_DIR, { recursive: false }, (_eventType, fname) => {
        if (fname === 'manifest.json') trigger();
    });
}
