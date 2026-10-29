#!/usr/bin/env node

import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, cpSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer } from 'node:http';
import { dirname, join, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const DIST_FIREFOX = join(ROOT, 'dist', 'firefox');
const WEB_EXT = join(ROOT, 'node_modules', '.bin', 'web-ext');

const args = process.argv.slice(2);
const STATIC_ONLY = args.includes('--static-only');
const RUN_FIREFOX = args.includes('--firefox');

const ADDON_ID = 'ragewarden@ragewarden';
const EXTENSION_INTERNAL_UUID = 'r4gewa1d-r4ge-r4ge-r4ge-r4gewardenext';

function fail(msg) {
    console.error(`[smoke-firefox] FAIL ${msg}`);
    process.exit(1);
}
function pass(msg) {
    console.log(`[smoke-firefox] OK   ${msg}`);
}
function info(msg) {
    console.log(`[smoke-firefox] info ${msg}`);
}

function validateManifest() {
    const manifestPath = join(DIST_FIREFOX, 'manifest.json');
    if (!existsSync(manifestPath)) {
        fail(`${manifestPath} missing -- run \`pnpm run build:firefox\` first.`);
    }
    const m = JSON.parse(readFileSync(manifestPath, 'utf8'));

    const gecko = m.browser_specific_settings?.gecko;
    if (!gecko || gecko.id !== ADDON_ID) {
        fail(`browser_specific_settings.gecko.id must be "${ADDON_ID}" (got ${JSON.stringify(gecko)})`);
    }
    if (!gecko.strict_min_version) {
        fail('browser_specific_settings.gecko.strict_min_version missing');
    }
    if (parseInt(gecko.strict_min_version, 10) < 132) {
        fail(`gecko.strict_min_version must be 132+ (got ${gecko.strict_min_version})`);
    }
    pass(`gecko.id=${gecko.id} strict_min_version=${gecko.strict_min_version}`);

    const bg = m.background;
    if (!bg) fail('background block missing');
    if (bg.service_worker) fail('background.service_worker is Chromium-only; Firefox MV3 uses background.scripts');
    if (bg.type === 'module') fail('background.type=module is unsupported in Firefox event pages');
    if (!Array.isArray(bg.scripts) || bg.scripts.length === 0) {
        fail('background.scripts must list at least one script');
    }
    pass(`background.scripts=${JSON.stringify(bg.scripts)}`);

    if (!Array.isArray(m.permissions) || !m.permissions.includes('nativeMessaging')) {
        fail('nativeMessaging missing: the PIV/FIDO2 bridge to rageterm opens a native port in Firefox too');
    }
    if (Array.isArray(m.permissions) && m.permissions.includes('sidePanel')) {
        fail('sidePanel is Chromium-only; remove from Firefox build');
    }
    if (m.side_panel) {
        fail('side_panel manifest key is Chromium-only; remove from Firefox build');
    }
    pass(`permissions=${JSON.stringify(m.permissions)}`);

    if (!m.action || m.action.default_popup !== 'popup/index.html') {
        fail('action.default_popup must point at popup/index.html (Firefox keeps the popup; side panel is Chromium-only)');
    }
    if (m.web_accessible_resources?.length) {
        fail(
            'web_accessible_resources must stay empty: the popup, the tap window and the '
            + 'background page load wasm/ as extension pages, which never consults it, so '
            + `any entry only makes the extension fingerprintable (got ${
                JSON.stringify(m.web_accessible_resources)})`,
        );
    }
    pass('manifest shape is valid for Firefox MV3');

    for (const f of [
        'background.js',
        'content.js',
        'popup/index.html',
        'wasm/ragemanifest.js',
        'wasm/ragemanifest_bg.wasm',
    ]) {
        if (!existsSync(join(DIST_FIREFOX, f))) {
            fail(`referenced file missing in dist/firefox: ${f}`);
        }
    }
    pass('all referenced files present in dist/firefox/');

    return m;
}

function runWebExtLint() {
    if (!existsSync(WEB_EXT)) {
        fail(`web-ext not found at ${WEB_EXT}; run \`pnpm install --frozen-lockfile\` in ragemanifest/ first.`);
    }
    let r;
    for (let attempt = 0; attempt < 2; attempt++) {
        r = spawnSync(WEB_EXT, [
            'lint',
            '--source-dir', DIST_FIREFOX,
            '--self-hosted',
            '--output', 'json',
            '--pretty',
        ], { encoding: 'utf8', maxBuffer: 50 * 1024 * 1024 });
        if (r.status === 0) break;
        info(`web-ext lint attempt ${attempt + 1} returned status=${r.status} signal=${r.signal}; retrying`);
    }
    if (r.status !== 0) {
        console.error('stdout:', r.stdout);
        console.error('stderr:', r.stderr);
        console.error('error:', r.error?.message);
        console.error('signal:', r.signal);
        fail(`web-ext lint exited ${r.status} (signal=${r.signal})`);
    }
    let report = null;
    try { report = JSON.parse(r.stdout); } catch {}
    if (report) {
        const errors = report.errors?.length ?? 0;
        const warnings = report.warnings?.length ?? 0;
        const notices = report.notices?.length ?? 0;
        if (errors > 0) {
            console.error(JSON.stringify(report.errors, null, 2));
            fail(`web-ext lint reported ${errors} error(s)`);
        }
        pass(`web-ext lint: 0 errors, ${warnings} warnings, ${notices} notices`);
    } else {
        pass('web-ext lint exited 0 (no parseable JSON report; warnings only)');
    }
}

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.wasm': 'application/wasm',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.ttf': 'font/ttf',
};

function startStaticServer(rootDir) {
    return new Promise((resolveServer) => {
        const server = createServer((req, res) => {
            try {
                const url = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
                if (url === '/favicon.ico') {
                    res.statusCode = 204;
                    res.end();
                    return;
                }
                let path = join(rootDir, url);
                if (existsSync(path) && req.url.endsWith('/')) path = join(path, 'index.html');
                if (!existsSync(path)) {
                    res.statusCode = 404;
                    res.end('not found');
                    return;
                }
                const data = readFileSync(path);
                res.setHeader('content-type', MIME_TYPES[extname(path)] || 'application/octet-stream');
                res.end(data);
            } catch (e) {
                res.statusCode = 500;
                res.end(String(e?.message || e));
            }
        });
        server.listen(0, '127.0.0.1', () => resolveServer(server));
    });
}

async function loadPopupInChromium() {
    let playwright;
    try {
        playwright = await import('playwright-core');
    } catch {
        try {
            playwright = await import('playwright');
        } catch {
            info('playwright not available; skipping Chromium-proxy popup load');
            info('install via `pnpm install --frozen-lockfile` (playwright-core is a pinned devDependency) to enable this layer');
            return;
        }
    }

    let executablePath;
    try {
        executablePath = playwright.chromium.executablePath?.();
    } catch {}
    if (!executablePath || !existsSync(executablePath)) {
        for (const c of [
            '/Applications/Chromium.app/Contents/MacOS/Chromium',
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        ]) {
            if (existsSync(c)) { executablePath = c; break; }
        }
    }
    if (!executablePath) {
        info('no Chromium binary found; skipping Chromium-proxy popup load');
        return;
    }
    info(`Chromium-proxy popup load using ${executablePath}`);

    const server = await startStaticServer(DIST_FIREFOX);
    const port = server.address().port;
    const url = `http://127.0.0.1:${port}/popup/index.html`;
    info(`serving dist/firefox at http://127.0.0.1:${port}`);

    const browser = await playwright.chromium.launch({
        executablePath,
        headless: true,
    });
    try {
        const ctx = await browser.newContext();
        const page = await ctx.newPage();
        const errors = [];
        page.on('pageerror', err => errors.push(`pageerror: ${err.message}`));
        page.on('console', msg => {
            if (msg.type() === 'error') errors.push(`console.error: ${msg.text()}`);
        });

        await page.goto(url, { waitUntil: 'load', timeout: 15_000 });

        const result = await page.evaluate(async () => {
            const mod = await import('../wasm/ragemanifest.js');
            if (typeof mod.default === 'function') await mod.default();
            const tag = mod.wasm_module_tag();
            const totp = mod.wasm_totp_generate('JBSWY3DPEHPK3PXP');
            return {
                tag,
                totp,
                phoneCount: document.querySelectorAll('.phone').length,
                screenCount: document.querySelectorAll('.screen').length,
                href: location.href,
            };
        });

        if (result.phoneCount !== 1) {
            fail(`expected .phone count=1, got ${result.phoneCount}`);
        }
        pass('popup contains exactly 1 .phone element');

        if (result.screenCount !== 1) {
            fail(`expected .screen count=1, got ${result.screenCount}`);
        }
        pass('popup contains exactly 1 .screen element');

        const expectedTag = 'ragemanifest 0.0.1 / ragewarden-core linked';
        if (result.tag !== expectedTag) {
            fail(`wasm_module_tag()=${JSON.stringify(result.tag)} (expected ${JSON.stringify(expectedTag)})`);
        }
        pass(`wasm_module_tag()=${result.tag}`);

        const totpCode = (typeof result.totp === 'string') ? result.totp : result.totp?.code;
        if (!/^\d{6}$/.test(String(totpCode))) {
            fail(`wasm_totp_generate('JBSWY3DPEHPK3PXP')=${JSON.stringify(result.totp)} (expected 6-digit code)`);
        }
        pass(`wasm_totp_generate('JBSWY3DPEHPK3PXP').code=${totpCode}`);

        if (errors.length) {
            console.error('[smoke-firefox] popup-side errors:');
            for (const e of errors) console.error(`  ${e}`);
        }
    } finally {
        await browser.close();
        server.close();
    }
}

async function launchFirefox() {
    const candidates = [
        '/Applications/Firefox.app/Contents/MacOS/firefox',
        '/opt/homebrew/Caskroom/firefox/149.0.2/Firefox.app/Contents/MacOS/firefox',
        '/usr/bin/firefox',
    ];
    let firefoxBin = null;
    for (const c of candidates) {
        if (existsSync(c)) { firefoxBin = c; break; }
    }
    if (!firefoxBin) {
        info('no Firefox binary found; skipping headed Firefox smoke');
        info('install with `brew install --cask firefox`');
        return;
    }

    const profileDir = mkdtempSync(join(tmpdir(), 'ragewarden-smoke-'));
    info(`headed Firefox profile=${profileDir}`);
    const popupUrl = `moz-extension://${EXTENSION_INTERNAL_UUID}/popup/index.html`;

    const webExtArgs = [
        'run',
        '--source-dir', DIST_FIREFOX,
        '--no-input',
        '--no-reload',
        '--verbose',
        '--start-url', popupUrl,
        '--firefox', firefoxBin,
        '--pref', `extensions.webextensions.uuids={"${ADDON_ID}":"${EXTENSION_INTERNAL_UUID}"}`,
        '--pref', 'browser.startup.homepage_override.mstone=ignore',
        '--pref', 'browser.aboutwelcome.enabled=false',
        '--pref', 'browser.shell.checkDefaultBrowser=false',
        '--pref', 'datareporting.policy.firstRunURL=',
    ];

    info('launching Firefox via web-ext (headed; window opens for ~15 seconds)');
    info(`popup URL: ${popupUrl}`);
    info('confirm by eye that the .phone container renders the popup UI');

    return new Promise((resolveLaunch, rejectLaunch) => {
        const child = spawn(WEB_EXT, webExtArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
        let buffer = '';
        let installed = false;
        const onChunk = (chunk) => {
            const s = chunk.toString('utf8');
            buffer += s;
            if (!installed && (
                /Installed.*as a temporary add-on/i.test(buffer)
                || /Reloading add-on/i.test(buffer)
                || /The extension.*has been installed temporarily/i.test(buffer)
                || /Connected to the remote Firefox/i.test(buffer)
                || /Executing Firefox binary/i.test(buffer)
            )) {
                installed = true;
                pass(`Firefox launched with dist/firefox as a temporary add-on (web-ext channel)`);
            }
        };
        child.stdout.on('data', onChunk);
        child.stderr.on('data', onChunk);

        const timer = setTimeout(() => {
            try { child.kill('SIGTERM'); } catch {}
        }, 15_000);
        child.on('exit', (code, signal) => {
            clearTimeout(timer);
            try { rmSync(profileDir, { recursive: true, force: true }); } catch {}
            if (!installed) {
                console.error('[smoke-firefox] web-ext output buffer follows:');
                console.error(buffer);
                rejectLaunch(new Error(
                    `web-ext run did not confirm install (exit=${code}, signal=${signal})`,
                ));
            } else {
                resolveLaunch();
            }
        });
    });
}

(async () => {
    info(`dist/firefox=${DIST_FIREFOX}`);
    validateManifest();
    runWebExtLint();
    if (STATIC_ONLY) {
        console.log('[smoke-firefox] all checks passed (static-only)');
        return;
    }
    await loadPopupInChromium();
    if (RUN_FIREFOX) {
        await launchFirefox();
    } else {
        info('skipping headed Firefox launch; pass --firefox to enable');
    }
    console.log('[smoke-firefox] all checks passed');
})().catch(err => {
    console.error('[smoke-firefox] uncaught:', err);
    process.exit(1);
});
