#!/usr/bin/env node
// Real Firefox, headless, driven over WebDriver BiDi: install a --test-hooks
// dist/firefox as a temporary add-on, cold-start its event page, mount the popup and the tap
// window under moz-extension://, and ask the background a question.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = resolve(process.argv[2] || join(ROOT, 'dist', 'firefox'));
const ADDON_ID = 'ragewarden@ragewarden';
const UUID = 'b1d1b1d1-0000-4000-8000-000000000001';
const FIREFOX = process.env.FIREFOX_BIN || 'firefox';

const fail = (msg) => { console.error(`[firefox-bidi] FAIL ${msg}`); process.exitCode = 1; throw new Error(msg); };
const ok = (msg) => console.log(`[firefox-bidi] OK   ${msg}`);
if (!existsSync(join(DIST, 'manifest.json'))) fail(`no ${DIST}/manifest.json -- run node build.mjs firefox`);

const profile = mkdtempSync(join(tmpdir(), 'rw-ff-'));
writeFileSync(join(profile, 'user.js'), [
    `user_pref("extensions.webextensions.uuids", ${JSON.stringify(JSON.stringify({ [ADDON_ID]: UUID }))});`,
    'user_pref("xpinstall.signatures.required", false);',
    'user_pref("browser.shell.checkDefaultBrowser", false);',
    'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
    'user_pref("browser.aboutwelcome.enabled", false);',
].join('\n'));

const ff = spawn(FIREFOX, ['--headless', '--no-remote', '--profile', profile, '--remote-debugging-port', '0',
    '--remote-allow-system-access'],
    { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, MOZ_CRASHREPORTER_DISABLE: '1' } });
let log = '';
const wsUrl = await new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error(`Firefox printed no BiDi endpoint:\n${log}`)), 60_000);
    const on = (b) => {
        log += b;
        const m = log.match(/WebDriver BiDi listening on (ws:\/\/[^\s]+)/);
        if (m) { clearTimeout(t); res(m[1]); }
    };
    ff.stdout.on('data', on);
    ff.stderr.on('data', on);
    ff.on('exit', (c) => rej(new Error(`Firefox exited ${c}:\n${log}`)));
});

const ws = new WebSocket(`${wsUrl.replace(/\/$/, '')}/session`);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
let seq = 0;
const pending = new Map();
ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
        const { res, rej } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.type === 'error') rej(new Error(`${msg.error}: ${msg.message}`)); else res(msg.result);
    }
};
const send = (method, params = {}) => new Promise((res, rej) => {
    const id = ++seq;
    pending.set(id, { res, rej });
    ws.send(JSON.stringify({ id, method, params }));
});

async function evaluate(context, expression) {
    const r = await send('script.evaluate', { expression, target: { context }, awaitPromise: true, serializationOptions: { maxObjectDepth: 3 } });
    if (r.type === 'exception') throw new Error(r.exceptionDetails.text);
    return r.result;
}
const value = (r) => (r.type === 'object' ? Object.fromEntries(r.value.map(([k, v]) => [k, v.value])) : r.value);

async function poll(context, expression, want, what, ms = 30_000) {
    const end = Date.now() + ms;
    let last;
    while (Date.now() < end) {
        try { last = value(await evaluate(context, expression)); } catch (e) { last = e.message; }
        if (last === want) return;
        await new Promise(r => setTimeout(r, 250));
    }
    fail(`${what}: last value ${JSON.stringify(last)}`);
}

try {
    await send('session.new', { capabilities: {} });
    const installed = await send('webExtension.install', { extensionData: { type: 'path', path: DIST } });
    if (installed.extension !== ADDON_ID) fail(`installed ${installed.extension}, expected ${ADDON_ID}`);
    ok(`temporary add-on ${installed.extension} installed from ${DIST}`);

    let context = null;
    for (let i = 0; i < 120 && !context; i++) {
        const { contexts } = await send('browsingContext.getTree', {});
        const hit = contexts.find(c => c.url.startsWith(`moz-extension://${UUID}/popup/index.html`));
        if (hit) context = hit.context;
        else await new Promise(r => setTimeout(r, 250));
    }
    if (!context) fail('the test build did not open its popup in a tab (is this a --test-hooks build?)');
    await poll(context, "document.querySelector('.ragewarden-onb-card h1')?.textContent ?? null",
        'Sign in to Bitwarden', 'the popup mounts and offers sign-in');
    ok('popup mounted under moz-extension:// and shows the sign-in card');

    const status = value(await evaluate(context,
        "browser.runtime.sendMessage({ kind: 'vault.status' }).then(r => JSON.stringify(r))"));
    const parsed = JSON.parse(status);
    if (!parsed.ok || parsed.signedIn !== false) fail(`vault.status from a cold event page: ${status}`);
    ok(`event page cold-started and answered vault.status: ${status}`);

    await evaluate(context, "location.href = '../tap.html?req=bogus'; true");
    await poll(context, "(document.getElementById('status')?.textContent || '').length > 0 && document.getElementById('authorize')?.disabled === true",
        true, 'the tap window runs, reports on the unknown request and keeps Authorize disabled');
    const said = value(await evaluate(context, "document.getElementById('status').textContent"));
    console.log(`[firefox-bidi] info tap window said: ${said}`);
    ok('tap window mounted and refused an unknown request id');
} finally {
    try { ws.close(); } catch {}
    ff.kill('SIGTERM');
    await new Promise(r => setTimeout(r, 500));
    rmSync(profile, { recursive: true, force: true });
}
if (!process.exitCode) console.log('[firefox-bidi] all checks passed');
