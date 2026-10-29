#!/usr/bin/env node
// Check a Chromium zip against the Chrome Web Store's upload rules and copy it to
// its store name. Nothing is uploaded.
import { copyFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const [zip, version, out] = process.argv.slice(2);
if (!zip || !version) {
    console.error('usage: check-store-package.mjs <chromium.zip> <version> [out.zip]');
    process.exit(2);
}
const fail = (msg) => { console.error(`[store-package] FAIL ${msg}`); process.exit(1); };

const entries = new Set(execFileSync('unzip', ['-Z1', zip], { encoding: 'utf8' }).split('\n').filter(Boolean));
if (!entries.has('manifest.json')) fail('manifest.json is not at the zip root');
const m = JSON.parse(execFileSync('unzip', ['-p', zip, 'manifest.json'], { encoding: 'utf8' }));

if (m.manifest_version !== 3) fail(`manifest_version ${m.manifest_version}`);
if (m.version !== version) fail(`manifest version ${m.version} is not the release version ${version}`);
if (!/^\d+(\.\d+){0,3}$/.test(m.version)) fail(`version ${m.version} is not 1-4 integers`);
if (!m.name || m.name.length > 75) fail(`name must be 1-75 characters (${(m.name || '').length})`);
if (/MOCK|test hooks|NOT SECURE/i.test(`${m.name} ${m.description}`)) fail('a development build cannot be a store package');
if ((m.description || '').length > 132) fail(`description is ${m.description.length} characters; the store allows 132`);
if (m.key || m.update_url) fail('key / update_url belong to self-hosted builds, not a store upload');
if ((m.host_permissions || []).length) fail('host_permissions at install; the server origin is requested at sign-in');
for (const size of ['16', '48', '128']) {
    const icon = m.icons && m.icons[size];
    if (!icon || !entries.has(icon)) fail(`icon ${size} missing from the zip`);
}
for (const f of [m.action && m.action.default_popup, m.background && m.background.service_worker]) {
    if (f && !entries.has(f)) fail(`${f} is referenced but not packaged`);
}
if ([...entries].some(e => e.startsWith('glue/dev-only/'))) fail('the mock tap backend is in the package');

if (out) copyFileSync(zip, out);
console.log(`[store-package] OK ${zip} v${m.version}${out ? ` -> ${out}` : ''}`);
