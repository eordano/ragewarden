import test from 'node:test';
import assert from 'node:assert/strict';
import { installFakeChrome } from './fake-chrome.mjs';
import { makeCredential, signedReceipt } from './webauthn-fixture.mjs';

const chrome = installFakeChrome();
const opened = [];
const alarms = [];
chrome.windows = {
    create(opts, cb) { opened.push(opts.url); queueMicrotask(() => cb({ id: opened.length })); },
    remove(_id, cb) { cb && cb(); },
    onRemoved: { addListener() {} },
};
chrome.alarms = {
    create(name, info) { alarms.push({ name, info }); },
    clear() {},
    onAlarm: { addListener() {} },
};
globalThis.__RAGEWARDEN_BUILD_FLAGS = { testHooks: true, allowMockTap: false };

const storage = await import('../../ext/glue/storage.js');
const passkeys = await import('../../ext/glue/passkey-store.js');
const snapshot = {
    ciphers: [
        { id: 'c1', kind: 'login', name: 'Example', username: 'me', site: 'example.com', rage: true, decryptable: true },
    ],
    folders: [],
};
let fetches = 0;
globalThis.__ragewardenBgModules = {
    storage,
    passkeys,
    match: await import('../../ext/glue/origin-match.js'),
    receipts: await import('../../ext/glue/receipt-check.js'),
    relay: await import('../../ext/glue/prf-relay.js'),
    inventory: await import('../../ext/glue/inventory.js'),
    wasm: {
        default: async () => {},
        wasm_fetch_vault_with_identities: async () => { fetches += 1; return snapshot; },
        wasm_fetch_registry: async () => ({ entries: [] }),
    },
};
await import('../../ext/background.js');
const bg = globalThis.__ragewardenBackground;

const tabSender = { id: chrome.runtime.id, tab: { id: 7 }, frameId: 0, url: 'https://example.com/login', origin: 'https://example.com' };
const tapSender = (req) => ({ id: chrome.runtime.id, url: chrome.runtime.getURL(`tap.html?req=${req}`) });
const pageSender = { id: chrome.runtime.id, url: chrome.runtime.getURL('popup/RageDroid.html') };
const request = { action: 'autofill', destination: 'example.com', cipherId: 'c1', origin: 'https://example.com' };

async function signedIn() {
    await storage.saveSession({ email: 'a@example.com' }, { password: 'pw' });
    bg.invalidateSession();
}

async function runTap(complete) {
    const pending = bg.handleMessage({ kind: 'vault.unlock', cipherId: 'c1', action: 'autofill' }, tabSender);
    while (opened.length === 0 || !opened.at(-1)) await new Promise(r => setTimeout(r, 5));
    await new Promise(r => setTimeout(r, 20));
    const req = new URL(opened.at(-1)).searchParams.get('req');
    const claim = await bg.handleMessage({ kind: 'tap.claim', requestId: req }, tapSender(req));
    assert.equal(claim.ok, true);
    await complete(req, claim.request);
    return pending;
}

test('lookup offers matching items only to the matching origin', async () => {
    await signedIn();
    const ok = await bg.handleMessage({ kind: 'vault.lookup' }, tabSender);
    assert.deepEqual(ok.matches.map(m => m.id), ['c1']);
    const evil = await bg.handleMessage({ kind: 'vault.lookup' }, { ...tabSender, origin: 'https://example.com.evil.net' });
    assert.deepEqual(evil.matches, []);
});

test('locking clears the worker cache through storage events', async () => {
    await signedIn();
    assert.equal((await bg.handleMessage({ kind: 'vault.lookup' }, tabSender)).matches.length, 1);
    await storage.lockSession();
    await new Promise(r => setTimeout(r, 10));
    assert.deepEqual((await bg.handleMessage({ kind: 'vault.lookup' }, tabSender)).matches, []);
});

test('a receipt for another item does not release plaintext', async () => {
    await signedIn();
    const cred = await makeCredential();
    opened.length = 0;
    const result = await runTap(async (req) => {
        const receipt = await signedReceipt(cred, { ...request, cipherId: 'other', nonce: 'n' });
        const r = await bg.handleMessage({
            kind: 'tap.complete', requestId: req, plaintext: { password: 'x' }, receipts: [receipt],
        }, tapSender(req));
        assert.equal(r.ok, false);
    });
    assert.equal(result.ok, false);
    assert.match(result.error, /refusing to release plaintext/);
});

test('a bound, signed receipt from an enrolled credential releases plaintext', async () => {
    await signedIn();
    const cred = await makeCredential();
    await passkeys.savePasskeyRecipient({
        kind: 'passkey_prf', credential_id_b64: cred.credentialIdB64, salt_b64: '', rp_id: 'x',
        public_key_spki_b64: cred.spkiB64, public_key_alg: -7,
    });
    opened.length = 0;
    const result = await runTap(async (req, claimed) => {
        const receipt = await signedReceipt(cred, {
            action: claimed.action, destination: claimed.destination, cipherId: claimed.cipherId,
            origin: claimed.origin, nonce: 'n',
        });
        const r = await bg.handleMessage({
            kind: 'tap.complete', requestId: req, plaintext: { username: 'me', password: 'pw' }, receipts: [receipt],
        }, tapSender(req));
        assert.equal(r.ok, true);
    });
    assert.equal(result.ok, true);
    assert.equal(result.plaintext.password, 'pw');
});

test('clipboard clears are scheduled in the worker and refused to pages', async () => {
    const r = await bg.handleMessage({ kind: 'clipboard.scheduleClear', seconds: 30 }, pageSender);
    assert.equal(r.ok, true);
    assert.ok(r.clearAt > Date.now());
    assert.ok(alarms.some(a => a.name === 'ragewarden-clipboard-clear'));
    const denied = await bg.handleMessage({ kind: 'clipboard.scheduleClear' }, tabSender);
    assert.equal(denied.ok, false);
});

test('Safari: native requests are relayed through the app with sendNativeMessage', async () => {
    const saved = { connectNative: chrome.runtime.connectNative, sendNativeMessage: chrome.runtime.sendNativeMessage };
    const sent = [];
    chrome.runtime.connectNative = undefined;
    chrome.runtime.sendNativeMessage = (host, message, cb) => {
        sent.push({ host, message });
        queueMicrotask(() => cb(message.method === 'probe'
            ? { capable: true, backends: [] }
            : { ok: true, file_key: 'Zmlr', tap: { backend: 'piv-x25519-v2', touched: true, verified: true } }));
    };
    try {
        const probe = await bg.handleMessage({ kind: 'native.probe' }, pageSender);
        assert.equal(probe.available, true);
        const stanza = { tag: 'piv-x25519-v2', args: ['a', 'b'], body: 'Ym9keQ' };
        const unwrap = await bg.handleMessage(
            { kind: 'native.unwrap', stanza, context: { action: 'reveal' }, challenge: 'Y2hhbA==' }, pageSender);
        assert.deepEqual(unwrap, { ok: true, fileKeyB64: 'Zmlr', tap: { backend: 'piv-x25519-v2', touched: true, verified: true } });
        assert.deepEqual(sent.map(s => s.message.method), ['probe', 'unwrap_stanza']);
        assert.equal(sent[1].message.challenge, 'Y2hhbA==');
    } finally {
        Object.assign(chrome.runtime, saved);
    }
});

test('only an extension page may open the passkey relay; a relay message from elsewhere is refused', async () => {
    const asTab = await bg.handleMessage({ kind: 'relay.prf', credentials: [] }, tabSender);
    assert.equal(asTab.ok, false);
    assert.match(asTab.error, /not available to content scripts/);
    await assert.rejects(
        bg.handleMessage({ kind: 'relay.hello', nonce: 'n'.repeat(24) }, tabSender),
        /only from the relay page/,
    );
});
