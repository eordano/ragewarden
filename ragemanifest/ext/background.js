const BUILD_FLAGS = Object.freeze(Object.assign(
    { profile: 'release', allowMockTap: false, forceMockTap: false, testHooks: false },
    (typeof globalThis !== 'undefined' && globalThis.__RAGEWARDEN_BUILD_FLAGS) || {},
));

const NATIVE_HOST_NAME = 'com.ragewarden.host';
const AUTOLOCK_ALARM = 'ragewarden-autolock';
const CLIPBOARD_ALARM = 'ragewarden-clipboard-clear';
const OFFSCREEN_DOC = 'glue/offscreen-clipboard.html';

/*
 * Glue modules are shared with the extension pages. A Chromium service worker
 * cannot call import(), so build.mjs prepends static imports and parks them on
 * globalThis.__ragewardenBgModules; Firefox's event page loads them on demand.
 */
const MODULE_PATHS = Object.freeze({
    wasm: 'wasm/ragemanifest.js',
    storage: 'glue/storage.js',
    match: 'glue/origin-match.js',
    receipts: 'glue/receipt-check.js',
    inventory: 'glue/inventory.js',
    passkeys: 'glue/passkey-store.js',
    relay: 'glue/prf-relay.js',
});
const modulePromises = {};

function getModule(name) {
    const pre = globalThis.__ragewardenBgModules;
    if (pre && pre[name]) return Promise.resolve(pre[name]);
    if (!modulePromises[name]) {
        modulePromises[name] = import(chrome.runtime.getURL(MODULE_PATHS[name]));
    }
    return modulePromises[name];
}

let wasmReady = null;
async function getWasm() {
    const mod = await getModule('wasm');
    if (!wasmReady) {
        wasmReady = typeof mod.default === 'function'
            ? mod.default({ module_or_path: chrome.runtime.getURL('wasm/ragemanifest_bg.wasm') })
            : Promise.resolve();
    }
    await wasmReady;
    return mod;
}

let cachedSessionPromise = null;
let cachedSnapshot = null;
let inFlightSnapshot = null;

async function getSession() {
    if (!cachedSessionPromise) {
        cachedSessionPromise = getModule('storage').then(s => s.loadSession()).catch(() => null);
    }
    return cachedSessionPromise;
}

function invalidateSession() {
    cachedSessionPromise = null;
    cachedSnapshot = null;
    inFlightSnapshot = null;
    for (const id of Array.from(pendingTaps.keys())) {
        settleTap(id, { ok: false, error: 'session changed while awaiting a hardware tap' });
    }
}

if (chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, area) => {
        if ((area === 'local' && changes['ragewarden:sessionEnvelope'])
            || (area === 'session' && changes['ragewarden:envelopeKey'])
            || (area === 'local' && changes['ragewarden:passkey-recipient'])
            || (area === 'local' && changes['ragewarden:software-identity'])) {
            invalidateSession();
        }
    });
}

async function fetchSnapshot(force = false) {
    if (cachedSnapshot && !force) return cachedSnapshot;
    if (inFlightSnapshot && !force) return inFlightSnapshot;
    inFlightSnapshot = (async () => {
        const session = await getSession();
        if (!session) throw new Error('Ragewarden is locked');
        const wasm = await getWasm();
        const { localIdentityInventory } = await getModule('inventory');
        const inventory = await localIdentityInventory(wasm, session, {
            nativeCapable: typeof chrome.runtime.connectNative === 'function',
        });
        const snap = await wasm.wasm_fetch_vault_with_identities(session, inventory);
        if (snap && snap.refreshed_session) {
            try {
                await (await getModule('storage')).saveSession(snap.refreshed_session);
            } catch {}
            cachedSessionPromise = Promise.resolve(snap.refreshed_session);
        }
        cachedSnapshot = snap;
        return snap;
    })();
    try {
        return await inFlightSnapshot;
    } finally {
        inFlightSnapshot = null;
    }
}

async function ciphersForOrigin(snapshot, origin) {
    const { ciphersForOrigin: match } = await getModule('match');
    return match((snapshot && snapshot.ciphers) || [], origin);
}

function originHost(originOrUrl) {
    try {
        return new URL(originOrUrl).hostname.toLowerCase();
    } catch {
        return String(originOrUrl || '').toLowerCase();
    }
}

const TAP_PAGE = 'tap.html';
const TAP_TIMEOUT_MS = 120_000;
const pendingTaps = new Map();

function newRequestId() {
    const b = crypto.getRandomValues(new Uint8Array(16));
    let s = '';
    for (const x of b) s += x.toString(16).padStart(2, '0');
    return s;
}

function settleTap(requestId, result) {
    const entry = pendingTaps.get(requestId);
    if (!entry) return;
    pendingTaps.delete(requestId);
    if (entry.timer) clearTimeout(entry.timer);
    if (entry.windowId != null && chrome.windows && chrome.windows.remove) {
        try { chrome.windows.remove(entry.windowId, () => void chrome.runtime.lastError); } catch {}
    }
    entry.resolve(result);
}

function brokerHardwareTap(request) {
    if (!chrome.windows || typeof chrome.windows.create !== 'function') {
        return Promise.resolve({
            ok: false,
            error: 'Use the Ragewarden extension popup to authorize this.',
        });
    }
    const requestId = newRequestId();
    const url = chrome.runtime.getURL(`${TAP_PAGE}?req=${encodeURIComponent(requestId)}`);
    return new Promise((resolve) => {
        const entry = { request, resolve, windowId: null, claimed: false, timer: null };
        entry.timer = setTimeout(() => settleTap(requestId, {
            ok: false,
            error: 'hardware tap timed out; nothing was decrypted',
        }), TAP_TIMEOUT_MS);
        pendingTaps.set(requestId, entry);
        try {
            chrome.windows.create(
                { url, type: 'popup', width: 460, height: 420, focused: true },
                (win) => {
                    const err = chrome.runtime.lastError;
                    if (err || !win) {
                        settleTap(requestId, {
                            ok: false,
                            error: `could not open the authorization window: ${(err && err.message) || 'unknown'}`,
                        });
                        return;
                    }
                    const e = pendingTaps.get(requestId);
                    if (e) e.windowId = win.id;
                },
            );
        } catch (e) {
            settleTap(requestId, {
                ok: false,
                error: `could not open the authorization window: ${(e && e.message) || String(e)}`,
            });
        }
    });
}

if (chrome.windows && chrome.windows.onRemoved) {
    chrome.windows.onRemoved.addListener((windowId) => {
        for (const [id, entry] of pendingTaps) {
            if (entry.windowId === windowId) {
                entry.windowId = null;
                settleTap(id, {
                    ok: false,
                    error: 'authorization window closed before a tap was completed',
                });
            }
        }
    });
}

function isExtensionPageSender(sender) {
    if (!sender || sender.id !== chrome.runtime.id) return false;
    const url = sender.url || '';
    if (!url) return false;
    return url.startsWith(chrome.runtime.getURL(''));
}

function isTapPageSender(sender) {
    return isExtensionPageSender(sender)
        && (sender.url || '').startsWith(chrome.runtime.getURL(TAP_PAGE));
}

/**
 * Where a fill lands, as the tap window names it. A login form inside a frame is
 * named by the frame's own origin -- the one its ciphers were matched against --
 * and by the page that embeds it.
 */
function frameDestination(sender, origin) {
    const host = originHost(origin);
    if (!sender.frameId) return host;
    let top = '';
    try { top = new URL(sender.tab && sender.tab.url ? sender.tab.url : '').hostname.toLowerCase(); } catch {}
    return top && top !== host ? `${host} (in a frame on ${top})` : host;
}

function senderOrigin(sender) {
    if (!sender) return '';
    if (sender.origin) return sender.origin;
    try {
        return new URL(sender.url || '').origin;
    } catch {
        return '';
    }
}

/*
 * The last reader of a receipt decides. The tap page checked these receipts,
 * but they crossed a message port to get here, so every one is re-validated
 * against the request this window was opened for: real backend (or an allowed
 * mock), user presence and verification read back out of authenticatorData, a
 * challenge bound to this action/item/destination, and -- when this profile
 * stored the credential's public key at enrolment -- the signature itself.
 */
async function validateReceipts(receipts, request) {
    const { verifyReceipt, publicKeysFromRecords } = await getModule('receipts');
    const { loadAllPasskeyRecipients } = await getModule('passkeys');
    const publicKeys = publicKeysFromRecords(await loadAllPasskeyRecipients());
    const purpose = {
        action: request.action, destination: request.destination,
        cipherId: request.cipherId, origin: request.origin,
    };
    for (const r of receipts) {
        await verifyReceipt(r, {
            allowMock: BUILD_FLAGS.allowMockTap === true, request: purpose, publicKeys,
        });
    }
}

/*
 * Safari has no native-messaging host manifests: runtime.sendNativeMessage
 * reaches the extension's own app (safari-host-app), whose handler relays the
 * same framed request to the rageterm it bundles and returns its reply.
 */
function safariRelay() {
    return typeof chrome.runtime.connectNative !== 'function'
        && typeof chrome.runtime.sendNativeMessage === 'function';
}

function relayToApp(message) {
    return new Promise((resolve) => {
        let done = false;
        const timer = setTimeout(() => { if (!done) { done = true; resolve(null); } }, TAP_TIMEOUT_MS);
        try {
            chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, message, (reply) => {
                if (done) return;
                done = true;
                clearTimeout(timer);
                resolve(reply || null);
            });
        } catch {
            done = true;
            clearTimeout(timer);
            resolve(null);
        }
    });
}

async function maybeNativeHostUnwrap(stanza, context, challenge = '') {
    if (safariRelay()) {
        const msg = await relayToApp({ method: 'unwrap_stanza', stanza, context, challenge });
        return msg && msg.ok && msg.file_key ? { fileKeyB64: msg.file_key, tap: msg.tap } : null;
    }
    if (!chrome.runtime.connectNative) return null;
    return new Promise((resolve) => {
        let port;
        try {
            port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
        } catch {
            resolve(null);
            return;
        }
        let settled = false;
        let timer = null;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            try { port.disconnect(); } catch {}
            resolve(value);
        };
        port.onMessage.addListener(msg => {
            // The host's `tap` attestation is what glue/hardware-tap.js turns
            // into a receipt; without it every native unlock fails closed.
            if (msg && msg.ok && msg.file_key) {
                finish({ fileKeyB64: msg.file_key, tap: msg.tap });
            }
            else finish(null);
        });
        port.onDisconnect.addListener(() => {
            if (!settled) finish(null);
        });
        try {
            port.postMessage({
                method: 'unwrap_stanza',
                stanza,
                context,
                challenge,
            });
        } catch {
            finish(null);
        }
        timer = setTimeout(() => finish(null), TAP_TIMEOUT_MS);
    });
}

async function lockNow() {
    try { await (await getModule('storage')).lockSession(); } catch {}
    invalidateSession();
}

if (chrome.alarms) {
    chrome.alarms.create(AUTOLOCK_ALARM, { periodInMinutes: 1 });
    chrome.alarms.onAlarm.addListener(async (alarm) => {
        if (alarm.name === AUTOLOCK_ALARM) {
            try {
                if (await (await getModule('storage')).lockIfIdle()) invalidateSession();
            } catch {}
        } else if (alarm.name === CLIPBOARD_ALARM) {
            await clearClipboardFromWorker();
        }
    });
}

if (chrome.idle && chrome.idle.onStateChanged) {
    chrome.idle.onStateChanged.addListener((state) => {
        if (state === 'locked') lockNow();
    });
}

async function ensureOffscreenClipboard() {
    if (!chrome.offscreen) return false;
    const url = chrome.runtime.getURL(OFFSCREEN_DOC);
    if (chrome.runtime.getContexts) {
        const existing = await chrome.runtime.getContexts({
            contextTypes: ['OFFSCREEN_DOCUMENT'], documentUrls: [url],
        });
        if (existing && existing.length > 0) return true;
    }
    try {
        await chrome.offscreen.createDocument({
            url: OFFSCREEN_DOC,
            reasons: ['CLIPBOARD'],
            justification: 'Overwrite a copied secret after the clipboard timeout.',
        });
    } catch (e) {
        if (!/single offscreen/i.test(String(e && e.message))) throw e;
    }
    return true;
}

/*
 * Runs in the worker, so the wipe happens even after the popup that copied
 * the secret has closed. Chromium writes from an offscreen document; Firefox's
 * event page has a DOM of its own.
 */
async function clearClipboardFromWorker() {
    try {
        if (await ensureOffscreenClipboard()) {
            await chrome.runtime.sendMessage({ target: 'offscreen-clipboard', kind: 'clear' });
            try { await chrome.offscreen.closeDocument(); } catch {}
            return true;
        }
        if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(' ');
            return true;
        }
        if (typeof document !== 'undefined' && document.body) {
            const ta = document.createElement('textarea');
            ta.value = ' ';
            document.body.appendChild(ta);
            ta.select();
            const ok = document.execCommand('copy');
            ta.remove();
            return ok;
        }
    } catch (e) {
        console.warn('[ragewarden] clipboard clear failed:', e);
    }
    return false;
}

let relayBroker = null;
async function relay() {
    if (!relayBroker) relayBroker = (await getModule('relay')).createRelayBroker({ tabs: chrome.tabs });
    return relayBroker;
}

if (chrome.tabs && chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener((tabId) => {
        if (relayBroker) relayBroker.tabClosed(tabId);
    });
}

async function handleMessage(msg, sender) {
    if (!msg || typeof msg !== 'object') return { ok: false, error: 'bad message' };
    if (!sender || sender.id !== chrome.runtime.id) {
        return { ok: false, error: 'rejected: message did not originate from this extension' };
    }
    const fromTab = !!(sender && sender.tab) && !isExtensionPageSender(sender);
    const EXTENSION_PAGE_ONLY = new Set([
        'vault.status', 'vault.fetch', 'vault.invalidate', 'vault.lock', 'native.probe',
        'native.unwrap', 'tap.claim', 'tap.complete', 'tap.fail',
        'clipboard.scheduleClear', 'clipboard.cancelClear', 'relay.prf',
    ]);
    if (EXTENSION_PAGE_ONLY.has(msg.kind) && !isExtensionPageSender(sender)) {
        return { ok: false, error: `rejected: ${msg.kind} is not available to content scripts` };
    }
    switch (msg.kind) {
        case 'vault.status': {
            const session = await getSession();
            return {
                ok: true,
                signedIn: !!session,
                email: session?.email ?? null,
            };
        }
        case 'vault.fetch': {
            const session = await getSession();
            if (!session) return { ok: false, error: 'Ragewarden is locked' };
            const snap = await fetchSnapshot(!!msg.force);
            return {
                ok: true,
                ciphers: snap.ciphers || [],
                folders: snap.folders || [],
            };
        }
        case 'vault.lookup': {
            const session = await getSession();
            if (!session) return { ok: true, matches: [] };
            const origin = fromTab ? senderOrigin(sender) : (msg.origin || '');
            if (fromTab && !origin) {
                return { ok: false, error: 'rejected: could not determine the sender origin' };
            }
            try {
                const snap = await fetchSnapshot();
                return { ok: true, matches: await ciphersForOrigin(snap, origin) };
            } catch (err) {
                return { ok: false, error: (err && err.message) || String(err) };
            }
        }
        case 'vault.unlock': {
            const session = await getSession();
            if (!session) {
                return { ok: false, error: 'Ragewarden is locked -- unlock it from the toolbar' };
            }
            const action = msg.action || 'autofill';
            const cipherId = msg.cipherId;
            if (!cipherId) return { ok: false, error: 'cipherId required' };

            const origin = fromTab ? senderOrigin(sender) : (msg.origin || '');
            if (fromTab && !origin) {
                return { ok: false, error: 'rejected: could not determine the sender origin' };
            }

            let snap;
            try {
                snap = await fetchSnapshot();
            } catch (err) {
                return { ok: false, error: (err && err.message) || String(err) };
            }
            const cipher = (snap.ciphers || []).find(c => c.id === cipherId);
            if (!cipher) return { ok: false, error: `unknown cipher ${cipherId}` };

            if (fromTab) {
                const allowed = (await ciphersForOrigin(snap, origin)).some(c => c.id === cipherId);
                if (!allowed) {
                    return {
                        ok: false,
                        error: `rejected: cipher ${cipherId} is not registered for ${origin}`,
                    };
                }
            }
            try { await (await getModule('storage')).touchSession(); } catch {}

            const destination = fromTab ? frameDestination(sender, origin) : (msg.destination || '');
            const result = await brokerHardwareTap({
                action,
                cipherId,
                cipherName: cipher.name || '',
                rage: !!cipher.rage,
                username: cipher.username || '',
                fieldName: msg.fieldName === 'username' ? 'username' : 'password',
                destination,
                origin,
                tabId: fromTab ? sender.tab.id : null,
                cipher,
            });
            if (!result.ok) {
                return { ok: false, error: result.error || 'hardware tap did not complete' };
            }
            return {
                ok: true,
                action,
                destination,
                plaintext: result.plaintext,
                ceremony: result.ceremony,
            };
        }
        case 'tap.claim': {
            if (!isTapPageSender(sender)) {
                return { ok: false, error: 'rejected: tap.claim is only for the tap page' };
            }
            const entry = pendingTaps.get(msg.requestId);
            if (!entry) return { ok: false, error: 'no such authorization request' };
            if (entry.claimed) return { ok: false, error: 'authorization request already claimed' };
            entry.claimed = true;
            return { ok: true, request: entry.request };
        }
        case 'tap.complete': {
            if (!isTapPageSender(sender)) {
                return { ok: false, error: 'rejected: tap.complete is only for the tap page' };
            }
            const entry = pendingTaps.get(msg.requestId);
            if (!entry) return { ok: false, error: 'no such authorization request' };
            const receipts = Array.isArray(msg.receipts) ? msg.receipts : [];
            if (receipts.length === 0) {
                settleTap(msg.requestId, {
                    ok: false,
                    error: 'tap page returned no tap receipt; refusing to release plaintext',
                });
                return { ok: false, error: 'no tap receipt' };
            }
            try {
                await validateReceipts(receipts, entry.request);
            } catch (err) {
                const error = `refusing to release plaintext: ${(err && err.message) || err}`;
                settleTap(msg.requestId, { ok: false, error });
                return { ok: false, error };
            }
            settleTap(msg.requestId, {
                ok: true,
                plaintext: msg.plaintext,
                ceremony: {
                    taps: receipts.length,
                    mock: receipts.some(r => r && r.mock === true),
                    backends: receipts.map(r => (r && (r.tapBackend || r.backend)) || 'unknown'),
                },
            });
            return { ok: true };
        }
        case 'tap.fail': {
            if (!isTapPageSender(sender)) {
                return { ok: false, error: 'rejected: tap.fail is only for the tap page' };
            }
            settleTap(msg.requestId, {
                ok: false,
                error: msg.error || msg.code || 'hardware tap failed',
            });
            return { ok: true };
        }
        case 'vault.invalidate': {
            invalidateSession();
            return { ok: true };
        }
        case 'vault.lock': {
            await lockNow();
            return { ok: true };
        }
        case 'clipboard.scheduleClear': {
            const seconds = Math.min(Math.max(Number(msg.seconds) || 30, 5), 600);
            const when = Date.now() + seconds * 1000;
            if (chrome.alarms) chrome.alarms.create(CLIPBOARD_ALARM, { when });
            else setTimeout(clearClipboardFromWorker, seconds * 1000);
            return { ok: true, clearAt: when };
        }
        case 'clipboard.cancelClear': {
            if (chrome.alarms) chrome.alarms.clear(CLIPBOARD_ALARM);
            return { ok: true };
        }
        case 'native.probe': {
            if (safariRelay()) {
                const reply = await relayToApp({ method: 'probe' });
                return { ok: true, available: !!reply, host: NATIVE_HOST_NAME, ...(reply || {}) };
            }
            const ok = typeof chrome.runtime.connectNative === 'function';
            return { ok: true, available: ok, host: NATIVE_HOST_NAME };
        }
        case 'relay.prf': {
            const value = await (await relay()).request({
                purpose: msg.purpose || {},
                credentials: Array.isArray(msg.credentials) ? msg.credentials : [],
                action: String(msg.action || ''),
                destination: String(msg.destination || ''),
            });
            return { ok: true, ...value };
        }
        // From relay-content.js; the broker checks the tab, its URL and the nonce.
        case 'relay.hello':
            return { ok: true, request: await (await relay()).hello(msg, sender) };
        case 'relay.result':
            await (await relay()).result(msg, sender);
            return { ok: true };
        case 'native.unwrap': {
            const fk = await maybeNativeHostUnwrap(msg.stanza || {}, msg.context || {}, msg.challenge || '');
            return { ok: !!fk, ...(fk || {}) };
        }
        default:
            return { ok: false, error: `unknown kind: ${msg.kind}` };
    }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.target === 'offscreen-clipboard') return false;
    handleMessage(msg, sender).then(r => sendResponse(r)).catch(err => {
        sendResponse({ ok: false, error: (err && err.message) || String(err) });
    });
    return true;
});

chrome.runtime.onInstalled.addListener(() => {
    getWasm().catch(() => {});
});

if (chrome.runtime.onStartup) {
    chrome.runtime.onStartup.addListener(() => {
        getWasm().catch(() => {});
    });
}

// test-hooks:begin
if (BUILD_FLAGS.testHooks === true) {
    self.__ragewardenBackground = {
        handleMessage,
        ciphersForOrigin,
        invalidateSession,
        validateReceipts,
        clearClipboardFromWorker,
        relay,
    };
    // WebDriver BiDi may not navigate a tab to moz-extension://, so a test
    // build opens its own popup in a tab for tests/firefox-bidi.mjs to drive.
    if (typeof browser !== 'undefined' && typeof browser.runtime.getBrowserInfo === 'function') {
        browser.runtime.onInstalled.addListener(() => {
            browser.tabs.create({ url: browser.runtime.getURL('popup/index.html') });
        });
    }
}
// test-hooks:end
