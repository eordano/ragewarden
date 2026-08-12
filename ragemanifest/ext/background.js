const BUILD_FLAGS = Object.freeze(Object.assign(
    { profile: 'release', allowMockTap: false, forceMockTap: false, testHooks: false },
    (typeof globalThis !== 'undefined' && globalThis.__RAGEWARDEN_BUILD_FLAGS) || {},
));

const STORAGE_LOCAL_KEY = 'ragewarden:sessionEnvelope';
const STORAGE_SESSION_KEY = 'ragewarden:envelopeKey';
const NATIVE_HOST_NAME = 'com.ragewarden.host';

let wasmModulePromise = null;
let cachedSessionPromise = null;
let cachedSnapshot = null;

async function getWasm() {
    if (!wasmModulePromise) {
        const url = chrome.runtime.getURL('wasm/ragemanifest.js');
        wasmModulePromise = (async () => {
            const mod = await import(url);
            if (typeof mod.default === 'function') {
                await mod.default(chrome.runtime.getURL('wasm/ragemanifest_bg.wasm'));
            }
            return mod;
        })();
    }
    return wasmModulePromise;
}

function bytesToB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}
function b64ToBytes(b64) {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
}

async function chromeStorageGet(area, key) {
    return new Promise((resolve, reject) => {
        try {
            area.get([key], items => {
                const err = chrome.runtime.lastError;
                if (err) reject(new Error(err.message)); else resolve(items?.[key] ?? null);
            });
        } catch (e) { reject(e); }
    });
}

async function loadSessionFromDisk() {
    const env = await chromeStorageGet(chrome.storage.local, STORAGE_LOCAL_KEY);
    if (!env || env.v !== 1) return null;
    const rawKeyB64 = await chromeStorageGet(chrome.storage.session, STORAGE_SESSION_KEY);
    if (!rawKeyB64) return null;
    try {
        const keyBytes = b64ToBytes(rawKeyB64);
        const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
        const pt = new Uint8Array(await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: b64ToBytes(env.iv) }, key, b64ToBytes(env.ct),
        ));
        return JSON.parse(new TextDecoder().decode(pt));
    } catch {
        return null;
    }
}

function getSession() {
    if (!cachedSessionPromise) cachedSessionPromise = loadSessionFromDisk();
    return cachedSessionPromise;
}

function invalidateSession() {
    cachedSessionPromise = null;
    cachedSnapshot = null;
    inFlightSnapshot = null;
    for (const id of Array.from(pendingTaps.keys())) {
        settleTap(id, { ok: false, error: 'session invalidated while awaiting a hardware tap' });
    }
}

let inFlightSnapshot = null;

async function fetchSnapshot(force = false) {
    if (cachedSnapshot && !force) return cachedSnapshot;
    if (inFlightSnapshot && !force) return inFlightSnapshot;
    inFlightSnapshot = (async () => {
        const session = await getSession();
        if (!session) throw new Error('not signed in');
        const wasm = await getWasm();
        const snap = await wasm.wasm_fetch_vault(session);
        cachedSnapshot = snap;
        return snap;
    })();
    try {
        return await inFlightSnapshot;
    } finally {
        inFlightSnapshot = null;
    }
}

function originHost(originOrUrl) {
    try {
        return new URL(originOrUrl).hostname.toLowerCase();
    } catch {
        return String(originOrUrl || '').toLowerCase();
    }
}

function eTld1Hint(host) {
    if (!host) return '';
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    return parts.slice(-2).join('.');
}

function ciphersForOrigin(snapshot, origin) {
    const host = originHost(origin);
    const baseDomain = eTld1Hint(host);
    const out = [];
    for (const c of snapshot.ciphers || []) {
        if (c.kind && c.kind !== 'login') continue;
        const candidate = (c.site || '').toLowerCase();
        if (!candidate) continue;
        const candHost = originHost(candidate.startsWith('http') ? candidate : `https://${candidate}`);
        if (!candHost) continue;
        if (candHost === host || candHost === baseDomain || host.endsWith(`.${candHost}`)) {
            out.push({
                id: c.id,
                name: c.name,
                username: c.username || null,
                site: c.site || null,
                rage: !!c.rage,
            });
        }
    }
    return out;
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
        // content.js prints this string verbatim into the page, so it carries the
        // one thing the reader can act on. Why the worker cannot raise the window
        // itself is a fact about service workers, not about their login.
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

function senderOrigin(sender) {
    if (!sender) return '';
    if (sender.origin) return sender.origin;
    try {
        return new URL(sender.url || '').origin;
    } catch {
        return '';
    }
}

async function maybeNativeHostUnwrap(stanza, context) {
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
        const finish = (value) => { if (!settled) { settled = true; try { port.disconnect(); } catch {} resolve(value); } };
        port.onMessage.addListener(msg => {
            // Forward `tap` as well as the key. The host's attestation block
            // (rageterm TapAttestation: backend/touched/verified/device/slot/at)
            // is what glue/hardware-tap.js turns into a receipt, and
            // assertReceiptIsRealTap refuses a native unwrap that arrives
            // without one. Dropping it here -- as this line did -- makes every
            // hardware unlock fail closed with "the native host replied without
            // a `tap` block", which is safe but indistinguishable from having
            // no key at all.
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
            });
        } catch {
            finish(null);
        }
        setTimeout(() => finish(null), 30_000);
    });
}

async function handleMessage(msg, sender) {
    if (!msg || typeof msg !== 'object') return { ok: false, error: 'bad message' };
    if (!sender || sender.id !== chrome.runtime.id) {
        return { ok: false, error: 'rejected: message did not originate from this extension' };
    }
    const fromTab = !!(sender && sender.tab) && !isExtensionPageSender(sender);
    if (fromTab && sender.frameId !== undefined && sender.frameId !== 0) {
        return { ok: false, error: 'rejected: subframe senders may not drive the vault' };
    }
    const EXTENSION_PAGE_ONLY = new Set([
        'vault.status', 'vault.fetch', 'vault.invalidate', 'vault.enroll', 'native.probe',
        'native.unwrap', 'tap.claim', 'tap.complete', 'tap.fail',
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
            if (!session) return { ok: false, error: 'not signed in' };
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
                return { ok: true, matches: ciphersForOrigin(snap, origin) };
            } catch (err) {
                return { ok: false, error: (err && err.message) || String(err) };
            }
        }
        case 'vault.unlock': {
            const session = await getSession();
            if (!session) return { ok: false, error: 'not signed in' };
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
                const allowed = ciphersForOrigin(snap, origin).some(c => c.id === cipherId);
                if (!allowed) {
                    return {
                        ok: false,
                        error: `rejected: cipher ${cipherId} is not registered for ${origin}`,
                    };
                }
            }

            const destination = fromTab ? originHost(origin) : (msg.destination || '');
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
        case 'vault.enroll': {
            // Enrolment runs its WebAuthn ceremonies in the focused tap window
            // (the side panel is not a reliable WebAuthn context). No cipher and
            // no plaintext are involved -- the window returns an enrollment
            // record which the caller publishes to the registry.
            const result = await brokerHardwareTap({
                action: 'enroll',
                destination: 'this browser',
                cipherName: msg.label || 'Primary passkey',
                rpId: msg.rpId || null,
                label: msg.label || 'Primary passkey',
            });
            if (!result.ok) {
                return { ok: false, error: result.error || 'enrolment did not complete' };
            }
            return { ok: true, enrollment: result.enrollment };
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
            // Enrolment returns a record, not plaintext, so it does not go through
            // the receipt/plaintext gate below (there is no secret to release).
            if (entry.request && entry.request.action === 'enroll') {
                if (!msg.enrollment) {
                    settleTap(msg.requestId, {
                        ok: false,
                        error: 'enrolment produced no record',
                    });
                    return { ok: false, error: 'no enrollment payload' };
                }
                settleTap(msg.requestId, { ok: true, enrollment: msg.enrollment });
                return { ok: true };
            }
            const receipts = Array.isArray(msg.receipts) ? msg.receipts : [];
            if (receipts.length === 0) {
                settleTap(msg.requestId, {
                    ok: false,
                    error: 'tap page returned no tap receipt; refusing to release plaintext',
                });
                return { ok: false, error: 'no tap receipt' };
            }
            const mock = receipts.some(r => r && r.mock === true);
            settleTap(msg.requestId, {
                ok: true,
                plaintext: msg.plaintext,
                ceremony: {
                    taps: receipts.length,
                    mock,
                    backends: receipts.map(r => (r && r.backend) || 'unknown'),
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
        case 'native.probe': {
            const ok = typeof chrome.runtime.connectNative === 'function';
            return { ok: true, available: ok, host: NATIVE_HOST_NAME };
        }
        case 'native.unwrap': {
            const fk = await maybeNativeHostUnwrap(msg.stanza || {}, msg.context || {});
            return { ok: !!fk, ...(fk || {}) };
        }
        default:
            return { ok: false, error: `unknown kind: ${msg.kind}` };
    }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
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


if (BUILD_FLAGS.testHooks === true) {
    self.__ragewardenBackground = {
        handleMessage,
        ciphersForOrigin,
        invalidateSession,
    };
}
