const LOCAL_KEY = 'ragewarden:sessionEnvelope';
const SESSION_KEY = 'ragewarden:envelopeKey';
const DEVICE_KEY = 'ragewarden:deviceId';

const subtle = (typeof crypto !== 'undefined' && crypto.subtle) ? crypto.subtle : null;

const ext = (() => {
    if (typeof chrome !== 'undefined' && chrome && chrome.storage) return chrome;
    if (typeof browser !== 'undefined' && browser && browser.storage) return browser;
    return null;
})();

function chromeLocal() {
    return (ext && ext.storage && ext.storage.local) || null;
}
function chromeSession() {
    return (ext && ext.storage && ext.storage.session) || null;
}

async function storageGet(area, key) {
    if (area && typeof area.get === 'function') {
        return new Promise((resolve, reject) => {
            try {
                area.get([key], (items) => {
                    const lastErr = ext?.runtime?.lastError;
                    if (lastErr) reject(new Error(lastErr.message));
                    else resolve(items?.[key] ?? null);
                });
            } catch (e) { reject(e); }
        });
    }
    const fallback = (key === LOCAL_KEY) ? localStorage : sessionStorage;
    const raw = fallback.getItem(key);
    return raw ? JSON.parse(raw) : null;
}

async function storageSet(area, key, value) {
    if (area && typeof area.set === 'function') {
        return new Promise((resolve, reject) => {
            try {
                area.set({ [key]: value }, () => {
                    const lastErr = ext?.runtime?.lastError;
                    if (lastErr) reject(new Error(lastErr.message));
                    else resolve();
                });
            } catch (e) { reject(e); }
        });
    }
    const fallback = (key === LOCAL_KEY) ? localStorage : sessionStorage;
    fallback.setItem(key, JSON.stringify(value));
}

async function storageRemove(area, key) {
    if (area && typeof area.remove === 'function') {
        return new Promise((resolve, reject) => {
            try {
                area.remove([key], () => {
                    const lastErr = ext?.runtime?.lastError;
                    if (lastErr) reject(new Error(lastErr.message));
                    else resolve();
                });
            } catch (e) { reject(e); }
        });
    }
    const fallback = (key === LOCAL_KEY) ? localStorage : sessionStorage;
    fallback.removeItem(key);
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

async function loadOrCreateEnvelopeKey() {
    if (!subtle) throw new Error('SubtleCrypto unavailable; cannot persist session');

    const existing = await storageGet(chromeSession(), SESSION_KEY);
    if (existing && typeof existing === 'string') {
        const raw = b64ToBytes(existing);
        return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    }
    const raw = crypto.getRandomValues(new Uint8Array(32));
    await storageSet(chromeSession(), SESSION_KEY, bytesToB64(raw));
    return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function saveSession(sessionBlob) {
    const key = await loadOrCreateEnvelopeKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(sessionBlob));
    const ciphertext = new Uint8Array(
        await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext),
    );
    await storageSet(chromeLocal(), LOCAL_KEY, {
        v: 1,
        iv: bytesToB64(iv),
        ct: bytesToB64(ciphertext),
    });
}

export async function loadSession() {
    if (!subtle) return null;
    const [env, sessionKeyB64] = await Promise.all([
        storageGet(chromeLocal(), LOCAL_KEY),
        storageGet(chromeSession(), SESSION_KEY),
    ]);
    if (!env || env.v !== 1) return null;
    if (!sessionKeyB64 || typeof sessionKeyB64 !== 'string') {
        await storageRemove(chromeLocal(), LOCAL_KEY);
        return null;
    }
    let key;
    try {
        const raw = b64ToBytes(sessionKeyB64);
        key = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    } catch {
        return null;
    }
    try {
        const iv = b64ToBytes(env.iv);
        const ct = b64ToBytes(env.ct);
        const pt = new Uint8Array(
            await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct),
        );
        return JSON.parse(new TextDecoder().decode(pt));
    } catch {
        await storageRemove(chromeLocal(), LOCAL_KEY);
        return null;
    }
}

export async function clearSession() {
    await storageRemove(chromeLocal(), LOCAL_KEY);
    await storageRemove(chromeSession(), SESSION_KEY);
}

/*
 * A stable per-install device identifier. Generated once and persisted so every
 * login re-presents the same device to the server, instead of minting a fresh
 * random id per sign-in (which bloats the server device table and, on servers
 * that bind access tokens to a device, breaks sync as soon as the next login
 * supersedes the previous device). Survives session clears -- it is not secret
 * and re-generating it would defeat its purpose.
 */
export async function getDeviceId() {
    const local = chromeLocal();
    const existing = await storageGet(local, DEVICE_KEY);
    if (existing && typeof existing === 'string') return existing;
    const id = (typeof crypto !== 'undefined' && crypto.randomUUID)
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    await storageSet(local, DEVICE_KEY, id);
    return id;
}
