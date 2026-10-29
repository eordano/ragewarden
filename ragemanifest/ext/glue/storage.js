import { b64ToBytes, bytesToB64 } from './b64.js';

const LOCAL_KEY = 'ragewarden:sessionEnvelope';
const SESSION_KEY = 'ragewarden:envelopeKey';
const DEVICE_KEY = 'ragewarden:deviceId';
const AUTOLOCK_KEY = 'ragewarden:autoLockMinutes';

export const STORAGE_KEYS = Object.freeze({
    envelope: LOCAL_KEY, unlockKey: SESSION_KEY, autoLock: AUTOLOCK_KEY,
});

export const DEFAULT_AUTOLOCK_MINUTES = 15;
const LOCK_KDF = Object.freeze({ alg: 'PBKDF2-SHA256', iterations: 600_000 });

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

function fallbackFor(key) {
    if (key === SESSION_KEY) return typeof sessionStorage !== 'undefined' ? sessionStorage : null;
    return typeof localStorage !== 'undefined' ? localStorage : null;
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
    const raw = fallbackFor(key)?.getItem(key);
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
    fallbackFor(key)?.setItem(key, JSON.stringify(value));
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
    fallbackFor(key)?.removeItem(key);
}

function requireSubtle() {
    if (!subtle) throw new Error('SubtleCrypto unavailable; cannot protect the session');
    return subtle;
}

async function importAes(raw, usages) {
    return requireSubtle().importKey('raw', raw, { name: 'AES-GCM' }, false, usages);
}

async function aesSeal(raw, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await importAes(raw, ['encrypt']);
    const ct = new Uint8Array(await requireSubtle().encrypt({ name: 'AES-GCM', iv }, key, plaintext));
    return { iv: bytesToB64(iv), ct: bytesToB64(ct) };
}

async function aesOpen(raw, box) {
    const key = await importAes(raw, ['decrypt']);
    return new Uint8Array(await requireSubtle().decrypt(
        { name: 'AES-GCM', iv: b64ToBytes(box.iv) }, key, b64ToBytes(box.ct),
    ));
}

async function derivePasswordKey(password, kdf) {
    if (!kdf || kdf.alg !== LOCK_KDF.alg) throw new Error(`unsupported lock KDF ${kdf && kdf.alg}`);
    const base = await requireSubtle().importKey(
        'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'],
    );
    const bits = await requireSubtle().deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(kdf.salt), iterations: kdf.iterations },
        base, 256,
    );
    return new Uint8Array(bits);
}

export async function autoLockMinutes() {
    const v = await storageGet(chromeLocal(), AUTOLOCK_KEY);
    const n = Number(v);
    return Number.isFinite(n) && n >= 1 && n <= 24 * 60 ? n : DEFAULT_AUTOLOCK_MINUTES;
}

export async function setAutoLockMinutes(minutes) {
    const n = Number(minutes);
    if (!Number.isFinite(n) || n < 1 || n > 24 * 60) {
        throw new Error('auto-lock must be between 1 minute and 24 hours');
    }
    await storageSet(chromeLocal(), AUTOLOCK_KEY, n);
}

async function readUnlockKey() {
    const v = await storageGet(chromeSession(), SESSION_KEY);
    if (!v) return null;
    if (typeof v === 'string') return { v: 1, raw: b64ToBytes(v) };
    if (v.v === 2 && typeof v.k === 'string') {
        return { v: 2, raw: b64ToBytes(v.k), deadline: Number(v.deadline) || 0 };
    }
    return null;
}

async function writeUnlockKey(raw) {
    const deadline = Date.now() + (await autoLockMinutes()) * 60_000;
    await storageSet(chromeSession(), SESSION_KEY, { v: 2, k: bytesToB64(raw), deadline });
}

export async function lockedEmail() {
    const env = await storageGet(chromeLocal(), LOCAL_KEY);
    return (env && typeof env.email === 'string') ? env.email : '';
}

export async function lockState() {
    const env = await storageGet(chromeLocal(), LOCAL_KEY);
    if (!env) return 'signed-out';
    const key = await readUnlockKey();
    if (env.v === 1) return key && key.v === 1 ? 'legacy-locked' : 'signed-out';
    if (env.v !== 2) return 'signed-out';
    if (!key || key.v !== 2) return 'locked';
    if (key.deadline && Date.now() > key.deadline) return 'locked';
    return 'unlocked';
}

/*
 * Envelope v2: the session is sealed under a random data key (DK); DK is
 * sealed under a key derived from the master password (PBKDF2-SHA256, 600k
 * iterations, random salt). Unlocking is local and works offline. While
 * unlocked, DK sits in storage.session (memory only, extension contexts only)
 * with an idle deadline; locking removes it, after which nothing on this
 * machine opens the session without the password. A v1 envelope (a raw key
 * beside it) is upgraded on the first unlock that proves the password.
 */
export async function saveSession(sessionBlob, { password } = {}) {
    const plaintext = new TextEncoder().encode(JSON.stringify(sessionBlob));
    const env = await storageGet(chromeLocal(), LOCAL_KEY);
    const key = await readUnlockKey();
    if (!password && env && env.v === 2 && key && key.v === 2) {
        const sealed = await aesSeal(key.raw, plaintext);
        await storageSet(chromeLocal(), LOCAL_KEY, {
            ...env, email: String(sessionBlob.email || env.email || ''), iv: sealed.iv, ct: sealed.ct,
        });
        return;
    }
    if (!password) {
        throw new Error('the vault is locked; unlock it before saving the session');
    }
    const dk = crypto.getRandomValues(new Uint8Array(32));
    const kdf = { ...LOCK_KDF, salt: bytesToB64(crypto.getRandomValues(new Uint8Array(16))) };
    const pk = await derivePasswordKey(password, kdf);
    try {
        const wrap = await aesSeal(pk, dk);
        const sealed = await aesSeal(dk, plaintext);
        await storageSet(chromeLocal(), LOCAL_KEY, {
            v: 2, email: String(sessionBlob.email || ''), kdf, wrap, iv: sealed.iv, ct: sealed.ct,
        });
        await writeUnlockKey(dk);
    } finally {
        pk.fill(0);
        dk.fill(0);
    }
}

export async function loadSession() {
    const env = await storageGet(chromeLocal(), LOCAL_KEY);
    if (!env) return null;
    const key = await readUnlockKey();
    if (env.v === 1) {
        if (!key || key.v !== 1) {
            await storageRemove(chromeLocal(), LOCAL_KEY);
            return null;
        }
        try {
            return JSON.parse(new TextDecoder().decode(await aesOpen(key.raw, env)));
        } catch {
            return null;
        }
    }
    if (env.v !== 2 || !key || key.v !== 2) return null;
    if (key.deadline && Date.now() > key.deadline) {
        await lockSession();
        return null;
    }
    try {
        return JSON.parse(new TextDecoder().decode(await aesOpen(key.raw, env)));
    } catch {
        return null;
    }
}

export async function unlockSession(password) {
    if (typeof password !== 'string' || password.length === 0) {
        throw new Error('enter your master password');
    }
    const env = await storageGet(chromeLocal(), LOCAL_KEY);
    if (!env || env.v !== 2) throw new Error('no local vault to unlock -- sign in again');
    const pk = await derivePasswordKey(password, env.kdf);
    let dk;
    try {
        dk = await aesOpen(pk, env.wrap);
    } catch {
        throw Object.assign(new Error('wrong master password'), { code: 'wrong_password' });
    } finally {
        pk.fill(0);
    }
    try {
        const session = JSON.parse(new TextDecoder().decode(await aesOpen(dk, env)));
        await writeUnlockKey(dk);
        return session;
    } finally {
        dk.fill(0);
    }
}

export async function verifyLocalPassword(password) {
    const env = await storageGet(chromeLocal(), LOCAL_KEY);
    if (!env || env.v !== 2) return false;
    const pk = await derivePasswordKey(String(password || ''), env.kdf);
    try {
        (await aesOpen(pk, env.wrap)).fill(0);
        return true;
    } catch {
        return false;
    } finally {
        pk.fill(0);
    }
}

export async function touchSession() {
    const key = await readUnlockKey();
    if (!key || key.v !== 2) return false;
    if (key.deadline && Date.now() > key.deadline) {
        await lockSession();
        return false;
    }
    await writeUnlockKey(key.raw);
    return true;
}

export async function lockIfIdle() {
    const key = await readUnlockKey();
    if (key && key.v === 2 && key.deadline && Date.now() > key.deadline) {
        await lockSession();
        return true;
    }
    return false;
}

export async function lockSession() {
    await storageRemove(chromeSession(), SESSION_KEY);
}

export async function clearSession() {
    await storageRemove(chromeLocal(), LOCAL_KEY);
    await storageRemove(chromeSession(), SESSION_KEY);
}

/*
 * A stable per-install device identifier, so every login presents the same
 * device to the server. Not secret, and kept across sign-outs.
 */
export async function getDeviceId() {
    const local = chromeLocal();
    const existing = await storageGet(local, DEVICE_KEY);
    if (existing && typeof existing === 'string') return existing;
    const id = (typeof crypto !== 'undefined' && crypto.randomUUID)
        ? crypto.randomUUID()
        : `${Date.now()}-${bytesToB64(crypto.getRandomValues(new Uint8Array(8)))}`;
    await storageSet(local, DEVICE_KEY, id);
    return id;
}
