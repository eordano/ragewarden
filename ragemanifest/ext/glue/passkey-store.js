const STORAGE_KEY = 'ragewarden:passkey-recipient';
const SOFTWARE_KEY = 'ragewarden:software-identity';

function chromeLocal() {
    return (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) || null;
}

function localStorageFallback() {
    return (typeof localStorage !== 'undefined') ? localStorage : null;
}

async function readKey(key) {
    const area = chromeLocal();
    if (area) {
        return new Promise((resolve, reject) => {
            try {
                area.get([key], items => {
                    const err = chrome.runtime?.lastError;
                    if (err) reject(new Error(err.message));
                    else resolve(items?.[key] ?? null);
                });
            } catch (e) { reject(e); }
        });
    }
    const fallback = localStorageFallback();
    if (!fallback) return null;
    const raw = fallback.getItem(key);
    return raw ? JSON.parse(raw) : null;
}

async function writeKey(key, value) {
    const area = chromeLocal();
    if (area) {
        return new Promise((resolve, reject) => {
            try {
                area.set({ [key]: value }, () => {
                    const err = chrome.runtime?.lastError;
                    if (err) reject(new Error(err.message)); else resolve();
                });
            } catch (e) { reject(e); }
        });
    }
    const fallback = localStorageFallback();
    if (fallback) fallback.setItem(key, JSON.stringify(value));
}

async function clearKey(key) {
    const area = chromeLocal();
    if (area) {
        return new Promise((resolve, reject) => {
            try {
                area.remove([key], () => {
                    const err = chrome.runtime?.lastError;
                    if (err) reject(new Error(err.message)); else resolve();
                });
            } catch (e) { reject(e); }
        });
    }
    const fallback = localStorageFallback();
    if (fallback) fallback.removeItem(key);
}

const readJson = () => readKey(STORAGE_KEY);
const writeJson = (v) => writeKey(STORAGE_KEY, v);
const clearJson = () => clearKey(STORAGE_KEY);

export async function loadPasskeyRecipient() {
    const v = await readJson();
    if (!v) return null;
    if (Array.isArray(v)) return v.length > 0 ? v[0] : null;
    if (v.kind !== 'passkey_prf') return null;
    return v;
}

export async function loadAllPasskeyRecipients() {
    const v = await readJson();
    if (!v) return [];
    if (Array.isArray(v)) return v.filter(r => r && r.kind === 'passkey_prf');
    if (v.kind === 'passkey_prf') return [v];
    return [];
}

export async function savePasskeyRecipient(record) {
    if (!record || record.kind !== 'passkey_prf') {
        throw new Error('record must be a passkey_prf recipient');
    }
    const existing = await loadAllPasskeyRecipients();
    const next = existing.filter(r => r.credential_id_b64 !== record.credential_id_b64);
    next.push(record);
    await writeJson(next);
}

export async function clearPasskeyRecipient() {
    await clearJson();
}

export async function loadSoftwareIdentity() {
    return readKey(SOFTWARE_KEY);
}

export async function saveSoftwareIdentity(record) {
    if (!record || !record.armored_pubkey
        || !record.wrapped_secret_iv_b64 || !record.wrapped_secret_ct_b64
        || !record.wrap_credential_id_b64 || !record.wrap_salt_b64) {
        throw new Error('software identity record missing fields');
    }
    await writeKey(SOFTWARE_KEY, record);
}

export async function clearSoftwareIdentity() {
    await clearKey(SOFTWARE_KEY);
}
