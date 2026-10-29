/**
 * The derivation parameters each (server, account) had on its last successful
 * login here, kept across sign-outs, so a server that later offers weaker ones
 * is refused before the master password is hashed (core::sync::check_server_kdf).
 */
const KEY = 'ragewarden:kdfPins';

function localArea() {
    const api = (typeof chrome !== 'undefined' && chrome.storage) ? chrome
        : ((typeof browser !== 'undefined' && browser.storage) ? browser : null);
    return api && api.storage && api.storage.local;
}

function read(area) {
    return new Promise((resolve) => {
        if (!area) { resolve({}); return; }
        area.get([KEY], (items) => resolve((items && items[KEY]) || {}));
    });
}

function write(area, value) {
    return new Promise((resolve) => {
        if (!area) { resolve(); return; }
        area.set({ [KEY]: value }, () => resolve());
    });
}

export function pinKey(server, email) {
    return `${new URL(server).origin}|${String(email).trim().toLowerCase()}`;
}

/** KdfParams (core's camelCase shape) from a session JSON's kdf_* fields. */
export function kdfFromSession(session) {
    const s = typeof session === 'string' ? JSON.parse(session) : session;
    if (!s || !Number.isFinite(s.kdf_iterations) || s.kdf_iterations <= 0) return null;
    const pin = { kdf: Number.isFinite(s.kdf_type) ? s.kdf_type : 0, iterations: s.kdf_iterations };
    if (Number.isFinite(s.kdf_memory_mib)) pin.memoryMib = s.kdf_memory_mib;
    if (Number.isFinite(s.kdf_parallelism)) pin.parallelism = s.kdf_parallelism;
    return pin;
}

export async function loadKdfPin(server, email, area = localArea()) {
    return (await read(area))[pinKey(server, email)] || null;
}

export async function saveKdfPinFromSession(server, email, session, area = localArea()) {
    const pin = kdfFromSession(session);
    if (!pin) return null;
    const all = await read(area);
    all[pinKey(server, email)] = pin;
    await write(area, all);
    return pin;
}
