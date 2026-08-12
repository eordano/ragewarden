const KEY = 'ragewarden:audit:v1';
const AUDIT_CAP = 1000;

/*
 * What the log is for: the handful of actions a reader of this log would want
 * to have been told about -- a secret leaving the vault, a recipient changing,
 * an item going away. It is capped at AUDIT_CAP entries, so anything else in
 * here is not free: it evicts those.
 *
 * `ListRecipients` and `Refresh` used to be in this list. Both were emitted by
 * merely *looking* -- opening the Recipients screen logged that the Recipients
 * screen had been opened, and every vault refresh wrote a row carrying the
 * account email. On the one screen that renders this log they buried
 * RevealPassword and DeleteCipher, which are the entries that screen exists to
 * show. Reads that do not decrypt anything do not belong here.
 */
export const KINDS = Object.freeze({
    SetCipher: 'SetCipher',
    EditCipher: 'EditCipher',
    RotateCipher: 'RotateCipher',
    DeleteCipher: 'DeleteCipher',
    CreateFolder: 'CreateFolder',
    RenameFolder: 'RenameFolder',
    DeleteFolder: 'DeleteFolder',
    EnrollRecovery: 'EnrollRecovery',
    EnrollPasskey: 'EnrollPasskey',
    RemoveRecipient: 'RemoveRecipient',
    Logout: 'Logout',
    RevealPassword: 'RevealPassword',
    CopyPassword: 'CopyPassword',
    AutofillPassword: 'AutofillPassword',
});

const VALID_KINDS = new Set(Object.values(KINDS));

const ext = (() => {
    if (typeof chrome !== 'undefined' && chrome && chrome.storage) return chrome;
    if (typeof browser !== 'undefined' && browser && browser.storage) return browser;
    return null;
})();

function localArea() {
    return (ext && ext.storage && ext.storage.local) || null;
}

const memory = { entries: [] };

async function readAll() {
    const area = localArea();
    if (!area || typeof area.get !== 'function') {
        return { entries: memory.entries.slice() };
    }
    return new Promise((resolve) => {
        try {
            area.get([KEY], (items) => {
                const got = items && items[KEY];
                if (got && Array.isArray(got.entries)) resolve({ entries: got.entries });
                else resolve({ entries: [] });
            });
        } catch {
            resolve({ entries: [] });
        }
    });
}

async function writeAll(state) {
    const area = localArea();
    if (!area || typeof area.set !== 'function') {
        memory.entries = state.entries.slice();
        return;
    }
    return new Promise((resolve) => {
        try {
            area.set({ [KEY]: state }, () => {
                resolve();
            });
        } catch {
            resolve();
        }
    });
}

export async function record(entry) {
    try {
        const kind = entry && entry.kind;
        if (!kind || !VALID_KINDS.has(kind)) {
            // eslint-disable-next-line no-console
            console.warn('[ragewarden:audit] dropping entry with unknown kind:', kind);
            return;
        }
        const recorded = {
            recordedAt: Date.now(),
            kind,
            target: typeof entry.target === 'string' ? entry.target : '',
            detail: typeof entry.detail === 'string' ? entry.detail : '',
        };
        const state = await readAll();
        state.entries.unshift(recorded);
        if (state.entries.length > AUDIT_CAP) {
            state.entries.length = AUDIT_CAP;
        }
        await writeAll(state);
    } catch (e) {
        // eslint-disable-next-line no-console
        console.warn('[ragewarden:audit] record failed:', e);
    }
}

export async function tail(limit) {
    const state = await readAll();
    const n = (typeof limit === 'number' && limit > 0) ? Math.min(limit, state.entries.length) : state.entries.length;
    return state.entries.slice(0, n);
}

export async function clear() {
    const area = localArea();
    if (!area || typeof area.remove !== 'function') {
        memory.entries = [];
        return;
    }
    return new Promise((resolve) => {
        try {
            area.remove([KEY], () => resolve());
        } catch {
            resolve();
        }
    });
}
