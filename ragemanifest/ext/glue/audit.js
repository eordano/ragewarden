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
/*
 * The names are core's shared audit vocabulary (core/tests/vectors/
 * audit_vocabulary_v1.json), so rageterm, ragedroid and this log speak the same
 * words; entries written under the older browser names are read back under
 * the new ones.
 */
export const KINDS = Object.freeze({
    Reveal: 'Reveal',
    Copy: 'Copy',
    Autofill: 'Autofill',
    Totp: 'Totp',
    Set: 'Set',
    Update: 'Update',
    Rotate: 'Rotate',
    Delete: 'Delete',
    CreateFolder: 'CreateFolder',
    RenameFolder: 'RenameFolder',
    DeleteFolder: 'DeleteFolder',
    EnrollIdentity: 'EnrollIdentity',
    RemoveRecipient: 'RemoveRecipient',
    Recover: 'Recover',
    BulkProtect: 'BulkProtect',
    Login: 'Login',
    Logout: 'Logout',
});

export const LEGACY_NAMES = Object.freeze({
    AutofillPassword: 'Autofill',
    CopyPassword: 'Copy',
    DeleteCipher: 'Delete',
    EditCipher: 'Update',
    Enroll: 'EnrollIdentity',
    EnrollPasskey: 'EnrollIdentity',
    EnrollRecovery: 'EnrollIdentity',
    RecoverFromPhrase: 'Recover',
    RevealPassword: 'Reveal',
    RotateCipher: 'Rotate',
    SetCipher: 'Set',
});

export const RESULTS = Object.freeze({ ok: 'ok', declined: 'declined', failed: 'failed' });

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

let writeChain = Promise.resolve();

function str(v) {
    return typeof v === 'string' ? v : '';
}

/*
 * Writes are serialised through one chain: record() is a read-modify-write of a
 * single storage key, and two unserialised records would each drop the other.
 * Callers record the OUTCOME (ok / declined / failed, with the error code and
 * which backend produced the tap), never the intent.
 */
export function record(entry) {
    const kind = entry && entry.kind;
    if (!kind || !VALID_KINDS.has(kind)) {
        console.warn('[ragewarden:audit] dropping entry with unknown kind:', kind);
        return writeChain;
    }
    const recorded = {
        recordedAt: Date.now(),
        kind,
        target: str(entry.target),
        detail: str(entry.detail),
        result: Object.values(RESULTS).includes(entry.result) ? entry.result : RESULTS.ok,
        ...(entry.error ? { error: str(entry.error).slice(0, 200) } : {}),
        ...(entry.code ? { code: str(entry.code) } : {}),
        ...(Array.isArray(entry.backends) && entry.backends.length
            ? { backends: entry.backends.map(str) } : {}),
        ...(entry.mock === true ? { mock: true } : {}),
        ...(entry.destination ? { destination: str(entry.destination) } : {}),
    };
    writeChain = writeChain.then(async () => {
        const state = await readAll();
        state.entries.unshift(recorded);
        if (state.entries.length > AUDIT_CAP) state.entries.length = AUDIT_CAP;
        await writeAll(state);
    }).catch(e => console.warn('[ragewarden:audit] record failed:', e));
    return writeChain;
}

export async function tail(limit) {
    const state = await readAll();
    const n = (typeof limit === 'number' && limit > 0) ? Math.min(limit, state.entries.length) : state.entries.length;
    return state.entries.slice(0, n)
        .map(e => (e && LEGACY_NAMES[e.kind] ? { ...e, kind: LEGACY_NAMES[e.kind] } : e));
}
