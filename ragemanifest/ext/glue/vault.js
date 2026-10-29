import * as crypto from './crypto.js';
import {
    saveSession, loadSession, clearSession, getDeviceId, lockSession, lockState, lockedEmail,
    touchSession, unlockSession, verifyLocalPassword, STORAGE_KEYS,
} from './storage.js';
import { showOnboarding, showProtectionWizard } from './onboarding.js';
import { defaultRpId, passkeyEnrollWithSoftwareKey } from './passkey.js';
import { b64FromHex, bytesToB64, hexFromB64, sha256Hex } from './b64.js';
import { cipherDecryptable, isInternalCipher } from './origin-match.js';
import {
    loadAllPasskeyRecipients,
    loadPasskeyRecipient,
    loadSoftwareIdentity,
    savePasskeyRecipient,
    saveSoftwareIdentity,
} from './passkey-store.js';
import { bumpCounter } from './tap-counters.js';
import { friendlyDecryptError, isUserDecline, openBatch, unlockCipherField } from './unlock.js';
import { probe as probeNativeHost } from './native-host.js';
import { localIdentityInventory, registryEntries } from './inventory.js';
import { relayCredentialsFromRegistry } from './prf-relay.js';
import {
    mockTapAllowed,
    backendIsMock,
    backendLabel,
    performPrfEnroll,
    performPrfTap,
} from './hardware-tap.js';
import { testHooksEnabled, vmServerUrl } from './build-flags.js';
import { missingServerOrigin } from './host-permission.js';
import { loadKdfPin, saveKdfPinFromSession } from './kdf-pin.js';
import { writeClipboard, clearClipboard } from './clipboard.js';
import * as audit from './audit.js';
import {
    ITEM_KINDS, buildDraft, isTypedKind, multiFieldError, planEdit, primaryField, refusesSingleSecret,
} from './item-types.js';

/**
 * A mock build must not publish recipients other clients would trust. No
 * exceptions -- not even in VM mode.
 *
 * rageterm and ragedroid read this registry and have no way to tell a stand-in
 * credential from a real one, so a mock-capable build that published would let
 * a laptop with no authenticator masquerade as an enrolled device -- and every
 * item wrapped to it afterwards would be openable by anyone with this source.
 *
 * VM mode used to be exempted whenever the session server was on loopback, on
 * the theory that "a Vaultwarden on loopback is by construction not a shared
 * registry". That is false in this product's own terms: `is_secure_url`
 * (core/src/sync.rs, core/DESIGN.md) deliberately accepts `http://` to loopback
 * as a *real* server, and an SSH-tunnelled or locally-bound Vaultwarden at
 * 127.0.0.1 is the same database every other client reaches. The hostname
 * allow-list the exemption used was itself sound; the property it tested was
 * simply not the property that matters.
 *
 * The "it is labelled as a stand-in" half of the old justification was cosmetic
 * as well: the label only ever reached `displayName`, and
 * `core/src/policy.rs::select_encrypt_recipients` branches on `kind` and
 * `default_encrypt` and never reads `displayName`. A published `Software`
 * stand-in is therefore an unconditional encrypt target for every client,
 * forever, and its age secret derives from constants committed to this
 * repository.
 *
 * There is no property of the *server* that could make this safe, so there is
 * no exemption. VM mode keeps its stand-in recipient on this machine instead --
 * see `localStandInRecipients()`.
 */
function registryPublishRefusal(what) {
    if (mockTapAllowed()) {
        return `refusing to publish ${what} to the cross-device registry: this build can `
            + 'fabricate hardware taps (allowMockTap), so any recipient it registers would '
            + 'be indistinguishable from a genuine device to every other client. '
            + 'Rebuild without --allow-mock-tap.';
    }
    // Unreachable while `selectedBackend()` gates the mock on `mockTapAllowed()`,
    // and kept so it stays unreachable: if a mock backend is ever selectable
    // some other way, this refuses rather than inheriting the gap above.
    if (backendIsMock()) {
        return `refusing to publish ${what} to the cross-device registry: the active tap `
            + `backend is ${backendLabel()}.`;
    }
    return null;
}

/** The fence itself, on the two functions that build a registry entry. */
function assertRegistryPublishAllowed(what) {
    const refusal = registryPublishRefusal(what);
    if (refusal) throw new Error(refusal);
}

/**
 * The one place that decides whether a credential can be created here.
 *
 * The mock backend supplies its own `create`, so probing
 * `navigator.credentials.create` -- which is what this used to test -- reported
 * "no" in exactly the headless context the mock exists to serve.
 */
function enrolmentPossible() {
    if (backendIsMock()) return true;
    return typeof navigator !== 'undefined'
        && !!navigator.credentials
        && typeof navigator.credentials.create === 'function';
}

/** The ceremony pair handed to passkey.js so enrolment cannot bypass the gate. */
const CEREMONY = Object.freeze({
    enroll: performPrfEnroll,
    prfTap: performPrfTap,
});

let sessionBlob = null;
let sessionHandle = null;

/**
 * The session's keys live inside the wasm instance behind a handle; only the
 * handle crosses the boundary on each call. sessionBlob stays for sealing the
 * storage envelope and for the email.
 */
async function setSession(blob) {
    const mod = await ensureWasm();
    if (sessionHandle !== null) {
        try { mod.wasm_session_close(sessionHandle); } catch {}
        sessionHandle = null;
    }
    sessionBlob = blob || null;
    sessionHandle = sessionBlob ? mod.wasm_session_open(sessionBlob) : null;
}

function wasmSession() {
    return sessionHandle ?? sessionBlob;
}
let snapshot = null;
const ciphersById = new Map();
let bootstrapPromise = null;

/**
 * The registry id a browser passkey is published under.
 *
 * Derived from the credential id rather than stored, which is what lets
 * `withoutPairedPasskeyHoles` recognise *this* browser's entry in a policy
 * result that carries ids and nothing else. Both callers go through here so the
 * scheme cannot drift between the publisher and the recogniser: if it ever did,
 * an already-published entry would stop being recognised as paired and would be
 * reported as a coverage hole -- wrong, but loud rather than silent.
 */
async function passkeyRegistryEntryId(credentialIdB64) {
    const idDigest = await sha256Hex(credentialIdB64);
    return 'passkey-' + idDigest.slice(0, 32);
}

/**
 * The registry `kind` this browser publishes its passkey under.
 *
 * NOT `Fido2`. A WebAuthn-PRF passkey wraps into the `webauthn-prf-v1` stanza;
 * `fido2-hmac` is a different tag with a different HKDF info string.
 * `core/src/registry.rs` decodes `Fido2` to `Recipient::Fido2HmacSecret` and
 * `PasskeyPrf` to `Recipient::PasskeyPrf`, and this extension has no fido2-hmac
 * code at all -- `src/wasm/sync.rs` only ever collects `TAG_WEBAUTHN_PRF_V1`
 * stanzas. So an item wrapped to a `Fido2` entry that is really this browser's
 * passkey is permanently unopenable in the very browser holding the key, and
 * nothing reports it: the wrap succeeds, only the tag is wrong.
 *
 * `Fido2` remains CORRECT for ragedroid, which genuinely wraps Android passkeys
 * as fido2-hmac (`RecipientPolicy.kt`), and rageterm has always published this
 * class of credential as `PasskeyPrf` (`rageterm/src/recipients.rs`). The
 * browser's entry was the only mistagged one.
 */
const PASSKEY_REGISTRY_KIND = 'PasskeyPrf';

/** What older builds of *this* client published a PRF passkey as. */
const LEGACY_PASSKEY_REGISTRY_KIND = 'Fido2';

async function passkeyRecordToRegistryEntry(record) {
    assertRegistryPublishAllowed('a WebAuthn-PRF passkey recipient');
    return {
        id: await passkeyRegistryEntryId(record.credential_id_b64),
        kind: PASSKEY_REGISTRY_KIND,
        displayName: record.label || 'Browser passkey',
        deviceLabel: 'Browser extension',
        createdAt: Date.now(),
        defaultEncrypt: true,
        fido2CredentialId: hexFromB64(record.credential_id_b64),
        fido2RpId: record.rp_id,
        fido2Salt: hexFromB64(record.salt_b64),
    };
}

/**
 * Repair passkey entries this browser published before it knew the difference
 * between `Fido2` and `PasskeyPrf`.
 *
 * Fixing `passkeyRecordToRegistryEntry` fixes only *new* enrolments, and
 * `enrollPasskey` runs once, at first sign-in. The wrong kind is durable,
 * account-wide, server-side state: without this, every already-enrolled user
 * keeps a `Fido2` entry forever and every item wrapped to it stays unopenable
 * in the browser that owns the key.
 *
 * It is a rename in place -- same registry id, same credential id, same salt,
 * same `createdAt`, same `defaultEncrypt`. Nothing that refers to the entry by
 * id (`withoutPairedPasskeyHoles`, the recipient list in the UI, a coverage
 * warning) has to change, and `wasm_publish_recipient_to_registry` upserts on
 * id so no duplicate appears.
 *
 * It touches ONLY entries it can prove this browser wrote, and the proof is not
 * a heuristic:
 *
 *   - the entry id must equal `passkeyRegistryEntryId(cred)` for a credential in
 *     *this profile's* passkey store. That is a sha256 over the credential id,
 *     so no client that does not hold the credential lands on the same id -- and
 *     the two other clients derive ids under different schemes entirely
 *     (`rageterm-fido2-<sha256(domain||rp||cred)>`), so their entries can never
 *     collide into this set;
 *   - the entry's own `fido2CredentialId` must be that same credential id, so a
 *     truncated-digest collision or a hand-edited registry is still rejected.
 *
 * Everything else is left exactly as it is, and that is the point. An Android
 * `Fido2` entry is CORRECT -- ragedroid really does wrap its passkeys as
 * fido2-hmac -- and retagging it would orphan every item the phone has written.
 * A `Fido2` entry this browser cannot account for is somebody else's; ambiguity
 * fails closed, meaning untouched and loudly reported rather than guessed at.
 *
 * Returns the ids it rewrote, so a caller (and the cross-client suite) can tell
 * "nothing to do" apart from "did something".
 */
async function migrateOwnPasskeyEntriesToPasskeyPrf(wasm) {
    const records = await loadAllPasskeyRecipients();
    if (records.length === 0) return [];

    // A build that may not publish may not rewrite either -- it is the same
    // registry write, and `registryPublishRefusal` is the one gate on it.
    if (registryPublishRefusal('a corrected passkey kind')) return [];

    // entry id -> the credential id hex that entry must carry to be ours.
    const ours = new Map();
    for (const r of records) {
        if (!r || !r.credential_id_b64) continue;
        ours.set(
            await passkeyRegistryEntryId(r.credential_id_b64),
            hexFromB64(r.credential_id_b64).toLowerCase(),
        );
    }
    if (ours.size === 0) return [];

    const reg = await wasm.wasm_fetch_registry(wasmSession());
    const entries = (reg && reg.entries) ? reg.entries : [];

    const migrated = [];
    for (const entry of entries) {
        if (!entry || entry.kind !== LEGACY_PASSKEY_REGISTRY_KIND) continue;
        const expectedCredential = ours.get(String(entry.id));
        if (expectedCredential === undefined) continue;
        if (String(entry.fido2CredentialId || '').toLowerCase() !== expectedCredential) {
            console.warn(
                '[ragemanifest] leaving registry entry ' + entry.id + ' as '
                + LEGACY_PASSKEY_REGISTRY_KIND + ': its id matches a passkey enrolled in '
                + 'this profile but its credential id does not, so this browser cannot '
                + 'prove the entry is its own.',
            );
            continue;
        }
        await wasm.wasm_publish_recipient_to_registry(
            wasmSession(), { ...entry, kind: PASSKEY_REGISTRY_KIND },
        );
        migrated.push(String(entry.id));
    }

    if (migrated.length > 0) {
        console.warn(
            '[ragemanifest] republished ' + migrated.join(', ') + ' as '
            + PASSKEY_REGISTRY_KIND + ' (was ' + LEGACY_PASSKEY_REGISTRY_KIND + '). Items '
            + 'written while the kind was wrong were wrapped into a fido2-hmac stanza this '
            + 'browser cannot open; re-save them to pick up the corrected recipient.',
        );
    }
    return migrated;
}

async function softwareIdentityToRegistryEntry(record, label) {
    assertRegistryPublishAllowed('a passkey-wrapped software recipient');
    const idDigest = await sha256Hex(record.armored_pubkey);
    return {
        id: 'browser-sw-' + idDigest.slice(0, 32),
        kind: 'Software',
        displayName: label ? `${label} (browser key)` : 'Browser software identity',
        deviceLabel: 'Browser extension',
        createdAt: Date.now(),
        defaultEncrypt: true,
        recoveryArmoredPubkey: record.armored_pubkey,
    };
}

function backgroundAvailable() {
    return typeof chrome !== 'undefined'
        && chrome.runtime
        && typeof chrome.runtime.sendMessage === 'function'
        && !!chrome.runtime.id;
}

function bgSend(message) {
    return new Promise((resolve, reject) => {
        try {
            chrome.runtime.sendMessage(message, r => {
                const err = chrome.runtime.lastError;
                if (err) reject(new Error(err.message));
                else resolve(r);
            });
        } catch (e) { reject(e); }
    });
}

async function ensureWasm() {
    return crypto.init();
}

async function ensureSession() {
    if (sessionBlob) return sessionBlob;
    await setSession(await loadSession());
    return sessionBlob;
}

function cipherRecipientCount(c) {
    return (c && typeof c.recipient_count === 'number') ? c.recipient_count : 0;
}

async function fetchVault() {
    const mod = await ensureWasm();
    let nativeCapable = false;
    try { nativeCapable = !!(await probeNativeHost()).capable; } catch {}
    const entries = await registryEntries(mod, wasmSession());
    relayCredentials = relayCredentialsFromRegistry(entries);
    const result = await mod.wasm_fetch_vault_with_identities(
        wasmSession(), await localIdentityInventory(mod, wasmSession(), { nativeCapable, entries }),
    );
    if (result && result.refreshed && sessionHandle !== null) {
        sessionBlob = mod.wasm_session_export(sessionHandle);
        try { await saveSession(sessionBlob); } catch (_) { /* best effort */ }
    } else if (result && result.refreshed_session) {
        await setSession(result.refreshed_session);
        try { await saveSession(sessionBlob); } catch (_) { /* best effort */ }
    }
    snapshot = result;
    ciphersById.clear();
    for (const c of (result.ciphers || [])) {
        c.protected_fields = [];
        if (c.rage && !c.internal) {
            try { c.protected_fields = mod.wasm_protected_field_names(wasmSession(), c) || []; } catch {}
        }
        ciphersById.set(c.id, c);
    }
    return result;
}

let view = { logins: [], byKind: [], folders: [] };
/** The registry's phone passkeys, opened through the passkey relay. */
let relayCredentials = [];

function buildView() {
    const ciphers = (snapshot && snapshot.ciphers) || [];
    const folders = (snapshot && snapshot.folders) || [];
    const folderNameById = new Map(folders.map(f => [f.id, f.name]));
    const folderCount = new Map();
    const logins = [];
    const byKind = [];
    for (const c of ciphers) {
        if (isInternalCipher(c)) continue;
        if (c.folder_id) folderCount.set(c.folder_id, (folderCount.get(c.folder_id) || 0) + 1);
        const item = {
            id: c.id,
            name: c.name,
            username: c.username || null,
            site: c.site || null,
            folder: folderNameById.get(c.folder_id) || null,
            folderId: c.folder_id || null,
            favorite: !!c.favorite,
            rage: !!c.rage,
            hasTotp: rawHasTotp(c),
            legacyWrap: !!c.legacy_wrap,
            protectedFields: Array.isArray(c.protected_fields) ? c.protected_fields.slice() : [],
            decryptable: cipherDecryptable(c),
            recipientCount: cipherRecipientCount(c),
        };
        if (c.kind === 'login') logins.push(item);
        else byKind.push({ ...item, kind: c.kind || 'other' });
    }
    return {
        logins,
        byKind,
        folders: folders.map(f => ({ id: f.id, name: f.name, count: folderCount.get(f.id) || 0 })),
    };
}

function attachToWindow() {
    view = buildView();
    // test-hooks:begin
    if (typeof window === 'undefined' || !testHooksEnabled()) return;
    window.__ragewardenSession = sessionBlob;
    window.__ragewardenMarkLegacyWrap = (id) => {
        const c = ciphersById.get(id);
        if (c) c.legacy_wrap = true;
        view = buildView();
    };
    window.VAULT = view.logins;
    window.ITEMS_BY_KIND = view.byKind;
    window.FOLDERS = view.folders;
    // test-hooks:end
}

export function items() {
    return [...view.logins.map(i => ({ ...i, kind: 'login' })), ...view.byKind];
}

export function folders() {
    return view.folders.slice();
}

function notifyWorker() {
    if (!backgroundAvailable()) return;
    bgSend({ kind: 'vault.invalidate' }).catch(() => {});
}

async function enrolFirstPasskey() {
    try {
        const existing = await loadPasskeyRecipient();
        if (existing || !enrolmentPossible()) return;
        let combined = null;
        const combinedEnroll = async (opts) => {
            const wasm = await ensureWasm();
            combined = await passkeyEnrollWithSoftwareKey(opts, wasm, CEREMONY);
            return combined.passkeyRecord;
        };
        const saveAndPublish = async (record) => {
            await savePasskeyRecipient(record);
            if (combined) await saveSoftwareIdentity(combined.softwareIdentity);
            try {
                const wasm = await ensureWasm();
                await wasm.wasm_publish_recipient_to_registry(
                    wasmSession(), await passkeyRecordToRegistryEntry(record),
                );
                if (combined) {
                    await wasm.wasm_publish_recipient_to_registry(
                        wasmSession(),
                        await softwareIdentityToRegistryEntry(combined.softwareIdentity, record.label),
                    );
                }
            } catch (e) {
                console.warn(
                    '[ragemanifest] passkey saved locally but not published to '
                    + 'cross-device registry:', e,
                );
            }
        };
        await showProtectionWizard({
            passkeyEnroll: combinedEnroll,
            savePasskeyRecipient: saveAndPublish,
            enrollBackupPasskey,
            generateRecovery,
            publishRecovery,
            defaultRpId: defaultRpId(),
        });
    } catch {}
}

/*
 * Runs once per unlock. The repair runs outside first sign-in on purpose: the
 * users who need it enrolled long ago. Its failure must not block the popup,
 * but it is reported.
 */
async function openVault(firstSignIn) {
    if (firstSignIn) await enrolFirstPasskey();
    try {
        await migrateOwnPasskeyEntriesToPasskeyPrf(await ensureWasm());
    } catch (e) {
        console.warn(
            '[ragemanifest] could not correct the kind of this browser\'s published '
            + 'passkey entry; items wrapped to it may be unopenable here:', e,
        );
    }
    let offline = null;
    try {
        await fetchVault();
    } catch (e) {
        if (firstSignIn) throw e;
        offline = (e && e.message) || String(e);
        console.warn('[ragewarden] unlocked, but the vault could not be fetched:', e);
    }
    attachToWindow();
    notifyWorker();
    return {
        locked: false,
        email: sessionBlob.email,
        ciphers: (snapshot && snapshot.ciphers && snapshot.ciphers.length) || 0,
        ...(offline ? { offline } : {}),
    };
}

/** Null, or the server origin this profile still has to grant (sessions made before sign-in asked). */
export async function serverOriginNeedingPermission() {
    return missingServerOrigin(sessionBlob);
}

export function bootstrap() {
    if (bootstrapPromise) return bootstrapPromise;
    bootstrapPromise = (async () => {
        const mod = await ensureWasm();
        const state = await lockState();
        if (state === 'locked' || state === 'legacy-locked') {
            return { locked: true, legacy: state === 'legacy-locked', email: await lockedEmail() };
        }
        let s = state === 'unlocked' ? await loadSession() : null;
        let firstSignIn = false;
        if (!s) {
            let password = null;
            s = await showOnboarding({
                wasmLogin: async (server, email, pw, deviceName, { allowLegacyKdf = false } = {}) => {
                    const pin = await loadKdfPin(server, email);
                    let session = await mod.wasm_login(server, email, pw, deviceName,
                        await getDeviceId(), pin, allowLegacyKdf);
                    if (allowLegacyKdf) {
                        session = await mod.wasm_upgrade_kdf(session, pw, deviceName, null);
                    }
                    await saveKdfPinFromSession(server, email, session);
                    audit.record({ kind: audit.KINDS.Login, target: email, detail: new URL(server).origin,
                        result: audit.RESULTS.ok });
                    password = pw;
                    return session;
                },
                wasmRegister: (server, email, name, pw, iters) =>
                    mod.wasm_register(server, email, name, pw, iters),
                ...(vmServerUrl() ? { defaultServerUrl: vmServerUrl() } : {}),
            });
            try {
                await saveSession(s, { password });
            } finally {
                password = null;
            }
            firstSignIn = true;
        }
        await setSession(s);
        return openVault(firstSignIn);
    })();
    bootstrapPromise.catch(() => { bootstrapPromise = null; });
    return bootstrapPromise;
}

/*
 * Local, offline unlock. A pre-v2 install has no password verifier on this
 * machine, so its one migration unlock is checked against the server; every
 * unlock after that is local.
 */
export async function unlock(password) {
    const state = await lockState();
    if (state === 'legacy-locked') {
        const legacy = await loadSession();
        if (!legacy) throw new Error('the session expired -- sign in again');
        await setSession(legacy);
        await verifyMasterPasswordRemote(password);
        await saveSession(legacy, { password });
    } else if (state === 'locked') {
        await setSession(await unlockSession(password));
    } else if (state === 'unlocked') {
        await setSession(await loadSession());
    } else {
        throw new Error('signed out -- sign in again');
    }
    bootstrapPromise = openVault(false);
    return bootstrapPromise;
}

function forgetUnlocked() {
    const closing = sessionHandle;
    sessionHandle = null;
    if (closing !== null) ensureWasm().then(m => m.wasm_session_close(closing)).catch(() => {});
    sessionBlob = null;
    snapshot = null;
    ciphersById.clear();
    bootstrapPromise = null;
    view = { logins: [], byKind: [], folders: [] };
    // test-hooks:begin
    if (typeof window !== 'undefined' && testHooksEnabled()) {
        window.VAULT = [];
        window.ITEMS_BY_KIND = [];
        window.FOLDERS = [];
        window.__ragewardenSession = null;
    }
    // test-hooks:end
}

export async function lock() {
    forgetUnlocked();
    await lockSession();
    notifyWorker();
    if (typeof window !== 'undefined') {
        try { window.dispatchEvent(new CustomEvent('ragewarden:locked')); } catch {}
    }
}

if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'session' && changes[STORAGE_KEYS.unlockKey]
            && !changes[STORAGE_KEYS.unlockKey].newValue && sessionBlob) {
            forgetUnlocked();
            try { window.dispatchEvent(new CustomEvent('ragewarden:locked')); } catch {}
        }
    });
}

function activity() {
    touchSession().catch(() => {});
}

async function afterWrite() {
    await fetchVault();
    attachToWindow();
    notifyWorker();
}

/**
 * The one refusal that happens before any ceremony: an item the snapshot says
 * this profile cannot open is never handed to the decrypt path at all. No tap
 * is requested, no stanza is tried, and the error carries the same
 * `no_matching_identity` code a decrypt-time mismatch would, so every caller
 * renders the one explanation.
 */
function notOnThisDeviceError(cipher) {
    const n = cipherRecipientCount(cipher);
    const err = new Error(n > 0
        ? `this item is wrapped to ${n} recipient${n === 1 ? '' : 's'}, none on this `
          + 'device -- re-wrap it from a device that holds one of its keys. '
          + 'Nothing was decrypted.'
        : 'this item is not encrypted for this device -- re-wrap it from a device '
          + 'that holds one of its keys. Nothing was decrypted.');
    err.code = 'no_matching_identity';
    return err;
}

function receiptSummary(receipts) {
    const list = Array.isArray(receipts) ? receipts : [];
    return {
        backends: list.map(r => (r && (r.tapBackend || r.backend)) || 'unknown'),
        mock: list.some(r => r && r.mock === true),
    };
}

async function audited(kind, target, detail, fn) {
    activity();
    try {
        const out = await fn();
        audit.record({
            kind, target, detail, result: audit.RESULTS.ok,
            ...(out && out.receipts ? receiptSummary(out.receipts) : {}),
        });
        return out;
    } catch (err) {
        audit.record({
            kind, target, detail,
            result: isUserDecline(err) ? audit.RESULTS.declined : audit.RESULTS.failed,
            code: (err && err.code) || '',
            error: (err && err.message) || String(err),
        });
        throw err;
    }
}

async function unlockOnce(itemId, ctx) {
    if (!sessionBlob) throw new Error('Ragewarden is locked');
    const cipher = ciphersById.get(itemId);
    if (!cipher) throw new Error(`unknown item ${itemId}`);
    if (isInternalCipher(cipher)) {
        throw new Error('this entry is Ragewarden bookkeeping, not an item');
    }
    if (!cipherDecryptable(cipher)) throw notOnThisDeviceError(cipher);

    await ensureWasm();
    let out;
    try {
        out = await unlockCipherField({
            session: wasmSession(),
            cipher,
            fieldName: ctx.fieldName || 'password',
            relayCredentials: async () => relayCredentials,
            action: ctx.action,
            destination: ctx.destination || '',
            origin: ctx.origin || (typeof location !== 'undefined' && location.origin) || '',
        });
    } catch (err) {
        throw friendlyDecryptError(err, cipher);
    }
    bumpCounter('js_decrypt');
    return out;
}

export async function revealPassword(itemId, fieldName = 'password') {
    const cipher = ciphersById.get(itemId);
    const out = await audited(audit.KINDS.Reveal, itemId, (cipher && cipher.name) || '',
        () => unlockOnce(itemId, {
            action: 'reveal', destination: (cipher && cipher.site) || 'this window', fieldName,
        }));
    return out.value;
}

/*
 * `destination` is the origin of the tab the caller will fill, captured before
 * the tap; the receipt is bound to it and the content script refuses a page
 * whose origin differs.
 */
function rawHasTotp(c) {
    const login = c && c.raw && (c.raw.Login || c.raw.login);
    return !!(login && (login.Totp || login.totp));
}

/**
 * The current code for an item's TOTP seed: the Bitwarden login.totp field when
 * the item has one and is not rage-wrapped, otherwise the item's protected
 * secret (how rageterm stores a seed). Same ceremony as a reveal; the seed
 * never leaves this function.
 */
export async function totpCode(itemId) {
    const cipher = ciphersById.get(itemId);
    const fieldName = cipher && ((!cipher.rage && rawHasTotp(cipher))
        || (cipher.protected_fields || []).includes('totp')) ? 'totp' : 'password';
    const out = await audited(audit.KINDS.Totp, itemId, (cipher && cipher.name) || '',
        () => unlockOnce(itemId, { action: 'totp', destination: 'this screen', fieldName }));
    let seed = out.value;
    try {
        const mod = await ensureWasm();
        const r = mod.wasm_totp_generate(String(seed).trim());
        return { code: r.code, secondsRemaining: r.seconds_remaining, period: r.period };
    } catch (err) {
        throw new Error(`this item does not hold a TOTP seed (${(err && err.message) || err})`);
    } finally {
        seed = '';
    }
}

export async function autofillPassword(itemId, destination) {
    if (!destination) throw new Error('autofill needs the destination origin');
    const cipher = ciphersById.get(itemId);
    const out = await audited(audit.KINDS.Autofill, itemId, destination,
        () => unlockOnce(itemId, { action: 'autofill', destination, fieldName: 'password' }));
    return out.value;
}

export const CLIPBOARD_CLEAR_SECONDS = 30;

/*
 * Every secret that reaches the clipboard goes through here, so every one gets
 * a clear scheduled in the background worker -- which outlives the popup.
 */
export async function copySecret(value) {
    const via = await writeClipboard(value);
    let clearAt = null;
    if (backgroundAvailable()) {
        try {
            const r = await bgSend({ kind: 'clipboard.scheduleClear', seconds: CLIPBOARD_CLEAR_SECONDS });
            if (r && r.ok) clearAt = r.clearAt;
        } catch {}
    }
    return { via, clearAt };
}

/**
 * Run the tap ceremony and put the plaintext on the clipboard. The plaintext
 * is not returned: it exists only long enough to reach the clipboard.
 */
export async function copyPassword(itemId, fieldName = 'password') {
    const cipher = ciphersById.get(itemId);
    const out = await audited(audit.KINDS.Copy, itemId, (cipher && cipher.name) || '',
        () => unlockOnce(itemId, {
            action: 'copy', destination: 'the clipboard', fieldName,
        }));
    let value = out.value;
    try {
        const { via, clearAt } = await copySecret(value);
        return { copied: true, chars: value.length, via, clearAt };
    } finally {
        value = '';
        out.value = '';
    }
}

export async function clearClipboardNow() {
    if (backgroundAvailable()) bgSend({ kind: 'clipboard.cancelClear' }).catch(() => {});
    return clearClipboard();
}

function serverBaseUrl(session) {
    const api = (session && session.api_url) || '';
    if (!api) {
        throw new Error('this session carries no api_url; cannot re-check the master password');
    }
    return api.replace(/\/api\/?$/, '');
}

async function verifyMasterPasswordRemote(password) {
    if (typeof password !== 'string' || password.length === 0) {
        throw new Error('enter your master password');
    }
    const mod = await ensureWasm();
    const device = 'ragemanifest-verify@'
        + ((typeof navigator !== 'undefined' && navigator.userAgent.split(' ')[0]) || 'browser');
    try {
        const server = serverBaseUrl(sessionBlob);
        await mod.wasm_login(server, sessionBlob.email, password, device,
            await getDeviceId(), await loadKdfPin(server, sessionBlob.email), false);
    } catch (err) {
        throw new Error((err && err.message) || String(err));
    }
    return true;
}

/** Checked locally against the envelope; no server round trip. */
export async function verifyMasterPassword(password) {
    if (!sessionBlob) throw new Error('Ragewarden is locked');
    if (typeof password !== 'string' || password.length === 0) {
        throw new Error('enter your master password');
    }
    if ((await lockState()) === 'unlocked') {
        if (!await verifyLocalPassword(password)) throw new Error('wrong master password');
        return true;
    }
    return verifyMasterPasswordRemote(password);
}

/**
 * The stand-in recipient a mock build wraps to, kept out of the registry.
 *
 * A mock build publishes nothing (`assertRegistryPublishAllowed`), so the
 * registry it reads back names no recipient it can open, `select_for_encrypt`
 * selects nobody, and a VM could sign in and enrol but never write an item it
 * could open again. The software identity that `enrollPasskey` already stored
 * in this browser profile is exactly the missing recipient.
 *
 * It is added here rather than published because publishing is what makes it
 * everybody's problem: core policy branches on `kind`/`default_encrypt` alone,
 * so a `Software` entry in the shared registry is an unconditional encrypt
 * target for rageterm and ragedroid too -- and this key's age secret derives
 * from constants committed to this repository. Local-only keeps the blast
 * radius inside the box: no other client can see the key, and the items it
 * wraps are openable only in this profile.
 *
 * This is deliberately an *addition*, never a filter -- see the warning on
 * `selectEncryptRecipients` below. It cannot be expressed as core policy
 * because core policy selects from the registry, and this key's whole point is
 * that it never reaches one.
 */
async function localStandInRecipients() {
    if (!backendIsMock()) return [];
    const software = await loadSoftwareIdentity();
    if (!software || !software.armored_pubkey) return [];
    return [{ type: 'software_passphrase', armored_pubkey: software.armored_pubkey }];
}

/**
 * Drop the one `no_local_authenticator` skip this browser can honestly account
 * for: its own passkey, whose paired `Software` twin is doing the work.
 *
 * Policy skips *every* PRF entry here, and must: wrapping to a Fido2 or
 * PasskeyPrf recipient needs a PRF output at wrap time
 * (`EncryptError::NeedsPrfOutput`, core/src/lib.rs), and
 * `wasm_create_cipher`/`wasm_update_cipher` do not tap. Naming this browser's
 * passkey in `local_prf_entry_ids` would therefore not fix the report -- it
 * would make policy select the passkey and every save would fail outright. The
 * skip is the truth about the *entry*; it is not the truth about the *user*,
 * because `enrollPasskey` publishes a `Software` twin wrapped by that same
 * passkey and the twin is an ordinary asymmetric recipient every client can
 * wrap to. Reported as-is it is a permanent false alarm on every save for every
 * enrolled user.
 *
 * The suppression is deliberately narrow, so a genuine hole still shows:
 *
 *   - it is keyed on `wrap_credential_id_b64` from *this profile's* software
 *     identity, so it can only ever match the passkey enrolled here. Another
 *     device's key hashes to a different entry id and is still reported.
 *   - it is conditional on the twin being in `recipients` for this very write.
 *     Unpublish the twin, or turn its `defaultEncrypt` off, and the passkey
 *     goes back to being a hole -- which by then it genuinely is.
 *
 * A `skipped` entry for any other reason is never touched.
 */
async function withoutPairedPasskeyHoles(recipients, skipped) {
    if (!skipped.some(s => s && s.reason === 'no_local_authenticator')) return skipped;

    const software = await loadSoftwareIdentity();
    if (!software || !software.armored_pubkey || !software.wrap_credential_id_b64) return skipped;

    const twinIsWrappedTo = recipients.some(r => r
        && r.type === 'software_passphrase'
        && r.armored_pubkey === software.armored_pubkey);
    if (!twinIsWrappedTo) return skipped;

    const coveredId = await passkeyRegistryEntryId(software.wrap_credential_id_b64);
    return skipped.filter(s => !(s
        && s.reason === 'no_local_authenticator'
        && s.id === coveredId));
}

/**
 * Canonical policy output for this session, plus the mock build's local
 * stand-in. Every write and every preview goes through here so the UI cannot
 * report a set the writer does not use -- nor a coverage hole the writer does
 * not have.
 *
 * The de-duplication is not theoretical: a VM vault created before mock builds
 * stopped publishing still carries the stand-in in its registry, so policy and
 * `localStandInRecipients()` would both name the same age key.
 */
async function ownPasskeyEntryIds() {
    const ids = [];
    for (const r of await loadAllPasskeyRecipients()) {
        if (r && r.credential_id_b64) ids.push(await passkeyRegistryEntryId(r.credential_id_b64));
    }
    return ids;
}

async function encryptSelection({ withOwnPasskeys = false } = {}) {
    const mod = await ensureWasm();
    const selection = await mod.wasm_select_encrypt_recipients(wasmSession(),
        withOwnPasskeys ? await ownPasskeyEntryIds() : null);
    const recipients = (selection && selection.recipients) ? selection.recipients.slice() : [];
    const rawSkipped = (selection && selection.skipped) ? selection.skipped : [];
    for (const standIn of await localStandInRecipients()) {
        const already = recipients.some(r => r
            && r.type === standIn.type
            && r.armored_pubkey === standIn.armored_pubkey);
        if (!already) recipients.push(standIn);
    }
    // After the stand-in is folded in, so a mock build's local-only twin counts
    // as coverage exactly the way a published one does.
    const skipped = await withoutPairedPasskeyHoles(recipients, rawSkipped);
    return { recipients, skipped };
}

/**
 * Recipient selection for a write, delegated to the one canonical policy in
 * core (`ragewarden_core::policy::select_for_encrypt`) via
 * `wasm_select_encrypt_recipients`.
 *
 * This function used to reimplement the policy here in JS and kept only
 * `Software` and `Recovery` entries. rageterm and ragedroid each had their own
 * different filter. The result was cross-client data loss: an item saved in the
 * browser had no stanza for the user's YubiKey or their phone's StrongBox key,
 * so it was cryptographically unopenable there -- silently, with the save
 * reporting success. Do not reintroduce a filter here; change the policy in
 * `core/src/policy.rs` so all three clients move together.
 *
 * Second argument: the registry ids of this browser's own passkeys when the
 * write will tap (setCipher, editCipher with a new secret, rotateCipher go
 * through sealWithOwnPasskey), otherwise null -- bulk protect does not tap, so
 * there its passkey entries come back under `skipped` with
 * `no_local_authenticator`, covered by the paired `Software` entry
 * (`withoutPairedPasskeyHoles` takes that case out of `skipped`).
 */
async function selectEncryptRecipients() {
    const { recipients, skipped } = await encryptSelection();
    const unreachable = skipped.filter(s => s.reason === 'no_local_authenticator');
    if (unreachable.length > 0) {
        console.warn(
            'ragewarden: not wrapping to ' + unreachable.length + ' recipient(s) whose '
            + 'authenticator this browser cannot reach during a write: '
            + unreachable.map(s => s.id + ' (' + s.kind + ')').join(', '),
        );
    }
    return recipients;
}

async function buildEncryptRecipients() {
    return selectEncryptRecipients();
}

/**
 * A single write wraps to this browser's own passkey too: every passkey
 * recipient gets a fresh CSPRNG salt (core's per-secret salts, A06), one
 * assertion evaluates them, and the credential that answered goes into the PRF
 * table. A passkey that did not answer is left out of this write rather than
 * wrapped with a salt nobody evaluated.
 */
async function sealWithOwnPasskey(recipients, { action, destination, cipherId }) {
    const local = new Set((await loadAllPasskeyRecipients()).map(r => r.credential_id_b64));
    const credOf = r => bytesToB64(Uint8Array.from(r.credential_id || []));
    const mine = recipients.filter(r => r && r.type === 'passkey_prf' && local.has(credOf(r)));
    if (mine.length === 0) return { recipients, table: [] };
    const pairs = mine.map(r => ({
        credentialId: credOf(r),
        salt: bytesToB64(globalThis.crypto.getRandomValues(new Uint8Array(32))),
        rpId: r.rp_id,
    }));
    const tap = await CEREMONY.prfTap({ pairs, rpId: pairs[0].rpId, action, destination, cipherId });
    const canon = v => (v instanceof Uint8Array ? bytesToB64(v) : String(v))
        .replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    const sameId = (a, b) => canon(a) === canon(b);
    const used = pairs.length === 1 ? pairs[0] : pairs.find(p => sameId(p.credentialId, tap.credentialId));
    if (!used) throw new Error('the authenticator answered for a passkey this write did not offer');
    const table = [{
        rp_id: used.rpId,
        credential_id_b64: used.credentialId,
        salt_b64: used.salt,
        prf_output_b64: bytesToB64(tap.prfOutput),
    }];
    if (tap.prfOutput && tap.prfOutput.fill) tap.prfOutput.fill(0);
    bumpCounter('prf');
    const kept = recipients.filter(r => !(mine.includes(r) && credOf(r) !== used.credentialId));
    return { recipients: kept, table };
}

async function writeRecipients() {
    const { recipients } = await encryptSelection({ withOwnPasskeys: true });
    if (recipients.length === 0) throw new Error('no recipients in registry -- enroll a passkey first');
    return recipients;
}

/**
 * The recipient set a write would actually use, plus what policy dropped and
 * why. The UI needs this to tell the truth about coverage instead of drawing a
 * checkbox list that selects nothing.
 */
export async function previewEncryptRecipients() {
    if (!sessionBlob) throw new Error('not signed in');
    return encryptSelection();
}

function buildPlaintextFields({ name, plaintext, type, username, site }) {
    const fields = { name, rage: plaintext };
    if (type === 'login') fields.cipher_type = 'login';
    if (username) fields.username = username;
    if (site) fields.site = site;
    return fields;
}

export async function setCipher(name, plaintext, opts = {}) {
    return audited(audit.KINDS.Set, String(name), String(opts.type || 'note'), async () => {
        if (!sessionBlob) throw new Error('not signed in');
        const mod = await ensureWasm();
        const sealed = await sealWithOwnPasskey(await writeRecipients(),
            { action: 'save', destination: 'this vault', cipherId: '' });
        const fields = buildPlaintextFields({
            name, plaintext, type: opts.type, username: opts.username, site: opts.site,
        });
        const saved = sealed.table.length > 0
            ? await mod.wasm_create_cipher_with_prf(wasmSession(), fields, sealed.recipients, sealed.table)
            : await mod.wasm_create_cipher(wasmSession(), fields, sealed.recipients);
        await afterWrite();
        return saved;
    });
}

/**
 * Re-encrypt an item, optionally under a new name.
 *
 * A null or undefined `plaintext` means "keep the stored secret". That is what
 * a rename is: the edit screen has no way to obtain the secret -- nothing short
 * of a tap can -- so requiring the caller to supply it made renaming impossible
 * and the item's `rage` field would have been rewritten as the string
 * "undefined". The secret is unlocked once, exactly as `rotateCipher` does it,
 * and re-wrapped under the current policy.
 *
 * So a rename costs one hardware tap. That is the product working: the new
 * blob has to be sealed around the same secret, and this browser can only get
 * that secret the way anyone else would.
 */
async function writeRewrapped(id, changed, secret, recipients) {
    const mod = await ensureWasm();
    const sealed = await sealWithOwnPasskey(recipients, { action: 'save', destination: 'this vault', cipherId: id });
    const fields = { ...changed, rage: secret };
    const saved = sealed.table.length > 0
        ? await mod.wasm_update_cipher_with_prf(wasmSession(), id, fields, sealed.recipients, sealed.table)
        : await mod.wasm_update_cipher(wasmSession(), id, fields, sealed.recipients);
    await afterWrite();
    return saved;
}

/** Only the fields that differ from the stored item; the wasm merges them in. */
function changedFields(id, { name, username, site } = {}) {
    const cipher = ciphersById.get(id) || {};
    const out = {};
    if (typeof name === 'string' && name.trim() && name !== cipher.name) out.name = name;
    if (typeof username === 'string' && username !== (cipher.username || '')) out.username = username;
    if (typeof site === 'string' && site !== (cipher.site || '')) out.site = site;
    return out;
}

async function requireRecipients() {
    const recipients = await buildEncryptRecipients();
    if (recipients.length === 0) throw new Error('no recipients in registry');
    return recipients;
}

/**
 * A null plaintext keeps the stored secret: only the changed fields go to the
 * server, nothing is re-wrapped and no tap is needed. A new secret is wrapped to
 * the current recipients and the old payload is kept in the history document.
 */
export async function editCipher(id, name, plaintext, opts = {}) {
    return audited(audit.KINDS.Update, String(id), String(name), async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!id) throw new Error('id required');
        if (!ciphersById.has(id)) throw new Error(`unknown cipher ${id}`);
        const changed = changedFields(id, { name, username: opts.username, site: opts.site });
        if (plaintext === null || plaintext === undefined) {
            if (Object.keys(changed).length === 0) return { id, unchanged: true };
            const mod = await ensureWasm();
            const saved = await mod.wasm_edit_cipher(wasmSession(), id, changed);
            await afterWrite();
            return saved;
        }
        const cipher = ciphersById.get(id);
        if (refusesSingleSecret(cipher.kind, cipher.protected_fields)) {
            throw multiFieldError(cipher.kind, cipher.protected_fields);
        }
        try {
            return await writeRewrapped(id, changed, plaintext, await writeRecipients());
        } catch (err) {
            if (err && err.code === 'multi_field') throw multiFieldError(cipher.kind, cipher.protected_fields);
            throw err;
        }
    });
}

export async function rotateCipher(id) {
    return audited(audit.KINDS.Rotate, String(id), '', async () => {
        if (!sessionBlob) throw new Error('not signed in');
        const cipher = ciphersById.get(id);
        if (!cipher) throw new Error(`unknown cipher ${id}`);
        const recipients = await writeRecipients();
        // The whole payload: every protected field goes back, in its format.
        const { value } = await unlockOnce(id, {
            action: 'rotate',
            destination: cipher.site || cipher.name,
            fieldName: cipher.rage ? '*' : primaryField(cipher.kind),
        });
        return writeRewrapped(id, {}, value, recipients);
    });
}

/** Move an item between folders (null = no folder). Nothing is re-wrapped. */
export async function setFolder(id, folderId) {
    return audited(audit.KINDS.Update, String(id), `folder:${folderId || ''}`, async () => {
        if (!sessionBlob) throw new Error('not signed in');
        const mod = await ensureWasm();
        const saved = await mod.wasm_set_folder(wasmSession(), id, folderId || null);
        await afterWrite();
        return saved;
    });
}

/** core's shared generator: every class requested is present, drawn from a CSPRNG. */
export async function generatePassword({ length = 20, lowercase = true, uppercase = true,
    digits = true, symbols = true } = {}) {
    const mod = await ensureWasm();
    return mod.wasm_generate_password(length, lowercase, uppercase, digits, symbols);
}

export async function generatePassphrase({ words = 6, separator = '-' } = {}) {
    const mod = await ensureWasm();
    return mod.wasm_generate_passphrase(words, separator);
}

/**
 * The Type-2 values of a typed item's unprotected fields, read with no tap.
 * Secret fields (number, code, private key, ...) are left out unless the
 * caller is re-sealing them, in which case they never reach the screen.
 */
async function typedValues(id, { includeSecrets = false } = {}) {
    const cipher = ciphersById.get(id);
    if (!cipher) throw new Error(`unknown cipher ${id}`);
    const spec = ITEM_KINDS[cipher.kind];
    if (!spec || !spec.block) return {};
    const mod = await ensureWasm();
    const out = {};
    for (const { name, secret } of spec.fields) {
        if ((secret && !includeSecrets) || (cipher.protected_fields || []).includes(name)) continue;
        try {
            const bytes = await mod.wasm_decrypt_cipher_field(wasmSession(), cipher, name, null);
            out[name] = new TextDecoder().decode(bytes);
            if (bytes && bytes.fill) bytes.fill(0);
        } catch {}
    }
    return out;
}

export async function itemDetails(id) {
    return typedValues(id);
}

/**
 * Create (`id` null) or edit a card, identity or SSH key. `values` holds the
 * editor's inputs by core field name and `protect` the fields to seal into the
 * rage blob. An edit that changes a protected value or the protected set reads
 * the current payload once (`*`, one tap) so every other protected field is
 * sealed again with it; an edit of plain fields alone needs no tap.
 */
export async function saveItem(id, { kind, name, values = {}, protect = [], folderId = null }) {
    return audited(id ? audit.KINDS.Update : audit.KINDS.Set, String(id || name), String(kind), async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!isTypedKind(kind)) throw new Error(`saveItem edits cards, identities and SSH keys, not ${kind}`);
        const mod = await ensureWasm();
        const sealedWrite = async (cipherId, item, fields) => {
            if (!fields) return mod.wasm_save_item(wasmSession(), cipherId, item, null, [], null);
            const sealed = await sealWithOwnPasskey(await writeRecipients(),
                { action: 'save', destination: 'this vault', cipherId: cipherId || '' });
            return mod.wasm_save_item(wasmSession(), cipherId, item, fields, sealed.recipients,
                sealed.table.length > 0 ? sealed.table : null);
        };
        let saved;
        if (!id) {
            const { draft, protectedFields } = buildDraft(kind, { name, values, protect, folderId });
            saved = await sealedWrite(null, draft, protectedFields);
        } else {
            const cipher = ciphersById.get(id);
            if (!cipher) throw new Error(`unknown cipher ${id}`);
            const args = {
                name, previousName: cipher.name, values, protect,
                previous: await typedValues(id, { includeSecrets: true }),
                wasProtected: cipher.protected_fields || [],
            };
            let plan = planEdit(kind, args);
            if (plan.needsPayload) {
                let { value } = await unlockOnce(id, {
                    action: 'edit', destination: 'this vault', fieldName: '*',
                });
                try {
                    plan = planEdit(kind, { ...args, payload: mod.wasm_open_payload(cipher, value) });
                } finally {
                    value = '';
                }
            }
            if (!plan.protectedFields && Object.keys(plan.edit).length === 0) return { id, unchanged: true };
            saved = await sealedWrite(id, plan.edit, plan.protectedFields);
        }
        await afterWrite();
        return saved;
    });
}

/** Which recipients an item's blob carries (no secret involved). */
export async function stanzaSummary(id) {
    const cipher = ciphersById.get(id);
    if (!cipher) throw new Error(`unknown cipher ${id}`);
    const mod = await ensureWasm();
    return mod.wasm_rage_stanza_summary(wasmSession(), cipher, 'password');
}

export async function deleteCipher(id) {
    return audited(audit.KINDS.Delete, String(id), String(''), async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!id) throw new Error('id required');
        const mod = await ensureWasm();
        await mod.wasm_delete_cipher(wasmSession(), id);
        await afterWrite();
        return { deleted: id };
    });
}

export async function createFolder(name) {
    return audited(audit.KINDS.CreateFolder, String(name), String(''), async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!name) throw new Error('name required');
        const mod = await ensureWasm();
        const f = await mod.wasm_create_folder(wasmSession(), name);
        await afterWrite();
        return f;
    });
}

export async function renameFolder(folderId, name) {
    return audited(audit.KINDS.RenameFolder, String(folderId), String(name), async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!folderId) throw new Error('folderId required');
        if (!name) throw new Error('name required');
        const mod = await ensureWasm();
        const f = await mod.wasm_update_folder(wasmSession(), folderId, name);
        await afterWrite();
        return f;
    });
}

export async function deleteFolder(folderId) {
    return audited(audit.KINDS.DeleteFolder, String(folderId), String(''), async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!folderId) throw new Error('folderId required');
        const mod = await ensureWasm();
        await mod.wasm_delete_folder(wasmSession(), folderId);
        await afterWrite();
        return { deleted: folderId };
    });
}

/**
 * A second authenticator for the same profile: a plain PRF passkey published as
 * its own PasskeyPrf recipient. No software twin -- the primary's stays the
 * profile's only software identity.
 */
export async function enrollBackupPasskey(opts = {}) {
    const label = opts.label || 'Backup passkey';
    return audited(audit.KINDS.EnrollIdentity, label, '', async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!enrolmentPossible()) throw new Error('WebAuthn unavailable in this context');
        const enrolled = await CEREMONY.enroll({ rpId: opts.rpId || defaultRpId(), label });
        await savePasskeyRecipient(enrolled.record);
        const refusal = registryPublishRefusal('this browser\'s backup passkey');
        if (refusal) return { passkeyRecord: enrolled.record, publishedToRegistry: false };
        const wasm = await ensureWasm();
        const entry = await passkeyRecordToRegistryEntry(enrolled.record);
        const id = await wasm.wasm_publish_recipient_to_registry(wasmSession(), entry);
        return { passkeyRecord: enrolled.record, registryEntryId: id || entry.id, publishedToRegistry: true };
    });
}

/**
 * A fresh recovery phrase and its public key. Nothing is published: the
 * recipient only reaches the registry through publishRecovery(), after the
 * user has proved they wrote the words down.
 */
export async function generateRecovery() {
    if (!sessionBlob) throw new Error('not signed in');
    const mod = await ensureWasm();
    const gen = mod.wasm_generate_recovery_phrase();
    const armoredPubkey = gen.armored_pubkey ?? gen.armoredPubkey;
    const phrase = gen.phrase;
    if (!armoredPubkey || !phrase) throw new Error('recovery generate returned unexpected shape');
    return { phrase, armoredPubkey };
}

export async function publishRecovery(armoredPubkey, label = 'Paper recovery') {
    return audited(audit.KINDS.EnrollIdentity, String(label), '', async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!armoredPubkey) throw new Error('armoredPubkey required');
        const mod = await ensureWasm();
        const digest = await globalThis.crypto.subtle.digest(
            'SHA-256', new TextEncoder().encode(armoredPubkey));
        const idDigest = Array.from(new Uint8Array(digest))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        const entry = {
            id: 'paper-recovery-' + idDigest.slice(0, 32),
            kind: 'Recovery',
            displayName: label,
            deviceLabel: 'Browser extension',
            createdAt: Date.now(),
            defaultEncrypt: true,
            recoveryArmoredPubkey: armoredPubkey,
        };
        await mod.wasm_publish_recipient_to_registry(wasmSession(), entry);
        return { registryEntryId: entry.id };
    });
}

export async function enrollRecovery(label = 'Paper recovery') {
    const { phrase, armoredPubkey } = await generateRecovery();
    const { registryEntryId } = await publishRecovery(armoredPubkey, label);
    return { phrase, armoredPubkey, registryEntryId };
}

/*
 * Checksum-only validation for the phrase-entry UI: derives the identity and
 * throws it away. Word-level validation happens client-side against the
 * wordlist; this is the final BIP39 checksum gate before the button arms.
 * Never signs anything and needs no session.
 */
export async function validateRecoveryPhrase(phrase) {
    const mod = await ensureWasm();
    try {
        mod.wasm_recovery_identity_from_phrase(phrase);
        return { ok: true };
    } catch (e) {
        return { ok: false, error: String((e && e.message) || e) };
    }
}

export async function recoverFromPhrase(cipherId, phrase, fieldName = null) {
    const cipher = ciphersById.get(cipherId);
    const out = await audited(audit.KINDS.Recover, String(cipherId),
        (cipher && cipher.name) || '', async () => {
            if (!sessionBlob) throw new Error('Ragewarden is locked');
            if (!cipherId || !phrase) throw new Error('cipherId and phrase required');
            if (!cipher) throw new Error(`unknown cipher ${cipherId}`);
            const mod = await ensureWasm();
            const recovered = mod.wasm_recovery_identity_from_phrase(phrase);
            let armoredSecret = recovered.armored_secret ?? recovered.armoredSecret;
            if (!armoredSecret) throw new Error('recovery_identity_from_phrase returned unexpected shape');
            try {
                const bytes = await mod.wasm_decrypt_cipher_field_with_secrets(
                    wasmSession(), cipher, fieldName || primaryField(cipher.kind), null, [armoredSecret],
                );
                const value = new TextDecoder().decode(bytes);
                if (bytes && bytes.fill) bytes.fill(0);
                bumpCounter('recovery_decrypt');
                return { value };
            } finally {
                armoredSecret = '';
            }
        });
    return out.value;
}

export async function listRecipients() {
    if (!sessionBlob) throw new Error('not signed in');
    const mod = await ensureWasm();
    const reg = await mod.wasm_fetch_registry(wasmSession());
    return (reg && reg.entries) ? reg.entries : [];
}

export async function removeRecipient(entryId) {
    return audited(audit.KINDS.RemoveRecipient, String(entryId), String(''), async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!entryId) throw new Error('entryId required');
        const mod = await ensureWasm();
        await mod.wasm_unpublish_from_registry(wasmSession(), entryId);
        return { removed: entryId };
    });
}

export async function enrollPasskey(opts = {}) {
    return audited(audit.KINDS.EnrollIdentity, String(opts.label || 'Browser passkey'), String(''), async () => {
        if (!sessionBlob) throw new Error('not signed in');
        if (!enrolmentPossible()) {
            throw new Error('WebAuthn unavailable in this context');
        }
        const label = opts.label || 'Browser passkey';
        const rpId = opts.rpId || defaultRpId();

        const wasm = await ensureWasm();
        const combined = await passkeyEnrollWithSoftwareKey({ rpId, label }, wasm, CEREMONY);

        await savePasskeyRecipient(combined.passkeyRecord);
        await saveSoftwareIdentity(combined.softwareIdentity);

        /*
         * A mock build enrols for real -- locally -- and publishes nothing.
         *
         * Letting `passkeyRecordToRegistryEntry` throw here would report failure for
         * an enrolment that did happen (both records are already stored above) and
         * leave the popup's Enrol button looking broken in exactly the build whose
         * purpose is to drive that button with no hardware. The stand-in reaches
         * writes through `localStandInRecipients()` instead of through the registry;
         * `publishedToRegistry` is how a caller tells the two enrolments apart
         * rather than inferring it from empty ids.
         */
        const refusal = registryPublishRefusal('this browser\'s recipients');
        if (refusal) {
            console.warn(`[ragemanifest] enrolled locally only: ${refusal}`);
            await afterWrite();
            return {
                passkeyRecord: combined.passkeyRecord,
                softwareIdentity: combined.softwareIdentity,
                registryEntryIds: { passkey: '', software: '' },
                publishedToRegistry: false,
                notPublishedReason: refusal,
            };
        }

        const passkeyEntry = await passkeyRecordToRegistryEntry(combined.passkeyRecord);
        const passkeyId = await wasm.wasm_publish_recipient_to_registry(wasmSession(), passkeyEntry);
        const swEntry = await softwareIdentityToRegistryEntry(combined.softwareIdentity, label);
        const softwareId = await wasm.wasm_publish_recipient_to_registry(wasmSession(), swEntry);

        await afterWrite();

        return {
            passkeyRecord: combined.passkeyRecord,
            softwareIdentity: combined.softwareIdentity,
            registryEntryIds: {
                passkey: typeof passkeyId === 'string' ? passkeyId : (passkeyId && passkeyId.toString) ? passkeyId.toString() : '',
                software: typeof softwareId === 'string' ? softwareId : (softwareId && softwareId.toString) ? softwareId.toString() : '',
            },
            publishedToRegistry: true,
        };
    });
}

export async function refresh() {
    if (!sessionBlob) throw new Error('not signed in');
    await afterWrite();
    return { ciphers: snapshot?.ciphers?.length ?? 0 };
}

export function tapCountersSnapshot() {
    const slot = (typeof globalThis !== 'undefined') && globalThis.__ragewardenTapCounters;
    return slot ? { ...slot } : {
        prf_eval: 0, presence_tap: 0, js_decrypt: 0, wasm_decrypt: 0, recovery_decrypt: 0,
    };
}

export async function logout() {
    const email = (sessionBlob && sessionBlob.email) || (await lockedEmail());
    audit.record({ kind: audit.KINDS.Logout, target: '', detail: email });
    forgetUnlocked();
    await clearSession();
    notifyWorker();
}

export { audit };

export async function loadHistory(cipherId) {
    if (!sessionBlob) return [];
    if (!cipherId) return [];
    const mod = await ensureWasm();
    if (typeof mod.wasm_load_history !== 'function') return [];
    try {
        const json = await mod.wasm_load_history(wasmSession(), cipherId);
        if (!json) return [];
        return JSON.parse(json);
    } catch (e) {
        // eslint-disable-next-line no-console
        console.warn('[ragewarden] loadHistory failed:', e);
        return [];
    }
}

export async function recordHistoryRevision(cipherId, priorPayloadArmored, recipientsSummary) {
    if (!sessionBlob || !cipherId) return;
    const mod = await ensureWasm();
    if (typeof mod.wasm_record_history_revision !== 'function') return;
    try {
        await mod.wasm_record_history_revision(
            wasmSession(), cipherId, priorPayloadArmored || '', recipientsSummary || [],
        );
    } catch (e) {
        console.warn('[ragewarden] recordHistoryRevision failed:', e);
    }
}

/**
 * Re-wrap `cipherIds` under the current encrypt policy.
 *
 * `recipientIds` used to be accepted and thrown away, so a UI could offer a
 * recipient picker whose selection had no effect on a single byte written.
 * It is now an *assertion of expected coverage*, checked before anything is
 * rewritten:
 *
 *   - an id that is not in the registry            -> throw
 *   - an id policy is dropping (`skipped`)         -> throw, naming the reason
 *   - anything else policy selects                 -> still wrapped to
 *
 * It is deliberately not a filter. `select_for_encrypt` in core is the one
 * canonical policy across rageterm/ragedroid/ragemanifest; narrowing its output
 * per write is exactly the cross-client data loss documented on
 * `selectEncryptRecipients` above. The returned `alsoWrappedTo` lists the
 * covered recipients the caller did not name, so a UI can say so out loud
 * rather than implying a subset was honoured.
 */
export async function bulkProtect(recipientIds, cipherIds) {
    if (!sessionBlob) throw new Error('Ragewarden is locked');
    activity();
    if (!Array.isArray(cipherIds) || cipherIds.length === 0) {
        throw new Error('bulkProtect: no items selected');
    }

    const expected = (Array.isArray(recipientIds) ? recipientIds : [])
        .filter(id => typeof id === 'string' && id.length > 0);

    const { recipients, skipped } = await previewEncryptRecipients();
    if (recipients.length === 0) {
        throw new Error(
            'refusing to bulk-protect: policy selects no recipients, so every item would '
            + 'be rewritten with nothing able to open it. Enrol a passkey or a paper '
            + 'recovery identity first.',
        );
    }

    const registry = await listRecipients();
    const registryIds = new Set(registry.map(e => String(e && e.id)));
    const skippedById = new Map(skipped.map(s => [String(s && s.id), s]));

    const unknown = expected.filter(id => !registryIds.has(id));
    if (unknown.length > 0) {
        throw new Error(
            `refusing to bulk-protect: ${unknown.join(', ')} `
            + `${unknown.length === 1 ? 'is' : 'are'} not in the recipient registry.`,
        );
    }
    const dropped = expected.filter(id => skippedById.has(id));
    if (dropped.length > 0) {
        const detail = dropped
            .map(id => `${id} (${skippedById.get(id).reason})`)
            .join(', ');
        throw new Error(
            `refusing to bulk-protect: the encrypt policy will not wrap to ${detail}. `
            + 'Nothing was rewritten. Ragewarden wraps every item to the whole '
            + 'default-encrypt set and cannot wrap to a chosen subset, so continuing '
            + 'would silently leave those recipients unable to open these items.',
        );
    }

    const alsoWrappedTo = registry
        .filter(e => e && registryIds.has(String(e.id))
            && !skippedById.has(String(e.id))
            && !expected.includes(String(e.id)))
        .map(e => ({ id: String(e.id), kind: e.kind, displayName: e.displayName }));

    // A mock build's stand-in is deliberately absent from the registry
    // (`localStandInRecipients`), so it cannot come out of `registry` above --
    // but it *is* wrapped to, and this list is what the UI uses to say so out
    // loud. Omitting it would understate coverage in exactly the build whose
    // recipient anyone holding this source can open.
    if ((await localStandInRecipients()).length > 0) {
        alsoWrappedTo.push({
            id: '(not in registry: local stand-in)',
            kind: 'Software',
            displayName: 'Local stand-in identity (MOCK -- NOT REAL HARDWARE)',
        });
    }

    /*
     * Re-wrapping starts with a decrypt, so an item this profile cannot open is
     * not a candidate -- it is dropped here, before any tap, rather than queued
     * into a failure. Internal bookkeeping ciphers are dropped for the same
     * reason `attachToWindow` never shows them. Both come back under
     * `skippedNotOnDevice` so a caller can say so instead of miscounting.
     */
    const skippedNotOnDevice = [];
    const targets = cipherIds.filter(id => {
        const c = ciphersById.get(id);
        if (c && (isInternalCipher(c) || !cipherDecryptable(c))) {
            skippedNotOnDevice.push(id);
            return false;
        }
        return true;
    });
    if (targets.length === 0) {
        throw new Error(
            'bulk-protect: none of the selected items can be opened on this device, '
            + 'so none can be re-wrapped here. Re-wrap them from a device that holds '
            + 'one of their keys.',
        );
    }

    const total = targets.length;
    const destination = `${total} item${total === 1 ? '' : 's'} (re-wrap)`;
    let protectedCount = 0;
    const failed = [];
    const progress = (detail) => {
        try {
            window.dispatchEvent(new CustomEvent('ragewarden:bulk-progress', { detail }));
        } catch {}
    };

    /*
     * One ceremony for the whole batch: unwrap this profile's software identity
     * once, then decrypt and re-wrap every item with it. An item the batch
     * secret cannot open falls back to its own tap.
     */
    const mod = await ensureWasm();
    let batch = null;
    try {
        batch = await openBatch({
            action: 'bulk-rewrap',
            destination,
            origin: (typeof location !== 'undefined' && location.origin) || '',
        });
    } catch (err) {
        if (isUserDecline(err)) {
            audit.record({
                kind: audit.KINDS.BulkProtect, target: destination, result: audit.RESULTS.declined,
            });
            throw err;
        }
        console.warn('[ragewarden] bulk-protect: no batch identity, tapping per item:', err);
    }
    try {
        for (let i = 0; i < total; i++) {
            const cipherId = targets[i];
            progress({ current: i, total, cipherId, status: 'encrypting' });
            try {
                const cipher = ciphersById.get(cipherId);
                if (!cipher) throw new Error(`unknown cipher ${cipherId}`);
                // A protected item is re-wrapped whole (`*`), so a multi-field
                // payload keeps every field; a plain one gets its primary field sealed.
                const fieldName = cipher.rage ? '*' : primaryField(cipher.kind);
                let value = null;
                if (batch) {
                    try {
                        value = await batch.decrypt(wasmSession(), cipher, fieldName);
                    } catch (e) {
                        if (!(e && e.code === 'no_matching_identity')) throw e;
                    }
                }
                if (value === null) {
                    value = (await unlockOnce(cipherId, {
                        action: 'rotate', destination: cipher.site || cipher.name, fieldName,
                    })).value;
                }
                try {
                    if (cipher.rage) {
                        await mod.wasm_update_cipher(wasmSession(), cipherId, { rage: value }, recipients);
                    } else {
                        await mod.wasm_save_item(wasmSession(), cipherId, {},
                            { [fieldName]: value }, recipients, null);
                    }
                } finally {
                    value = '';
                }
                protectedCount++;
                progress({ current: i, total, cipherId, status: 'done' });
            } catch (err) {
                const msg = (err && err.message) || String(err);
                failed.push({ id: cipherId, error: msg });
                progress({ current: i, total, cipherId, status: 'failed', error: msg });
            }
        }
    } finally {
        if (batch) batch.close();
    }

    audit.record({
        kind: audit.KINDS.BulkProtect,
        target: destination,
        detail: `${protectedCount} re-wrapped, ${failed.length} failed`,
        result: failed.length === 0 ? audit.RESULTS.ok : audit.RESULTS.failed,
        ...(batch ? receiptSummary([batch.receipt]) : {}),
    });
    await afterWrite();
    return {
        protected: protectedCount,
        failed,
        skippedNotOnDevice,
        recipientsUsed: recipients.length,
        requestedRecipients: expected,
        alsoWrappedTo,
        ceremonies: batch ? 1 : protectedCount + failed.length,
    };
}

/*
 * Browser-extension registry entries this profile holds no key for. A Firefox
 * reinstall (new moz-extension UUID, so a new rp.id) or a cleared profile
 * leaves the old entries in the registry with defaultEncrypt on, and every
 * client keeps wrapping to keys nothing holds. Another browser profile's
 * entries look the same from here, so removal is always the user's call.
 */
export async function staleBrowserRecipients() {
    if (!sessionBlob) return [];
    const registry = await listRecipients();
    const ours = new Set();
    for (const r of await loadAllPasskeyRecipients()) {
        if (r && r.credential_id_b64) ours.add(await passkeyRegistryEntryId(r.credential_id_b64));
    }
    const software = await loadSoftwareIdentity();
    if (software && software.armored_pubkey) {
        ours.add('browser-sw-' + (await sha256Hex(software.armored_pubkey)).slice(0, 32));
    }
    return registry
        .filter(e => e && e.deviceLabel === 'Browser extension'
            && e.kind !== 'Recovery' && !ours.has(String(e.id)))
        .map(e => ({
            id: String(e.id), kind: e.kind, displayName: e.displayName || e.id, createdAt: e.createdAt || 0,
        }));
}

export function status() {
    return {
        wasmReady: crypto.isReady(),
        signedIn: !!sessionBlob,
        unlocked: !!sessionBlob,
        ciphers: ciphersById.size,
        email: (sessionBlob && sessionBlob.email) || null,
    };
}
