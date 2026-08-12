import * as crypto from './crypto.js';
import { saveSession, loadSession, clearSession, getDeviceId } from './storage.js';
import { showOnboarding, showProtectionWizard } from './onboarding.js';
import {
    passkeyEnrollWithSoftwareKey,
} from './passkey.js';
import {
    loadAllPasskeyRecipients,
    loadPasskeyRecipient,
    loadSoftwareIdentity,
    savePasskeyRecipient,
    saveSoftwareIdentity,
} from './passkey-store.js';
import { bumpCounter } from './tap-counters.js';
import { friendlyDecryptError, unlockCipherField } from './unlock.js';
import { probe as probeNativeHost } from './native-host.js';
import {
    mockTapAllowed,
    backendIsMock,
    backendLabel,
    performPrfEnroll,
    performPrfTap,
} from './hardware-tap.js';
import { testHooksEnabled, vmServerUrl } from './build-flags.js';
import { writeClipboard, clearClipboard } from './clipboard.js';
import * as audit from './audit.js';

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

    const reg = await wasm.wasm_fetch_registry(sessionBlob);
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
            sessionBlob, { ...entry, kind: PASSKEY_REGISTRY_KIND },
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

async function sha256Hex(input) {
    const bytes = new TextEncoder().encode(input);
    const digest = await crypto_subtle().digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function crypto_subtle() {
    return globalThis.crypto.subtle;
}

function hexFromB64(b64) {
    const bin = atob(b64);
    let hex = '';
    for (let i = 0; i < bin.length; i++) {
        hex += bin.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return hex;
}

function b64FromHex(hex) {
    let bin = '';
    for (let i = 0; i + 1 < hex.length; i += 2) {
        bin += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    }
    return btoa(bin);
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
    sessionBlob = await loadSession();
    return sessionBlob;
}

/**
 * Registry/history bookkeeping ciphers, which are storage and never items.
 *
 * The wasm marks these with `internal: true`; the name check only covers a
 * snapshot produced by a wasm build older than that field, so a stale bundle
 * still cannot render `__ragedroid_recipients_v1__` as a clickable login.
 */
function isInternalCipher(c) {
    if (!c) return false;
    if (c.internal === true) return true;
    const name = String(c.name || '');
    return /^__.+__/.test(name) || name === 'Ragewarden Recipients (do not edit)';
}

/**
 * `decryptable` with the fail-closed default the directive demands: a rage item
 * is openable here only when the snapshot positively says so. A snapshot from a
 * wasm build without the field therefore dims every rage item rather than
 * offering decrypts that end in a stanza mismatch.
 */
function cipherDecryptable(c) {
    if (!c) return false;
    if (!c.rage) return true;
    return c.decryptable === true;
}

function cipherRecipientCount(c) {
    return (c && typeof c.recipient_count === 'number') ? c.recipient_count : 0;
}

/**
 * What this profile can actually open, in the shape
 * `wasm_fetch_vault_with_identities` expects (LocalIdentityInventory).
 *
 * - the software identity counts only because its record exists here, which
 *   means the wrapping passkey was enrolled in this profile;
 * - passkey credential ids come from this profile's passkey store;
 * - piv/fido2 entries from the shared registry are claimed only when the
 *   browser can open a native-messaging port to rageterm. `probe()` reports
 *   "worth attempting", not "installed", so this can over-claim -- a decrypt
 *   attempt then fails with code `no_matching_identity` and the same
 *   "not on this device" copy. Under-claiming would be worse: it would dim
 *   items the native host genuinely opens, with no way to try.
 */
async function localIdentityInventory() {
    const inventory = {
        software_armored_pubkeys: [],
        passkey_credential_ids_b64: [],
        fido2_credential_ids_b64: [],
        piv_pubkeys_hex: [],
        keystore_handles: [],
    };
    try {
        const software = await loadSoftwareIdentity();
        if (software && software.armored_pubkey && software.wrap_credential_id_b64) {
            inventory.software_armored_pubkeys.push(software.armored_pubkey);
        }
        for (const r of await loadAllPasskeyRecipients()) {
            if (r && r.credential_id_b64) {
                inventory.passkey_credential_ids_b64.push(r.credential_id_b64);
            }
        }
    } catch (e) {
        console.warn('[ragewarden] could not read local identities for the snapshot:', e);
    }
    try {
        const host = await probeNativeHost();
        if (host && host.capable) {
            const mod = await ensureWasm();
            const reg = await mod.wasm_fetch_registry(sessionBlob);
            for (const e of (reg && reg.entries) || []) {
                if (!e) continue;
                if (e.pivPubkey) inventory.piv_pubkeys_hex.push(String(e.pivPubkey));
                if (e.kind === 'Fido2' && e.fido2CredentialId) {
                    inventory.fido2_credential_ids_b64.push(b64FromHex(String(e.fido2CredentialId)));
                }
            }
        }
    } catch {}
    return inventory;
}

/*
 * Always fetched here, with this profile's identity inventory -- not through the
 * background worker. The worker fetches with `wasm_fetch_vault`, whose empty
 * inventory marks every rage item `decryptable: false` (fail closed), and it
 * cannot be handed the inventory without widening its message surface; a popup
 * rendering that snapshot would dim the whole vault.
 */
async function fetchVault() {
    const mod = await ensureWasm();
    let result;
    if (typeof mod.wasm_fetch_vault_with_identities === 'function') {
        result = await mod.wasm_fetch_vault_with_identities(
            sessionBlob, await localIdentityInventory(),
        );
    } else {
        console.warn(
            '[ragewarden] wasm module has no wasm_fetch_vault_with_identities export; '
            + 'every rage item will show as not decryptable here (rebuild the wasm)',
        );
        result = await mod.wasm_fetch_vault(sessionBlob);
    }
    // The fetch refreshes an expired access token in place; when it does, it
    // returns the updated session so we persist it, otherwise every later fetch
    // reuses the dead token and 401s again.
    if (result && result.refreshed_session) {
        sessionBlob = result.refreshed_session;
        try { await saveSession(sessionBlob); } catch (_) { /* best effort */ }
    }
    snapshot = result;
    ciphersById.clear();
    for (const c of (result.ciphers || [])) ciphersById.set(c.id, c);
    return result;
}

export async function lookupForOrigin(origin) {
    if (backgroundAvailable()) {
        try {
            const r = await bgSend({ kind: 'vault.lookup', origin });
            if (r && r.ok) return r.matches || [];
        } catch {}
    }
    if (!snapshot) return [];
    const out = [];
    let host;
    try { host = new URL(origin).hostname.toLowerCase(); } catch { host = String(origin || '').toLowerCase(); }
    for (const c of snapshot.ciphers || []) {
        // No internal bookkeeping item and no item this profile cannot open is
        // ever offered for a fill: both would only be selectable failures.
        if (isInternalCipher(c) || !cipherDecryptable(c)) continue;
        const site = (c.site || '').toLowerCase();
        if (!site) continue;
        const candHost = (() => {
            try { return new URL(site.startsWith('http') ? site : `https://${site}`).hostname.toLowerCase(); }
            catch { return ''; }
        })();
        if (candHost && (candHost === host || host.endsWith(`.${candHost}`))) {
            out.push({ id: c.id, name: c.name, username: c.username || null, site: c.site, rage: !!c.rage });
        }
    }
    return out;
}

function attachToWindow() {
    if (typeof window !== 'undefined' && testHooksEnabled()) {
        window.__ragewardenSession = sessionBlob;
    }
    const ciphers = (snapshot && snapshot.ciphers) || [];
    const folders = (snapshot && snapshot.folders) || [];

    const folderNameById = new Map();
    for (const f of folders) folderNameById.set(f.id, f.name);

    const logins = [];
    const byKind = [];
    for (const c of ciphers) {
        // Registry/history bookkeeping never reaches the UI at all -- rendering
        // it as a clickable item is how "Reveal: decrypt: no login.password"
        // used to leak out of __ragedroid_recipients_v1__.
        if (isInternalCipher(c)) continue;
        const folderName = folderNameById.get(c.folder_id) || null;
        const item = {
            id: c.id,
            name: c.name,
            username: c.username || null,
            site: c.site || null,
            folder: folderName,
            favorite: !!c.favorite,
            rage: !!c.rage,
            decryptable: cipherDecryptable(c),
            recipientCount: cipherRecipientCount(c),
        };
        if (c.kind === 'login') logins.push(item);
        else byKind.push({ ...item, kind: c.kind || 'other' });
    }

    window.VAULT = logins;
    window.ITEMS_BY_KIND = byKind;
    const folderCount = new Map();
    for (const c of ciphers) {
        if (isInternalCipher(c)) continue;
        if (c.folder_id) folderCount.set(c.folder_id, (folderCount.get(c.folder_id) || 0) + 1);
    }
    window.FOLDERS = folders.map(f => ({
        id: f.id,
        name: f.name,
        count: folderCount.get(f.id) || 0,
    }));
}

export function bootstrap() {
    if (bootstrapPromise) return bootstrapPromise;
    bootstrapPromise = (async () => {
        await ensureWasm();
        let s = await ensureSession();
        let firstSignIn = false;
        if (!s) {
            const mod = await ensureWasm();
            s = await showOnboarding({
                wasmLogin: async (server, email, password, deviceName) =>
                    mod.wasm_login(server, email, password, deviceName, await getDeviceId()),
                wasmRegister: (server, email, name, password, iters) =>
                    mod.wasm_register(server, email, name, password, iters),
                // Prefill only. A VM build still has to submit the form, so the
                // sign-in path under test is the same one a user walks.
                ...(vmServerUrl() ? { defaultServerUrl: vmServerUrl() } : {}),
            });
            sessionBlob = s;
            await saveSession(s);
            firstSignIn = true;
        }
        if (firstSignIn) {
            try {
                const existing = await loadPasskeyRecipient();
                if (!existing && enrolmentPossible()) {
                    let combined = null;
                    const combinedEnroll = async (opts) => {
                        const wasm = await ensureWasm();
                        combined = await passkeyEnrollWithSoftwareKey(opts, wasm, CEREMONY);
                        return combined.passkeyRecord;
                    };
                    const saveAndPublish = async (record) => {
                        await savePasskeyRecipient(record);
                        if (combined) {
                            await saveSoftwareIdentity(combined.softwareIdentity);
                        }
                        try {
                            const wasm = await ensureWasm();
                            const passkeyEntry = await passkeyRecordToRegistryEntry(record);
                            await wasm.wasm_publish_recipient_to_registry(sessionBlob, passkeyEntry);
                            if (combined) {
                                const swEntry = await softwareIdentityToRegistryEntry(
                                    combined.softwareIdentity, record.label,
                                );
                                await wasm.wasm_publish_recipient_to_registry(sessionBlob, swEntry);
                            }
                        } catch (e) {
                            console.warn(
                                '[ragemanifest] passkey saved locally but not published to '
                                + 'cross-device registry:', e
                            );
                        }
                    };
                    await showProtectionWizard({
                        passkeyEnroll: combinedEnroll,
                        savePasskeyRecipient: saveAndPublish,
                    });
                }
            } catch {
            }
        }
        /*
         * Outside the `firstSignIn` branch on purpose: the users who need the
         * repair are precisely the ones who enrolled long ago, so the one code
         * path that never runs for them is the enrolment path. A failure here
         * must not block sign-in -- the registry is remote state and the popup
         * has to open without it -- but it is reported, because a silently
         * skipped migration leaves the account in the broken state this exists
         * to leave behind.
         */
        try {
            await migrateOwnPasskeyEntriesToPasskeyPrf(await ensureWasm());
        } catch (e) {
            console.warn(
                '[ragemanifest] could not correct the kind of this browser\'s published '
                + 'passkey entry; items wrapped to it may be unopenable here:', e,
            );
        }
        await fetchVault();
        attachToWindow();
        return {
            email: s.email,
            ciphers: (snapshot && snapshot.ciphers && snapshot.ciphers.length) || 0,
        };
    })();
    return bootstrapPromise;
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

async function unlockOnce(itemId, ctx) {
    const fieldName = ctx.fieldName || 'password';
    const action = ctx.action;
    const destination = ctx.destination || '';

    if (!sessionBlob) throw new Error('not signed in');
    const cipher = ciphersById.get(itemId);
    if (!cipher) throw new Error(`unknown item ${itemId}`);
    if (isInternalCipher(cipher)) {
        throw new Error('this entry is Ragewarden bookkeeping, not an item');
    }
    if (!cipherDecryptable(cipher)) throw notOnThisDeviceError(cipher);

    await ensureWasm();
    let value;
    try {
        ({ value } = await unlockCipherField({
            session: sessionBlob,
            cipher,
            fieldName,
            action,
            destination,
            origin: (typeof location !== 'undefined' && location.origin) || '',
        }));
    } catch (err) {
        throw friendlyDecryptError(err, cipher);
    }
    bumpCounter('js_decrypt');
    return value;
}

export async function revealPassword(itemId, fieldName = 'password') {
    const cipher = ciphersById.get(itemId);
    const dest = (cipher && cipher.site) || '';
    void audit.record({
        kind: audit.KINDS.RevealPassword,
        target: itemId,
        detail: (cipher && cipher.name) || '',
    });
    return unlockOnce(itemId, { action: 'reveal', destination: dest, fieldName });
}

export async function autofillPassword(itemId, destination) {
    const cipher = ciphersById.get(itemId);
    const dest = destination || (cipher && cipher.site) || '';
    void audit.record({
        kind: audit.KINDS.AutofillPassword,
        target: itemId,
        detail: dest,
    });
    return unlockOnce(itemId, {
        action: 'autofill',
        destination: dest,
        fieldName: 'password',
    });
}

/**
 * Run the tap ceremony and put the plaintext on the clipboard.
 *
 * The plaintext is deliberately not returned: the caller never needs it, and
 * anything it did with it (rendering, logging) would be a second copy of a
 * secret that is supposed to exist only long enough to reach the clipboard.
 * A refused clipboard write throws -- it must never look like a success.
 */
export async function copyPassword(itemId) {
    const cipher = ciphersById.get(itemId);
    const dest = (cipher && cipher.site) || '';
    void audit.record({
        kind: audit.KINDS.CopyPassword,
        target: itemId,
        detail: (cipher && cipher.name) || '',
    });
    let value = await unlockOnce(itemId, {
        action: 'copy', destination: dest, fieldName: 'password',
    });
    try {
        const via = await writeClipboard(value);
        return { copied: true, chars: value.length, via };
    } finally {
        value = '';
    }
}

export async function clearClipboardNow() {
    return clearClipboard();
}

function serverBaseUrl(session) {
    const api = (session && session.api_url) || '';
    if (!api) {
        throw new Error('this session carries no api_url; cannot re-check the master password');
    }
    return api.replace(/\/api\/?$/, '');
}

/**
 * Re-check the master password against the Bitwarden server.
 *
 * Resolves only when the server accepted the password; every other outcome
 * throws with the underlying message, so a caller cannot mistake "server
 * unreachable" for "password correct". The issued session is discarded -- this
 * is an authentication check, not a sign-in.
 *
 * This is a re-authentication gate, not a decryption gate: `bootstrap()` has
 * already loaded the session envelope by the time any UI can call this. It is
 * what makes the popup's lock screen mean something; it is not what protects
 * the secrets. That is the per-item hardware tap in `unlockCipherField`.
 */
export async function verifyMasterPassword(password) {
    if (!sessionBlob) throw new Error('not signed in');
    if (typeof password !== 'string' || password.length === 0) {
        throw new Error('enter your master password');
    }
    const mod = await ensureWasm();
    const base = serverBaseUrl(sessionBlob);
    const device = 'ragemanifest-verify@'
        + ((typeof navigator !== 'undefined' && navigator.userAgent.split(' ')[0]) || 'browser');
    try {
        await mod.wasm_login(base, sessionBlob.email, password, device, await getDeviceId());
    } catch (err) {
        throw new Error((err && err.message) || String(err));
    }
    return true;
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
async function encryptSelection() {
    const mod = await ensureWasm();
    const selection = await mod.wasm_select_encrypt_recipients(sessionBlob, null);
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
 * Second argument is `null` -- the set of PRF authenticators this page can
 * evaluate *during a wrap*. `setCipher`/`editCipher` go through
 * `wasm_create_cipher`/`wasm_update_cipher`, which do not tap, so nothing is
 * reachable. Passkey-kind entries therefore come back under `skipped` with
 * `no_local_authenticator` rather than being dropped without a trace; browser
 * passkeys stay covered through the paired `Software` entry that
 * `enrollPasskey` publishes alongside them -- or, in a mock build that publishes
 * nothing, through the local-only copy of that same key
 * (`localStandInRecipients`). That paired case is not a coverage hole and
 * `withoutPairedPasskeyHoles` takes it out of `skipped`; what is left here is
 * a key this browser cannot reach and nothing else covers.
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
 * The recipient set a write would actually use, plus what policy dropped and
 * why. The UI needs this to tell the truth about coverage instead of drawing a
 * checkbox list that selects nothing.
 */
export async function previewEncryptRecipients() {
    if (!sessionBlob) throw new Error('not signed in');
    return encryptSelection();
}

function buildPlaintextFields({ name, plaintext, type }) {
    const fields = { name, rage: plaintext };
    if (type === 'login') fields.cipher_type = 'login';
    return fields;
}

export async function setCipher(name, plaintext, opts = {}) {
    void audit.record({ kind: audit.KINDS.SetCipher, target: name, detail: opts.type || 'note' });
    if (!sessionBlob) throw new Error('not signed in');
    const mod = await ensureWasm();
    const recipients = await buildEncryptRecipients();
    if (recipients.length === 0) throw new Error('no recipients in registry -- enroll a passkey first');
    const fields = buildPlaintextFields({ name, plaintext, type: opts.type });
    const saved = await mod.wasm_create_cipher(sessionBlob, fields, recipients);
    await fetchVault();
    attachToWindow();
    return saved;
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
export async function editCipher(id, name, plaintext, opts = {}) {
    void audit.record({ kind: audit.KINDS.EditCipher, target: id, detail: name });
    if (!sessionBlob) throw new Error('not signed in');
    if (!id) throw new Error('id required');
    const mod = await ensureWasm();
    // Recipients first: asking for a tap and only then discovering there is
    // nobody to wrap to spends the user's hardware on a write that cannot land.
    const recipients = await buildEncryptRecipients();
    if (recipients.length === 0) throw new Error('no recipients in registry');
    let secret = plaintext;
    if (secret === null || secret === undefined) {
        const cipher = ciphersById.get(id);
        if (!cipher) throw new Error(`unknown cipher ${id}`);
        secret = await unlockOnce(id, {
            action: 'rename',
            destination: cipher.site || cipher.name,
            fieldName: 'password',
        });
    }
    const fields = buildPlaintextFields({ name, plaintext: secret, type: opts.type });
    const saved = await mod.wasm_update_cipher(sessionBlob, id, fields, recipients);
    await fetchVault();
    attachToWindow();
    return saved;
}

export async function rotateCipher(id) {
    void audit.record({ kind: audit.KINDS.RotateCipher, target: id });
    if (!sessionBlob) throw new Error('not signed in');
    const cipher = ciphersById.get(id);
    if (!cipher) throw new Error(`unknown cipher ${id}`);
    const plaintext = await unlockOnce(id, {
        action: 'rotate',
        destination: cipher.site || cipher.name,
        fieldName: 'password',
    });
    return editCipher(id, cipher.name, plaintext);
}

export async function deleteCipher(id) {
    void audit.record({ kind: audit.KINDS.DeleteCipher, target: id });
    if (!sessionBlob) throw new Error('not signed in');
    if (!id) throw new Error('id required');
    const mod = await ensureWasm();
    await mod.wasm_delete_cipher(sessionBlob, id);
    await fetchVault();
    attachToWindow();
    return { deleted: id };
}

export async function createFolder(name) {
    void audit.record({ kind: audit.KINDS.CreateFolder, target: name });
    if (!sessionBlob) throw new Error('not signed in');
    if (!name) throw new Error('name required');
    const mod = await ensureWasm();
    const f = await mod.wasm_create_folder(sessionBlob, name);
    await fetchVault();
    attachToWindow();
    return f;
}

export async function renameFolder(folderId, name) {
    void audit.record({ kind: audit.KINDS.RenameFolder, target: folderId, detail: name });
    if (!sessionBlob) throw new Error('not signed in');
    if (!folderId) throw new Error('folderId required');
    if (!name) throw new Error('name required');
    const mod = await ensureWasm();
    const f = await mod.wasm_update_folder(sessionBlob, folderId, name);
    await fetchVault();
    attachToWindow();
    return f;
}

export async function deleteFolder(folderId) {
    void audit.record({ kind: audit.KINDS.DeleteFolder, target: folderId });
    if (!sessionBlob) throw new Error('not signed in');
    if (!folderId) throw new Error('folderId required');
    const mod = await ensureWasm();
    await mod.wasm_delete_folder(sessionBlob, folderId);
    await fetchVault();
    attachToWindow();
    return { deleted: folderId };
}

export async function enrollRecovery(label = 'Paper recovery') {
    void audit.record({ kind: audit.KINDS.EnrollRecovery, target: label });
    if (!sessionBlob) throw new Error('not signed in');
    const mod = await ensureWasm();
    const gen = mod.wasm_generate_recovery_phrase();
    const armoredPubkey = gen.armored_pubkey ?? gen.armoredPubkey;
    const phrase = gen.phrase;
    if (!armoredPubkey || !phrase) throw new Error('recovery generate returned unexpected shape');

    const sha256Hex = async (s) => {
        const bytes = new TextEncoder().encode(s);
        const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
        return Array.from(new Uint8Array(digest))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    };
    const idDigest = await sha256Hex(armoredPubkey);
    const entry = {
        id: 'paper-recovery-' + idDigest.slice(0, 32),
        kind: 'Recovery',
        displayName: label,
        deviceLabel: 'Browser extension',
        createdAt: Date.now(),
        defaultEncrypt: true,
        recoveryArmoredPubkey: armoredPubkey,
    };
    await mod.wasm_publish_recipient_to_registry(sessionBlob, entry);
    return { phrase, armoredPubkey, registryEntryId: entry.id };
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

export async function recoverFromPhrase(cipherId, phrase, fieldName = 'password') {
    void audit.record({ kind: audit.KINDS.RevealPassword, target: cipherId, detail: 'via paper recovery' });
    if (!sessionBlob) throw new Error('not signed in');
    if (!cipherId || !phrase) throw new Error('cipherId and phrase required');
    const mod = await ensureWasm();
    const cipher = ciphersById.get(cipherId);
    if (!cipher) throw new Error(`unknown cipher ${cipherId}`);
    const recovered = mod.wasm_recovery_identity_from_phrase(phrase);
    const armoredSecret = recovered.armored_secret ?? recovered.armoredSecret;
    if (!armoredSecret) throw new Error('recovery_identity_from_phrase returned unexpected shape');
    const bytes = await mod.wasm_decrypt_cipher_field_with_secrets(
        sessionBlob, cipher, fieldName, null, [armoredSecret],
    );
    return new TextDecoder().decode(bytes);
}

export async function listRecipients() {
    if (!sessionBlob) throw new Error('not signed in');
    const mod = await ensureWasm();
    const reg = await mod.wasm_fetch_registry(sessionBlob);
    return (reg && reg.entries) ? reg.entries : [];
}

export async function removeRecipient(entryId) {
    void audit.record({ kind: audit.KINDS.RemoveRecipient, target: entryId });
    if (!sessionBlob) throw new Error('not signed in');
    if (!entryId) throw new Error('entryId required');
    const mod = await ensureWasm();
    await mod.wasm_unpublish_from_registry(sessionBlob, entryId);
    return { removed: entryId };
}

export async function enrollPasskey(opts = {}) {
    void audit.record({ kind: audit.KINDS.EnrollPasskey, target: opts.label || 'Browser passkey' });
    if (!sessionBlob) throw new Error('not signed in');
    if (!enrolmentPossible()) {
        throw new Error('WebAuthn unavailable in this context');
    }
    const label = opts.label || 'Browser passkey';
    const rpId = opts.rpId || (typeof location !== 'undefined' ? location.hostname : 'ragewarden');

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
        await fetchVault();
        attachToWindow();
        return {
            passkeyRecord: combined.passkeyRecord,
            softwareIdentity: combined.softwareIdentity,
            registryEntryIds: { passkey: '', software: '' },
            publishedToRegistry: false,
            notPublishedReason: refusal,
        };
    }

    const passkeyEntry = await passkeyRecordToRegistryEntry(combined.passkeyRecord);
    const passkeyId = await wasm.wasm_publish_recipient_to_registry(sessionBlob, passkeyEntry);
    const swEntry = await softwareIdentityToRegistryEntry(combined.softwareIdentity, label);
    const softwareId = await wasm.wasm_publish_recipient_to_registry(sessionBlob, swEntry);

    await fetchVault();
    attachToWindow();

    return {
        passkeyRecord: combined.passkeyRecord,
        softwareIdentity: combined.softwareIdentity,
        registryEntryIds: {
            passkey: typeof passkeyId === 'string' ? passkeyId : (passkeyId && passkeyId.toString) ? passkeyId.toString() : '',
            software: typeof softwareId === 'string' ? softwareId : (softwareId && softwareId.toString) ? softwareId.toString() : '',
        },
        publishedToRegistry: true,
    };
}

export async function refresh() {
    if (!sessionBlob) throw new Error('not signed in');
    await fetchVault();
    attachToWindow();
    return { ciphers: snapshot?.ciphers?.length ?? 0 };
}

export function tapCountersSnapshot() {
    const slot = (typeof globalThis !== 'undefined') && globalThis.__ragewardenTapCounters;
    return slot ? { ...slot } : { prf_eval: 0, presence_tap: 0, js_decrypt: 0, wasm_decrypt: 0 };
}

export async function logout() {
    const email = (sessionBlob && sessionBlob.email) || '';
    void audit.record({
        kind: audit.KINDS.Logout,
        target: '',
        detail: email,
    });
    sessionBlob = null;
    snapshot = null;
    ciphersById.clear();
    bootstrapPromise = null;
    await clearSession();
}

export { audit };

export async function loadHistory(cipherId) {
    if (!sessionBlob) return [];
    if (!cipherId) return [];
    const mod = await ensureWasm();
    if (typeof mod.wasm_load_history !== 'function') return [];
    try {
        const json = await mod.wasm_load_history(sessionBlob, cipherId);
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
            sessionBlob,
            cipherId,
            priorPayloadArmored || '',
            recipientsSummary || [],
        );
    } catch (e) {
        // eslint-disable-next-line no-console
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
    if (!sessionBlob) throw new Error('not signed in');
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

    void audit.record({ kind: audit.KINDS.RotateCipher, target: `bulk(${targets.length})` });
    const total = targets.length;
    let protectedCount = 0;
    const failed = [];

    for (let i = 0; i < total; i++) {
        const cipherId = targets[i];
        const progress = { current: i, total, cipherId, status: 'encrypting' };
        try {
            window.dispatchEvent(new CustomEvent('ragewarden:bulk-progress', { detail: progress }));
        } catch {}

        try {
            await rotateCipher(cipherId);
            protectedCount++;
            try {
                window.dispatchEvent(new CustomEvent('ragewarden:bulk-progress', {
                    detail: { current: i, total, cipherId, status: 'done' },
                }));
            } catch {}
        } catch (err) {
            const msg = (err && err.message) || String(err);
            failed.push({ id: cipherId, error: msg });
            try {
                window.dispatchEvent(new CustomEvent('ragewarden:bulk-progress', {
                    detail: { current: i, total, cipherId, status: 'failed', error: msg },
                }));
            } catch {}
        }
    }

    await fetchVault();
    attachToWindow();
    return {
        protected: protectedCount,
        failed,
        skippedNotOnDevice,
        recipientsUsed: recipients.length,
        requestedRecipients: expected,
        alsoWrappedTo,
    };
}

export function status() {
    return {
        wasmReady: crypto.isReady(),
        signedIn: !!sessionBlob,
        ciphers: ciphersById.size,
        email: (sessionBlob && sessionBlob.email) || null,
    };
}
