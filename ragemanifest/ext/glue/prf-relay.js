import {
    authenticatorFlags, checkClientData, purposeChallenge, verifyAssertionSignature,
} from './assertion.js';
import { b64FromHex, b64ToBytes, bytesToB64, bytesToB64Url } from './b64.js';

/*
 * The passkey relay. A passkey made for ragewarden.decent.foundation -- the
 * phone's, created by RageDroid or synced through a password manager -- can
 * only be asked from a page on that origin, so its PRF output reaches this
 * extension through https://ragewarden.decent.foundation/prf: the worker opens
 * the page, relay-content.js carries the request in and the answer out.
 *
 * The page sees the PRF output, so the relay origin is trusted for items
 * wrapped to such a passkey (DESIGN.md, SECURITY.md). What it cannot do is
 * replay: the challenge is the purpose hash of one action, item and
 * destination, and the assertion must verify against the key the passkey's
 * registry entry publishes.
 */
export const RELAY_RP_ID = 'ragewarden.decent.foundation';
export const RELAY_ORIGIN = `https://${RELAY_RP_ID}`;
export const RELAY_PATH = '/prf';
export const RELAY_URL = `${RELAY_ORIGIN}${RELAY_PATH}`;
export const RELAY_TIMEOUT_MS = 180_000;

const canon = v => String(v || '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
export const sameCredentialId = (a, b) => canon(a) === canon(b);

const OID = {
    ec: [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
    ed25519: [0x06, 0x03, 0x2b, 0x65, 0x70],
    rsa: [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
};

function contains(hay, needle) {
    outer: for (let i = 0; i + needle.length <= hay.length; i++) {
        for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
        return true;
    }
    return false;
}

/** The COSE algorithm of an SPKI public key (ES256, EdDSA or RS256), or null. */
export function algFromSpki(spkiB64) {
    let spki;
    try { spki = b64ToBytes(spkiB64); } catch { return null; }
    if (contains(spki, OID.ec)) return -7;
    if (contains(spki, OID.ed25519)) return -8;
    if (contains(spki, OID.rsa)) return -257;
    return null;
}

/**
 * The registry's phone passkeys: PasskeyPrf entries for the relay's rp id.
 * Each carries the credential's public key (`attestationPublicKey`, SPKI);
 * one without it cannot be verified and is left out.
 */
export function relayCredentialsFromRegistry(entries) {
    const out = [];
    for (const e of entries || []) {
        if (!e || e.kind !== 'PasskeyPrf' || e.fido2RpId !== RELAY_RP_ID || !e.fido2CredentialId) continue;
        const spkiB64 = typeof e.attestationPublicKey === 'string' ? e.attestationPublicKey : '';
        const alg = spkiB64 ? algFromSpki(spkiB64) : null;
        if (!spkiB64 || alg === null) continue;
        out.push({ credentialIdB64: b64FromHex(String(e.fido2CredentialId)), spkiB64, alg, label: e.displayName || '' });
    }
    return out;
}

async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/**
 * Everything a relayed answer must prove before its PRF output is used: the
 * credential is one that was asked for, the client data is a get for this
 * purpose's challenge on the relay origin, the authenticator data names the
 * relay rp id with user presence and verification, and the signature verifies
 * under that credential's published key.
 */
export async function verifyRelayAssertion({ result, purpose, credentials }) {
    if (!result || typeof result !== 'object') throw new Error('the relay returned nothing');
    const want = (credentials || []).find(c => sameCredentialId(c.credentialIdB64, result.credentialId));
    if (!want) throw new Error('the relay answered for a passkey this request did not ask');
    if (!want.spkiB64 || !want.alg) throw new Error('this passkey publishes no public key to check its answer');
    const clientData = await checkClientData(b64ToBytes(result.clientDataJSON || ''), purpose);
    if (clientData.origin !== RELAY_ORIGIN) {
        throw new Error(`the relayed assertion was made on ${JSON.stringify(clientData.origin)}, not ${RELAY_ORIGIN}`);
    }
    if (clientData.crossOrigin === true) throw new Error('the relayed assertion was made in a cross-origin frame');
    const ad = b64ToBytes(result.authenticatorData || '');
    const rpHash = await sha256(new TextEncoder().encode(RELAY_RP_ID));
    if (ad.length < 37 || rpHash.some((b, i) => ad[i] !== b)) {
        throw new Error('the relayed assertion is not for the relay rp id');
    }
    const flags = authenticatorFlags(ad);
    if (!flags.userPresent || !flags.userVerified) {
        throw new Error('the relayed assertion lacks user presence or verification');
    }
    const ok = await verifyAssertionSignature({
        publicKeySpki: want.spkiB64,
        alg: want.alg,
        authenticatorData: ad,
        clientDataJSON: b64ToBytes(result.clientDataJSON),
        signature: result.signature || '',
    });
    if (!ok) throw new Error('the relayed assertion signature does not verify');
    const prfOutput = b64ToBytes(result.prfFirst || '');
    if (prfOutput.length !== 32) throw new Error('the relay returned no 32-byte PRF output');
    return { credentialIdB64: want.credentialIdB64, prfOutput, flags };
}

function randomNonce() {
    return bytesToB64Url(crypto.getRandomValues(new Uint8Array(18)));
}

/**
 * The worker's side: one pending request per nonce, answered only by the tab
 * it opened, before the deadline; the tab is closed once it answers.
 * `tabs` is chrome.tabs (create/update/remove), injectable for tests.
 */
export function createRelayBroker({
    tabs, now = () => Date.now(), timeoutMs = RELAY_TIMEOUT_MS, nonce = randomNonce,
    verify = verifyRelayAssertion,
} = {}) {
    const pending = new Map();
    let adoptTabId = null;
    let lastStrayTabId = null;

    const closeTab = (tabId) => {
        try {
            const r = tabs.remove(tabId);
            if (r && r.catch) r.catch(() => {});
        } catch {}
    };

    function settle(key, outcome) {
        const p = pending.get(key);
        if (!p) return;
        pending.delete(key);
        clearTimeout(p.timer);
        closeTab(p.tabId);
        if (outcome.error) p.reject(outcome.error);
        else p.resolve(outcome.value);
    }

    function senderIsRelay(sender) {
        let url;
        try { url = new URL(sender && sender.url ? sender.url : ''); } catch { return false; }
        return url.origin === RELAY_ORIGIN && url.pathname === RELAY_PATH;
    }

    function match(msg, sender) {
        if (!senderIsRelay(sender) || !sender.tab) {
            throw new Error('relay messages are accepted only from the relay page');
        }
        const p = pending.get(String((msg && msg.nonce) || ''));
        if (!p) {
            lastStrayTabId = sender.tab.id;
            throw new Error('no relay request has that nonce');
        }
        if (p.tabId !== sender.tab.id) throw new Error('that relay request belongs to another tab');
        if (now() > p.deadline) {
            settle(p.nonce, { error: new Error('the relay request expired') });
            throw new Error('the relay request expired');
        }
        return p;
    }

    return {
        /** Open the relay for `credentials` ({credentialIdB64, saltB64, spkiB64, alg}). */
        async request({ purpose, credentials, action = '', destination = '' }) {
            if (!Array.isArray(credentials) || credentials.length === 0) {
                throw new Error('the relay needs at least one phone passkey to ask');
            }
            const key = nonce();
            const url = `${RELAY_URL}#${key}`;
            let tabId;
            if (adoptTabId !== null) {
                tabId = adoptTabId;
                adoptTabId = null;
                await tabs.update(tabId, { url, active: true });
            } else {
                tabId = (await tabs.create({ url, active: true })).id;
            }
            return new Promise((resolve, reject) => {
                const timer = setTimeout(
                    () => settle(key, { error: new Error('no answer from the passkey relay in time') }), timeoutMs);
                pending.set(key, {
                    nonce: key, tabId, purpose, credentials, action, destination, resolve, reject, timer,
                    deadline: now() + timeoutMs,
                });
            });
        },

        async hello(msg, sender) {
            const p = match(msg, sender);
            return {
                nonce: p.nonce,
                rpId: RELAY_RP_ID,
                challenge: bytesToB64Url(await purposeChallenge(p.purpose)),
                credentials: p.credentials.map(c => ({
                    id: bytesToB64Url(b64ToBytes(c.credentialIdB64)), salt: c.saltB64,
                })),
                action: p.action,
                destination: p.destination,
            };
        },

        async result(msg, sender) {
            const p = match(msg, sender);
            const r = (msg && msg.result) || {};
            if (r.error) {
                settle(p.nonce, { error: new Error(`the passkey did not answer: ${r.error}`) });
                return;
            }
            try {
                const checked = await verify({ result: r, purpose: p.purpose, credentials: p.credentials });
                settle(p.nonce, {
                    value: {
                        credentialIdB64: checked.credentialIdB64,
                        prfOutputB64: bytesToB64(checked.prfOutput),
                        assertion: {
                            credentialId: r.credentialId,
                            clientDataJSON: r.clientDataJSON,
                            authenticatorData: r.authenticatorData,
                            signature: r.signature,
                        },
                        flags: checked.flags,
                    },
                });
            } catch (err) {
                settle(p.nonce, { error: err });
            }
        },

        tabClosed(tabId) {
            for (const p of Array.from(pending.values())) {
                if (p.tabId === tabId) settle(p.nonce, { error: new Error('the passkey relay tab was closed') });
            }
        },

        /* test-only seams: run the next request in an open relay tab */
        adopt(tabId) { adoptTabId = tabId; },
        lastStrayTab() { return lastStrayTabId; },
        pendingCount() { return pending.size; },
    };
}
