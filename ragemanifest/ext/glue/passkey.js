import { b64ToBytes, bytesToB64, bytesToB64Url } from './b64.js';
import { authenticatorFlags as flagsFromAuthData, checkClientData, purposeChallenge } from './assertion.js';

const DEFAULT_RP_NAME = 'Ragewarden';

export const PRF_UNSUPPORTED = 'this browser or authenticator does not support the WebAuthn PRF '
    + 'extension, which Ragewarden needs to derive keys from a passkey (Chrome/Edge 116+, Firefox '
    + '132+, Safari 18+, with a passkey provider that implements it). Use another authenticator, '
    + 'or protect items with a paper recovery phrase.';

export function defaultRpId() {
    if (typeof location !== 'undefined' && location.hostname) return location.hostname;
    throw new Error(
        'rpId is required in this context: no location.hostname to derive it from. '
        + 'WebAuthn rp.id must be a registrable suffix of the calling origin; for an '
        + 'extension page that is the extension id, never a bare label.',
    );
}

export function authenticatorFlags(assertion) {
    try {
        const ad = assertion && assertion.response && assertion.response.authenticatorData;
        return flagsFromAuthData(ad ? new Uint8Array(ad) : null);
    } catch {
        return { userPresent: false, userVerified: false, known: false };
    }
}

/**
 * Refuse an assertion that is not evidence of the user action we asked for.
 *
 * Every `navigator.credentials.get()` in this module sends
 * `userVerification: 'required'`, so both flags are checked here. Asking for UV
 * and *reading it back* are different claims: the request is an instruction to
 * the client, and only the UV bit in authenticatorData says the authenticator
 * actually verified the user. Checking UP alone accepts a bare touch on a key
 * whose PIN or biometric was never presented -- precisely the guarantee a PRF
 * unlock is sold on, and precisely what a hostile or buggy client can hand back
 * while the request still says 'required'.
 *
 * A future call site that deliberately asks for a weaker userVerification must
 * not use this helper; it would fail here on a correct assertion.
 */
function requireUserAction(assertion, what) {
    const flags = authenticatorFlags(assertion);
    if (!flags.known) {
        throw new Error(`${what}: authenticatorData unreadable, cannot prove a tap happened`);
    }
    if (!flags.userPresent) {
        throw new Error(`${what}: authenticator reported no user presence (UP flag clear)`);
    }
    if (!flags.userVerified) {
        throw new Error(
            `${what}: authenticator did not perform user verification `
            + '(UV flag clear) despite userVerification:"required"',
        );
    }
    return flags;
}

function ensureSalt(salt) {
    if (salt instanceof Uint8Array) {
        if (salt.length !== 32) throw new Error(`salt must be 32 bytes, got ${salt.length}`);
        return salt;
    }
    if (typeof salt === 'string') {
        const bytes = b64ToBytes(salt);
        if (bytes.length !== 32) throw new Error(`salt b64 must decode to 32 bytes, got ${bytes.length}`);
        return bytes;
    }
    throw new Error('salt must be Uint8Array or base64 string');
}

export async function passkeyEnroll(opts = {}) {
    const rpId = opts.rpId || defaultRpId();
    const rpName = opts.rpName || DEFAULT_RP_NAME;
    const label = opts.label || 'Primary passkey';
    const salt = opts.salt instanceof Uint8Array
        ? opts.salt
        : (opts.salt ? ensureSalt(opts.salt) : crypto.getRandomValues(new Uint8Array(32)));

    const userId = opts.userIdBytes instanceof Uint8Array
        ? opts.userIdBytes
        : crypto.getRandomValues(new Uint8Array(16));
    const userName = opts.userName || 'ragewarden-user';
    const userDisplayName = opts.userDisplayName || label;

    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const cred = await navigator.credentials.create({
        publicKey: {
            rp: { id: rpId, name: rpName },
            user: { id: userId, name: userName, displayName: userDisplayName },
            challenge,
            pubKeyCredParams: [
                { type: 'public-key', alg: -7 },
                { type: 'public-key', alg: -257 },
            ],
            authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'required',
            },
            attestation: 'none',
            extensions: { prf: { eval: { first: salt } } },
        },
    });
    if (!cred) throw new Error('passkey create failed (no credential returned)');

    const extResults = (cred.getClientExtensionResults && cred.getClientExtensionResults()) || {};
    if (!extResults.prf || extResults.prf.enabled === false) {
        throw new Error(PRF_UNSUPPORTED);
    }
    const prfFirst = extResults.prf && extResults.prf.results && extResults.prf.results.first;
    const resp = cred.response || {};
    const spki = typeof resp.getPublicKey === 'function' ? resp.getPublicKey() : null;
    const alg = typeof resp.getPublicKeyAlgorithm === 'function' ? resp.getPublicKeyAlgorithm() : null;

    return {
        record: {
            kind: 'passkey_prf',
            credential_id_b64: bytesToB64(new Uint8Array(cred.rawId)),
            salt_b64: bytesToB64(salt),
            rp_id: rpId,
            label,
            ...(spki ? { public_key_spki_b64: bytesToB64(new Uint8Array(spki)), public_key_alg: alg } : {}),
        },
        // PRF output the authenticator returned from create() itself (CTAP2.1
        // hmac-secret at make-credential). PRF is deterministic in (credential,
        // salt), so this equals what a follow-up get() would produce -- using it
        // lets enrolment wrap the software key from the single register tap
        // instead of asking for a second tap. TRANSIENT: never stored in the
        // persisted/published record above. null when the authenticator does
        // not return it at create time, in which case the caller taps again.
        prfOutput: prfFirst ? new Uint8Array(prfFirst) : null,
    };
}

function requirePurpose(purpose, what) {
    if (!purpose || typeof purpose !== 'object' || !purpose.nonce) {
        throw new Error(`${what}: a purpose {action, destination, cipherId, origin, nonce} is required`);
    }
    return purpose;
}

async function assertionEvidence(assertion, purpose) {
    const resp = assertion.response;
    const clientDataJSON = new Uint8Array(resp.clientDataJSON);
    await checkClientData(clientDataJSON, purpose);
    return {
        purpose,
        clientDataJSON: bytesToB64(clientDataJSON),
        authenticatorData: bytesToB64(new Uint8Array(resp.authenticatorData)),
        signature: bytesToB64(new Uint8Array(resp.signature)),
    };
}

export async function passkeyPresenceAssert(opts = {}) {
    const ids = (opts.credentialIds || []).map(c => (
        c instanceof Uint8Array ? c : b64ToBytes(c)
    ));
    if (ids.length === 0) {
        throw new Error('passkeyPresenceAssert: credentialIds must not be empty');
    }
    const rpId = opts.rpId || defaultRpId();
    const purpose = requirePurpose(opts.purpose, 'passkeyPresenceAssert');
    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: await purposeChallenge(purpose),
            rpId,
            allowCredentials: ids.map(id => ({ id, type: 'public-key' })),
            userVerification: 'required',
        },
    });
    if (!assertion) throw new Error('passkey assertion failed (no assertion returned)');
    const flags = requireUserAction(assertion, 'passkeyPresenceAssert');
    return {
        credentialId: new Uint8Array(assertion.rawId),
        flags,
        evidence: await assertionEvidence(assertion, purpose),
    };
}

export async function passkeyUnlockMulti(opts) {
    const pairs = (opts.pairs || []).map(p => ({
        credentialId: p.credentialId instanceof Uint8Array
            ? p.credentialId
            : b64ToBytes(p.credentialId),
        salt: ensureSalt(p.salt),
    }));
    if (pairs.length === 0) {
        throw new Error('passkeyUnlockMulti: pairs must not be empty');
    }
    const rpId = opts.rpId || defaultRpId();
    const purpose = requirePurpose(opts.purpose, 'passkeyUnlockMulti');

    const allowCredentials = pairs.map(p => ({
        id: p.credentialId,
        type: 'public-key',
    }));
    const evalByCredential = {};
    for (const p of pairs) {
        evalByCredential[bytesToB64Url(p.credentialId)] = { first: p.salt };
    }

    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: await purposeChallenge(purpose),
            rpId,
            allowCredentials,
            userVerification: 'required',
            extensions: { prf: { evalByCredential } },
        },
    });
    if (!assertion) throw new Error('passkey assertion failed (no assertion returned)');
    const flags = requireUserAction(assertion, 'passkeyUnlockMulti');
    const ext = assertion.getClientExtensionResults();
    const prf = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    if (!prf) throw new Error(PRF_UNSUPPORTED);
    const prfOutput = new Uint8Array(prf);
    if (prfOutput.length !== 32) {
        throw new Error(`PRF output must be 32 bytes, got ${prfOutput.length}`);
    }
    const credentialId = new Uint8Array(assertion.rawId);
    return { credentialId, prfOutput, flags, evidence: await assertionEvidence(assertion, purpose) };
}

async function wrapWithPrf(prfOutput, armoredSecret) {
    if (prfOutput.length !== 32) {
        throw new Error(`wrap key must be 32 bytes, got ${prfOutput.length}`);
    }
    const baseKey = await crypto.subtle.importKey(
        'raw', prfOutput, 'HKDF', false, ['deriveKey'],
    );
    const aesKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0),
            info: new TextEncoder().encode('webauthn-prf-software-wrap-v1'),
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        new TextEncoder().encode(armoredSecret),
    ));
    return { iv_b64: bytesToB64(iv), ct_b64: bytesToB64(ct) };
}

export async function unwrapWithPrf(prfOutput, ivB64, ctB64) {
    if (prfOutput.length !== 32) {
        throw new Error(`unwrap key must be 32 bytes, got ${prfOutput.length}`);
    }
    const baseKey = await crypto.subtle.importKey(
        'raw', prfOutput, 'HKDF', false, ['deriveKey'],
    );
    const aesKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0),
            info: new TextEncoder().encode('webauthn-prf-software-wrap-v1'),
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
    const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBytes(ivB64) },
        aesKey,
        b64ToBytes(ctB64),
    );
    return new TextDecoder().decode(pt);
}

/**
 * Enrol a credential and wrap a fresh software identity to its PRF.
 *
 * `ceremony` is injected rather than imported so this module stays the raw
 * WebAuthn layer with no dependency on hardware-tap.js (which imports *it*).
 * It is required, not defaulted: a caller that forgets it gets an error, never
 * a silent bypass of the backend gate that decides real-vs-mock.
 */
export async function passkeyEnrollWithSoftwareKey(opts, wasm, ceremony) {
    if (!ceremony || typeof ceremony.enroll !== 'function' || typeof ceremony.prfTap !== 'function') {
        throw new Error(
            'passkeyEnrollWithSoftwareKey: ceremony {enroll, prfTap} is required -- '
            + 'enrolment must go through hardware-tap.js, not straight to navigator.credentials',
        );
    }
    const enrolled = await ceremony.enroll(opts);
    const passkeyRecord = enrolled.record;
    if (!wasm || typeof wasm.wasm_software_keygen !== 'function') {
        throw new Error('passkeyEnrollWithSoftwareKey: wasm.wasm_software_keygen missing');
    }
    // If the register ceremony already yielded the PRF (create-time hmac-secret),
    // wrap from that single tap. Otherwise ask for the second tap.
    let prfOutput = enrolled.prfOutput || null;
    if (!prfOutput) {
        const tap = await ceremony.prfTap({
            pairs: [{
                credentialId: passkeyRecord.credential_id_b64,
                salt: passkeyRecord.salt_b64,
            }],
            rpId: passkeyRecord.rp_id,
            action: 'enroll',
            destination: 'wrap software identity',
        });
        prfOutput = tap.prfOutput;
    }
    const keygen = wasm.wasm_software_keygen();
    const armoredPubkey = keygen.armored_pubkey ?? keygen.armoredPubkey;
    const armoredSecret = keygen.armored_secret ?? keygen.armoredSecret;
    if (!armoredPubkey || !armoredSecret) {
        throw new Error('wasm_software_keygen returned unexpected shape');
    }
    const wrapped = await wrapWithPrf(prfOutput, armoredSecret);
    if (prfOutput && prfOutput.fill) prfOutput.fill(0);
    return {
        passkeyRecord,
        softwareIdentity: {
            armored_pubkey: armoredPubkey,
            wrapped_secret_iv_b64: wrapped.iv_b64,
            wrapped_secret_ct_b64: wrapped.ct_b64,
            wrap_credential_id_b64: passkeyRecord.credential_id_b64,
            wrap_salt_b64: passkeyRecord.salt_b64,
            wrap_rp_id: passkeyRecord.rp_id,
        },
    };
}

