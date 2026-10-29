import { purposeChallenge } from '../../ext/glue/assertion.js';
import { bytesToB64, bytesToB64Url } from '../../ext/glue/b64.js';

export async function makeCredential() {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    return { pair, spkiB64: bytesToB64(spki), alg: -7, credentialIdB64: bytesToB64(crypto.getRandomValues(new Uint8Array(16))) };
}

export function rawToDer(raw) {
    const int = (b) => {
        let v = Array.from(b);
        while (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) v.shift();
        if (v[0] & 0x80) v = [0, ...v];
        return [0x02, v.length, ...v];
    };
    const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
    return new Uint8Array([0x30, body.length, ...body]);
}

export async function signedReceipt(cred, purpose, { flags = 0x05, der = true, mutate } = {}) {
    const challenge = bytesToB64Url(await purposeChallenge(purpose));
    const clientData = new TextEncoder().encode(JSON.stringify({
        type: 'webauthn.get', challenge, origin: 'chrome-extension://test-extension-id',
    }));
    const authData = new Uint8Array(37);
    authData.set(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('test-extension-id'))), 0);
    authData[32] = flags;
    const cdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientData));
    const signed = new Uint8Array(authData.length + 32);
    signed.set(authData, 0);
    signed.set(cdHash, authData.length);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, cred.pair.privateKey, signed));
    const receipt = {
        backend: 'webauthn-prf',
        mock: false,
        userPresent: (flags & 1) !== 0,
        userVerified: (flags & 4) !== 0,
        credentialIdB64: cred.credentialIdB64,
        purpose,
        clientDataJSON: bytesToB64(clientData),
        authenticatorData: bytesToB64(authData),
        signature: bytesToB64(der ? rawToDer(raw) : raw),
    };
    return mutate ? mutate(receipt) : receipt;
}
