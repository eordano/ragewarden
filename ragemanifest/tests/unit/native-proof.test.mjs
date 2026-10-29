import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    attestationKeysForStanza, newChallenge, proofMessage, verifyUnwrapProof,
} from '../../ext/glue/native-proof.js';

const subtle = globalThis.crypto.subtle;
const b64 = (buf) => Buffer.from(new Uint8Array(buf)).toString('base64');
const stanza = { tag: 'piv-p256', args: ['AbCd', 'x'], body: 'Ym9keQ' };
const context = { action: 'autofill', destination: 'login.example.test' };

async function device() {
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = b64(await subtle.exportKey('spki', pair.publicKey));
    const sign = async (fields) => b64(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey,
        await proofMessage(fields)));
    return { spki, sign };
}

test('a proof signed over this challenge, stanza and destination by a published key is attested', async () => {
    const d = await device();
    const challenge = newChallenge();
    const proof = { alg: 'ES256', public_key: d.spki, signature: await d.sign({ challenge, stanza, ...context }) };
    assert.deepEqual(await verifyUnwrapProof({ proof, challenge, stanza, context, trustedKeys: [d.spki] }), { attested: true });
});

test('replayed for another challenge, another stanza or another destination it is refused', async () => {
    const d = await device();
    const challenge = newChallenge();
    const proof = { alg: 'ES256', public_key: d.spki, signature: await d.sign({ challenge, stanza, ...context }) };
    const args = { proof, challenge, stanza, context, trustedKeys: [d.spki] };
    await assert.rejects(verifyUnwrapProof({ ...args, challenge: newChallenge() }), /does not verify/);
    await assert.rejects(verifyUnwrapProof({ ...args, stanza: { ...stanza, body: 'b3RoZXI' } }), /does not verify/);
    await assert.rejects(verifyUnwrapProof({ ...args, context: { ...context, destination: 'evil.test' } }), /does not verify/);
});

test('a key no registry entry publishes is refused even with a valid signature', async () => {
    const d = await device();
    const other = await device();
    const challenge = newChallenge();
    const proof = { alg: 'ES256', public_key: d.spki, signature: await d.sign({ challenge, stanza, ...context }) };
    await assert.rejects(verifyUnwrapProof({ proof, challenge, stanza, context, trustedKeys: [other.spki] }), /no registry entry publishes/);
});

test('an unsigned reply is refused once the recipient publishes a key, and recorded as unattested otherwise', async () => {
    const d = await device();
    await assert.rejects(verifyUnwrapProof({ proof: undefined, challenge: newChallenge(), stanza, context, trustedKeys: [d.spki] }), /no signed proof/);
    assert.deepEqual(await verifyUnwrapProof({ proof: undefined, challenge: newChallenge(), stanza, context }), { attested: false });
});

test('every unwrap gets a fresh 32-byte challenge', () => {
    const a = newChallenge();
    assert.equal(Buffer.from(a, 'base64').length, 32);
    assert.notEqual(a, newChallenge());
});

test('the native bridge serves the v2 PIV stanza and accepts its tap backend', async () => {
    const { NATIVE_ONLY_STANZA_TAGS } = await import('../../ext/glue/native-host.js');
    const { NATIVE_HOST_TAP_BACKENDS } = await import('../../ext/glue/receipt-check.js');
    assert.ok(NATIVE_HOST_TAP_BACKENDS.includes('piv-x25519-v2'));
    assert.ok(NATIVE_ONLY_STANZA_TAGS.includes('piv-x25519-v2'));
});

/*
 * The vector rageterm's native_proof.rs verifies too
 * (the_cross_client_vector_verifies_and_regenerates): one P-256 key (d =
 * 0x11..11), one message, a PIV proof and a FIDO2 assertion proof over it.
 */
const VECTOR = {
    challenge: 'dmVjdG9yLWNoYWxsZW5nZQ==',
    stanza: { tag: 'piv-p256', args: ['AbCdEf', 'Ag'], body: 'Ym9keQ' },
    context: { action: 'autofill', destination: 'login.example.test' },
    spki: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAhfmF/C2RDkoJ4+WmZ5pojpPLBUr321s32bluAKC1O0ZSn3ry5dxLS3aPKhaqHZaVvRfx1hZllLyiXxlMG5XlA==',
    pivSignature: 'vzmVzoZnX0/C5uYhrnk31YmbQDmdNjsTali1T8l/omNWh2xFrK3Q/ttJ5nG7jUSgIFUTjDVhy4eB5KKNi+Rnnw==',
    fidoAuthenticatorData: 'W1FavAM2GKNCKyuyNuk48flkj12XcmOu3tnVbkWma/4BAAAAAA==',
    fidoSignature: 'OtwPMX8PfqdbxBDNihJUth+5vXvQZtMiIDE5CedxG2zjve8Pb4+6Gh4BraxwPLuv5YpMRn2fEnEpXP0KBW0XYw==',
};
const vectorArgs = (proof, overrides = {}) => ({
    proof, challenge: VECTOR.challenge, stanza: VECTOR.stanza, context: VECTOR.context,
    trustedKeys: [VECTOR.spki], ...overrides,
});
const vectorFido = {
    kind: 'fido2-assertion', alg: 'ES256', public_key: VECTOR.spki,
    authenticatorData: VECTOR.fidoAuthenticatorData, signature: VECTOR.fidoSignature,
};

test('the cross-client vector verifies: the PIV proof and the FIDO2 assertion proof', async () => {
    const piv = { alg: 'ES256', public_key: VECTOR.spki, signature: VECTOR.pivSignature };
    assert.deepEqual(await verifyUnwrapProof(vectorArgs(piv)), { attested: true });
    assert.deepEqual(await verifyUnwrapProof(vectorArgs(vectorFido)), { attested: true });
});

test('a FIDO2 proof needs the UP flag, its own destination and its own signature kind', async () => {
    const auth = Buffer.from(VECTOR.fidoAuthenticatorData, 'base64');
    auth[32] = 0;
    await assert.rejects(verifyUnwrapProof(vectorArgs({ ...vectorFido, authenticatorData: auth.toString('base64') })),
        /user-presence/);
    await assert.rejects(verifyUnwrapProof(vectorArgs(vectorFido, {
        context: { ...VECTOR.context, destination: 'evil.test' },
    })), /does not verify/);
    await assert.rejects(verifyUnwrapProof(vectorArgs({ ...vectorFido, signature: VECTOR.pivSignature })),
        /does not verify/);
    await assert.rejects(verifyUnwrapProof(vectorArgs({ ...vectorFido, kind: 'something-else' })), /unsupported proof kind/);
});

test('a FIDO2 assertion made over SHA-256 of the proof message is attested', async () => {
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = b64(await subtle.exportKey('spki', pair.publicKey));
    const challenge = newChallenge();
    const message = await proofMessage({ challenge, stanza, ...context });
    const rpIdHash = new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode('ragewarden')));
    const auth = new Uint8Array([...rpIdHash, 0x05, 0, 0, 0, 7]);
    const clientDataHash = new Uint8Array(await subtle.digest('SHA-256', message));
    const signature = b64(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey,
        new Uint8Array([...auth, ...clientDataHash])));
    const proof = { kind: 'fido2-assertion', alg: 'ES256', public_key: spki, authenticatorData: b64(auth), signature };
    assert.deepEqual(await verifyUnwrapProof({ proof, challenge, stanza, context, trustedKeys: [spki] }), { attested: true });
});

test('trusted keys are the stanza recipient\'s own: PIV by its key tag, FIDO2 by its credential', async () => {
    const p256Hex = '02' + '11'.repeat(32);
    const tag = createHash('sha256').update(Buffer.from(p256Hex, 'hex')).digest().subarray(0, 4)
        .toString('base64').replace(/=+$/, '');
    const credHex = Buffer.from('credential-1').toString('hex');
    const entries = [
        { pivPubkey: p256Hex, fido2CredentialId: null, attestationPublicKey: 'PIVKEY' },
        { pivPubkey: null, fido2CredentialId: credHex, attestationPublicKey: 'FIDOKEY' },
        { pivPubkey: '03' + '22'.repeat(32), fido2CredentialId: null, attestationPublicKey: 'OTHER' },
    ];
    assert.deepEqual(await attestationKeysForStanza({ tag: 'piv-p256', args: [tag, 'A'.repeat(44)] }, entries), ['PIVKEY']);
    const credArg = Buffer.from('credential-1').toString('base64url');
    assert.deepEqual(await attestationKeysForStanza({ tag: 'fido2-hmac', args: [credArg, 's', 'w'] }, entries), ['FIDOKEY']);
    const x25519 = { tag: 'piv-p256', args: ['B'.repeat(43), 'ZZZZZZ'] };
    assert.deepEqual(await attestationKeysForStanza(x25519, entries), []);
});

test('an unattested recipient keeps working beside one that publishes a key', async () => {
    const d = await device();
    const entries = [{ pivPubkey: '02' + '11'.repeat(32), fido2CredentialId: null, attestationPublicKey: d.spki }];
    const legacy = { tag: 'piv-p256', args: ['B'.repeat(43), 'ZZZZZZ'], body: 'Ym9keQ' };
    const trustedKeys = await attestationKeysForStanza(legacy, entries);
    assert.deepEqual(
        await verifyUnwrapProof({ proof: undefined, challenge: newChallenge(), stanza: legacy, context, trustedKeys }),
        { attested: false },
    );
});
