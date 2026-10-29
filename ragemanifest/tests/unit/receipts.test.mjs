import test from 'node:test';
import assert from 'node:assert/strict';
import { newPurpose } from '../../ext/glue/assertion.js';
import { checkReceiptShape, verifyReceipt } from '../../ext/glue/receipt-check.js';
import { makeCredential, signedReceipt } from './webauthn-fixture.mjs';

const request = { action: 'autofill', destination: 'example.com', cipherId: 'c1', origin: 'https://example.com' };

test('a signed, purpose-bound assertion verifies', async () => {
    const cred = await makeCredential();
    const receipt = await signedReceipt(cred, newPurpose(request));
    const r = await verifyReceipt(receipt, {
        allowMock: false, request, publicKeys: { [cred.credentialIdB64]: { spkiB64: cred.spkiB64, alg: cred.alg } },
    });
    assert.equal(r.signatureVerified, true);
});

test('a tap made for another item or destination is refused', async () => {
    const cred = await makeCredential();
    const receipt = await signedReceipt(cred, newPurpose({ ...request, destination: 'evil.example' }));
    await assert.rejects(verifyReceipt(receipt, { allowMock: false, request }), /different action/);
});

test('rewriting the purpose after the fact breaks the challenge', async () => {
    const cred = await makeCredential();
    const receipt = await signedReceipt(cred, newPurpose({ ...request, cipherId: 'other' }), {
        mutate: (r) => ({ ...r, purpose: { ...r.purpose, cipherId: 'c1' } }),
    });
    await assert.rejects(verifyReceipt(receipt, { allowMock: false, request }), /challenge does not match/);
});

test('a forged signature is refused when the public key is known', async () => {
    const cred = await makeCredential();
    const other = await makeCredential();
    const receipt = await signedReceipt(other, newPurpose(request), {
        mutate: (r) => ({ ...r, credentialIdB64: cred.credentialIdB64 }),
    });
    await assert.rejects(verifyReceipt(receipt, {
        allowMock: false, request, publicKeys: { [cred.credentialIdB64]: { spkiB64: cred.spkiB64, alg: -7 } },
    }), /signature does not verify/);
});

test('authenticatorData without UV is refused even if the receipt claims it', async () => {
    const cred = await makeCredential();
    const receipt = await signedReceipt(cred, newPurpose(request), {
        flags: 0x01, mutate: (r) => ({ ...r, userVerified: true }),
    });
    await assert.rejects(verifyReceipt(receipt, { allowMock: false, request }), /verification/);
});

test('mock receipts pass only where mocks are allowed', () => {
    const mock = { backend: 'MOCK-NO-DEVICE', mock: true };
    assert.throws(() => checkReceiptShape(mock, { allowMock: false }), /forbids mock/);
    checkReceiptShape(mock, { allowMock: true });
});

test('raw (P1363) signatures verify too', async () => {
    const cred = await makeCredential();
    const receipt = await signedReceipt(cred, newPurpose(request), { der: false });
    const r = await verifyReceipt(receipt, {
        allowMock: false, request, publicKeys: { [cred.credentialIdB64]: { spkiB64: cred.spkiB64, alg: -7 } },
    });
    assert.equal(r.signatureVerified, true);
});
