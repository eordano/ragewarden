import test from 'node:test';
import assert from 'node:assert/strict';
import { newPurpose, purposeChallenge } from '../../ext/glue/assertion.js';
import { b64ToBytes, bytesToB64, bytesToB64Url } from '../../ext/glue/b64.js';
import {
    RELAY_ORIGIN, RELAY_RP_ID, RELAY_URL, algFromSpki, createRelayBroker, relayCredentialsFromRegistry,
    verifyRelayAssertion,
} from '../../ext/glue/prf-relay.js';
import { makeCredential, rawToDer } from './webauthn-fixture.mjs';

const enc = s => new TextEncoder().encode(s);
const sha = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));

async function answer(cred, purpose, { origin = RELAY_ORIGIN, rpId = RELAY_RP_ID, flags = 0x05, signer = cred } = {}) {
    const clientData = enc(JSON.stringify({
        type: 'webauthn.get', challenge: bytesToB64Url(await purposeChallenge(purpose)), origin,
    }));
    const ad = new Uint8Array(37);
    ad.set(await sha(enc(rpId)), 0);
    ad[32] = flags;
    const signed = new Uint8Array([...ad, ...await sha(clientData)]);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signer.pair.privateKey, signed));
    return {
        credentialId: bytesToB64Url(b64ToBytes(cred.credentialIdB64)),
        prfFirst: bytesToB64(new Uint8Array(32).fill(7)),
        authenticatorData: bytesToB64(ad),
        clientDataJSON: bytesToB64(clientData),
        signature: bytesToB64(rawToDer(raw)),
    };
}

function fakeTabs() {
    const tabs = { created: [], updated: [], removed: [], next: 40 };
    tabs.create = async ({ url }) => { const id = tabs.next++; tabs.created.push({ id, url }); return { id }; };
    tabs.update = async (id, { url }) => { tabs.updated.push({ id, url }); return { id }; };
    tabs.remove = async (id) => { tabs.removed.push(id); };
    return tabs;
}

const relaySender = (tabId, nonce) => ({ tab: { id: tabId }, url: `${RELAY_URL}#${nonce}` });

async function opened(broker, tabs, creds, purpose) {
    const credentials = creds.map(c => ({ ...c, saltB64: bytesToB64(new Uint8Array(32).fill(1)) }));
    const promise = broker.request({ purpose, credentials, action: 'reveal', destination: 'this window' });
    while (tabs.created.length === 0) await new Promise(r => setTimeout(r, 1));
    const { id, url } = tabs.created.at(-1);
    return { promise, tabId: id, nonce: new URL(url).hash.slice(1) };
}

test('the registry\'s phone passkeys are PasskeyPrf entries for the relay rp id with a published key', async () => {
    const cred = await makeCredential();
    const hex = Buffer.from(b64ToBytes(cred.credentialIdB64)).toString('hex');
    const entries = [
        { kind: 'PasskeyPrf', fido2RpId: RELAY_RP_ID, fido2CredentialId: hex, attestationPublicKey: cred.spkiB64, displayName: 'Pixel' },
        { kind: 'PasskeyPrf', fido2RpId: RELAY_RP_ID, fido2CredentialId: 'aa' },
        { kind: 'PasskeyPrf', fido2RpId: 'abc.chromiumapp.org', fido2CredentialId: 'bb', attestationPublicKey: cred.spkiB64 },
        { kind: 'Fido2', fido2RpId: RELAY_RP_ID, fido2CredentialId: 'cc', attestationPublicKey: cred.spkiB64 },
    ];
    assert.deepEqual(relayCredentialsFromRegistry(entries),
        [{ credentialIdB64: cred.credentialIdB64, spkiB64: cred.spkiB64, alg: -7, label: 'Pixel' }]);
    assert.equal(algFromSpki(cred.spkiB64), -7);
});

test('the relay opens a tab, hands its request only to that tab, and closes it after a verified answer', async () => {
    const tabs = fakeTabs();
    const broker = createRelayBroker({ tabs });
    const cred = await makeCredential();
    const purpose = newPurpose({ action: 'reveal', destination: 'this window', cipherId: 'c1', origin: 'chrome-extension://x' });
    const { promise, tabId, nonce } = await opened(broker, tabs, [cred], purpose);
    assert.match(tabs.created[0].url, new RegExp(`^${RELAY_URL}#`));
    assert.ok(nonce.length >= 16);

    await assert.rejects(broker.hello({ nonce }, relaySender(tabId + 1, nonce)), /another tab/);
    await assert.rejects(broker.hello({ nonce: 'x'.repeat(24) }, relaySender(tabId, 'x')), /no relay request/);
    await assert.rejects(broker.hello({ nonce }, { tab: { id: tabId }, url: `https://evil.example/prf#${nonce}` }), /only from the relay page/);
    await assert.rejects(broker.hello({ nonce }, { tab: { id: tabId }, url: `${RELAY_ORIGIN}/other#${nonce}` }), /only from the relay page/);

    const req = await broker.hello({ nonce }, relaySender(tabId, nonce));
    assert.equal(req.rpId, RELAY_RP_ID);
    assert.equal(req.challenge, bytesToB64Url(await purposeChallenge(purpose)));
    assert.deepEqual(req.credentials.map(c => c.id), [bytesToB64Url(b64ToBytes(cred.credentialIdB64))]);

    await broker.result({ nonce, result: await answer(cred, purpose) }, relaySender(tabId, nonce));
    const value = await promise;
    assert.equal(value.credentialIdB64, cred.credentialIdB64);
    assert.equal(value.prfOutputB64, bytesToB64(new Uint8Array(32).fill(7)));
    assert.deepEqual(tabs.removed, [tabId]);
    assert.equal(broker.pendingCount(), 0);
    await assert.rejects(broker.result({ nonce, result: await answer(cred, purpose) }, relaySender(tabId, nonce)),
        /no relay request/, 'a nonce answers once');
});

test('a forged, misdirected or replayed answer is refused and nothing is released', async () => {
    const cred = await makeCredential();
    const other = await makeCredential();
    const purpose = newPurpose({ action: 'reveal', destination: 'this window', cipherId: 'c1', origin: 'o' });
    const cases = [
        ['signed by another key', () => answer(cred, purpose, { signer: other }), /signature does not verify/],
        ['made on another origin', () => answer(cred, purpose, { origin: 'https://evil.example' }), /not https:\/\/ragewarden/],
        ['for another rp id', () => answer(cred, purpose, { rpId: 'evil.example' }), /not for the relay rp id/],
        ['without user verification', () => answer(cred, purpose, { flags: 0x01 }), /presence or verification/],
        ['for another purpose', async () => answer(cred, { ...purpose, cipherId: 'c2' }), /challenge does not match/],
        ['for a passkey not asked', () => answer(other, purpose), /did not ask/],
    ];
    for (const [what, make, why] of cases) {
        const tabs = fakeTabs();
        const broker = createRelayBroker({ tabs });
        const { promise, tabId, nonce } = await opened(broker, tabs, [cred], purpose);
        await broker.result({ nonce, result: await make() }, relaySender(tabId, nonce));
        await assert.rejects(promise, why, what);
        assert.deepEqual(tabs.removed, [tabId], `${what}: the tab is closed`);
    }
    await assert.rejects(verifyRelayAssertion({
        result: await answer(cred, purpose), purpose, credentials: [{ ...cred, spkiB64: '' }],
    }), /publishes no public key/);
});

test('a late answer, a closed tab and a page error each end the request', async () => {
    let t = 1_000;
    const cred = await makeCredential();
    const purpose = newPurpose({ action: 'copy', destination: 'the clipboard', cipherId: 'c1', origin: 'o' });

    let tabs = fakeTabs();
    let broker = createRelayBroker({ tabs, now: () => t, timeoutMs: 50_000 });
    let r = await opened(broker, tabs, [cred], purpose);
    t += 60_000;
    await assert.rejects(broker.result({ nonce: r.nonce, result: await answer(cred, purpose) }, relaySender(r.tabId, r.nonce)), /expired/);
    await assert.rejects(r.promise, /expired/);

    tabs = fakeTabs();
    broker = createRelayBroker({ tabs });
    r = await opened(broker, tabs, [cred], purpose);
    broker.tabClosed(r.tabId);
    await assert.rejects(r.promise, /tab was closed/);

    tabs = fakeTabs();
    broker = createRelayBroker({ tabs });
    r = await opened(broker, tabs, [cred], purpose);
    await broker.result({ nonce: r.nonce, result: { error: 'NotAllowedError: cancelled' } }, relaySender(r.tabId, r.nonce));
    await assert.rejects(r.promise, /did not answer: NotAllowedError/);
    assert.deepEqual(tabs.removed, [r.tabId]);
});
