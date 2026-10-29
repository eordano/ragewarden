import test from 'node:test';
import assert from 'node:assert/strict';
import { installFakeChrome } from './fake-chrome.mjs';

const chrome = installFakeChrome();
const storage = await import('../../ext/glue/storage.js');

const session = { email: 'a@example.com', access_token: 'tok', user_enc_key: 'k' };

test('sign-in seals the session under the password and leaves it unlocked', async () => {
    await storage.clearSession();
    assert.equal(await storage.lockState(), 'signed-out');
    await storage.saveSession(session, { password: 'correct horse' });
    assert.equal(await storage.lockState(), 'unlocked');
    const env = chrome.storage.local.data.get(storage.STORAGE_KEYS.envelope);
    assert.equal(env.v, 2);
    assert.equal(env.email, 'a@example.com');
    assert.ok(!JSON.stringify(env).includes('tok'));
    assert.deepEqual(await storage.loadSession(), session);
});

test('lock removes the key; nothing loads until the password unlocks it again, offline', async () => {
    await storage.saveSession(session, { password: 'correct horse' });
    await storage.lockSession();
    assert.equal(await storage.lockState(), 'locked');
    assert.equal(chrome.storage.session.data.has(storage.STORAGE_KEYS.unlockKey), false);
    assert.equal(await storage.loadSession(), null);
    await assert.rejects(storage.unlockSession('wrong'), e => e.code === 'wrong_password');
    assert.equal(await storage.lockState(), 'locked');
    assert.deepEqual(await storage.unlockSession('correct horse'), session);
    assert.equal(await storage.lockState(), 'unlocked');
    assert.equal(await storage.verifyLocalPassword('correct horse'), true);
    assert.equal(await storage.verifyLocalPassword('nope'), false);
});

test('a refreshed session is re-sealed without the password while unlocked', async () => {
    await storage.saveSession(session, { password: 'pw' });
    await storage.saveSession({ ...session, access_token: 'tok2' });
    assert.equal((await storage.loadSession()).access_token, 'tok2');
    await storage.lockSession();
    await assert.rejects(storage.saveSession(session), /locked/);
});

test('an idle deadline in the past locks', async () => {
    await storage.saveSession(session, { password: 'pw' });
    const k = chrome.storage.session.data.get(storage.STORAGE_KEYS.unlockKey);
    chrome.storage.session.data.set(storage.STORAGE_KEYS.unlockKey, { ...k, deadline: Date.now() - 1 });
    assert.equal(await storage.lockState(), 'locked');
    assert.equal(await storage.lockIfIdle(), true);
    assert.equal(chrome.storage.session.data.has(storage.STORAGE_KEYS.unlockKey), false);
});

test('touch extends the deadline by the configured auto-lock', async () => {
    await storage.setAutoLockMinutes(5);
    await storage.saveSession(session, { password: 'pw' });
    assert.equal(await storage.touchSession(), true);
    const k = chrome.storage.session.data.get(storage.STORAGE_KEYS.unlockKey);
    assert.ok(k.deadline > Date.now() + 4 * 60_000 && k.deadline <= Date.now() + 5 * 60_000);
    await assert.rejects(storage.setAutoLockMinutes(0), /between/);
});

test('a v1 envelope with its raw key present is legacy-locked; without the key it is signed out', async () => {
    await storage.clearSession();
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key,
        new TextEncoder().encode(JSON.stringify(session))));
    const b64 = (b) => Buffer.from(b).toString('base64');
    chrome.storage.local.data.set(storage.STORAGE_KEYS.envelope, { v: 1, iv: b64(iv), ct: b64(ct) });
    chrome.storage.session.data.set(storage.STORAGE_KEYS.unlockKey, b64(raw));
    assert.equal(await storage.lockState(), 'legacy-locked');
    assert.deepEqual(await storage.loadSession(), session);
    await storage.saveSession(session, { password: 'upgraded' });
    assert.equal(chrome.storage.local.data.get(storage.STORAGE_KEYS.envelope).v, 2);
    chrome.storage.session.data.delete(storage.STORAGE_KEYS.unlockKey);
    chrome.storage.local.data.set(storage.STORAGE_KEYS.envelope, { v: 1, iv: b64(iv), ct: b64(ct) });
    assert.equal(await storage.lockState(), 'signed-out');
});
