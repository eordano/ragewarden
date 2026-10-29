import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { test, expect, randomSuffix, waitForBootstrap } from './fixtures';

const STATE = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '.playwright-state.json'), 'utf8'));
const VAULTWARDEN_DB = join(dirname(fileURLToPath(import.meta.url)), '..', '.vaultwarden-cache', 'data', 'db.sqlite3');

/*
 * A legacy account: PBKDF2 at 5 000 iterations, the 2013-era default. Neither
 * Ragewarden nor Vaultwarden creates one any more, so the test registers at
 * 100 000 and then rewrites the user row the way an old account looks: the
 * client KDF count, the server-side password hash and the wrapped user key.
 */
const subtle = webcrypto.subtle;
const enc = new TextEncoder();
const b64 = (b: ArrayBuffer | Uint8Array) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString('base64');

async function pbkdf2(password: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, iterations: number) {
  const k = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, k, 256));
}

async function hkdfExpand(prk: Uint8Array<ArrayBuffer>, info: string) {
  const k = await subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, Buffer.concat([enc.encode(info), Buffer.from([1])])));
}

async function type2(plain: Uint8Array<ArrayBuffer>, encKey: Uint8Array<ArrayBuffer>, macKey: Uint8Array<ArrayBuffer>) {
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const ek = await subtle.importKey('raw', encKey, 'AES-CBC', false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, ek, plain));
  const mk = await subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await subtle.sign('HMAC', mk, Buffer.concat([iv, ct])));
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

async function accountKeys(email: string, password: string, iterations: number, userKey: Uint8Array<ArrayBuffer>) {
  const masterKey = await pbkdf2(enc.encode(password), enc.encode(email.toLowerCase()), iterations);
  const hash = b64(await pbkdf2(masterKey, enc.encode(password), 1));
  const key = await type2(userKey, await hkdfExpand(masterKey, 'enc'), await hkdfExpand(masterKey, 'mac'));
  return { hash, key };
}

async function makeLegacy(email: string, password: string, iterations: number, userKey: Uint8Array<ArrayBuffer>) {
  const { hash, key } = await accountKeys(email, password, iterations, userKey);
  const db = new DatabaseSync(VAULTWARDEN_DB);
  const row = db.prepare('SELECT salt, password_iterations FROM users WHERE email = ?').get(email) as { salt: Uint8Array; password_iterations: number };
  const serverHash = await pbkdf2(enc.encode(hash), new Uint8Array(row.salt), row.password_iterations);
  db.prepare('UPDATE users SET client_kdf_iter = ?, password_hash = ?, akey = ? WHERE email = ?').run(iterations, serverHash, key, email);
  db.close();
}

async function registerLegacy(server: string, email: string, password: string, iterations: number) {
  const userKey = webcrypto.getRandomValues(new Uint8Array(64));
  const masterKey = await pbkdf2(enc.encode(password), enc.encode(email.toLowerCase()), iterations);
  const hash = b64(await pbkdf2(masterKey, enc.encode(password), 1));
  const key = await type2(userKey, await hkdfExpand(masterKey, 'enc'), await hkdfExpand(masterKey, 'mac'));
  const rsa = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['encrypt', 'decrypt']);
  const publicKey = b64(await subtle.exportKey('spki', rsa.publicKey));
  const encryptedPrivateKey = await type2(new Uint8Array(await subtle.exportKey('pkcs8', rsa.privateKey)), userKey.slice(0, 32), userKey.slice(32));
  const res = await fetch(`${server}/identity/accounts/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email, name: 'legacy', masterPasswordHash: hash, masterPasswordHint: null, key,
      keys: { publicKey, encryptedPrivateKey }, kdf: 0, kdfIterations: iterations, referenceData: null,
    }),
  });
  expect(res.ok, `register account: ${res.status} ${await res.clone().text()}`).toBe(true);
  return userKey;
}

async function prelogin(server: string, email: string) {
  const res = await fetch(`${server}/identity/accounts/prelogin`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email }),
  });
  const body = await res.json();
  return body.kdfIterations ?? body.KdfIterations;
}

async function startSignIn(context: import('@playwright/test').BrowserContext, popupUrl: string, server: string, email: string, password: string) {
  const page = await context.newPage();
  await page.goto(popupUrl);
  await page.waitForSelector('.ragewarden-onb-root');
  const inputs = page.locator('.ragewarden-onb-card input');
  await inputs.nth(0).fill(server);
  await inputs.nth(1).fill(email);
  await inputs.nth(2).fill(password);
  await page.click('.ragewarden-onb-primary');
  return page;
}

test('a legacy-KDF account signs in only with consent, is upgraded on the server, and its pin is kept', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(150_000);
  const email = `legacy-${randomSuffix()}@ragewarden.test`;
  const password = `legacy-${randomSuffix()}-pw`;
  test.skip(STATE.mode !== 'native', 'rewriting the user row needs the native Vaultwarden the dev shell runs');
  const userKey = await registerLegacy(vaultwardenUrl, email, password, 100000);
  await makeLegacy(email, password, 5000, userKey);
  expect(await prelogin(vaultwardenUrl, email)).toBe(5000);

  const declined = await startSignIn(context, popupUrl, vaultwardenUrl, email, password);
  const consent = declined.getByRole('alertdialog', { name: /Upgrade this account/ });
  await expect(consent).toContainText('5,000 PBKDF2');
  await consent.getByRole('button', { name: 'Cancel' }).click();
  await expect(declined.locator('.ragewarden-onb-error')).toContainText('sign-in cancelled');
  expect(await prelogin(vaultwardenUrl, email), 'declining changes nothing on the server').toBe(5000);
  await declined.close();

  const page = await startSignIn(context, popupUrl, vaultwardenUrl, email, password);
  await page.getByRole('button', { name: 'Upgrade and sign in' }).click();
  const wizard = page.locator('.ragewarden-onb-card h1', { hasText: 'Set up Ragewarden protection' });
  await wizard.waitFor({ state: 'visible', timeout: 60_000 });
  await page.click('.ragewarden-onb-secondary');
  await page.click('.ragewarden-onb-secondary');
  await waitForBootstrap(page);

  expect(await prelogin(vaultwardenUrl, email), 'the server now derives at today\'s count').toBe(600000);
  const pins = await page.evaluate(() => new Promise(r => chrome.storage.local.get(['ragewarden:kdfPins'], i => r(i['ragewarden:kdfPins']))));
  expect(Object.values(pins as Record<string, { iterations: number }>).map(p => p.iterations)).toContain(600000);

  await page.evaluate(() => (window as unknown as { RagewardenVault: { logout(): Promise<unknown> } }).RagewardenVault.logout());
  const pinsAfter = await page.evaluate(() => new Promise(r => chrome.storage.local.get(['ragewarden:kdfPins'], i => r(i['ragewarden:kdfPins']))));
  expect(pinsAfter, 'the pin outlives sign-out').toEqual(pins);
  await page.close();
});
