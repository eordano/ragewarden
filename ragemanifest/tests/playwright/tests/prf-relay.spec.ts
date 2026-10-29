import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BrowserContext, Page } from '@playwright/test';
import { test, expect, attachAuthenticator, signIn, waitForBootstrap } from './fixtures';

/*
 * I14: a passkey made for ragewarden.decent.foundation -- the phone's -- opens
 * an item in this browser through the relay page. The page is the real
 * relay/ source, served on its real origin by route interception with the
 * headers vpnhead sends; the phone is a virtual authenticator on that tab.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const RELAY_DIR = resolve(__dirname, '..', '..', '..', 'relay');
const RP_ID = 'ragewarden.decent.foundation';
const RELAY_URL = `https://${RP_ID}/prf`;
const CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
const FILES: Record<string, [string, string]> = {
  '/prf': ['prf.html', 'text/html; charset=utf-8'],
  '/prf.js': ['prf.js', 'text/javascript; charset=utf-8'],
  '/prf.css': ['prf.css', 'text/css; charset=utf-8'],
};

async function serveRelay(context: BrowserContext) {
  await context.route(`https://${RP_ID}/**`, (route) => {
    const hit = FILES[new URL(route.request().url()).pathname];
    if (!hit) return route.fulfill({ status: 404, body: '' });
    return route.fulfill({
      status: 200,
      contentType: hit[1],
      headers: { 'content-security-policy': CSP, 'cache-control': 'no-store' },
      body: readFileSync(join(RELAY_DIR, hit[0])),
    });
  });
}

type Phone = { idB64: string; idHex: string; spkiB64: string; saltB64: string; saltHex: string; prfB64: string };

/** What RageDroid does at enrolment: a passkey for the rp id, its public key and one PRF output. */
async function enrolPhonePasskey(relay: Page): Promise<Phone> {
  return relay.evaluate(async (rpId) => {
    const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
    const hex = (b: ArrayBuffer | Uint8Array) => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, '0')).join('');
    const c = await navigator.credentials.create({ publicKey: {
      rp: { id: rpId, name: 'Ragewarden' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'phone', displayName: 'phone' },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      extensions: { prf: {} },
    } }) as PublicKeyCredential;
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const a = await navigator.credentials.get({ publicKey: {
      rpId, challenge: crypto.getRandomValues(new Uint8Array(32)), userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: c.rawId }],
      extensions: { prf: { eval: { first: salt } } },
    } }) as PublicKeyCredential;
    const prf = (a.getClientExtensionResults() as { prf: { results: { first: ArrayBuffer } } }).prf.results.first;
    const spki = (c.response as AuthenticatorAttestationResponse).getPublicKey()!;
    return { idB64: b64(c.rawId), idHex: hex(c.rawId), spkiB64: b64(spki), saltB64: b64(salt), saltHex: hex(salt), prfB64: b64(prf) };
  }, RP_ID);
}

async function worker(context: BrowserContext) {
  const sw = context.serviceWorkers().find(w => w.url().startsWith('chrome-extension://'))
    ?? await context.waitForEvent('serviceworker');
  return sw;
}

test('a phone passkey opens an item in this browser through the relay page, bound to that reveal', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);
  await serveRelay(context);
  // No passkey and no software identity here: only the phone can open the item.
  const { page } = await signIn(context, popupUrl, vaultwardenUrl);

  const relay = await context.newPage();
  await attachAuthenticator(relay);
  await relay.goto(RELAY_URL);
  await expect(relay.getByRole('button', { name: 'Use my passkey' })).toBeDisabled();
  const phone = await enrolPhonePasskey(relay);

  const secret = `phone-only-${Date.now()}`;
  await page.evaluate(async ({ phone, secret, rpId }) => {
    const w = window as unknown as {
      RagewardenVault: { crypto: { init(): Promise<{
        wasm_publish_recipient_to_registry(s: unknown, e: unknown): Promise<unknown>;
        wasm_create_cipher_with_prf(s: unknown, f: unknown, r: unknown, t: unknown): Promise<unknown>;
      }> } };
      __ragewardenSession: unknown;
    };
    const wasm = await w.RagewardenVault.crypto.init();
    await wasm.wasm_publish_recipient_to_registry(w.__ragewardenSession, {
      id: 'ragedroid-pixel', kind: 'PasskeyPrf', displayName: 'Pixel passkey', deviceLabel: 'RageDroid',
      createdAt: Date.now(), defaultEncrypt: true, fido2CredentialId: phone.idHex, fido2RpId: rpId,
      fido2Salt: phone.saltHex, attestationPublicKey: phone.spkiB64,
    });
    const bytes = (b: string) => Array.from(atob(b), ch => ch.charCodeAt(0));
    await wasm.wasm_create_cipher_with_prf(w.__ragewardenSession, { name: 'phone-item', rage: secret },
      [{ type: 'passkey_prf', credential_id: bytes(phone.idB64), salt: bytes(phone.saltB64), rp_id: rpId, label: 'Pixel passkey' }],
      [{ rp_id: rpId, credential_id_b64: phone.idB64, salt_b64: phone.saltB64, prf_output_b64: phone.prfB64 }]);
  }, { phone, secret, rpId: RP_ID });

  await page.reload();
  await waitForBootstrap(page);
  const row = page.locator('.vrow', { hasText: 'phone-item' });
  await expect(row).toBeVisible({ timeout: 30_000 });

  // The worker opens a fresh tab in use; here it runs in the tab holding the
  // virtual phone (a virtual authenticator belongs to one tab).
  const sw = await worker(context);
  await relay.evaluate(() => { location.hash = 'not-a-request'; });
  await expect.poll(() => sw.evaluate(async () =>
    (await (self as unknown as { __ragewardenBackground: { relay(): Promise<{ lastStrayTab(): number | null }> } })
      .__ragewardenBackground.relay()).lastStrayTab())).not.toBeNull();
  await sw.evaluate(async () => {
    const r = await (self as unknown as { __ragewardenBackground: { relay(): Promise<{ lastStrayTab(): number; adopt(id: number): void }> } })
      .__ragewardenBackground.relay();
    r.adopt(r.lastStrayTab());
  });

  await row.click();
  await page.getByRole('group', { name: 'Password' }).getByRole('button', { name: 'Reveal' }).click();

  await expect(relay.getByText('Ragewarden asks your passkey to reveal')).toBeVisible({ timeout: 30_000 });
  await relay.getByRole('button', { name: 'Use my passkey' }).click();

  await expect(page.getByRole('group', { name: 'Password' }).locator('.secret-value')).toHaveText(secret, { timeout: 30_000 });
  await expect.poll(() => relay.isClosed(), { message: 'the worker closes the relay tab' }).toBe(true);
  await page.close();
});
