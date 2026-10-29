import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BrowserContext, Page } from '@playwright/test';
import { test, expect, fillOnboarding, waitForBootstrap, randomSuffix } from './fixtures';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_HTML = readFileSync(join(__dirname, 'fixtures', 'login-form.html'));
const PASSWORD = 'lock-and-fill-correct-horse';

interface Bridge {
  RagewardenVault: {
    lock(): Promise<void>;
    unlock(pw: string): Promise<{ locked: boolean; offline?: string }>;
    status(): { unlocked: boolean };
  };
  RagewardenInit?: { phase: string; locked?: boolean };
}

async function signIn(context: BrowserContext, popupUrl: string, vaultwardenUrl: string): Promise<Page> {
  const page = await context.newPage();
  await page.goto(popupUrl);
  await fillOnboarding(page, {
    server: vaultwardenUrl,
    email: `lock-${randomSuffix()}@ragewarden.test`,
    password: PASSWORD,
    mode: 'register',
  });
  await waitForBootstrap(page);
  return page;
}

async function sessionKey(page: Page): Promise<unknown> {
  return page.evaluate(() => new Promise(resolve => {
    chrome.storage.session.get(['ragewarden:envelopeKey'], items => resolve(items['ragewarden:envelopeKey'] ?? null));
  }));
}

async function initState(page: Page) {
  await expect.poll(() => page.evaluate(() => (window as unknown as Bridge).RagewardenInit?.phase ?? null),
    { timeout: 30_000 }).toBe('ready');
  return page.evaluate(() => (window as unknown as Bridge).RagewardenInit!);
}

test('lock removes the key; the next open is locked and unlocks offline with the password only', async ({ context, popupUrl, vaultwardenUrl }) => {
  const page = await signIn(context, popupUrl, vaultwardenUrl);
  expect(await sessionKey(page)).not.toBeNull();

  await page.evaluate(() => (window as unknown as Bridge).RagewardenVault.lock());
  expect(await sessionKey(page)).toBeNull();

  await page.reload();
  expect((await initState(page)).locked).toBe(true);
  await expect(page.getByText('Locked', { exact: false })).toBeVisible();

  await context.route(`${vaultwardenUrl}/**`, route => route.abort());
  const wrong = await page.evaluate(async () => {
    try {
      await (window as unknown as Bridge).RagewardenVault.unlock('not the password');
      return '';
    } catch (e) {
      return (e as Error).message;
    }
  });
  expect(wrong).toMatch(/wrong master password/);
  expect(await sessionKey(page)).toBeNull();

  const opened = await page.evaluate(pw => (window as unknown as Bridge).RagewardenVault.unlock(pw), PASSWORD);
  expect(opened.locked).toBe(false);
  expect(opened.offline, 'the server was unreachable, so the vault list could not be fetched').toBeTruthy();
  expect(await page.evaluate(() => (window as unknown as Bridge).RagewardenVault.status().unlocked)).toBe(true);
  await context.unroute(`${vaultwardenUrl}/**`);

  await page.reload();
  expect((await initState(page)).locked).toBe(false);
  await page.close();
});

test('an idle deadline in the past locks the vault', async ({ context, popupUrl, vaultwardenUrl }) => {
  const page = await signIn(context, popupUrl, vaultwardenUrl);
  await page.evaluate(() => new Promise<void>(resolve => {
    chrome.storage.session.get(['ragewarden:envelopeKey'], items => {
      const k = items['ragewarden:envelopeKey'];
      chrome.storage.session.set({ 'ragewarden:envelopeKey': { ...k, deadline: Date.now() - 1 } }, () => resolve());
    });
  }));
  await page.reload();
  expect((await initState(page)).locked).toBe(true);
  await page.close();
});

test('a popup fill lands only on the origin it was authorized for', async ({ context, popupUrl, vaultwardenUrl }) => {
  const popup = await signIn(context, popupUrl, vaultwardenUrl);
  await context.route('https://login.example.test/**', route =>
    route.fulfill({ status: 200, contentType: 'text/html', body: FIXTURE_HTML }));
  const site = await context.newPage();
  await site.goto('https://login.example.test/login');
  await site.locator('#login-password').focus();

  const send = (expectedOrigin: string) => popup.evaluate(async (origin) => {
    const tabs = await chrome.tabs.query({ url: 'https://login.example.test/*' });
    return new Promise<{ ok: boolean; error?: string }>(resolve => {
      chrome.tabs.sendMessage(tabs[0].id!, {
        kind: 'ragewarden.fill', expectedOrigin: origin, username: 'me', password: 'pinned-secret',
      }, { frameId: 0 }, r => resolve(r));
    });
  }, expectedOrigin);

  let refused: { ok: boolean; error?: string } | undefined;
  await expect.poll(async () => {
    refused = await send('https://elsewhere.example.test').catch(() => undefined);
    return refused?.ok;
  }, { timeout: 15_000 }).toBe(false);
  expect(refused!.error).toMatch(/nothing was filled/);
  expect(await site.evaluate(() => (document.getElementById('login-password') as HTMLInputElement).value)).toBe('');

  const filled = await send('https://login.example.test');
  expect(filled.ok).toBe(true);
  expect(await site.evaluate(() => (document.getElementById('login-password') as HTMLInputElement).value)).toBe('pinned-secret');
  await site.close();
  await popup.close();
});

test('the background worker loads the wasm and answers lookups for the signed-in vault', async ({ context, popupUrl, vaultwardenUrl }) => {
  const popup = await signIn(context, popupUrl, vaultwardenUrl);
  const ask = (msg: object) => popup.evaluate(m => new Promise<{ ok: boolean; error?: string; ciphers?: unknown[]; matches?: unknown[] }>(
    resolve => chrome.runtime.sendMessage(m, r => resolve(r))), msg);
  const fetched = await ask({ kind: 'vault.fetch', force: true });
  expect(fetched.error ?? '').toBe('');
  expect(fetched.ok).toBe(true);
  expect(Array.isArray(fetched.ciphers)).toBe(true);
  const lookup = await ask({ kind: 'vault.lookup', origin: 'https://login.example.test' });
  expect(lookup.ok).toBe(true);

  await popup.evaluate(() => (window as unknown as Bridge).RagewardenVault.lock());
  await expect.poll(async () => (await ask({ kind: 'vault.fetch' })).ok, { timeout: 10_000 }).toBe(false);
  await popup.close();
});
