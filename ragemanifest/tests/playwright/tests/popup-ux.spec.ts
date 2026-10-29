import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Page } from '@playwright/test';
import {
  test, expect, attachAuthenticator, signIn, waitForBootstrap, randomSuffix,
} from './fixtures';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_HTML = readFileSync(join(__dirname, 'fixtures', 'login-form.html'));
const TOTP_SEED = 'JBSWY3DPEHPK3PXP';

type Registry = { id: string; kind: string }[];
interface Vault {
  RagewardenVault: {
    listRecipients(): Promise<Registry>;
    setCipher(n: string, pt: string, o?: unknown): Promise<unknown>;
    crypto: { init(): Promise<{ wasm_totp_generate(s: string): { code: string } }> };
  };
}

const registry = (page: Page) =>
  page.evaluate(() => (window as unknown as Vault).RagewardenVault.listRecipients());

async function openRecoveryNew(page: Page) {
  await page.getByTitle('Settings').click();
  await page.getByText('Paper recovery', { exact: true }).click();
  await page.getByRole('button', { name: 'Create a recovery phrase' }).click();
  await page.getByRole('button', { name: 'Generate a phrase' }).click();
  await expect(page.locator('.phrase-grid')).toBeVisible();
}

async function confirmPopupPhrase(page: Page): Promise<string> {
  const words = (await page.locator('.phrase-word .mono').allTextContents()).map(w => w.trim());
  const labels = page.locator('label.field > .eyebrow', { hasText: /^Word \d+$/ });
  const n = await labels.count();
  for (let i = 0; i < n; i++) {
    const idx = Number((await labels.nth(i).textContent())!.replace(/\D+/g, '')) - 1;
    await page.getByLabel(`Word ${idx + 1}`, { exact: true }).fill(words[idx]);
  }
  await page.getByRole('button', { name: 'I have written it down' }).click();
  return words.join(' ');
}

test('a recovery phrase reaches the registry only after three words are confirmed', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(150_000);
  const { page } = await signIn(context, popupUrl, vaultwardenUrl);
  const recoveries = async () => (await registry(page)).filter(e => e.kind === 'Recovery').length;
  expect(await recoveries()).toBe(0);

  await openRecoveryNew(page);
  await expect(page.getByRole('button', { name: 'Copy phrase' })).toHaveCount(0);
  await expect(page.getByTitle('Back')).toHaveCount(0);
  expect(await recoveries(), 'generating publishes nothing').toBe(0);

  await page.reload();
  await waitForBootstrap(page);
  expect(await recoveries(), 'closing the popup with the words on screen leaves nothing behind').toBe(0);

  await expect(page.locator('#vault-list')).toBeVisible({ timeout: 30_000 });
  await openRecoveryNew(page);
  const phrase = await confirmPopupPhrase(page);
  await expect(page.getByText('Recovery phrase published')).toBeVisible();
  expect(await recoveries(), 'confirming publishes exactly one entry').toBe(1);

  const secret = `paper-${randomSuffix()}`;
  await page.evaluate(([n, s]) => (window as unknown as Vault).RagewardenVault.setCipher(n, s), [`paper-item`, secret]);
  await page.getByRole('button', { name: 'Test it now' }).click();
  await expect(page.getByText('Test your paper backup')).toBeVisible();
  await page.locator('textarea').fill(phrase);
  await page.getByRole('button', { name: 'Open the item' }).click();
  await expect(page.locator('.secret-value')).toHaveText(secret, { timeout: 30_000 });
  await expect(page.locator('.secret-value'), 'the recovered value hides itself').toHaveCount(0, { timeout: 13_000 });
  await page.close();
});

test('popup ceremonies name action, item and destination before the authenticator is asked; TOTP', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(150_000);
  await context.addInitScript(() => {
    const w = window as unknown as { __askedWith: string[] };
    w.__askedWith = [];
    const orig = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async (o?: CredentialRequestOptions) => {
      w.__askedWith.push(document.body.innerText);
      return orig(o);
    };
  });
  const { page: popup } = await signIn(context, popupUrl, vaultwardenUrl, { passkey: true });
  const name = `ceremony-${randomSuffix()}`;
  await popup.evaluate(([n, s]) => (window as unknown as Vault).RagewardenVault.setCipher(n, s), [name, TOTP_SEED]);
  await popup.reload();
  await waitForBootstrap(popup);
  await expect(popup.locator('.vrow-name', { hasText: name })).toBeVisible({ timeout: 30_000 });
  await popup.locator('.vrow-name', { hasText: name }).click();

  const password = popup.getByRole('group', { name: 'Password' });
  for (const name of ['Autofill', 'Copy', 'Reveal']) {
    await expect(password.getByRole('button', { name, exact: true }),
      `the ${name} button is named "${name}", not by the field label`).toHaveCount(1);
  }
  await expect(popup.getByRole('group', { name: 'One-time code' })
    .getByRole('button', { name: 'Show TOTP code', exact: true })).toHaveCount(1);

  await popup.evaluate(() => { (window as unknown as { __askedWith: string[] }).__askedWith = []; });
  await popup.getByRole('button', { name: 'Reveal', exact: true }).click();
  await expect(popup.locator('.secret-value')).toHaveText(TOTP_SEED, { timeout: 30_000 });
  const asked = await popup.evaluate(() => (window as unknown as { __askedWith: string[] }).__askedWith);
  expect(asked.length, 'the reveal went through the authenticator').toBeGreaterThan(0);
  expect(asked[0]).toContain(`Reveal ${name}`);
  expect(asked[0]).toContain('to this screen');

  await popup.getByRole('button', { name: 'Show TOTP code', exact: true }).click();
  const code = (await popup.locator('.totp-code').textContent({ timeout: 30_000 }))!.trim();
  const expected = await popup.evaluate(async (seed) => {
    const wasm = await (window as unknown as Vault).RagewardenVault.crypto.init();
    const now = wasm.wasm_totp_generate(seed).code;
    return now;
  }, TOTP_SEED);
  expect(code).toMatch(/^\d{6}$/);
  expect(code).toBe(expected);
  await popup.close();
});

test('popup sheets are modal dialogs: focus inside, Escape closes, focus returns; the sign-in toggle is a button', async ({ context, popupUrl, vaultwardenUrl }) => {
  const first = await context.newPage();
  await first.goto(popupUrl);
  const toggle = first.locator('.ragewarden-onb-toggle button');
  await toggle.focus();
  await first.keyboard.press('Enter');
  await expect(first.locator('.ragewarden-onb-card h1')).toHaveText('Create a Bitwarden account');
  await first.close();

  const { page } = await signIn(context, popupUrl, vaultwardenUrl);
  await page.getByTitle('Settings').click();
  const signOut = page.getByRole('button', { name: 'Sign out' });
  await signOut.click();
  const dialog = page.getByRole('dialog', { name: 'Sign out?' });
  await expect(dialog).toBeVisible();
  await expect(dialog).toHaveAttribute('aria-modal', 'true');
  await expect.poll(() => page.evaluate(() => !!document.activeElement?.closest('.sheet-card'))).toBe(true);
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  expect(await page.evaluate(() => !!document.activeElement?.closest('.sheet-card')), 'Tab stays in the dialog').toBe(true);
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(signOut).toBeFocused();
  await page.close();
});

test('the vault list puts the active tab\'s items first', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(150_000);
  const { page } = await signIn(context, popupUrl, vaultwardenUrl, { passkey: true });
  await page.evaluate(() => (window as unknown as Vault).RagewardenVault.setCipher('aaa-other', 'x', { type: 'login', site: 'https://other.example.test' }));
  await page.evaluate(() => (window as unknown as Vault).RagewardenVault.setCipher('zzz-here', 'y', { type: 'login', site: 'https://login.example.test', username: 'me' }));

  await context.route('https://login.example.test/**', route =>
    route.fulfill({ status: 200, contentType: 'text/html', body: FIXTURE_HTML }));
  const site = await context.newPage();
  await site.goto('https://login.example.test/login');
  await site.bringToFront();
  await page.reload();
  await waitForBootstrap(page);
  await expect(page.locator('#vault-list .eyebrow').first()).toHaveText(/For this site · login\.example\.test/, { timeout: 30_000 });
  await expect(page.locator('#vault-list .vrow-name').first()).toHaveText('zzz-here');
  await site.close();
  await page.close();
});

test('edits send only what changed: a rename or folder move needs no tap; a new secret and a delete land in the history', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);
  await context.addInitScript(() => {
    const w = window as unknown as { __gets: number };
    w.__gets = 0;
    const orig = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async (o?: CredentialRequestOptions) => { w.__gets++; return orig(o); };
  });
  const { page } = await signIn(context, popupUrl, vaultwardenUrl, { passkey: true });
  type Bridge = { RagewardenVault: {
    createFolder(n: string): Promise<{ id?: string; Id?: string }>;
    setCipher(n: string, s: string, o?: unknown): Promise<{ id?: string; Id?: string }>;
    deleteCipher(id: string): Promise<unknown>;
    history: { load(id: string): Promise<{ deleted?: boolean; stanzaTags?: string[] }[]> };
  } };
  const created = await page.evaluate(() => (window as unknown as Bridge).RagewardenVault.createFolder('Work'));
  const folderId = (created.id ?? created.Id)!;
  const saved = await page.evaluate(() => (window as unknown as Bridge).RagewardenVault.setCipher(
    'edit-me', 'secret-v1', { type: 'login', username: 'me@x.test', site: 'https://edit.example.test' }));
  const id = (saved.id ?? saved.Id)!;
  await page.reload();
  await waitForBootstrap(page);
  const gets = () => page.evaluate(() => (window as unknown as { __gets: number }).__gets);

  await page.locator('.vrow-name', { hasText: 'edit-me' }).click();
  await page.getByTitle('Edit').click();
  await page.getByLabel('Name', { exact: true }).fill('edited');
  await page.locator('label.field', { has: page.locator('.eyebrow', { hasText: /^Folder$/ }) }).locator('select').selectOption(folderId);
  const before = await gets();
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(page.locator('.appbar-title')).toHaveText('edited', { timeout: 30_000 });
  expect(await gets() - before, 'a rename and a folder move are not a re-wrap').toBe(0);
  const item = await page.evaluate((cid) => (window as unknown as { VAULT: { id: string; name: string; folderId: string | null; username: string }[] })
    .VAULT.find(v => v.id === cid), id);
  expect(item).toMatchObject({ name: 'edited', folderId, username: 'me@x.test' });

  await page.getByTitle('Edit').click();
  await page.locator('textarea').fill('secret-v2');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(page.locator('.appbar-title')).toHaveText('edited', { timeout: 30_000 });
  await expect(page.locator('[data-history="revision"]')).toHaveCount(1, { timeout: 30_000 });
  await page.getByRole('button', { name: 'Reveal', exact: true }).click();
  await expect(page.locator('.secret-value')).toHaveText('secret-v2', { timeout: 30_000 });

  await page.evaluate((cid) => (window as unknown as Bridge).RagewardenVault.deleteCipher(cid), id);
  const history = await page.evaluate((cid) => (window as unknown as Bridge).RagewardenVault.history.load(cid), id);
  expect(history.filter(e => e.deleted).length, 'the delete is recorded with the last payload').toBe(1);
  expect(history.filter(e => !e.deleted).length).toBe(1);
  expect(history.every(e => (e.stanzaTags || []).length > 0), 'entries carry the stanza tags read from the payload').toBe(true);
  await page.close();
});

test('a write wraps to this browser\'s own passkey with one tap and fresh salts', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(150_000);
  await context.addInitScript(() => {
    const w = window as unknown as { __gets: number };
    w.__gets = 0;
    const orig = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async (o?: CredentialRequestOptions) => { w.__gets++; return orig(o); };
  });
  const { page } = await signIn(context, popupUrl, vaultwardenUrl, { passkey: true });
  type Bridge = { RagewardenVault: {
    setCipher(n: string, s: string): Promise<{ id?: string; Id?: string }>;
    stanzaSummary(id: string): Promise<{ prfCredentialIdsB64: string[]; x25519: number }>;
    revealPassword(id: string): Promise<string>;
    hardware: { inventory(): Promise<{ passkeys: unknown[] }> };
  } };
  const own = await page.evaluate(() => new Promise<string[]>(r => chrome.storage.local.get(null, items => {
    const recs = Object.values(items).flat().filter((v: any) => v && v.kind === 'passkey_prf') as { credential_id_b64: string }[];
    r(recs.map(x => x.credential_id_b64));
  })));
  expect(own.length, 'the wizard enrolled a passkey').toBeGreaterThan(0);

  const before = await page.evaluate(() => (window as unknown as { __gets: number }).__gets);
  const saved = await page.evaluate(() => (window as unknown as Bridge).RagewardenVault.setCipher('own-wrap', 'own-secret'));
  const id = (saved.id ?? saved.Id)!;
  expect(await page.evaluate(() => (window as unknown as { __gets: number }).__gets) - before, 'one tap per write').toBe(1);

  await page.reload();
  await waitForBootstrap(page);
  const summary = await page.evaluate((cid) => (window as unknown as Bridge).RagewardenVault.stanzaSummary(cid), id);
  expect(summary.prfCredentialIdsB64.some(c => own.includes(c)), 'the item carries a stanza for this browser\'s passkey').toBe(true);
  expect(summary.x25519, 'and still the public-key recipients').toBeGreaterThan(0);
  expect(await page.evaluate((cid) => (window as unknown as Bridge).RagewardenVault.revealPassword(cid), id)).toBe('own-secret');
  await page.close();
});

test('an item in the pre-wrap-salt format is flagged and Re-save rewrites it', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(150_000);
  const { page } = await signIn(context, popupUrl, vaultwardenUrl, { passkey: true });
  const saved = await page.evaluate(() => (window as unknown as { RagewardenVault: {
    setCipher(n: string, s: string): Promise<{ id?: string; Id?: string }> } }).RagewardenVault.setCipher('legacy-item', 'legacy-secret'));
  const id = (saved.id ?? saved.Id)!;
  await page.reload();
  await waitForBootstrap(page);
  // No writer produces the old format any more; flag the row the way a snapshot of one does.
  await page.evaluate((cid) => (window as unknown as { __ragewardenMarkLegacyWrap(id: string): void }).__ragewardenMarkLegacyWrap(cid), id);
  await page.evaluate(() => window.dispatchEvent(new Event('ragewarden:vault-updated')));
  const row = page.locator('.vrow', { hasText: 'legacy-item' });
  await expect(row.locator('.tag', { hasText: 're-save' })).toBeVisible();
  await row.click();
  await expect(page.getByText('Older wrapping')).toBeVisible();
  await page.getByRole('button', { name: 'Re-save' }).click();
  await expect(page.getByText('Re-saved in the current format.')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText('Older wrapping'), 'the fresh snapshot no longer flags it').toHaveCount(0);
  await page.close();
});

test('the generator fills the secret from core\'s generator', async ({ context, popupUrl, vaultwardenUrl }) => {
  const { page } = await signIn(context, popupUrl, vaultwardenUrl);
  await page.getByTitle('Add item').click();
  const secret = page.locator('textarea');
  await page.getByRole('button', { name: 'Generate password', exact: true }).click();
  await expect(secret).toHaveValue(/^.{20}$/);
  const pw = await secret.inputValue();
  for (const cls of [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/]) expect(pw).toMatch(cls);
  await page.getByRole('button', { name: 'Generate password', exact: true }).click();
  await expect(secret, 'every press draws a new one').not.toHaveValue(pw);
  await page.getByRole('button', { name: 'Generate passphrase', exact: true }).click();
  expect((await secret.inputValue()).split('-')).toHaveLength(6);
  await page.close();
});
