import type { Page } from '@playwright/test';
import { test, expect, signIn, waitForBootstrap } from './fixtures';

type Item = { id: string; name: string; kind: string; rage: boolean; protectedFields: string[] };
type Bridge = { RagewardenVault: {
  items(): Item[];
  rotateCipher(id: string): Promise<unknown>;
  bulkProtect(recipientIds: string[], cipherIds: string[]): Promise<{ protected: number; failed: unknown[] }>;
  editCipher(id: string, name: string, secret: string | null): Promise<unknown>;
} };

const byName = (page: Page, name: string) =>
  page.evaluate((n) => (window as unknown as Bridge).RagewardenVault.items().find(i => i.name === n)!, name);

async function create(page: Page, kind: string, name: string, values: Record<string, string>) {
  await page.getByTitle('Add item').click();
  const labelled = (text: string) => page.locator('label.field', { has: page.locator('.eyebrow', { hasText: new RegExp(`^${text}$`) }) });
  await labelled('Type').locator('select').selectOption(kind);
  await labelled('Name').locator('input').fill(name);
  for (const [field, value] of Object.entries(values)) {
    await page.locator(`[data-edit-field="${field}"]`).locator('input:not([type=checkbox]), textarea').fill(value);
  }
  await page.getByRole('button', { name: 'Create' }).click();
  await expect(page.getByText('Created.')).toBeVisible({ timeout: 30_000 });
}

async function reveal(page: Page, field: string): Promise<string> {
  const host = page.locator(`[data-field="${field}"]`);
  await host.getByRole('button', { name: 'Reveal' }).click();
  const value = host.locator('.secret-value');
  await expect(value).toBeVisible({ timeout: 30_000 });
  const text = (await value.textContent()) ?? '';
  await host.getByRole('button', { name: 'Hide' }).click();
  return text;
}

async function openDetail(page: Page, name: string) {
  await page.reload();
  await waitForBootstrap(page);
  await page.locator('.vrow', { hasText: name }).click();
}

test('a card protects its number and CVV, reveals each, and keeps both through rotation, re-wrap and edits', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(240_000);
  const { page } = await signIn(context, popupUrl, vaultwardenUrl, { passkey: true });
  await create(page, 'card', 'Visa', {
    cardholderName: 'Ada Lovelace', brand: 'Visa', number: '4111111111111111', expMonth: '12', expYear: '2030', code: '123',
  });

  const item = await byName(page, 'Visa');
  expect(item.kind).toBe('card');
  expect(item.rage).toBe(true);
  expect([...item.protectedFields].sort()).toEqual(['code', 'number']);

  await openDetail(page, 'Visa');
  await expect(page.locator('[data-field="number"] .tag', { hasText: 'protected' })).toBeVisible();
  await expect(page.locator('[data-field="code"] .tag', { hasText: 'protected' })).toBeVisible();
  await expect(page.getByText('Ada Lovelace'), 'a descriptive field reads with no tap').toBeVisible();
  expect(await reveal(page, 'number')).toBe('4111111111111111');
  expect(await reveal(page, 'code')).toBe('123');

  await page.evaluate((id) => (window as unknown as Bridge).RagewardenVault.rotateCipher(id), item.id);
  const bulk = await page.evaluate((id) => (window as unknown as Bridge).RagewardenVault.bulkProtect([], [id]), item.id);
  expect(bulk.protected, JSON.stringify(bulk.failed)).toBe(1);

  const single = await page.evaluate(async (id) => {
    try {
      await (window as unknown as Bridge).RagewardenVault.editCipher(id, 'Visa', 'one-secret');
      return 'saved';
    } catch (err) {
      return `${(err as { code?: string }).code}: ${(err as Error).message}`;
    }
  }, item.id);
  expect(single).toMatch(/^multi_field: This item protects several fields \(Security code, Number\)/);

  await openDetail(page, 'Visa');
  expect(await reveal(page, 'number'), 'rotation, re-wrap and the refused overwrite lost nothing').toBe('4111111111111111');
  expect(await reveal(page, 'code')).toBe('123');

  await page.getByTitle('Edit').click();
  await page.locator('[data-edit-field="code"] input:not([type=checkbox])').fill('987');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved.')).toBeVisible({ timeout: 30_000 });
  await openDetail(page, 'Visa');
  expect(await reveal(page, 'code'), 'the new CVV').toBe('987');
  expect(await reveal(page, 'number'), 'the other protected field survives the edit').toBe('4111111111111111');
  await expect(page.locator('[data-history]').first()).toBeVisible();
  await page.close();
});

// Not a key: three lines stand in for one, since only the bytes have to survive.
const PRIVATE_KEY = ['test-only private key, line 1', 'line 2 with  spaces ', 'line 3'].join('\n');

test('an SSH key keeps its private key protected, shows the public half, and survives rotation', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(200_000);
  const { page } = await signIn(context, popupUrl, vaultwardenUrl, { passkey: true });
  await create(page, 'ssh_key', 'deploy key', {
    privateKey: PRIVATE_KEY, publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFestival deploy@ragewarden', keyFingerprint: 'SHA256:festival',
  });
  const item = await byName(page, 'deploy key');
  expect(item.kind).toBe('ssh_key');
  expect(item.protectedFields).toEqual(['privateKey']);

  await openDetail(page, 'deploy key');
  await expect(page.getByText('SHA256:festival')).toBeVisible();
  await expect(page.getByText(/^ssh-ed25519 AAAAC3/)).toBeVisible();
  await expect(page.locator('[data-field="privateKey"] .tag', { hasText: 'protected' })).toBeVisible();
  expect(await reveal(page, 'privateKey')).toBe(PRIVATE_KEY);

  await page.evaluate((id) => (window as unknown as Bridge).RagewardenVault.rotateCipher(id), item.id);
  await openDetail(page, 'deploy key');
  expect(await reveal(page, 'privateKey'), 'rotation keeps the key byte for byte').toBe(PRIVATE_KEY);
  await expect(page.getByText('SHA256:festival')).toBeVisible();

  await page.reload();
  await waitForBootstrap(page);
  await expect(page.locator('.vrow', { hasText: 'deploy key' }).locator('.vrow-sub')).toHaveText('SSH key');
  await page.close();
});
