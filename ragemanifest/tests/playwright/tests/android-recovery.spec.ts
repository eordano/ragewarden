import { test, expect, fillOnboarding, waitForBootstrap } from './fixtures';
import type { Page } from '@playwright/test';

/*
 * The browser half of tests/journey/run.sh. rageterm registered the account and
 * enrolled a 24-word paper recipient; the phone signed in, enrolled nothing,
 * and wrote an item wrapped to that set. This browser enrols nothing either, so
 * the phrase is the only key it holds: it must refuse the decoy phrase and open
 * both the phone's item and rageterm's with the real one. run.sh passes the
 * account through JOURNEY_* and the server through VAULTWARDEN_URL, and fails
 * the journey if this test was skipped.
 */
const env = (name: string) => process.env[name] ?? '';
const journey = {
  email: env('JOURNEY_EMAIL'),
  password: env('JOURNEY_PASSWORD'),
  phrase: env('JOURNEY_PHRASE'),
  decoy: env('JOURNEY_DECOY_PHRASE'),
  item: env('JOURNEY_ITEM'),
  secret: env('JOURNEY_SECRET'),
  androidItem: env('JOURNEY_ANDROID_ITEM'),
  androidSecret: env('JOURNEY_ANDROID_SECRET'),
};

test.skip(!journey.phrase, 'needs the account tests/journey/run.sh seeds (JOURNEY_*)');

async function openWithPhrase(page: Page, name: string, phrase: string) {
  await page.locator('select').selectOption({ label: name });
  await page.locator('textarea').fill(phrase);
  await page.getByRole('button', { name: 'Open the item' }).click();
}

test('the browser opens an item protected on Android with the paper phrase', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(150_000);
  for (const [k, v] of Object.entries(journey)) expect(v, `JOURNEY_* is missing ${k}`).not.toBe('');

  const page = await context.newPage();
  await page.goto(popupUrl);
  await fillOnboarding(page, {
    server: vaultwardenUrl, email: journey.email, password: journey.password, mode: 'login',
  });
  await waitForBootstrap(page);
  await expect(page.locator('#vault-list')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.vrow', { hasText: journey.androidItem })).toBeVisible();

  type Bridge = { RagewardenVault: {
    items(): { id: string; name: string }[];
    stanzaSummary(id: string): Promise<{ prfCredentialIdsB64: string[]; x25519: number }>;
  } };
  const summary = await page.evaluate(async (name) => {
    const v = (window as unknown as Bridge).RagewardenVault;
    const it = v.items().find(i => i.name === name)!;
    return v.stanzaSummary(it.id);
  }, journey.androidItem);
  expect(summary.prfCredentialIdsB64, 'the phone enrolled nothing, so no passkey stanza').toHaveLength(0);
  // The phone wraps to the registry's recipients. rageterm's identity.age is not one
  // (enroll-software-identity keeps it local; rageterm adds it to its own writes only),
  // so the phone's item carries the paper stanza the rest of this test opens it with.
  expect(summary.x25519, 'the paper recipient, from the registry').toBeGreaterThanOrEqual(1);

  await page.getByTitle('Settings').click();
  await page.getByText('Paper recovery', { exact: true }).click();
  await page.getByRole('button', { name: 'Open an item with a phrase' }).click();

  await openWithPhrase(page, journey.androidItem, journey.decoy);
  await expect(page.getByText('Recovery failed'), 'a valid phrase that is not a recipient is refused')
    .toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.secret-value')).toHaveCount(0);

  await openWithPhrase(page, journey.androidItem, journey.phrase);
  await expect(page.locator('.secret-value')).toHaveText(journey.androidSecret, { timeout: 30_000 });
  await page.getByRole('button', { name: 'Hide' }).click();

  await openWithPhrase(page, journey.item, journey.phrase);
  await expect(page.locator('.secret-value')).toHaveText(journey.secret, { timeout: 30_000 });
  await page.close();
});
