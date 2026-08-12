import { test, expect, fillOnboarding, waitForBootstrap, randomSuffix } from './fixtures';

test('onboarding registers, logs in, exposes RagewardenVault, dispatches vault-updated', async ({ context, popupUrl, vaultwardenUrl }) => {
  const page = await context.newPage();

  await page.addInitScript(() => {
    (window as unknown as { __ragewardenVaultUpdated?: boolean }).__ragewardenVaultUpdated = false;
    window.addEventListener('ragewarden:vault-updated', () => {
      (window as unknown as { __ragewardenVaultUpdated?: boolean }).__ragewardenVaultUpdated = true;
    });
  });

  await page.goto(popupUrl);

  await expect(page.locator('.ragewarden-onb-card h1')).toHaveText('Sign in to Bitwarden');

  const suffix = randomSuffix();
  const email = `e2e-${suffix}@ragewarden.test`;
  const password = 'e2e-onboarding-correct-horse-battery';

  await fillOnboarding(page, {
    server: vaultwardenUrl,
    email,
    password,
    mode: 'register',
  });

  await waitForBootstrap(page);

  const bootstrap = await page.evaluate(() => {
    const w = window as unknown as { RagewardenVault: { bootstrapResult: { email: string; ciphers: number } } };
    return w.RagewardenVault.bootstrapResult;
  });
  expect(bootstrap.email).toBe(email);
  expect(typeof bootstrap.ciphers).toBe('number');

  await expect.poll(
    async () => page.evaluate(() => (window as unknown as { __ragewardenVaultUpdated: boolean }).__ragewardenVaultUpdated),
    { timeout: 5_000, intervals: [100, 200, 400] },
  ).toBe(true);

  const status = await page.evaluate(() => {
    const w = window as unknown as { RagewardenVault: { status(): { wasmReady: boolean; signedIn: boolean; email: string | null } } };
    return w.RagewardenVault.status();
  });
  expect(status.wasmReady).toBe(true);
  expect(status.signedIn).toBe(true);
  expect(status.email).toBe(email);

  const onboardingGone = await page.locator('.ragewarden-onb-root').count();
  expect(onboardingGone).toBe(0);

  await page.close();
});
