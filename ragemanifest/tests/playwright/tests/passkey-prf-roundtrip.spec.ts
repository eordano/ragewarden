import { test, expect, fillOnboarding, finishWizardWithPaper, waitForBootstrap, randomSuffix } from './fixtures';
import type { CDPSession, Page } from '@playwright/test';

async function attachVirtualAuthenticator(page: Page): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const result = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  });
  return { cdp, authenticatorId: result.authenticatorId };
}

/**
 * The SHIPPED write/read path, end to end, through the CDP virtual
 * authenticator: `RagewardenVault.setCipher` -> popup reboot ->
 * `RagewardenVault.revealPassword`.
 *
 * Both tests above drive `window.__ragewardenHarness`, which builds its own
 * passkey record and calls wasm directly. They prove the crypto. They do not
 * prove that the extension's own glue -- `enrollPasskey`'s registry entry,
 * `selectEncryptRecipients`, `unlockOnce`'s tap ceremony -- is wired to it, and
 * they count taps only inside the harness they installed themselves.
 *
 * So this asserts two things that must both hold, and neither alone is worth
 * anything:
 *
 *   - the plaintext comes back, and
 *   - a WebAuthn assertion was actually requested to get it.
 *
 * Then the same reveal is run with `navigator.credentials.get` refused, and it
 * must fail. Without that control, "the plaintext came back" is satisfied by a
 * cached copy, a plaintext write, or a software secret sitting unsealed on
 * disk -- the reveal succeeding tells you nothing about where the key came from.
 *
 * The refusal is a throwing wrapper installed via `addInitScript`, NOT
 * `WebAuthn.removeVirtualAuthenticator`: with the authenticator removed
 * `credentials.get` never settles and the test burns its whole timeout instead
 * of failing.
 */
test('principles 0b-0d on the shipped glue: the browser opens what it writes, only by asking the authenticator, every time', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);

  const page = await context.newPage();
  await attachVirtualAuthenticator(page);

  // Installed before any page script, so nothing can capture the original
  // `credentials.get` first and route around the counter.
  await page.addInitScript(() => {
    const w = window as unknown as { __prfCalls: number; __prfBreak: boolean };
    w.__prfCalls = 0;
    w.__prfBreak = false;
    const orig = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async (o?: CredentialRequestOptions) => {
      w.__prfCalls++;
      if (w.__prfBreak) throw new Error('simulated: no authenticator present');
      return orig(o);
    };
  });

  const suffix = randomSuffix();
  const email = `e2e-shipped-${suffix}@ragewarden.test`;
  const password = `e2e-shipped-pw-${suffix}`;

  await page.goto(popupUrl);
  // dismissProtectionWizard:false + click the PRIMARY button: this test needs
  // the real `enrollPasskey`, not the skip path the other two take.
  await fillOnboarding(page, {
    server: vaultwardenUrl, email, password, mode: 'register',
    dismissProtectionWizard: false,
  });
  await page.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
  await expect(page.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
  await page.click('.ragewarden-onb-primary');
  await finishWizardWithPaper(page);
  await waitForBootstrap(page);

  const registry = await page.evaluate(async () => {
    const w = window as unknown as {
      RagewardenVault: { listRecipients: () => Promise<{ id: string; kind: string }[]> };
    };
    return w.RagewardenVault.listRecipients();
  });
  expect(
    registry.filter(e => e.kind === 'PasskeyPrf' && e.id.startsWith('passkey-')).length,
    'the enrolment under test published a PasskeyPrf entry',
  ).toBe(1);

  const SHIPPED_PLAINTEXT = `shipped-path-secret-${suffix}`;
  const SHIPPED_NAME = `shipped-item-${suffix}`;
  await page.evaluate(async ([n, pt]) => {
    const w = window as unknown as {
      RagewardenVault: { setCipher: (n: string, pt: string, o?: unknown) => Promise<unknown> };
    };
    await w.RagewardenVault.setCipher(n as string, pt as string, {});
  }, [SHIPPED_NAME, SHIPPED_PLAINTEXT]);

  const listItem = async () => page.evaluate((n) => {
    type C = { name: string; id: string; rage?: boolean }[];
    const w = window as unknown as { ITEMS_BY_KIND?: C; VAULT?: C };
    const all = [...(w.VAULT ?? []), ...(w.ITEMS_BY_KIND ?? [])];
    const hit = all.find(c => c.name === n && !!c.rage);
    return hit ? hit.id : null;
  }, SHIPPED_NAME);

  const reboot = async () => {
    await page.goto('about:blank');
    await page.goto(popupUrl);
    await waitForBootstrap(page);
  };

  // Reboot first: an in-memory secret from the write would make the reveal
  // below prove nothing about what reached the server.
  await reboot();
  const cipherId = await listItem();
  expect(cipherId, 'the popup lists the item it just wrote').toBeTruthy();

  const prfCalls = async () =>
    page.evaluate(() => (window as unknown as { __prfCalls: number }).__prfCalls);

  const before = await prfCalls();
  const revealed = await page.evaluate(async (id) => {
    const w = window as unknown as {
      RagewardenVault: { revealPassword: (id: string) => Promise<string> };
    };
    return w.RagewardenVault.revealPassword(id as string);
  }, cipherId!);
  const after = await prfCalls();

  expect(revealed, 'POSITIVE -- the browser opens what it wrote').toBe(SHIPPED_PLAINTEXT);
  expect(
    after - before,
    'the reveal really went through the virtual authenticator; a plaintext returned with '
    + 'zero assertions means the secret came from somewhere it should not exist',
  ).toBeGreaterThanOrEqual(1);

  const again = await prfCalls();
  expect(await page.evaluate(async (id) => (window as unknown as {
    RagewardenVault: { revealPassword: (id: string) => Promise<string> };
  }).RagewardenVault.revealPassword(id as string), cipherId!)).toBe(SHIPPED_PLAINTEXT);
  expect(await prfCalls() - again, '§0b -- a second use is a second tap; nothing is cached').toBeGreaterThanOrEqual(1);

  const atRest = await page.evaluate(async () => {
    const dump = async (area: chrome.storage.StorageArea) =>
      JSON.stringify(await new Promise(r => area.get(null, r)));
    return [await dump(chrome.storage.local), await dump(chrome.storage.session),
      JSON.stringify({ ...localStorage }), JSON.stringify({ ...sessionStorage })].join('\n');
  });
  expect(atRest.includes(SHIPPED_PLAINTEXT), '§0c -- no plaintext is left at rest after a reveal').toBe(false);

  const token = await page.evaluate(() => {
    const raw = (window as unknown as { __ragewardenSession?: unknown }).__ragewardenSession;
    const s = (typeof raw === 'string' ? JSON.parse(raw) : raw) as Record<string, string> | null;
    return s ? (s.access_token ?? s.accessToken ?? '') : '';
  });
  expect(token, 'the test-hooks build exposes the session').not.toBe('');
  await assertServerHoldsNoPlaintext(vaultwardenUrl, token, cipherId!, SHIPPED_PLAINTEXT);

  await reboot();
  await page.evaluate(() => {
    (window as unknown as { __prfBreak: boolean }).__prfBreak = true;
  });
  const cipherId2 = await listItem();
  expect(cipherId2, 'the item survives a second reboot').toBeTruthy();

  let threw = '';
  try {
    await page.evaluate(async (id) => {
      const w = window as unknown as {
        RagewardenVault: { revealPassword: (id: string) => Promise<string> };
      };
      return w.RagewardenVault.revealPassword(id as string);
    }, cipherId2!);
  } catch (e) {
    threw = (e as Error).message;
  }
  expect(
    threw,
    'CONTROL -- refuse the assertion and the identical reveal must fail. If this reveal '
    + 'succeeds, the positive one above was not being paid for by the authenticator.',
  ).not.toBe('');
  expect(
    threw.includes(SHIPPED_PLAINTEXT),
    'the failure path must not carry the plaintext in its message',
  ).toBe(false);

  await page.close();
});

/** §0d -- the server's copy of the item carries a Type-2 EncString and never the plaintext. */
async function assertServerHoldsNoPlaintext(server: string, token: string, cipherId: string, plaintext: string): Promise<void> {
  const res = await fetch(`${server}/api/sync`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Bitwarden-Client-Name': 'web',
      'Bitwarden-Client-Version': '2024.10.0',
    },
  });
  expect(res.ok, '/api/sync').toBe(true);
  const body = await res.json();
  const ciphers: Array<Record<string, unknown>> = body?.Ciphers ?? body?.ciphers ?? [];
  const ours = ciphers.find(c => (c.Id ?? c.id) === cipherId);
  expect(ours, 'the item is on the server').toBeTruthy();
  const haystack = JSON.stringify(ours);
  expect(haystack.includes(plaintext), '§0d -- the server never sees the plaintext').toBe(false);
  expect(haystack, 'Type-2 EncString markers').toContain('2.');
}
