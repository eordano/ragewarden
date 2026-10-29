import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BrowserContext, Frame, Page } from '@playwright/test';
import { test, expect, fillOnboarding, finishWizardWithPaper, waitForBootstrap, randomSuffix } from './fixtures';

/*
 * The content-script leg, driven the way a user drives it: a trusted click on the
 * chip (it lives in a closed shadow root, so it is hit by coordinates), the
 * Ragewarden tap window that opens outside the page, and the fill that lands in
 * the form. Runs against the mock-tap build: the CDP virtual authenticator does
 * not follow into the tap window.
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
const LOGIN_HTML = readFileSync(join(__dirname, 'fixtures', 'login-form.html'), 'utf8');
const SITE = 'https://login.example.test';

interface Vault {
  RagewardenVault: { setCipher(n: string, pt: string, o?: unknown): Promise<unknown> };
}

async function signIn(context: BrowserContext, popupUrl: string, server: string): Promise<Page> {
  const popup = await context.newPage();
  await popup.goto(popupUrl);
  await fillOnboarding(popup, {
    server, email: `cs-${randomSuffix()}@ragewarden.test`, password: `cs-${randomSuffix()}-pw`,
    mode: 'register', dismissProtectionWizard: false,
  });
  await expect(popup.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
  await popup.click('.ragewarden-onb-primary');
  await finishWizardWithPaper(popup);
  await waitForBootstrap(popup);
  return popup;
}

async function addLogin(popup: Page, name: string, username: string, password: string, site = SITE) {
  await popup.evaluate(([n, u, p, s]) => (window as unknown as Vault).RagewardenVault.setCipher(
    n, p, { type: 'login', username: u, site: s }), [name, username, password, site]);
  await popup.evaluate(() => new Promise<void>(resolve => chrome.runtime.sendMessage({ kind: 'vault.invalidate' }, () => resolve())));
}

async function serve(context: BrowserContext, host: string, body: string) {
  await context.route(`${host}/**`, route => route.fulfill({ status: 200, contentType: 'text/html', body }));
}

/** True when the point is covered by the extension's shadow host, i.e. the chip. */
function chipAt(frame: Frame, x: number, y: number) {
  return frame.evaluate(([px, py]) => {
    const hit = document.elementFromPoint(px, py);
    return !!hit && hit.tagName === 'DIV' && hit.id !== '' && !hit.closest('form');
  }, [x, y]);
}

/** Focus the password field until the chip shows, then click it by coordinates. */
async function clickChip(page: Page, frame: Frame) {
  const field = frame.locator('#login-password');
  await field.focus();
  const inFrame = await field.evaluate(el => {
    const r = el.getBoundingClientRect();
    return { x: r.right - 12, y: r.top - 17 };
  });
  await expect.poll(() => chipAt(frame, inFrame.x, inFrame.y), { timeout: 20_000 }).toBe(true);
  const box = (await field.boundingBox())!;
  const tap = page.context().waitForEvent('page');
  await page.mouse.click(box.x + box.width - 12, box.y - 17);
  return tap;
}

async function authorize(tap: Page) {
  await tap.waitForLoadState('domcontentloaded');
  await expect(tap.locator('#authorize')).toBeEnabled({ timeout: 20_000 });
  await expect(tap.locator('#authorize'), 'Authorize has focus, so Enter authorizes').toBeFocused();
  const named = {
    destination: (await tap.locator('#destination').textContent())!.trim(),
    item: (await tap.locator('#item').textContent())!.trim(),
  };
  const closed = tap.waitForEvent('close', { timeout: 60_000 });
  await tap.keyboard.press('Enter');
  await closed;
  return named;
}

test('the chip opens the Ragewarden window, which names item and destination, and the fill lands', async ({ mockContext, mockPopupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);
  const popup = await signIn(mockContext, mockPopupUrl, vaultwardenUrl);
  const secret = `cs-secret-${randomSuffix()}`;
  await addLogin(popup, 'example login', 'me@example.test', secret);
  await serve(mockContext, SITE, LOGIN_HTML);

  const site = await mockContext.newPage();
  await site.goto(`${SITE}/login`);
  const named = await authorize(await clickChip(site, site.mainFrame()));
  expect(named.destination).toBe('login.example.test');
  expect(named.item).toBe('example login');
  await expect(site.locator('#login-password')).toHaveValue(secret, { timeout: 20_000 });
  await expect(site.locator('#login-username')).toHaveValue('me@example.test');
  const counters = await site.evaluate(() =>
    (window as unknown as { __ragewardenFixtureForm: { counters: Record<string, number> } }).__ragewardenFixtureForm.counters);
  expect(counters.input, 'the fill types through InputEvents').toBeGreaterThanOrEqual(secret.length);
});

test('two logins for one origin: the chip offers both, and the tap window names the chosen one', async ({ mockContext, mockPopupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);
  const popup = await signIn(mockContext, mockPopupUrl, vaultwardenUrl);
  await addLogin(popup, 'first account', 'a@example.test', 'pw-a');
  await addLogin(popup, 'second account', 'b@example.test', 'pw-b');
  await serve(mockContext, SITE, LOGIN_HTML);

  const site = await mockContext.newPage();
  await site.goto(`${SITE}/login`);
  const viewport = site.viewportSize()!;
  const choose = async (keys: string[]) => {
    const field = site.locator('#login-password');
    await field.focus();
    const box = (await field.boundingBox())!;
    const x = box.x + box.width - 12;
    const y = box.y - 17;
    await expect.poll(() => chipAt(site.mainFrame(), x, y), { timeout: 20_000 }).toBe(true);
    await site.mouse.click(x, y);
    await expect.poll(() => chipAt(site.mainFrame(), viewport.width / 2, viewport.height - 5),
      { timeout: 10_000, message: 'the picker covers the page' }).toBe(true);
    const tap = mockContext.waitForEvent('page');
    for (const k of keys) await site.keyboard.press(k);
    return authorize(await tap);
  };
  const a = await choose(['Enter']);
  await expect(site.locator('#login-password')).toHaveValue(a.item === 'first account' ? 'pw-a' : 'pw-b', { timeout: 20_000 });
  const b = await choose(['Tab', 'Enter']);
  expect(new Set([a.item, b.item]), 'both logins are offered').toEqual(new Set(['first account', 'second account']));
  await expect(site.locator('#login-password')).toHaveValue(b.item === 'first account' ? 'pw-a' : 'pw-b', { timeout: 20_000 });
});

test('a login form in a cross-origin frame: the tap window names the frame and its embedder', async ({ mockContext, mockPopupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);
  const popup = await signIn(mockContext, mockPopupUrl, vaultwardenUrl);
  const secret = `frame-${randomSuffix()}`;
  await addLogin(popup, 'framed login', 'f@example.test', secret);
  await serve(mockContext, SITE, LOGIN_HTML);
  await serve(mockContext, 'https://embedder.example.test',
    `<!doctype html><body style="margin:0"><iframe src="${SITE}/login" style="border:0;width:600px;height:500px;margin:40px"></iframe></body>`);

  const page = await mockContext.newPage();
  await page.goto('https://embedder.example.test/');
  const frame = page.frameLocator('iframe');
  await expect(frame.locator('#login-password')).toBeVisible();
  const inner = page.frames().find(f => f.url().startsWith(SITE))!;
  const named = await authorize(await clickChip(page, inner));
  expect(named.destination).toBe('login.example.test (in a frame on embedder.example.test)');
  await expect(frame.locator('#login-password')).toHaveValue(secret, { timeout: 20_000 });
});

test('the chip stays inside the viewport for a field at the left edge', async ({ mockContext, mockPopupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);
  const popup = await signIn(mockContext, mockPopupUrl, vaultwardenUrl);
  await addLogin(popup, 'edge login', 'e@example.test', 'pw-edge');
  await serve(mockContext, SITE, `<!doctype html><body style="margin:0;padding-top:80px">
    <form><input id="login-username" type="email" style="width:40px;margin:0">
    <input id="login-password" type="password" style="width:40px;margin:0;display:block"></form></body>`);
  const site = await mockContext.newPage();
  await site.goto(`${SITE}/edge`);
  await site.locator('#login-password').focus();
  const box = (await site.locator('#login-password').boundingBox())!;
  await expect.poll(() => chipAt(site.mainFrame(), 8, box.y - 17), { timeout: 20_000 }).toBe(true);
  expect(await chipAt(site.mainFrame(), 1, box.y - 17), 'nothing of the chip is left of the 4px margin').toBe(false);
});
