import { test as base, chromium, expect, type BrowserContext, type Page } from '@playwright/test';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLAYWRIGHT_DIR = resolve(__dirname, '..');
const EXTENSION_DIST = resolve(PLAYWRIGHT_DIR, 'dist', 'extension');
const STATE_FILE = resolve(PLAYWRIGHT_DIR, '.playwright-state.json');

interface State { vaultwardenUrl: string }

function readState(): State {
  return JSON.parse(readFileSync(STATE_FILE, 'utf8')) as State;
}

interface Fixtures {
  context: BrowserContext;
  extensionId: string;
  popupUrl: string;
  vaultwardenUrl: string;
  mockContext: BrowserContext;
  mockPopupUrl: string;
}

const MOCK_EXTENSION_DIST = resolve(PLAYWRIGHT_DIR, 'dist', 'extension-mock');

async function launchWith(dist: string): Promise<BrowserContext> {
  const userDataDir = mkdtempSync(join(tmpdir(), 'ragewarden-pw-'));
  return chromium.launchPersistentContext(userDataDir, {
    headless: false,
    executablePath: resolveChromiumExecutable(),
    args: [
      '--headless=new',
      `--disable-extensions-except=${dist}`,
      `--load-extension=${dist}`,
      '--no-sandbox',
      '--disable-gpu',
    ],
  });
}

function resolveChromiumExecutable(): string | undefined {
  if (process.env.BROWSER_PATH && process.env.BROWSER_PATH.length > 0) {
    return process.env.BROWSER_PATH;
  }
  const homedir = process.env.HOME || '';
  const candidates = [
    `${homedir}/Library/Caches/ms-playwright/chromium-1217/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`,
    `${homedir}/Library/Caches/ms-playwright/chromium-1217/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`,
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/opt/homebrew/bin/chromium',
    '/usr/bin/chromium',
    '/usr/bin/google-chrome',
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return undefined;
}

export const test = base.extend<Fixtures>({
  context: async ({}, use) => {
    const userDataDir = mkdtempSync(join(tmpdir(), 'ragewarden-pw-'));
    const executablePath = resolveChromiumExecutable();
    const ctx = await chromium.launchPersistentContext(userDataDir, {
      headless: false,
      executablePath,
      args: [
        '--headless=new',
        `--disable-extensions-except=${EXTENSION_DIST}`,
        `--load-extension=${EXTENSION_DIST}`,
        '--no-sandbox',
        '--disable-gpu',
      ],
    });
    await use(ctx);
    await ctx.close();
  },
  extensionId: async ({ context }, use) => {
    const id = await resolveExtensionId(context);
    await use(id);
  },
  popupUrl: async ({ extensionId }, use) => {
    await use(`chrome-extension://${extensionId}/popup/index.html`);
  },
  vaultwardenUrl: async ({}, use) => {
    await use(readState().vaultwardenUrl);
  },
  mockContext: async ({}, use) => {
    const ctx = await launchWith(MOCK_EXTENSION_DIST);
    await use(ctx);
    await ctx.close();
  },
  mockPopupUrl: async ({ mockContext }, use) => {
    await use(`chrome-extension://${await resolveExtensionId(mockContext)}/popup/index.html`);
  },
});

async function resolveExtensionId(context: BrowserContext): Promise<string> {
  for (let i = 0; i < 80; i++) {
    let workers = context.serviceWorkers();
    if (workers.length === 0) {
      workers = await Promise.race([
        new Promise<typeof workers>(r => context.once('serviceworker', sw => r([sw]))),
        new Promise<typeof workers>(r => setTimeout(() => r([]), 250)),
      ]);
    }
    for (const sw of workers) {
      const m = sw.url().match(/^chrome-extension:\/\/([a-p]+)\//);
      if (m) return m[1];
    }
    const pages = context.pages();
    for (const p of pages) {
      const m = p.url().match(/^chrome-extension:\/\/([a-p]+)\//);
      if (m) return m[1];
    }
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error('could not resolve extension id (no chrome-extension:// service worker / page found)');
}

export { expect };

export async function fillOnboarding(
  page: Page,
  opts: {
    server: string;
    email: string;
    password: string;
    mode?: 'login' | 'register';
    dismissProtectionWizard?: boolean;
  },
): Promise<void> {
  await page.waitForSelector('.ragewarden-onb-root');
  if (opts.mode === 'register') {
    await page.click('.ragewarden-onb-toggle button');
    await expect(page.locator('.ragewarden-onb-card h1')).toHaveText('Create a Bitwarden account');
  }
  const inputs = page.locator('.ragewarden-onb-card input');
  await inputs.nth(0).fill(opts.server);
  await inputs.nth(1).fill(opts.email);
  await inputs.nth(2).fill(opts.password);
  if (opts.mode === 'register') {
    await inputs.nth(3).fill('e2e-tester');
  }
  await page.click('.ragewarden-onb-primary');

  if (opts.dismissProtectionWizard !== false) {
    const wizardTitle = page.locator('.ragewarden-onb-card h1', {
      hasText: 'Set up Ragewarden protection',
    });
    try {
      await wizardTitle.waitFor({ state: 'visible', timeout: 15_000 });
    } catch {
      return;
    }
    await page.click('.ragewarden-onb-secondary');
    await expect(page.locator('.ragewarden-onb-card h1')).toHaveText('Not protected yet');
    await page.click('.ragewarden-onb-secondary');
  }
}

/**
 * Remove every Recovery entry from the registry, for specs that assert the exact
 * wrap set of a write and do not want the wizard's paper recipient in it.
 */
export async function dropRecoveryRecipients(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const w = window as unknown as { RagewardenVault: {
      listRecipients: () => Promise<{ id: string; kind: string }[]>;
      removeRecipient: (id: string) => Promise<unknown>;
    } };
    for (const e of await w.RagewardenVault.listRecipients()) {
      if (e.kind === 'Recovery') await w.RagewardenVault.removeRecipient(e.id);
    }
  });
}

/** Type the three requested words of the phrase shown in the wizard and confirm. */
export async function confirmWizardPhrase(page: Page): Promise<string> {
  const words = await page.locator('.ragewarden-onb-phrase li').allTextContents();
  const labels = await page.locator('.ragewarden-onb-card .ragewarden-onb-field span').allTextContents();
  const inputs = page.locator('.ragewarden-onb-card .ragewarden-onb-field input');
  for (let n = 0; n < labels.length; n++) {
    const idx = Number(labels[n].replace(/\D+/g, '')) - 1;
    await inputs.nth(n).fill(words[idx].trim());
  }
  await page.click('.ragewarden-onb-primary');
  return words.map(w => w.trim()).join(' ');
}

/**
 * After the first passkey: skip the backup passkey, which makes the paper step
 * mandatory, and complete it. Returns the phrase.
 */
export async function finishWizardWithPaper(page: Page): Promise<string> {
  await expect(page.locator('.ragewarden-onb-card h1')).toHaveText('Add a backup passkey');
  await page.click('.ragewarden-onb-secondary');
  await expect(page.locator('.ragewarden-onb-card h1')).toHaveText('Write down your recovery phrase');
  return confirmWizardPhrase(page);
}

export async function waitForBootstrap(page: Page): Promise<void> {
  await expect.poll(
    async () =>
      page.evaluate(() => {
        const w = window as unknown as { RagewardenVault?: { bootstrapResult?: { email?: string } } };
        return Boolean(w.RagewardenVault?.bootstrapResult?.email);
      }),
    { timeout: 60_000, intervals: [200, 500, 1000] },
  ).toBe(true);
}

export function randomSuffix(): string {
  return Math.random().toString(16).slice(2, 10);
}

export async function attachAuthenticator(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
      hasPrf: true, automaticPresenceSimulation: true, isUserVerified: true,
    },
  });
}

/** A fresh account in a new popup page; with `passkey`, through the wizard's passkey and paper steps. */
export async function signIn(context: BrowserContext, popupUrl: string, server: string, opts: { passkey?: boolean } = {}) {
  const page = await context.newPage();
  if (opts.passkey) await attachAuthenticator(page);
  await page.goto(popupUrl);
  const password = `ux-${randomSuffix()}-correct-horse`;
  await fillOnboarding(page, {
    server, email: `ux-${randomSuffix()}@ragewarden.test`, password, mode: 'register',
    dismissProtectionWizard: !opts.passkey,
  });
  if (opts.passkey) {
    await expect(page.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
    await page.click('.ragewarden-onb-primary');
    await finishWizardWithPaper(page);
  }
  await waitForBootstrap(page);
  await expect(page.locator('#vault-list')).toBeVisible({ timeout: 30_000 });
  return { page, password };
}
