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
    await use(`chrome-extension://${extensionId}/popup/RageDroid.html`);
  },
  vaultwardenUrl: async ({}, use) => {
    await use(readState().vaultwardenUrl);
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
    await page.click('.ragewarden-onb-toggle a');
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
      await page.click('.ragewarden-onb-secondary');
    } catch {
    }
  }
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
