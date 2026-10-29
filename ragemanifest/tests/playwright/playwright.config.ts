import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

export const EXTENSION_DIST = resolve(__dirname, 'dist', 'extension');
export const MOCK_EXTENSION_DIST = resolve(__dirname, 'dist', 'extension-mock');
export const PLAYWRIGHT_DIR = __dirname;

export default defineConfig({
  testDir: './tests',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI
    ? [['html', { open: 'never' }], ['list']]
    : [['list']],
  use: {
    actionTimeout: 15_000,
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
  },
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  projects: [
    {
      name: 'chromium-extension',
      use: {
        channel: undefined,
        headless: true,
      },
    },
  ],
});
