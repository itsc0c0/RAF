import { defineConfig } from '@playwright/test';

/**
 * End-to-end tests of the web workbench (`npm run test:e2e`): headless Chromium against real R$F
 * servers with the demo workspace. The global setup starts the shared server (`raf serve` on
 * 127.0.0.1, serving `web/dist`, so run `npm run build` first); tests that change data or need a
 * token start their own. `RAF_BIN` selects the raf executable (default `../.venv/bin/raf`).
 */
export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.ts',
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI
    ? [['list'], ['github'], ['html', { open: 'never' }]]
    : [['list'], ['html', { open: 'never' }]],
  use: {
    browserName: 'chromium',
    headless: true,
    viewport: { width: 1440, height: 900 },
    locale: 'en-US',
    timezoneId: 'UTC',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium' }],
});
