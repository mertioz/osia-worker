import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './test/browser', workers: 1, retries: 0,
  outputDir: './test-results/admin',
  use: { baseURL: 'http://127.0.0.1:8790', channel: process.env.OSIA_QA_BROWSER || 'msedge',
    locale: 'en-US', timezoneId: 'America/New_York', viewport: { width: 1440, height: 1000 }, screenshot: 'only-on-failure' },
  webServer: { command: 'node scripts/admin_preview.mjs', url: 'http://127.0.0.1:8790/reports', reuseExistingServer: false },
});
