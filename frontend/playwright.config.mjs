import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './test/e2e',
  timeout: 30_000,
  retries: 1,
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:5173',
    headless: true,
    trace: 'retain-on-failure'
  }
});
