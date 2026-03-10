import { test, expect } from '@playwright/test';

test('user can sign in and reach console', async ({ page }) => {
  const username = process.env.E2E_USER || 'admin';
  const password = process.env.E2E_PASSWORD || 'Admin123';

  await page.goto('/');

  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await page.getByLabel('User').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: /Sign in/i }).click();

  await expect(page.getByRole('button', { name: /Sign out/i })).toBeVisible();
  await expect(page.getByText('WebBastion Console')).toBeVisible();
});
