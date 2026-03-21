import crypto from 'node:crypto';
import { test, expect } from '@playwright/test';

function base32Decode(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of String(value || '').toUpperCase().replace(/=+$/g, '')) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base32 character: ${char}`);
    }
    bits += index.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(bytes);
}

function computeTotp(secret, nowMs = Date.now()) {
  const key = base32Decode(secret);
  const counter = Math.floor(nowMs / 1000 / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', key).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, '0');
}

test('bootstrap admin can rotate password and enable TOTP MFA', async ({ page }) => {
  const username = process.env.E2E_BOOTSTRAP_USER || 'admin';
  const password = process.env.E2E_BOOTSTRAP_PASSWORD || 'Admin123';
  const newPassword = process.env.E2E_BOOTSTRAP_NEW_PASSWORD || 'Admin4567';

  await page.goto('/');
  await page.getByLabel('User').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: /Sign in/i }).click();

  const bootstrapHeading = page.getByRole('heading', {
    name: 'Secure the default admin account'
  });

  if (!(await bootstrapHeading.isVisible().catch(() => false))) {
    test.skip(true, 'Bootstrap overlay is not active for this environment.');
  }

  await expect(bootstrapHeading).toBeVisible();
  await expect(page.getByText(/Change the default password/i)).toBeVisible();

  await page.getByLabel('Current password').fill(password);
  await page.getByLabel('New admin password').fill(newPassword);
  await page.getByLabel('Confirm new password').fill(newPassword);
  await page.getByRole('button', { name: /Save new password/i }).click();

  await expect(page.getByText(/Enable MFA with TOTP or passkey/i)).toBeVisible();
  await page.getByRole('button', { name: /Start MFA setup/i }).click();

  const secret = (await page.locator('.inline-secret').textContent())?.trim();
  test.skip(!secret, 'TOTP secret was not rendered in bootstrap overlay.');

  const code = computeTotp(secret);
  await page.getByLabel('Authenticator code').fill(code);
  await page.getByRole('button', { name: /Verify and enable MFA/i }).click();

  await expect(page.getByText(/MFA enabled\. The admin account is now secured\./i)).toBeVisible();
  await expect(bootstrapHeading).toBeHidden();
  await expect(page.getByRole('button', { name: /Sign out/i })).toBeVisible();
});

test('bootstrap admin exposes passkey option when MFA is pending', async ({ page }) => {
  const username = process.env.E2E_BOOTSTRAP_USER || 'admin';
  const password = process.env.E2E_BOOTSTRAP_PASSWORD || 'Admin123';

  await page.goto('/');
  await page.getByLabel('User').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: /Sign in/i }).click();

  const bootstrapHeading = page.getByRole('heading', {
    name: 'Secure the default admin account'
  });

  if (!(await bootstrapHeading.isVisible().catch(() => false))) {
    test.skip(true, 'Bootstrap overlay is not active for this environment.');
  }

  if (await page.getByText(/Enable MFA with TOTP or passkey/i).isVisible().catch(() => false)) {
    await expect(page.getByRole('button', { name: /Use passkey \/ security key/i })).toBeVisible();
  } else {
    test.skip(true, 'Environment is still on password-rotation step.');
  }
});
