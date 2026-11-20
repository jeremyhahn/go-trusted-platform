import type { Page, Request, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

/**
 * Real-server port of the mocked eab.spec.ts (#1667, #2035): every EAB REST
 * operation reachable from /ca/eab or /ca/eab/[id], against the real server.
 *
 * Each test seeds its own credentials through the SDK (sdk.eab.create) and
 * deletes them afterwards. The page talks to the real server; the tests
 * watch the requests it sends and assert on what the server answers. The
 * gaps (an expired credential, a fixed id) are listed in
 * docs/plans/1665-port-1.md.
 */

/** A profile id above Number.MAX_SAFE_INTEGER: a Number conversion would round it. */
const BIG_PROFILE = '1762905600987654321';
const PROFILE = '7';

interface SentCall {
  method: string;
  path: string;
  body: unknown;
}

interface Seeded {
  id: string;
  keyId: string;
  hmacKey: string;
}

function credentialOf(data: unknown): Record<string, unknown> {
  const d = (data ?? {}) as { credential?: Record<string, unknown> } & Record<string, unknown>;
  return d.credential ?? d;
}

async function seedCredential(sdk: PlatformClient, tenantId: string, profileId = PROFILE): Promise<Seeded> {
  const res = await sdk.eab.create({ profileId, tenantId, expiresInSeconds: 3600 });
  if (!res.success) throw new Error(`[real-server] eab.create: ${JSON.stringify(res.error)}`);
  const c = credentialOf(res.data);
  if (!c.id || !c.keyId) throw new Error(`[real-server] eab.create answered ${JSON.stringify(res.data)}`);
  return { id: String(c.id), keyId: String(c.keyId), hmacKey: String(c.hmacKey ?? '') };
}

/** Records the page's EAB calls, with the path after /eab/credentials. */
function watchCalls(page: Page): SentCall[] {
  const calls: SentCall[] = [];
  page.on('request', (req: Request) => {
    const path = new URL(req.url()).pathname;
    const at = path.indexOf('/eab/credentials');
    if (at < 0) return;
    let body: unknown = null;
    try {
      body = req.postDataJSON();
    } catch {
      body = req.postData();
    }
    calls.push({ method: req.method(), path: path.slice(at + '/eab/credentials'.length), body });
  });
  return calls;
}

function seen(calls: SentCall[], method: string, path: string): boolean {
  return calls.some((c) => c.method === method && c.path === path);
}

function answer(page: Page, method: string, suffix: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && new URL(r.url()).pathname.endsWith(`/eab/credentials${suffix}`),
  );
}

/**
 * Open a detail page the way the platform's static server does: it serves the
 * exported __placeholder__ HTML, and the client resolves the real id from the
 * pathname.
 */
async function openPlaceholderDetail(page: Page, id: string) {
  await page.goto('/ca/eab/__placeholder__/');
  await page.waitForLoadState('networkidle');
  await page.evaluate((credId) => window.history.pushState(null, '', `/ca/eab/${credId}/`), id);
}

test.describe('CA EAB credentials - list page', () => {
  test('lists credentials (ListCredentials)', async ({ adminPage: page, sdk, tenant }) => {
    const a = await seedCredential(sdk, tenant.id);
    const b = await seedCredential(sdk, tenant.id);
    try {
      await sdk.eab.revoke(b.id);
      const calls = watchCalls(page);
      await page.goto('/ca/eab');
      await expect(page.getByRole('heading', { name: 'EAB Credentials' })).toBeVisible();
      await expect(page.getByTestId(`eab-row-${a.id}`)).toContainText(a.keyId);
      await expect(page.getByTestId(`eab-row-${a.id}`)).toContainText('ACTIVE');
      const revoked = await sdk.eab.get(b.id);
      const status = String(credentialOf(revoked.data).status ?? '').replace('EAB_CREDENTIAL_STATUS_', '');
      if (status) await expect(page.getByTestId(`eab-row-${b.id}`)).toContainText(status);
      expect(seen(calls, 'GET', '')).toBe(true);
    } finally {
      await sdk.eab.delete(a.id);
      await sdk.eab.delete(b.id);
    }
  });

  for (const expires of ['3600', '']) {
    const title = expires
      ? 'creates a credential (CreateCredential)'
      : 'creates a non-expiring credential when the expiration is blank (CreateCredential)';
    test(title, async ({ adminPage: page, sdk, tenant }) => {
      let id: string | null = null;
      try {
        const calls = watchCalls(page);
        await page.goto('/ca/eab');
        await page.getByLabel('Profile ID').fill(PROFILE);
        await page.getByLabel('Tenant ID').fill(tenant.id);
        if (expires) await page.getByLabel('Expires in (seconds)').fill(expires);
        const created = answer(page, 'POST', '');
        await page.getByRole('button', { name: 'Create' }).click();
        const res = await created;
        expect(res.ok()).toBe(true);
        const c = credentialOf(await res.json());
        id = String(c.id);

        await expect(page.getByTestId('eab-created')).toContainText(String(c.hmacKey));
        await expect(page.getByTestId(`eab-row-${id}`)).toContainText(tenant.id);
        const create = calls.find((x) => x.method === 'POST' && x.path === '');
        expect(create?.body).toEqual(
          expires
            ? { profileId: PROFILE, tenantId: tenant.id, expiresInSeconds: Number(expires) }
            : { profileId: PROFILE, tenantId: tenant.id },
        );
      } finally {
        if (id) await sdk.eab.delete(id);
      }
    });
  }

  test('refuses a non-positive expiration (CreateCredential)', async ({ adminPage: page, tenant }) => {
    const calls = watchCalls(page);
    await page.goto('/ca/eab');
    await page.getByLabel('Profile ID').fill(PROFILE);
    await page.getByLabel('Tenant ID').fill(tenant.id);
    await page.getByLabel('Expires in (seconds)').fill('-1');
    await page.getByRole('button', { name: 'Create' }).click();

    await expect(page.getByText('Expires in must be a positive whole number of seconds, or blank')).toBeVisible();
    expect(calls.find((c) => c.method === 'POST' && c.path === '')).toBeUndefined();
    await expect(page.getByTestId('eab-created')).not.toBeVisible();
  });

  test('creates a credential with a profile ID above MAX_SAFE_INTEGER (CreateCredential)', async ({
    adminPage: page,
    sdk,
    tenant,
  }) => {
    let id: string | null = null;
    try {
      const calls = watchCalls(page);
      await page.goto('/ca/eab');
      await page.getByLabel('Profile ID').fill(BIG_PROFILE);
      await page.getByLabel('Tenant ID').fill(tenant.id);
      await page.getByLabel('Expires in (seconds)').fill('3600');
      const created = answer(page, 'POST', '');
      await page.getByRole('button', { name: 'Create' }).click();
      const res = await created;

      const create = calls.find((c) => c.method === 'POST' && c.path === '');
      expect((create?.body as { profileId?: unknown } | undefined)?.profileId).toBe(BIG_PROFILE);
      expect(res.ok()).toBe(true);
      const c = credentialOf(await res.json());
      id = String(c.id);
      await expect(page.getByTestId('eab-created')).toContainText(String(c.hmacKey));
      expect(String(c.profileId)).toBe(BIG_PROFILE);
    } finally {
      if (id) await sdk.eab.delete(id);
    }
  });

  test('revokes a credential (RevokeCredential)', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await page.goto('/ca/eab');
      await page.getByTestId(`eab-row-${c.id}`).getByRole('button', { name: 'Revoke' }).click();

      await expect(page.getByTestId('eab-message')).toHaveText(`Credential ${c.id} revoked`);
      await expect(page.getByTestId(`eab-row-${c.id}`)).toContainText('REVOKED');
      expect(seen(calls, 'POST', `/${c.id}/revoke`)).toBe(true);
      expect(String(credentialOf((await sdk.eab.get(c.id)).data).status)).toContain('REVOKED');
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('deletes a credential (DeleteCredential)', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await page.goto('/ca/eab');
      page.once('dialog', (dialog) => void dialog.accept());
      await page.getByTestId(`eab-row-${c.id}`).getByRole('button', { name: 'Delete' }).click();

      await expect(page.getByTestId('eab-message')).toHaveText(`Credential ${c.id} deleted`);
      await expect(page.getByTestId(`eab-row-${c.id}`)).toHaveCount(0);
      expect(seen(calls, 'DELETE', `/${c.id}`)).toBe(true);
      expect((await sdk.eab.get(c.id)).success).toBe(false);
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('validates a credential (ValidateCredential)', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await page.goto('/ca/eab');
      const form = page.locator('form', { has: page.getByRole('button', { name: 'Validate' }) });
      await form.getByLabel('Key ID').fill(c.keyId);
      await form.getByLabel('HMAC Key').fill(c.hmacKey);
      await form.getByRole('button', { name: 'Validate' }).click();
      await expect(page.getByTestId('eab-validation')).toHaveText('Valid');

      await form.getByLabel('HMAC Key').fill(`${c.hmacKey}x`);
      await form.getByRole('button', { name: 'Validate' }).click();
      await expect(page.getByTestId('eab-validation')).toHaveText('Invalid');

      const validate = calls.filter((x) => x.method === 'POST' && x.path === '/validate');
      expect(validate[0]?.body).toEqual({ keyId: c.keyId, hmacKey: c.hmacKey });
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  // Gap: the SDK cannot seed an already-expired credential, so the case
  // asserts the server's count and that an active credential survives.
  test('cleans up expired credentials (CleanupExpiredCredentials)', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await page.goto('/ca/eab');
      await expect(page.getByTestId(`eab-row-${c.id}`)).toBeVisible();

      const cleaned = answer(page, 'POST', '/cleanup');
      await page.getByRole('button', { name: 'Clean Up Expired' }).click();
      expect((await cleaned).ok()).toBe(true);
      await expect(page.getByTestId('eab-message')).toHaveText(/^Deleted \d+ expired credentials$/);
      await expect(page.getByTestId(`eab-row-${c.id}`)).toBeVisible();
      expect(seen(calls, 'POST', '/cleanup')).toBe(true);
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('looks up a credential by key ID (GetCredentialByKeyID)', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await page.goto('/ca/eab');
      const form = page.locator('form', { has: page.getByRole('button', { name: 'Look Up' }) });
      await form.getByLabel('Key ID').fill(c.keyId);
      await form.getByRole('button', { name: 'Look Up' }).click();

      await expect(page.getByTestId('eab-lookup-result')).toContainText(`Credential ${c.id}`);
      expect(seen(calls, 'GET', `/key/${c.keyId}`)).toBe(true);

      await form.getByLabel('Key ID').fill(`kid-missing-${Date.now().toString(36)}`);
      await form.getByRole('button', { name: 'Look Up' }).click();
      await expect(page.getByRole('alert')).toBeVisible();
    } finally {
      await sdk.eab.delete(c.id);
    }
  });
});

test.describe('CA EAB credentials - detail page', () => {
  test('shows a credential (GetCredential)', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await page.goto(`/ca/eab/${c.id}`);
      await expect(page.getByRole('heading', { name: `EAB Credential ${c.id}` })).toBeVisible();
      await expect(page.getByText(c.keyId)).toBeVisible();
      await expect(page.getByTestId('eab-status')).toHaveText('ACTIVE');
      expect(seen(calls, 'GET', `/${c.id}`)).toBe(true);
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('resolves the id from the pathname on the exported placeholder page', async ({
    adminPage: page,
    sdk,
    tenant,
  }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await openPlaceholderDetail(page, c.id);
      await expect(page.getByRole('heading', { name: `EAB Credential ${c.id}` })).toBeVisible();
      await expect(page.getByTestId('eab-status')).toHaveText('ACTIVE');
      expect(seen(calls, 'GET', `/${c.id}`)).toBe(true);
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('opens the detail page from the list', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      await page.goto('/ca/eab');
      await page.getByTestId(`eab-row-${c.id}`).getByRole('link', { name: c.id }).click();
      await expect(page).toHaveURL(new RegExp(`/ca/eab/${c.id}/?$`));
      await expect(page.getByRole('heading', { name: `EAB Credential ${c.id}` })).toBeVisible();
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  // The server mints ids from a nanosecond timestamp, so a seeded id is
  // already timestamp-sized; the profile id is above MAX_SAFE_INTEGER too.
  test('opens a timestamp-sized credential id from the list (GetCredential)', async ({
    adminPage: page,
    sdk,
    tenant,
  }) => {
    const c = await seedCredential(sdk, tenant.id, BIG_PROFILE);
    try {
      const calls = watchCalls(page);
      await page.goto('/ca/eab');
      await page.getByTestId(`eab-row-${c.id}`).getByRole('link', { name: c.id }).click();
      await expect(page).toHaveURL(new RegExp(`/ca/eab/${c.id}/?$`));
      await expect(page.getByRole('heading', { name: `EAB Credential ${c.id}` })).toBeVisible();
      expect(seen(calls, 'GET', `/${c.id}`)).toBe(true);
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('QR code, enrollment URL and mark used keep a timestamp-sized id', async ({
    adminPage: page,
    sdk,
    tenant,
  }) => {
    const c = await seedCredential(sdk, tenant.id, BIG_PROFILE);
    try {
      const calls = watchCalls(page);
      await page.goto(`/ca/eab/${c.id}`);
      await expect(page.getByRole('heading', { name: `EAB Credential ${c.id}` })).toBeVisible();

      await page.getByRole('button', { name: 'Show QR Code' }).click();
      await expect(page.getByAltText('EAB enrollment QR code')).toBeVisible();
      await page.getByRole('button', { name: 'Get Enrollment URL' }).click();
      await expect(page.getByTestId('eab-enrollment-url')).toContainText(`kid=${c.keyId}`);
      await page.getByRole('button', { name: 'Mark Used' }).click();
      await expect(page.getByTestId('eab-status')).toHaveText('USED');

      expect(seen(calls, 'GET', `/${c.id}/qrcode`)).toBe(true);
      expect(seen(calls, 'GET', `/${c.id}/url`)).toBe(true);
      expect(seen(calls, 'POST', `/${c.id}/used`)).toBe(true);
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('shows the QR code (GetCredentialQRCode)', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await page.goto(`/ca/eab/${c.id}`);
      await page.getByRole('button', { name: 'Show QR Code' }).click();
      await expect(page.getByAltText('EAB enrollment QR code')).toBeVisible();
      expect(seen(calls, 'GET', `/${c.id}/qrcode`)).toBe(true);
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('shows the enrollment URL (GetEnrollmentURL)', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await page.goto(`/ca/eab/${c.id}`);
      const url = answer(page, 'GET', `/${c.id}/url`);
      await page.getByRole('button', { name: 'Get Enrollment URL' }).click();
      expect((await url).ok()).toBe(true);
      await expect(page.getByTestId('eab-enrollment-url')).toContainText(`kid=${c.keyId}`);
      expect(seen(calls, 'GET', `/${c.id}/url`)).toBe(true);
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('marks a credential used (MarkCredentialUsed)', async ({ adminPage: page, sdk, tenant }) => {
    const c = await seedCredential(sdk, tenant.id);
    try {
      const calls = watchCalls(page);
      await page.goto(`/ca/eab/${c.id}`);
      await page.getByRole('button', { name: 'Mark Used' }).click();

      await expect(page.getByTestId('eab-message')).toHaveText('Credential marked as used');
      await expect(page.getByTestId('eab-status')).toHaveText('USED');
      expect(seen(calls, 'POST', `/${c.id}/used`)).toBe(true);
      expect(String(credentialOf((await sdk.eab.get(c.id)).data).status)).toContain('USED');
    } finally {
      await sdk.eab.delete(c.id);
    }
  });

  test('shows an error for an unknown credential', async ({ adminPage: page, sdk, tenant }) => {
    // A seeded and deleted id: the server knows no credential with it.
    const c = await seedCredential(sdk, tenant.id);
    await sdk.eab.delete(c.id);
    await page.goto(`/ca/eab/${c.id}`);
    await expect(page.getByRole('alert')).toBeVisible();
  });
});
