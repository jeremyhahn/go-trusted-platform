import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures';

/**
 * The Device IDevID cases of the mocked web/e2e/devices.spec.ts, against the
 * real-server harness (#2035, epic #1665).
 *
 * The page (web/src/app/(dashboard)/devices/idevid/page.tsx) reads
 * GET /api/v1/idevid and renders `data.idevids` as its table. The server's
 * GET /api/v1/idevid is the daemon's own IDevID info
 * (pkg/webservice/v1/rest/idevid/handlers.go GetIDevIDInfo; 503 when the
 * service is not configured), not a certificate list, and
 * GET /api/v1/idevid/expiring always answers `{count: 0}`. So every case here
 * reads the answer the page got and asserts what the page renders for it: the
 * error toast when the read fails, the rows the answer carries, the empty
 * state when it carries none. A case that needs a certificate row the server
 * does not serve is a `// gap:` line for the route audit.
 *
 * Nothing here changes the daemon's own IDevID (no generate, delete, CSR,
 * install or revoke): other specs share the daemon. The issue dialog is
 * driven up to the validation the form does itself; the devices it offers
 * are the tenant's devices the server lists, seeded through the SDK under
 * unique names and deleted in afterEach.
 */

const LIST_PATH = '/api/v1/idevid';
const EXPIRING_PATH = '/api/v1/idevid/expiring';

interface ListAnswer {
  ok: boolean;
  status: number;
  body: { idevids?: unknown } | null;
}

function isGet(r: Response, pathname: string): boolean {
  return r.request().method() === 'GET' && new URL(r.url()).pathname === pathname;
}

async function jsonOf(r: Response): Promise<Record<string, unknown> | null> {
  return (await r.json().catch(() => null)) as Record<string, unknown> | null;
}

/** The rows the page renders for the list answer: `data.idevids`, or none. */
function rowsOf(answer: ListAnswer): number {
  return answer.ok && Array.isArray(answer.body?.idevids) ? (answer.body.idevids as unknown[]).length : 0;
}

/** Asserts what the page renders for the list answer the server gave. */
async function expectListState(page: Page, answer: ListAnswer): Promise<void> {
  await expect(page.getByText('Loading certificates...')).toBeHidden();
  if (!answer.ok) {
    // The page throws on !response.ok and toasts its own message.
    await expect(page.getByText('Failed to fetch IDevID certificates').first()).toBeVisible();
  }
  const rows = rowsOf(answer);
  if (rows === 0) {
    await expect(page.getByRole('cell', { name: 'No IDevID certificates found' })).toBeVisible();
  } else {
    await expect(page.locator('tbody tr')).toHaveCount(rows);
  }
}

/** Opens the IDevID page, reads the two answers the page got, asserts the state it renders. */
async function openIDevID(page: Page): Promise<ListAnswer> {
  const listP = page.waitForResponse((r) => isGet(r, LIST_PATH));
  const expiringP = page.waitForResponse((r) => isGet(r, EXPIRING_PATH));
  await page.goto('/devices/idevid');
  const [list, expiring] = await Promise.all([listP, expiringP]);
  const answer: ListAnswer = { ok: list.ok(), status: list.status(), body: await jsonOf(list) };

  // The page reads `data.count` of the expiring answer and shows the banner when it is > 0.
  const expBody = await jsonOf(expiring);
  const count = expiring.ok() ? Number(expBody?.count ?? 0) : 0;
  const banner = page.getByText('Certificates Expiring Soon');
  if (count > 0) {
    await expect(banner).toBeVisible();
  } else {
    await expect(banner).toBeHidden();
  }

  await expectListState(page, answer);
  return answer;
}

/** The status (first) and expiration (second) filter selects of the filter bar. */
function filterSelect(page: Page, which: 'status' | 'expiration') {
  return page.getByRole('combobox').nth(which === 'status' ? 0 : 1);
}

/** Opens the issue dialog; resolves on the dialog. */
async function openIssueDialog(page: Page) {
  await page.getByRole('button', { name: 'Issue IDevID' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('heading', { name: 'Issue IDevID Certificate' })).toBeVisible();
  return dialog;
}

/** Records every request the page sends that would change the daemon's IDevID. */
function watchIssueRequests(page: Page): string[] {
  const sent: string[] = [];
  page.on('request', (req) => {
    const p = new URL(req.url()).pathname;
    if (req.method() !== 'GET' && p.startsWith(LIST_PATH)) sent.push(`${req.method()} ${p}`);
  });
  return sent;
}

test.describe('Device IDevID, real server', () => {
  test.describe('IDevID Certificate List', () => {
    test('should display IDevID page with table structure', async ({ adminPage: page }) => {
      await openIDevID(page);
      await expect(page.getByRole('heading', { name: 'IDevID Certificates' })).toBeVisible();
      for (const h of ['Device', 'Subject', 'Serial Number', 'Status', 'Issued', 'Expires', 'Actions']) {
        await expect(page.getByRole('columnheader', { name: h, exact: true })).toBeVisible();
      }
    });

    test('should show empty state when no certificates', async ({ adminPage: page }) => {
      const answer = await openIDevID(page);
      // The server's list read is the daemon's IDevID info: it carries no `idevids` list.
      expect(Array.isArray(answer.body?.idevids)).toBe(false);
      await expect(page.getByRole('cell', { name: 'No IDevID certificates found' })).toBeVisible();
    });

    test('should display Issue IDevID button', async ({ adminPage: page }) => {
      await openIDevID(page);
      await expect(page.getByRole('button', { name: 'Issue IDevID' })).toBeEnabled();
    });

    test('should display filter controls', async ({ adminPage: page }) => {
      await openIDevID(page);
      await expect(page.getByPlaceholder('Search certificates...')).toBeVisible();
      await expect(filterSelect(page, 'status')).toHaveText(/All statuses/);
      await expect(filterSelect(page, 'expiration')).toHaveText(/All certificates/);
      await expect(page.getByRole('button', { name: 'Clear filters' })).toHaveCount(0);
    });
  });

  test.describe('IDevID Filtering UI', () => {
    test('should allow typing in search field', async ({ adminPage: page }) => {
      await openIDevID(page);
      // A filter change makes the page read the list again; it renders that answer.
      const again = page.waitForResponse((r) => isGet(r, LIST_PATH));
      await page.getByPlaceholder('Search certificates...').fill('e2e-idev-search');
      const res = await again;
      await expect(page.getByPlaceholder('Search certificates...')).toHaveValue('e2e-idev-search');
      await expectListState(page, { ok: res.ok(), status: res.status(), body: await jsonOf(res) });
    });

    test('should open status filter dropdown', async ({ adminPage: page }) => {
      await openIDevID(page);
      await filterSelect(page, 'status').click();
      for (const o of ['All statuses', 'Active', 'Revoked', 'Expired', 'Pending']) {
        await expect(page.getByRole('option', { name: o, exact: true })).toBeVisible();
      }
    });

    test('should open expiration filter dropdown', async ({ adminPage: page }) => {
      await openIDevID(page);
      await filterSelect(page, 'expiration').click();
      for (const o of ['All certificates', 'Expiring in 7 days', 'Expiring in 30 days', 'Expiring in 90 days']) {
        await expect(page.getByRole('option', { name: o, exact: true })).toBeVisible();
      }
    });

    test('should show clear filters button when filter is applied', async ({ adminPage: page }) => {
      await openIDevID(page);
      await expect(page.getByRole('button', { name: 'Clear filters' })).toHaveCount(0);
      const again = page.waitForResponse((r) => isGet(r, LIST_PATH));
      await filterSelect(page, 'status').click();
      await page.getByRole('option', { name: 'Active', exact: true }).click();
      const res = await again;
      await expectListState(page, { ok: res.ok(), status: res.status(), body: await jsonOf(res) });
      await expect(filterSelect(page, 'status')).toHaveText(/Active/);
      await page.getByRole('button', { name: 'Clear filters' }).click();
      await expect(page.getByRole('button', { name: 'Clear filters' })).toHaveCount(0);
      await expect(filterSelect(page, 'status')).toHaveText(/All statuses/);
    });
  });

  test.describe('Issue IDevID Certificate', () => {
    let seeded: string[] = [];

    test.afterEach(async ({ sdk }) => {
      for (const id of seeded) await sdk.device.deleteDevice(id).catch(() => undefined);
      seeded = [];
    });

    test('should open issue IDevID dialog', async ({ adminPage: page }) => {
      await openIDevID(page);
      const dialog = await openIssueDialog(page);
      await expect(dialog.getByText('Issue a new device identity certificate for a registered device')).toBeVisible();
    });

    test('should display issue form with all fields', async ({ adminPage: page }) => {
      await openIDevID(page);
      const dialog = await openIssueDialog(page);
      for (const l of ['Device', 'Certificate Subject', 'Validity Period (Days)', 'Key Algorithm', 'Key Size (bits)']) {
        await expect(dialog.getByText(l, { exact: true })).toBeVisible();
      }
      await expect(dialog.getByPlaceholder('CN=device-name,O=Organization')).toBeVisible();
      await expect(dialog.getByRole('spinbutton')).toHaveValue('365');
      await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeVisible();
      await expect(dialog.getByRole('button', { name: 'Issue Certificate' })).toBeVisible();
    });

    test('should validate device selection is required', async ({ adminPage: page }) => {
      await openIDevID(page);
      const sent = watchIssueRequests(page);
      const dialog = await openIssueDialog(page);
      await dialog.getByRole('button', { name: 'Issue Certificate' }).click();
      await expect(dialog.getByText('Device is required')).toBeVisible();
      // The form refuses before any request reaches the server.
      expect(sent).toEqual([]);
    });

    test('should validate subject is required', async ({ adminPage: page, sdk }) => {
      const serial = `e2e-idev-${Date.now()}-1`;
      const created = await sdk.device.createDevice({ device: { serial, model: serial } });
      expect(created.success).toBe(true);
      const id = String((created.data as { id?: string | number } | undefined)?.id ?? '');
      expect(id).not.toBe('');
      seeded.push(id);

      await openIDevID(page);
      const sent = watchIssueRequests(page);
      const dialog = await openIssueDialog(page);
      await dialog.getByRole('combobox').first().click();
      // The form offers the tenant's devices the server lists, by serial.
      await page.getByRole('option', { name: serial, exact: true }).click();
      const subject = dialog.getByPlaceholder('CN=device-name,O=Organization');
      await expect(subject).toHaveValue(`CN=${serial}`);
      await subject.fill('');
      await dialog.getByRole('button', { name: 'Issue Certificate' }).click();
      await expect(dialog.getByText('Subject is required')).toBeVisible();
      await expect(dialog.getByText('Device is required')).toHaveCount(0);
      expect(sent).toEqual([]);
    });

    test('should show RSA key algorithm as default', async ({ adminPage: page }) => {
      await openIDevID(page);
      const dialog = await openIssueDialog(page);
      await expect(dialog.getByRole('combobox').nth(1)).toHaveText(/RSA/);
      await expect(dialog.getByText('Key Size (bits)', { exact: true })).toBeVisible();
      await expect(dialog.getByRole('combobox').nth(2)).toHaveText(/2048 bits/);
    });

    test('should switch to ECC algorithm and show curve options', async ({ adminPage: page }) => {
      await openIDevID(page);
      const dialog = await openIssueDialog(page);
      await dialog.getByRole('combobox').nth(1).click();
      await page.getByRole('option', { name: 'ECC (Elliptic Curve)' }).click();
      await expect(dialog.getByText('Curve', { exact: true })).toBeVisible();
      await expect(dialog.getByText('Key Size (bits)', { exact: true })).toHaveCount(0);
      await dialog.getByRole('combobox').nth(2).click();
      for (const o of ['P-256 (NIST)', 'P-384 (NIST)', 'P-521 (NIST)']) {
        await expect(page.getByRole('option', { name: o })).toBeVisible();
      }
    });

    test('should close dialog on escape key', async ({ adminPage: page }) => {
      await openIDevID(page);
      await openIssueDialog(page);
      await page.keyboard.press('Escape');
      await expect(page.getByRole('dialog')).toHaveCount(0);
    });

    // gap: should issue certificate successfully: the form's submit generates the daemon's own IDevID key (POST /api/v1/idevid/generate) and a CSR; the daemon is shared by every real-server spec, so the harness cannot issue without changing state other specs read, and the server issues no per-device certificate the list would then show
  });

  test.describe('IDevID Certificate Actions', () => {
    // gap: should open actions menu: the row menu needs a certificate row; GET /api/v1/idevid answers the daemon's IDevID info, not the `idevids` list the page renders (route audit: the IDevID certificate list route)
    // gap: should navigate to certificate details: needs a certificate row to open from; the server serves no IDevID certificate list
    // gap: should download certificate: needs a certificate row to open the menu on; the server serves no IDevID certificate list
    // gap: should renew certificate: needs an active certificate row; renew deletes and regenerates the daemon's own IDevID, which other specs share
    // gap: should revoke certificate with confirmation: needs an active certificate row; revoke deletes the daemon's own IDevID certificate, which other specs share
    // gap: should cancel revoke when dialog is dismissed: needs an active certificate row; the server serves no IDevID certificate list
    // gap: should not show renew/revoke for non-active certificates: needs a revoked or expired certificate row; the server serves no list and no per-certificate status
  });

  test.describe('IDevID Error States', () => {
    test('should show empty state when no certificates exist', async ({ adminPage: page, sdk }) => {
      // Whatever the daemon's own IDevID is (generated or not), the server serves no list of certificates.
      const has = await sdk.idevid.hasIDevID();
      const info = await sdk.idevid.getIDevIDInfo();
      expect(typeof has.success).toBe('boolean');
      expect(typeof info.success).toBe('boolean');
      const answer = await openIDevID(page);
      expect(rowsOf(answer)).toBe(0);
      await expect(page.locator('tbody tr')).toHaveCount(1);
      await expect(page.getByRole('cell', { name: 'No IDevID certificates found' })).toBeVisible();
    });

    // gap: should handle revoke certificate error: needs a certificate row to revoke from, and an injected revoke failure the real server does not produce on demand
    // gap: should handle download certificate error: needs a certificate row to download from, and an injected download failure the real server does not produce on demand
  });

  test.describe('IDevID Access Control', () => {
    // gap: should allow tenant members to view IDevID page: the harness signs in only its admin (tenant owner); it cannot create a tenant-member session

    test('should redirect unauthenticated users to login', async ({ page }) => {
      await page.goto('/devices/idevid');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  });

  test.describe('IDevID Table Display', () => {
    // gap: should display certificate subject: needs a certificate row; the server serves no IDevID certificate list
    // gap: should display serial number in monospace font: needs a certificate row; the server serves no IDevID certificate list
    // gap: should display formatted dates: needs a certificate row with issued and expiry dates; the server serves no IDevID certificate list
    // gap: should display multiple certificates: the daemon has one IDevID per host and the server serves no list, so there are never several rows
  });
});
