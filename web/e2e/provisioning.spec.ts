/**
 * Provisioning sessions — the console reads what the server sends.
 *
 * The session pages render `ek_serial`, `mac_address`, `created_at` and
 * `expires_at` from `GET /api/v1/provisioning/sessions`. Until #425 the
 * SDK declared those fields in camelCase, so every read was `undefined`: the
 * list showed "-", the detail page "Not reported", and dates were invalid, for
 * values the server had sent. These mocks answer with the Go `Session` struct's
 * JSON — snake_case, `profile_id` as a string — and assert the values reach the
 * screen. The fixture shape is pinned server-side by
 * `pkg/provisioning/configdelivery/session_wire_parity_test.go`.
 */

import { test, expect, Page } from '@playwright/test';
import { mockTenantApi } from './fixtures/api-mock';
import { createTenantOwnerSession } from './fixtures/auth-setup';

/** The wire: pkg/provisioning/configdelivery/types.go `Session`. */
interface WireSession {
  id: string;
  ek_serial?: string;
  mac_address?: string;
  tenant_id?: string;
  profile_id?: string;
  fulfilled: boolean;
  created_at: string;
  expires_at: string;
}

const CREATED = '2026-09-05T10:00:00.000Z';
const FUTURE = new Date(Date.now() + 60 * 60 * 1000).toISOString();

function wireSession(overrides: Partial<WireSession> = {}): WireSession {
  return {
    id: 'sess-7',
    ek_serial: 'EK-SERIAL-0001',
    mac_address: '52:54:00:aa:bb:cc',
    tenant_id: 'tenant-1',
    fulfilled: false,
    created_at: CREATED,
    expires_at: FUTURE,
    ...overrides,
  };
}

async function mockSessionApi(page: Page, sessions: WireSession[]): Promise<void> {
  await page.route('**/api/v1/provisioning/sessions', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(sessions) });
  });
  // The pages also load templates for the assign dialog; an empty list keeps
  // that call from failing without asserting anything about templates.
  await page.route('**/api/v1/device*/templates**', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ templates: [] }) });
  });
}

test.describe('Provisioning Sessions', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
  });

  test('the list shows the serial, MAC and timestamps the server sent', async ({ page }) => {
    await mockSessionApi(page, [wireSession()]);

    await page.goto('/provisioning/sessions');

    // Before #425 these cells rendered "-" and an invalid date, and the status
    // computed from `new Date(undefined)` read as expired.
    const row = page.getByRole('row', { name: /EK-SERIAL-0001/ });
    await expect(row).toBeVisible();
    await expect(row).toContainText('52:54:00:aa:bb:cc');
    await expect(row).toContainText('Pending');
    await expect(row).not.toContainText('Invalid Date');
  });

  // The detail page (/provisioning/sessions/[sessionId]) reads the same six
  // fields through the same SDK type and is covered by the typecheck; it is not
  // exercised here because `next dev` under `output: 'export'` refuses any
  // dynamic id that generateStaticParams did not list (Next's own runtime
  // error), and the client resolves the literal `__placeholder__` to an empty
  // id by design. The devices detail tests carry the same limitation.

  test('a session the server marks expired renders as expired', async ({ page }) => {
    // The control for the timestamp read: with the real field name the status
    // is computed from a real date. Before #425 `new Date(undefined)` made
    // every session read as expired.
    await mockSessionApi(page, [wireSession({ id: 'sess-old', expires_at: '2020-01-01T00:00:00.000Z' })]);

    await page.goto('/provisioning/sessions');

    await expect(page.getByText(/expired/i).first()).toBeVisible();
  });
});
