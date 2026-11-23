import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Provisioning sessions against the real platformd (#2046, epic #1665).
 *
 * The list page and the session detail page, with no route mocks: every
 * assertion compares the page with what the server answered, and follows the
 * server's capability answer (an op that is off leaves its control disabled
 * with the reason as its title, or shows the page's not-enabled state).
 */

const LIST_OP = 'GET /api/v1/provisioning/sessions';
const GET_OP = 'GET /api/v1/provisioning/sessions/{sessionID}';
const LIST_PATH = /^\/api\/v1\/provisioning\/sessions$/;
const UNKNOWN_ID = 'e2e-no-such-session';

/** Waits for the page's own request with this method whose path matches. */
function apiResponse(page: Page, method: string, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && path.test(new URL(r.url()).pathname),
  );
}

/** An SDK answer is `{ success, data, error }`, not the payload envelope. */
function sdkData<T>(res: { success: boolean; data?: T; error?: unknown }, what: string): T {
  expect(res.success, `${what}: ${JSON.stringify(res.error)}`).toBeTruthy();
  return res.data as T;
}

/** What the server offers: `on(op)` and the `reason(op)` an off op carries. */
async function capabilities(sdk: PlatformClient) {
  const caps = sdkData(await sdk.capabilities.list(), 'capabilities');
  const byOp = new Map(caps.capabilities.map((c) => [c.op, c]));
  return {
    on: (op: string) => byOp.get(op)?.enabled === true,
    reason: (op: string) => byOp.get(op)?.reason ?? '',
  };
}

type WireSession = { id: string };

/** The list answer: a bare array, or `{ sessions: [...] }`. */
function sessionIds(data: unknown): string[] {
  const list = Array.isArray(data)
    ? (data as WireSession[])
    : ((data as { sessions?: WireSession[] } | undefined)?.sessions ?? []);
  return list.map((s) => s.id);
}

test.describe('provisioning sessions against the real server', () => {
  test('lists the sessions the server answers', async ({ adminPage, sdk }) => {
    const caps = await capabilities(sdk);
    const refresh = adminPage.getByRole('button', { name: /Refresh/ });

    if (!caps.on(LIST_OP)) {
      await adminPage.goto('/provisioning/sessions');
      await expect(refresh).toBeDisabled();
      await expect(refresh).toHaveAttribute('title', caps.reason(LIST_OP));
      return;
    }

    const listRes = apiResponse(adminPage, 'GET', LIST_PATH);
    await adminPage.goto('/provisioning/sessions');
    const res = await listRes;
    expect(res.ok(), `${res.url()} answered ${res.status()}`).toBeTruthy();
    const pageIds = sessionIds(unwrapPayload<unknown>(await res.json()));

    const ids = sessionIds(sdkData(await sdk.device.listProvisioningSessions(), 'sessions'));
    // The page and the SDK read the same server: every session the page was
    // answered is one the SDK reads too.
    for (const id of pageIds) expect(ids).toContain(id);
    if (ids.length === 0) {
      await expect(adminPage.getByText('No provisioning sessions found')).toBeVisible();
      return;
    }
    for (const id of ids) {
      await expect(adminPage.getByTestId(`provisioning-session-${id}`)).toBeVisible();
    }
  });

  test('Refresh re-reads the list', async ({ adminPage, sdk }) => {
    const caps = await capabilities(sdk);
    const refresh = adminPage.getByRole('button', { name: /Refresh/ });

    if (!caps.on(LIST_OP)) {
      await adminPage.goto('/provisioning/sessions');
      await expect(refresh).toBeDisabled();
      await expect(refresh).toHaveAttribute('title', caps.reason(LIST_OP));
      return;
    }

    const first = apiResponse(adminPage, 'GET', LIST_PATH);
    await adminPage.goto('/provisioning/sessions');
    await first;
    await expect(refresh).toBeEnabled();
    const again = apiResponse(adminPage, 'GET', LIST_PATH);
    await refresh.click();
    const res = await again;
    expect(res.ok(), `${res.url()} answered ${res.status()}`).toBeTruthy();
  });

  test('an unknown session id shows its not-found or not-enabled state', async ({
    adminPage,
    sdk,
  }) => {
    const caps = await capabilities(sdk);

    if (!caps.on(GET_OP)) {
      await adminPage.goto(`/provisioning/sessions/${UNKNOWN_ID}`);
      await expect(adminPage.getByTestId('session-not-enabled')).toBeVisible();
      return;
    }

    const getRes = apiResponse(
      adminPage,
      'GET',
      new RegExp(`^/api/v1/provisioning/sessions/${UNKNOWN_ID}$`),
    );
    await adminPage.goto(`/provisioning/sessions/${UNKNOWN_ID}`);
    const res = await getRes;
    expect(res.ok(), `${res.url()} answered ${res.status()}`).toBeFalsy();
    await expect(adminPage.getByText('Session Not Found')).toBeVisible();
  });
});
