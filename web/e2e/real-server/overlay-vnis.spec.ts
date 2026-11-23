import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Overlay VNIs page against the real platformd (#2059, epic #1665).
 *
 * The page lists the VNIs (GET /api/v1/overlay/vnis) and gates Create Overlay
 * and Refresh on GET /api/v1/capabilities. The test daemon has no overlay
 * controller, so the overlay routes answer 503 and the capabilities list the
 * writes as not configured; with a controller the same assertions hold for a
 * 200. No spec here submits the create dialog: the daemon is shared by every
 * spec, so nothing is created.
 */

type AdminPage = Parameters<Parameters<typeof test>[2]>[0]['adminPage'];
type ApiResponse = Awaited<ReturnType<AdminPage['waitForResponse']>>;

const PAGE = '/networking/overlays';
const VNIS = '/api/v1/overlay/vnis';

type VniList = { vnis?: Array<{ config: { vni: number; name?: string } }> };

/** Waits for the page's own GET of exactly `path`. */
function ownGet(page: AdminPage, path: string): Promise<ApiResponse> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

/** The refusal text of a server JSON error envelope; fails on anything else. */
async function refusalText(r: ApiResponse): Promise<string> {
  const status = r.status();
  expect(status, `${r.url()} must not refuse the admin`).not.toBe(401);
  expect(status, `${r.url()} must not refuse the admin`).not.toBe(403);
  expect(status, `${r.url()} must be a served route`).not.toBe(404);
  expect(status, `${r.url()} must be a served route`).not.toBe(405);
  expect(status, `${r.url()} without an overlay controller`).toBe(503);
  const body = (await r.json()) as { error?: unknown; message?: unknown };
  const err = body.error;
  const text =
    typeof err === 'string' && err !== ''
      ? err
      : typeof err === 'object' && err !== null && typeof (err as { message?: unknown }).message === 'string'
        ? (err as { message: string }).message
        : typeof body.message === 'string'
          ? body.message
          : '';
  expect(text, `${r.url()} answered ${status} with ${JSON.stringify(body)}`).not.toBe('');
  return text;
}

test.describe('Overlay VNIs (real server)', () => {
  test('the list shows the VNIs GET /api/v1/overlay/vnis answered, or its refusal', async ({ adminPage }) => {
    const [res] = await Promise.all([ownGet(adminPage, VNIS), adminPage.goto(PAGE)]);

    if (res.ok()) {
      const { vnis = [] } = unwrapPayload<VniList>(await res.json());
      const table = adminPage.getByTestId('overlays-table');
      if (vnis.length === 0) {
        await expect(adminPage.getByText('No network overlays found')).toBeVisible();
      } else {
        await expect(table).toBeVisible();
        for (const v of vnis) {
          const label = v.config.name || `VNI-${v.config.vni}`;
          await expect(table.getByText(label, { exact: true }).first(), label).toBeVisible();
        }
      }
      await expect(adminPage.getByTestId('overlays-list-error')).toHaveCount(0);
    } else {
      const text = await refusalText(res);
      const error = adminPage.getByTestId('overlays-list-error');
      await expect(error).toBeVisible();
      await expect(error).toContainText(text);
    }
  });

  test('Create Overlay and Refresh follow the server capability and send no write', async ({ adminPage }) => {
    const sent: string[] = [];
    adminPage.on('request', (req) => {
      sent.push(`${req.method()} ${new URL(req.url()).pathname}`);
    });

    const [res] = await Promise.all([ownGet(adminPage, '/api/v1/capabilities'), adminPage.goto(PAGE)]);
    expect(res.ok(), `capabilities answered ${res.status()}`).toBeTruthy();
    const { capabilities = [] } = unwrapPayload<{
      capabilities?: Array<{ op: string; enabled: boolean; reason?: string }>;
    }>(await res.json());
    const answer = (op: string) => {
      const cap = capabilities.find((c) => c.op === op);
      return cap
        ? { enabled: cap.enabled === true, reason: cap.reason }
        : { enabled: false, reason: 'not offered by this server' };
    };

    const gates = [
      [`POST ${VNIS}`, adminPage.getByRole('button', { name: 'Create Overlay' })],
      [`GET ${VNIS}`, adminPage.getByRole('button', { name: 'Refresh overlays' })],
    ] as const;
    for (const [op, button] of gates) {
      const want = answer(op);
      await expect(button, op).toHaveAttribute('data-capability-op', op);
      await expect(button, op).toHaveAttribute('data-capability-enabled', String(want.enabled));
      if (!want.enabled) {
        await expect(button, op).toBeDisabled();
        if (want.reason) {
          await expect(button, op).toHaveAttribute('title', want.reason);
        }
      }
    }

    if (answer(`POST ${VNIS}`).enabled) {
      await adminPage.getByRole('button', { name: 'Create Overlay' }).click();
      const dialog = adminPage.getByRole('dialog');
      await expect(dialog).toBeVisible();
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await expect(dialog).toHaveCount(0);
    }

    await adminPage.waitForLoadState('networkidle');
    expect(sent.filter((s) => s === `POST ${VNIS}`)).toEqual([]);
  });

  test('Manage on a VNI row opens the VTEPs page', async ({ adminPage }) => {
    const [res] = await Promise.all([ownGet(adminPage, VNIS), adminPage.goto(PAGE)]);
    const vnis = res.ok() ? (unwrapPayload<VniList>(await res.json()).vnis ?? []) : [];
    const manage = adminPage.locator('[data-testid^="overlay-manage-"]');

    if (vnis.length === 0) {
      await expect(manage).toHaveCount(0);
      return;
    }
    await manage.first().click();
    await expect(adminPage).toHaveURL(/\/networking\/overlays\/vteps$/);
  });
});
