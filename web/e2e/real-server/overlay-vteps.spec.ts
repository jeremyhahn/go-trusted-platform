import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Overlay VTEPs page against the real platformd (#2059, epic #1665).
 *
 * The page reads every OverlayService view (status, VTEPs, VNIs, tunnels,
 * remote MACs) and gates Delete VNI / Forget MAC on GET /api/v1/capabilities.
 * The test daemon has no overlay controller, so the overlay routes answer
 * 503 and the capabilities list the writes as not configured; with a
 * controller the same assertions hold for a 200. No spec here clicks a
 * confirm button: the daemon is shared by every spec, so nothing is deleted.
 */

type AdminPage = Parameters<Parameters<typeof test>[2]>[0]['adminPage'];
type ApiResponse = Awaited<ReturnType<AdminPage['waitForResponse']>>;

const PAGE = '/networking/overlays/vteps';

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

test.describe('Overlay VTEPs (real server)', () => {
  test('the status section shows what GET /api/v1/overlay/status answered', async ({ adminPage }) => {
    const statusRes = ownGet(adminPage, '/api/v1/overlay/status');
    const [res] = await Promise.all([statusRes, adminPage.goto(PAGE)]);

    const section = adminPage.getByTestId('overlay-status');
    await expect(section).toBeVisible();
    if (res.ok()) {
      const payload = unwrapPayload<{ status?: { nodeId?: string }; nodeId?: string }>(await res.json());
      const nodeId = payload.status?.nodeId ?? payload.nodeId ?? '';
      await expect(section).toContainText(nodeId || '-');
      await expect(adminPage.getByTestId('overlay-status-error')).toHaveCount(0);
    } else {
      const text = await refusalText(res);
      const error = adminPage.getByTestId('overlay-status-error');
      await expect(error).toBeVisible();
      await expect(error).toContainText(text);
    }
  });

  test('each list shows its rows or the server refusal', async ({ adminPage }) => {
    const lists = [
      ['/api/v1/overlay/vteps', 'vteps-table', 'vteps-list-error'],
      ['/api/v1/overlay/vnis', 'vnis-table', 'vnis-list-error'],
      ['/api/v1/overlay/tunnels', 'tunnels-table', 'tunnels-list-error'],
      ['/api/v1/overlay/macs', 'macs-table', 'macs-list-error'],
    ] as const;
    const pending = lists.map(([path]) => ownGet(adminPage, path));
    const [responses] = await Promise.all([Promise.all(pending), adminPage.goto(PAGE)]);

    for (const [i, [path, table, errorCell]] of lists.entries()) {
      const res = responses[i];
      await expect(adminPage.getByTestId(table), path).toBeVisible();
      if (res.ok()) {
        unwrapPayload<unknown>(await res.json());
        await expect(adminPage.getByTestId(errorCell), path).toHaveCount(0);
      } else {
        const text = await refusalText(res);
        const cell = adminPage.getByTestId(errorCell);
        await expect(cell, path).toBeVisible();
        await expect(cell, path).toContainText(text);
      }
    }
  });

  test('delete and forget follow the server capability and send nothing', async ({ adminPage }) => {
    const sent: string[] = [];
    adminPage.on('request', (req) => {
      sent.push(`${req.method()} ${new URL(req.url()).pathname}`);
    });

    const capsRes = ownGet(adminPage, '/api/v1/capabilities');
    const [res] = await Promise.all([capsRes, adminPage.goto(PAGE)]);
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

    await expect(adminPage.getByTestId('overlay-admin-note')).toHaveCount(0);

    const forgetOp = 'DELETE /api/v1/overlay/macs';
    const forget = answer(forgetOp);
    const button = adminPage
      .getByTestId('overlay-forget-mac')
      .getByRole('button', { name: 'Forget MAC', exact: true });
    await expect(button).toHaveAttribute('data-capability-op', forgetOp);
    await expect(button).toHaveAttribute('data-capability-enabled', String(forget.enabled));
    if (!forget.enabled) {
      await expect(button).toBeDisabled();
      if (forget.reason) {
        await expect(button).toHaveAttribute('title', forget.reason);
      }
    }

    // Row controls (Delete VNI, Forget on a MAC row) carry the same gate.
    const rowControls = adminPage.locator('[data-capability-op^="DELETE /api/v1/overlay/"]');
    for (const control of await rowControls.all()) {
      const op = (await control.getAttribute('data-capability-op')) ?? '';
      await expect(control, op).toHaveAttribute('data-capability-enabled', String(answer(op).enabled));
    }

    await adminPage.waitForLoadState('networkidle');
    expect(sent.filter((s) => s.startsWith('DELETE /api/v1/overlay/'))).toEqual([]);
  });
});
