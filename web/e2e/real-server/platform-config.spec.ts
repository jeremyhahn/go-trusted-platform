import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Platform config against the real platformd (Refs #2047, epic #1665,
 * coverage-matrix slice 10 "UI PlatformDaemon").
 *
 * Nothing is mocked: each test waits for the page's own answer from the test
 * daemon and compares the page with it, so the assertions hold whatever the
 * daemon reports (no config file or several, a write enabled or disabled in
 * GET /api/v1/capabilities).
 *
 * No test clicks Reload, Apply, Snapshot, Roll back or Delete: the daemon is
 * shared by every real-server spec (one worker), and a reload or a section
 * update would change its configuration for the others. The write controls
 * are checked against the server capability only, and a request recorder
 * proves that opening the page sends no write.
 */

/** The ops the page reads or gates, as GET /api/v1/capabilities names them. */
const OP = {
  config: 'GET /api/v1/platform/config',
  reload: 'POST /api/v1/platform/config/reload',
  update: 'PUT /api/v1/platform/config/sections/{section}',
  capabilities: 'GET /api/v1/capabilities',
} as const;

/** The path of an op: `GET /api/v1/x` -> `/api/v1/x`. */
function opPath(op: string): string {
  return op.slice(op.indexOf(' ') + 1);
}

/** A RegExp matching exactly the path of a parameterless op. */
function exactPath(op: string): RegExp {
  return new RegExp(`^${opPath(op).replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&')}$`);
}

/** Waits for the page's own request whose method and path match. */
function apiResponse(page: Page, method: string, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && path.test(new URL(r.url()).pathname),
  );
}

async function json<T>(r: Response): Promise<T> {
  expect(r.ok(), `${r.url()} answered ${r.status()}`).toBeTruthy();
  return unwrapPayload<T>(await r.json());
}

/** Waits for the page's own GET /api/v1/capabilities: op -> enabled. */
async function capabilities(page: Page): Promise<Map<string, boolean>> {
  const r = await apiResponse(page, 'GET', exactPath(OP.capabilities));
  const body = await json<{ capabilities: { op: string; enabled: boolean }[] }>(r);
  return new Map(body.capabilities.map((c) => [c.op, c.enabled === true]));
}

/**
 * Records every request the page sends, as `METHOD /path`. The no-write
 * test reads only the write methods (POST, PUT, PATCH, DELETE) from it:
 * the console also sends HEAD requests to page routes, which are not writes.
 */
function recordRequests(page: Page): string[] {
  const sent: string[] = [];
  page.on('request', (r) => {
    sent.push(`${r.method()} ${new URL(r.url()).pathname}`);
  });
  return sent;
}

/** The body of GET /api/v1/platform/config. */
interface ConfigView {
  sources: { path: string; format: string }[];
  tree: Record<string, unknown>;
}

test.describe('platform config (real server)', () => {
  test('the Sources card lists the files GET /api/v1/platform/config answered', async ({
    adminPage,
  }) => {
    const [r] = await Promise.all([
      apiResponse(adminPage, 'GET', /^\/api\/v1\/platform\/config$/),
      adminPage.goto('/platform/config'),
    ]);
    const view = await json<ConfigView>(r);
    const sources = view.sources ?? [];

    await expect(adminPage.getByText('Sources', { exact: true })).toBeVisible();
    if (sources.length === 0) {
      await expect(adminPage.getByText('No config file is currently loaded.')).toBeVisible();
    } else {
      for (const source of sources) {
        await expect(adminPage.getByText(source.path, { exact: true }).first()).toBeVisible();
        await expect(adminPage.getByText(source.format, { exact: true }).first()).toBeVisible();
      }
    }
  });

  test('Reload and Apply follow the server capabilities', async ({ adminPage }) => {
    const [caps] = await Promise.all([capabilities(adminPage), adminPage.goto('/platform/config')]);

    const reloadControl = adminPage.getByRole('button').filter({ hasText: /^\s*Reload\s*$/ });
    await expect(reloadControl).toHaveAttribute('data-capability-op', OP.reload);
    await expect(reloadControl).toHaveAttribute(
      'data-capability-enabled',
      String(caps.get(OP.reload) === true),
    );

    const applyControl = adminPage
      .getByTestId('config-section-editor')
      .getByRole('button')
      .filter({ hasText: /^\s*Apply\s*$/ });
    await expect(applyControl).toHaveAttribute('data-capability-op', OP.update);
    await expect(applyControl).toHaveAttribute(
      'data-capability-enabled',
      String(caps.get(OP.update) === true),
    );
  });

  test('opening the page sends no write', async ({ adminPage }) => {
    const sent = recordRequests(adminPage);
    await Promise.all([
      apiResponse(adminPage, 'GET', exactPath(OP.config)),
      adminPage.goto('/platform/config'),
    ]);
    await expect(adminPage.getByText('Sources', { exact: true })).toBeVisible();

    expect(sent.filter((s) => /^(POST|PUT|PATCH|DELETE) /.test(s))).toEqual([]);
  });
});
