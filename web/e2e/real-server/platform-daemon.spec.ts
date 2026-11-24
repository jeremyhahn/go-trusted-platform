import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload, wireCount } from './fixtures/wire';

/**
 * Platform health and services against the real platformd (Refs #2047, epic
 * #1665, coverage-matrix slice 10 "UI PlatformDaemon").
 *
 * Nothing is mocked: each test waits for the page's own answer from the test
 * daemon and compares the card with it, so the assertions hold whatever the
 * daemon reports (alive or not, ready or not, an empty or a long service
 * list, a write enabled or disabled in GET /api/v1/capabilities).
 *
 * The daemon is shared by every real-server spec (one worker), so no test
 * ever confirms a shutdown, a stop or a restart, and none clicks Start: the
 * write controls are checked against the server capability, and a confirm
 * dialog is only ever cancelled, with a request recorder proving that no
 * write left the page.
 *
 * Not covered here: /platform/config (a later slice, after it moves onto the
 * SDK client).
 */

/** The ops the cards read or gate, as GET /api/v1/capabilities names them. */
const OP = {
  status: 'GET /api/v1/platform/status',
  liveness: 'GET /api/v1/platform/liveness',
  readiness: 'GET /api/v1/platform/readiness',
  version: 'GET /api/v1/platform/version',
  entityTypes: 'GET /api/v1/platform/entity-types',
  services: 'GET /api/v1/platform/services',
  shutdown: 'POST /api/v1/platform/shutdown',
  start: 'POST /api/v1/platform/services/{service}/start',
  stop: 'POST /api/v1/platform/services/{service}/stop',
  restart: 'POST /api/v1/platform/services/{service}/restart',
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
  const r = await apiResponse(page, 'GET', /^\/api\/v1\/capabilities$/);
  const body = await json<{ capabilities: { op: string; enabled: boolean }[] }>(r);
  return new Map(body.capabilities.map((c) => [c.op, c.enabled === true]));
}

/** Records every request the page sends, as `METHOD /path`. */
function recordRequests(page: Page): string[] {
  const sent: string[] = [];
  page.on('request', (r) => {
    sent.push(`${r.method()} ${new URL(r.url()).pathname}`);
  });
  return sent;
}

interface PlatformStatus {
  status?: string;
  system?: { os?: string; arch?: string };
}
interface PlatformVersion {
  version?: string;
  go_version?: string;
}
interface EntityTypes {
  entityTypes?: { name: string; entityCount?: number | string; status?: string }[];
  totalEntities?: number | string;
}
interface ServiceInfo {
  name: string;
  status: string;
}

test.describe('Platform health (real server)', () => {
  test('the probes card shows the status, liveness and readiness the server answered', async ({
    adminPage,
  }) => {
    const [status, liveness, readiness] = await Promise.all([
      apiResponse(adminPage, 'GET', exactPath(OP.status)),
      apiResponse(adminPage, 'GET', exactPath(OP.liveness)),
      apiResponse(adminPage, 'GET', exactPath(OP.readiness)),
      adminPage.goto('/platform/health'),
    ]);

    const refused = async (key: string, r: Response) => {
      await expect(adminPage.getByTestId(`probe-${key}-error`)).toContainText(`HTTP ${r.status()}`);
    };

    if (status.ok()) {
      const body = unwrapPayload<PlatformStatus>(await status.json());
      const shown = adminPage.getByTestId('probe-status');
      if (body.status) await expect(shown).toContainText(body.status);
      if (body.system?.os) await expect(shown).toContainText(body.system.os);
    } else {
      await refused('status', status);
    }

    if (liveness.ok()) {
      const body = unwrapPayload<{ alive?: boolean }>(await liveness.json());
      await expect(adminPage.getByTestId('probe-liveness')).toHaveText(
        body.alive === true ? 'Alive' : 'Not alive',
      );
    } else {
      await refused('liveness', liveness);
    }

    if (readiness.ok()) {
      const body = unwrapPayload<{ ready?: boolean }>(await readiness.json());
      await expect(adminPage.getByTestId('probe-readiness')).toHaveText(
        body.ready === true ? /^Ready \(/ : /^Not ready \(/,
      );
    } else {
      await refused('readiness', readiness);
    }
  });

  test('the version card shows the build the server answered', async ({ adminPage }) => {
    const [r] = await Promise.all([
      apiResponse(adminPage, 'GET', exactPath(OP.version)),
      adminPage.goto('/platform/health'),
    ]);
    const body = await json<PlatformVersion>(r);
    const shown = (v: string | undefined) => (v === undefined || v === '' ? '—' : v);

    const card = adminPage.locator('dl', { has: adminPage.locator('dt', { hasText: 'Go version' }) });
    await expect(card.locator('dt:text-is("Version") + dd')).toHaveText(shown(body.version));
    await expect(card.locator('dt:text-is("Go version") + dd')).toHaveText(shown(body.go_version));
  });

  test('the entity types card matches GET /api/v1/platform/entity-types', async ({ adminPage }) => {
    const [r] = await Promise.all([
      apiResponse(adminPage, 'GET', exactPath(OP.entityTypes)),
      adminPage.goto('/platform/health'),
    ]);
    const card = adminPage.getByTestId('platform-entity-types');

    expect(r.ok(), 'GET /api/v1/platform/entity-types answers 200').toBe(true);
    const body = unwrapPayload<EntityTypes>(await r.json());
    const types = body.entityTypes ?? [];
    for (const t of types) {
      await expect(card.getByTestId(`entity-type-${t.name}`)).toBeVisible();
    }
    await expect(card.locator('[data-testid^="entity-type-"]')).toHaveCount(types.length);
    await expect(card.getByTestId('entity-types-total')).toHaveText(
      `Total entities: ${wireCount(body.totalEntities ?? 0)}`,
    );
  });

  test('the shutdown button follows the server capability and Cancel sends nothing', async ({
    adminPage,
  }) => {
    const sent = recordRequests(adminPage);
    const [caps] = await Promise.all([capabilities(adminPage), adminPage.goto('/platform/health')]);
    const enabled = caps.get(OP.shutdown) === true;

    const button = adminPage
      .getByTestId('platform-shutdown')
      .getByRole('button', { name: 'Shut down', exact: true });
    await expect(button).toHaveAttribute('data-capability-op', OP.shutdown);
    await expect(button).toHaveAttribute('data-capability-enabled', String(enabled));

    if (enabled) {
      await button.click();
      const dialog = adminPage.getByRole('dialog', { name: 'Shut the daemon down?' });
      await expect(dialog).toBeVisible();
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
      await expect(dialog).toBeHidden();
    }
    expect(sent).not.toContain(`POST ${opPath(OP.shutdown)}`);
  });
});

test.describe('Platform services (real server)', () => {
  /** Opens /platform/services; returns the list and the capabilities the page read. */
  async function openServices(page: Page) {
    const [r, caps] = await Promise.all([
      apiResponse(page, 'GET', exactPath(OP.services)),
      capabilities(page),
      page.goto('/platform/services'),
    ]);
    const body = await json<{ services?: ServiceInfo[] }>(r);
    return { services: body.services ?? [], caps };
  }

  test('the control card lists the services the server answered', async ({ adminPage }) => {
    const { services } = await openServices(adminPage);
    const card = adminPage.getByTestId('platform-service-control-card');

    for (const svc of services) {
      await expect(card.getByTestId(`service-row-${svc.name}`)).toBeVisible();
      await expect(card.getByTestId(`service-status-${svc.name}`)).toHaveText(svc.status);
    }
    await expect(card.locator('[data-testid^="service-row-"]')).toHaveCount(services.length);
  });

  test('Details shows GET /api/v1/platform/services/{service}', async ({ adminPage }) => {
    const { services } = await openServices(adminPage);
    // The daemon's default Services (pkg/api/daemon/config.go:329: tpm, sdn, compute and dns, all enabled) are registered
    // by registerConfiguredServices (pkg/api/daemon/daemon.go:3550, called at :2886) whether or not each subsystem is wired, so an empty list is a failure.
    expect(services.length, 'the test daemon registers its configured services').toBeGreaterThan(0);

    const first = services[0];
    const [r] = await Promise.all([
      apiResponse(adminPage, 'GET', /^\/api\/v1\/platform\/services\/[^/]+$/),
      adminPage
        .getByTestId(`service-row-${first.name}`)
        .getByRole('button', { name: 'Details', exact: true })
        .click(),
    ]);
    const detail = await json<ServiceInfo>(r);

    const dl = adminPage.getByTestId('service-detail');
    await expect(dl.locator('dt:text-is("Service") + dd')).toHaveText(detail.name);
    await expect(dl.locator('dt:text-is("Status") + dd')).toHaveText(detail.status);
  });

  test('start, stop and restart follow the server capabilities and a cancelled stop sends nothing', async ({
    adminPage,
  }) => {
    const sent = recordRequests(adminPage);
    const { services, caps } = await openServices(adminPage);
    expect(services.length, 'the test daemon registers its configured services').toBeGreaterThan(0);

    const name = services[0].name;
    const row = adminPage.getByTestId(`service-row-${name}`);
    const controls = [
      { label: `Start ${name}`, op: OP.start },
      { label: `Stop ${name}`, op: OP.stop },
      { label: `Restart ${name}`, op: OP.restart },
    ];
    for (const c of controls) {
      const button = row.getByRole('button', { name: c.label, exact: true });
      await expect(button).toHaveAttribute('data-capability-op', c.op);
      await expect(button).toHaveAttribute('data-capability-enabled', String(caps.get(c.op) === true));
    }

    if (caps.get(OP.stop) === true) {
      await row.getByRole('button', { name: `Stop ${name}`, exact: true }).click();
      const dialog = adminPage.getByRole('dialog', { name: `Stop ${name}?` });
      await expect(dialog).toBeVisible();
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
      await expect(dialog).toBeHidden();
    }
    const prefix = `POST ${opPath(OP.services)}/`;
    expect(sent.filter((s) => s.startsWith(prefix))).toEqual([]);
  });
});
