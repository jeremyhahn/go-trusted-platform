import { test, expect } from './fixtures';
import type { Page, Request } from '@playwright/test';

/**
 * vTPM bundles and templates pages against the real server.
 *
 * Ported from web/e2e/vtpm.spec.ts (#2037). Each test creates its own
 * template or bundle through sdk.vtpm (unique id), drives the page with it,
 * checks the page against what the server reports through the SDK, and
 * deletes what it created afterwards. Start/stop, the socket path while
 * running and PCR reads are covered by vtpm-runtime.spec.ts. The mocked
 * cases with no server behaviour behind them are listed in
 * docs/plans/1665-port-3.md (### vtpm).
 */

const unique = (prefix: string): string =>
  `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function must<T>(res: { success: boolean; data?: T; error?: any }, what: string): T {
  if (!res.success || res.data === undefined) {
    throw new Error(`${what} failed: ${JSON.stringify(res.error)}`);
  }
  return res.data;
}

const createdBundles: string[] = [];
const createdTemplates: string[] = [];

/** A runner without the swtpm binary: the server refuses every bundle or template create. */
const MISSING_SWTPM = /swtpm not installed/;

/** gap records what this run could not check, as a test annotation. */
function gap(description: string): void {
  test.info().annotations.push({ type: 'gap', description });
}

/**
 * The refusal text when the server refused for want of swtpm, else undefined.
 * Any other refusal still throws through `must`.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function swtpmRefusal(res: { success: boolean; data?: unknown; error?: any }): string | undefined {
  if (res.success && res.data !== undefined) return undefined;
  const text = JSON.stringify(res.error) ?? '';
  return MISSING_SWTPM.test(text) ? text : undefined;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function newBundle(sdk: any, hostname = unique('vtpm-e2e')): Promise<string | undefined> {
  const reply = await sdk.vtpm.createBundle({ options: { hostname } });
  const refused = swtpmRefusal(reply);
  if (refused !== undefined) {
    gap(`vtpm.createBundle refused: ${refused}`);
    return undefined;
  }
  const res = must(reply, 'vtpm.createBundle') as { id: string };
  createdBundles.push(res.id);
  return res.id;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function newTemplate(sdk: any): Promise<string | undefined> {
  const id = unique('tmpl-e2e');
  const reply = await sdk.vtpm.createTemplate({
    options: { id, description: `${id} description`, ekAlgorithm: 'ECC', secureBootEnabled: false },
  });
  const refused = swtpmRefusal(reply);
  if (refused !== undefined) {
    gap(`vtpm.createTemplate refused: ${refused}`);
    return undefined;
  }
  must(reply, 'vtpm.createTemplate');
  createdTemplates.push(id);
  return id;
}

/** With no template to drive, the templates page still loads its list. */
async function templatesPageOnly(page: Page): Promise<void> {
  await page.goto('/devices/vtpm/templates/');
  await expect(page.getByTestId('vtpm-template-list')).toBeVisible();
}

/** With no bundle to drive, the bundles page still loads its list. */
async function bundlesPageOnly(page: Page): Promise<void> {
  await page.goto('/devices/vtpm/bundles/');
  await expect(page.getByTestId('vtpm-bundle-list')).toBeVisible();
}

/** The server's capability answer: op to enabled. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function offered(sdk: any): Promise<Map<string, boolean>> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  const caps = (res.data?.capabilities ?? []) as { op: string; enabled: boolean }[];
  return new Map(caps.map((c) => [c.op, c.enabled] as [string, boolean]));
}

/** Every gated control on the page carries the server's answer for its op. */
async function expectGatedMatches(page: Page, caps: Map<string, boolean>): Promise<void> {
  const gated = page.locator('[data-capability-op]');
  await expect(gated.first()).toBeVisible();
  const n = await gated.count();
  expect(n, 'gated controls on the page').toBeGreaterThan(0);
  for (let i = 0; i < n; i++) {
    const el = gated.nth(i);
    const op = (await el.getAttribute('data-capability-op')) as string;
    await expect(el, op).toHaveAttribute('data-capability-enabled', String(caps.get(op) ?? false));
  }
}

/** The first absolute path among a reply's string fields (path, socket_path, ...). */
function pathIn(data: unknown): string | undefined {
  if (typeof data !== 'object' || data === null) return undefined;
  const d = data as Record<string, unknown>;
  if (typeof d.path === 'string') return d.path;
  return Object.values(d).find((v): v is string => typeof v === 'string' && v.startsWith('/'));
}

function recordVTPM(page: Page): Request[] {
  const seen: Request[] = [];
  page.on('request', (r) => {
    if (r.url().includes('/api/v1/vtpm/')) seen.push(r);
  });
  return seen;
}

function count(seen: Request[], method: string, path: string): number {
  return seen.filter((r) => r.method() === method && new URL(r.url()).pathname === path).length;
}

async function openTemplates(page: Page, id: string): Promise<Request[]> {
  const seen = recordVTPM(page);
  await page.goto('/devices/vtpm/templates/');
  await expect(page.getByTestId('vtpm-template-list')).toContainText(id);
  return seen;
}

function templateRow(page: Page, id: string) {
  return page.getByTestId('vtpm-template-list').getByRole('row').filter({ hasText: id });
}

async function openBundle(page: Page, id: string): Promise<Request[]> {
  const seen = recordVTPM(page);
  await page.goto('/devices/vtpm/bundles/__placeholder__/');
  // pushState is only router-integrated once the app has hydrated.
  await page.getByText('Loading bundle').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate((target) => window.history.pushState(null, '', target), `/devices/vtpm/bundles/${id}/`);
  await expect(page.getByTestId('vtpm-bundle-detail')).toBeVisible();
  return seen;
}

test.afterEach(async ({ sdk }) => {
  while (createdBundles.length > 0) {
    await sdk.vtpm.deleteBundle(createdBundles.pop() as string);
  }
  while (createdTemplates.length > 0) {
    await sdk.vtpm.deleteTemplate(createdTemplates.pop() as string);
  }
});

test.describe('vTPM bundles and templates (real server)', () => {
  test('ListTemplates', async ({ adminPage, sdk }) => {
    const id = await newTemplate(sdk);
    if (id === undefined) return templatesPageOnly(adminPage);
    const listed = must(await sdk.vtpm.listTemplates(), 'vtpm.listTemplates');
    expect(JSON.stringify(listed)).toContain(id);

    const seen = await openTemplates(adminPage, id);
    expect(count(seen, 'GET', '/api/v1/vtpm/templates')).toBeGreaterThanOrEqual(1);
    await expect(templateRow(adminPage, id)).toContainText('ECC');
  });

  test('CreateTemplate', async ({ adminPage, sdk }) => {
    const seed = await newTemplate(sdk);
    if (seed === undefined) await templatesPageOnly(adminPage);
    else await openTemplates(adminPage, seed);
    const id = unique('tmpl-ui');
    createdTemplates.push(id);

    await adminPage.getByRole('button', { name: 'New template' }).click();
    await adminPage.locator('#vt-id').fill(id);
    await adminPage.locator('#vt-description').fill('a fresh template');
    await adminPage.locator('#vt-ek-algorithm').selectOption('ECC');
    await adminPage.locator('#vt-secure-boot').check();
    const post = adminPage.waitForResponse(
      (r) => new URL(r.url()).pathname === '/api/v1/vtpm/templates' && r.request().method() === 'POST',
    );
    await adminPage.getByRole('button', { name: 'Create template' }).click();
    const reply = await post;
    expect(reply.request().postDataJSON()).toEqual({
      id,
      description: 'a fresh template',
      ek_algorithm: 'ECC',
      secure_boot_enabled: true,
    });
    if (!reply.ok()) {
      const text = await reply.text();
      if (MISSING_SWTPM.test(text)) {
        // The page shows the server's refusal; the create itself is a gap on this runner.
        await expect(adminPage.getByText(/swtpm/).first()).toBeVisible();
        gap(`vtpm.createTemplate (page) refused: ${text}`);
        return;
      }
    }
    expect(reply.ok()).toBe(true);

    await expect(adminPage.getByTestId('vtpm-template-list')).toContainText(id);
    const got = await sdk.vtpm.getTemplate(id);
    expect(got.success).toBe(true);
    expect(JSON.stringify(got.data)).toContain('a fresh template');
  });

  test('GetTemplate', async ({ adminPage, sdk }) => {
    const id = await newTemplate(sdk);
    if (id === undefined) return templatesPageOnly(adminPage);
    const got = must(await sdk.vtpm.getTemplate(id), 'vtpm.getTemplate') as unknown as Record<string, unknown>;
    const tmpl = (got.template ?? got) as Record<string, unknown>;
    const stateDir = tmpl.tpmStateDir ?? tmpl.tpm_state_dir;
    const nvram = tmpl.nvramPath ?? tmpl.nvram_path;

    const seen = await openTemplates(adminPage, id);
    await templateRow(adminPage, id).getByRole('button', { name: 'Details' }).click();
    const details = adminPage.getByTestId('vtpm-template-details');
    await expect(details).toContainText(id);
    if (typeof stateDir === 'string' && stateDir) await expect(details).toContainText(stateDir);
    if (typeof nvram === 'string' && nvram) await expect(details).toContainText(nvram);
    expect(count(seen, 'GET', `/api/v1/vtpm/templates/${id}`)).toBe(1);
  });

  test('CloneTemplate', async ({ adminPage, sdk }) => {
    const id = await newTemplate(sdk);
    if (id === undefined) return templatesPageOnly(adminPage);
    await openTemplates(adminPage, id);
    const hostname = unique('web');

    await templateRow(adminPage, id).getByRole('button', { name: 'Clone', exact: true }).click();
    await adminPage.locator('#vt-clone-hostname').fill(hostname);
    const post = adminPage.waitForResponse(
      (r) => new URL(r.url()).pathname === `/api/v1/vtpm/templates/${id}/clone` && r.request().method() === 'POST',
    );
    await adminPage.getByRole('button', { name: 'Clone to bundle' }).click();
    const reply = await post;
    expect(reply.request().postDataJSON()).toMatchObject({ hostname });
    expect(reply.ok()).toBe(true);
    const body = (await reply.json()) as { payload?: unknown } & Record<string, unknown>;
    const payload = (body.payload ?? body) as { id?: string; bundle?: { id?: string } };
    const bundleId = payload.bundle?.id ?? payload.id;
    expect(typeof bundleId).toBe('string');
    createdBundles.push(bundleId as string);

    const result = adminPage.getByTestId('vtpm-clone-result');
    await expect(result).toContainText(bundleId as string);
    await expect(result.getByRole('link', { name: bundleId as string })).toHaveAttribute(
      'href',
      new RegExp(`/devices/vtpm/bundles/${bundleId}/?$`),
    );
    expect((await sdk.vtpm.getBundle(bundleId as string)).success).toBe(true);
  });

  test('DeleteTemplate', async ({ adminPage, sdk }) => {
    const keep = await newTemplate(sdk);
    if (keep === undefined) return templatesPageOnly(adminPage);
    const id = await newTemplate(sdk);
    if (id === undefined) return templatesPageOnly(adminPage);
    const seen = await openTemplates(adminPage, id);

    await templateRow(adminPage, id).getByRole('button', { name: 'Delete' }).click();
    await expect(adminPage.getByRole('button', { name: 'Confirm' })).toBeVisible();
    expect(count(seen, 'DELETE', `/api/v1/vtpm/templates/${id}`)).toBe(0);

    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByTestId('vtpm-template-list')).not.toContainText(id);
    expect(count(seen, 'DELETE', `/api/v1/vtpm/templates/${id}`)).toBe(1);
    await expect(adminPage.getByTestId('vtpm-template-list')).toContainText(keep);
    expect((await sdk.vtpm.getTemplate(id)).success).toBe(false);
  });

  test('ImportBundle sends the archive raw; the server refuses a non-archive', async ({
    adminPage,
    sdk,
  }) => {
    await adminPage.goto('/devices/vtpm/bundles/');
    await expect(adminPage.getByTestId('vtpm-bundle-list')).toBeVisible();

    // A gzip header with no tar inside: the server cannot import it.
    const archive = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04]);
    await adminPage.locator('#vb-import-file').setInputFiles({
      name: 'bundle.tar.gz',
      mimeType: 'application/gzip',
      buffer: archive,
    });
    const post = adminPage.waitForResponse(
      (r) => new URL(r.url()).pathname === '/api/v1/vtpm/bundles/import' && r.request().method() === 'POST',
    );
    await adminPage.getByRole('button', { name: 'Import bundle' }).click();
    const reply = await post;
    expect(reply.request().postDataBuffer()?.equals(archive)).toBe(true);
    expect(reply.ok()).toBe(false);
    await expect(adminPage.getByTestId('vtpm-import-result')).toHaveCount(0);
  });

  test('GetBundle', async ({ adminPage, sdk }) => {
    const hostname = unique('host');
    const id = await newBundle(sdk, hostname);
    if (id === undefined) return bundlesPageOnly(adminPage);
    expect((await sdk.vtpm.getBundle(id)).success).toBe(true);

    const seen = await openBundle(adminPage, id);
    await expect(adminPage.getByTestId('vtpm-bundle-detail')).toContainText(hostname);
    expect(count(seen, 'GET', `/api/v1/vtpm/bundles/${id}`)).toBeGreaterThanOrEqual(1);
  });

  test('GetBundle switches ID', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    if (id === undefined) return bundlesPageOnly(adminPage);
    const missing = unique('bundle-missing');
    expect((await sdk.vtpm.getBundle(missing)).success).toBe(false);

    await openBundle(adminPage, id);
    await expect(adminPage.getByRole('heading', { name: `vTPM bundle ${id}` })).toBeVisible();
    await adminPage.evaluate(
      (target) => window.history.pushState(null, '', target),
      `/devices/vtpm/bundles/${missing}/`,
    );
    await expect(adminPage.getByText(`Bundle ${missing} could not be loaded.`)).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: `vTPM bundle ${id}` })).toHaveCount(0);
    await expect(adminPage.getByTestId('vtpm-bundle-detail')).toHaveCount(0);
  });

  test('BundleList pages by offset', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    if (id === undefined) return bundlesPageOnly(adminPage);
    const seen = recordVTPM(adminPage);
    await adminPage.goto('/devices/vtpm/bundles/');
    await expect(adminPage.getByTestId('vtpm-bundle-range')).toHaveText(/^Bundles 1-\d+$/);
    const first = seen.find((r) => r.method() === 'GET' && new URL(r.url()).pathname === '/api/v1/vtpm/bundles');
    expect(first?.url() ?? '').not.toContain('page=');

    const next = adminPage.getByRole('button', { name: 'Next' });
    if (await next.isDisabled()) {
      // One page only: the new bundle is on it.
      await expect(adminPage.getByTestId('vtpm-bundle-list')).toContainText(id);
      return;
    }
    await next.click();
    await expect(adminPage.getByTestId('vtpm-bundle-range')).toHaveText(/^Bundles 101-\d+$/);
    const lastList = seen
      .filter((r) => r.method() === 'GET' && new URL(r.url()).pathname === '/api/v1/vtpm/bundles')
      .pop();
    expect(new URL(lastList?.url() ?? 'http://x/').searchParams.get('offset')).toBe('100');
    expect(lastList?.url() ?? '').not.toContain('page=');
  });

  test('ValidateBundle', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    if (id === undefined) return bundlesPageOnly(adminPage);
    const verdict = must(await sdk.vtpm.validateBundle(id), 'vtpm.validateBundle') as {
      valid?: boolean;
      errors?: string[];
    };

    const seen = await openBundle(adminPage, id);
    await adminPage.getByRole('button', { name: 'Validate bundle' }).click();
    const result = adminPage.getByTestId('vtpm-validate-result');
    if (verdict.valid) {
      await expect(result).toContainText(/^\s*Valid/);
    } else {
      await expect(result).toContainText('Invalid');
      for (const e of verdict.errors ?? []) await expect(result).toContainText(e);
    }
    expect(count(seen, 'POST', `/api/v1/vtpm/bundles/${id}/validate`)).toBe(1);
  });

  test('GetBundlePath', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    if (id === undefined) return bundlesPageOnly(adminPage);
    const path = pathIn(must(await sdk.vtpm.getBundlePath(id), 'vtpm.getBundlePath'));
    expect(path).toBeTruthy();

    const seen = await openBundle(adminPage, id);
    await adminPage.getByRole('button', { name: 'Get bundle path' }).click();
    await expect(adminPage.getByTestId('vtpm-bundle-path')).toContainText(path as string);
    expect(count(seen, 'GET', `/api/v1/vtpm/bundles/${id}/path`)).toBe(1);
  });

  test('GetTPMSocketPath', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    if (id === undefined) return bundlesPageOnly(adminPage);
    const res = await sdk.vtpm.getTPMSocketPath(id);

    const seen = await openBundle(adminPage, id);
    await adminPage.getByRole('button', { name: 'Get TPM socket path' }).click();
    const shown = adminPage.getByTestId('vtpm-socket-path');
    const path = res.success ? pathIn(res.data) : undefined;
    if (path) {
      await expect(shown).toContainText(path);
    }
    expect(count(seen, 'GET', `/api/v1/vtpm/bundles/${id}/tpm-socket`)).toBe(1);
  });

  test('GetNVRAMPath', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    if (id === undefined) return bundlesPageOnly(adminPage);
    const path = pathIn(must(await sdk.vtpm.getNVRAMPath(id), 'vtpm.getNVRAMPath'));
    expect(path).toBeTruthy();

    const seen = await openBundle(adminPage, id);
    await adminPage.getByRole('button', { name: 'Get NVRAM path' }).click();
    await expect(adminPage.getByTestId('vtpm-nvram-path')).toContainText(path as string);
    expect(count(seen, 'GET', `/api/v1/vtpm/bundles/${id}/nvram`)).toBe(1);
  });

  // #2071: the /devices/vtpm/[id] page seals through the bundle seal route.
  test('Seal on the bundle page returns a sealed blob', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    if (id === undefined) return bundlesPageOnly(adminPage);
    must(await sdk.vtpm.startBundle(id), 'vtpm.startBundle');
    try {
      const seen = await openBundlePage(adminPage, id);
      await adminPage.getByRole('button', { name: 'Seal Data' }).first().click();
      const dialog = adminPage.getByRole('dialog');
      await dialog.getByLabel('Name').fill('e2e-sealed');
      await dialog.getByLabel('Data to Seal').fill('hello');
      await dialog.getByRole('button', { name: 'Seal Data' }).click();
      await expect(adminPage.getByTestId('vtpm-sealed-blob')).not.toBeEmpty();
      expect(count(seen, 'POST', `/api/v1/vtpm/bundles/${id}/seal`)).toBe(1);
    } finally {
      await sdk.vtpm.stopBundle(id);
    }
  });

  // #2071: Delete on the bundle page removes the bundle after the confirm.
  test('Delete on the bundle page removes the bundle', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    if (id === undefined) return bundlesPageOnly(adminPage);
    await openBundlePage(adminPage, id);
    adminPage.once('dialog', (d) => d.accept());
    await adminPage.getByRole('button', { name: 'Delete' }).click();
    await expect(adminPage).toHaveURL(/\/devices\/vtpm\/?$/);
    const res = await sdk.vtpm.getBundle(id);
    expect(res.success).toBe(false);
  });

  test('gated vTPM controls carry the server capability answer', async ({ adminPage, sdk }) => {
    const caps = await offered(sdk);
    const id = await newBundle(sdk);

    await templatesPageOnly(adminPage);
    await expectGatedMatches(adminPage, caps);

    await bundlesPageOnly(adminPage);
    await expectGatedMatches(adminPage, caps);

    if (id === undefined) {
      gap('no bundle: bundle detail gating not checked');
      return;
    }
    await openBundle(adminPage, id);
    await expectGatedMatches(adminPage, caps);
  });
});

/** openBundlePage opens /devices/vtpm/[id] for a bundle (static export: placeholder, then pushState). */
async function openBundlePage(page: Page, id: string): Promise<Request[]> {
  const seen = recordVTPM(page);
  await page.goto('/devices/vtpm/__placeholder__/');
  await page.getByText('vTPM not found').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate((target) => window.history.pushState(null, '', target), `/devices/vtpm/${id}/`);
  await expect(page.getByText('vTPM Information')).toBeVisible();
  return seen;
}
