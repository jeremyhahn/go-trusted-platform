import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi } from './fixtures/api-mock';

/**
 * vTPM templates, bundles and bundle detail (#1674, UI epic #1665 slice 34).
 *
 * The API is mocked at the route layer with the flat snake_case payloads
 * the server emits (pkg/webservice/v1/rest/vtpm), wrapped in the platform
 * envelope. Every request is recorded so each test asserts both what the UI
 * sent and what it shows.
 */

interface RecordedRequest {
  method: string;
  path: string;
  body: unknown;
  raw: Buffer | null;
}

interface TemplateWire {
  id: string;
  description?: string;
  tpm_state_dir: string;
  nvram_path: string;
  secure_boot_keys_dir?: string;
  ek_algorithm: string;
  secure_boot_enabled: boolean;
  created_at?: string;
}

interface VTPMMock {
  requests: RecordedRequest[];
  /** Answers for successive POST .../validate calls, in order */
  validateAnswers: Array<{ valid: boolean; errors?: string[] }>;
}

function template(id: string, ek: string, secureBoot: boolean): TemplateWire {
  return {
    id,
    description: `${id} description`,
    tpm_state_dir: `/var/lib/vtpm/templates/${id}/tpm`,
    nvram_path: `/var/lib/vtpm/templates/${id}/OVMF_VARS.fd`,
    ek_algorithm: ek,
    secure_boot_enabled: secureBoot,
    created_at: '2026-11-01T10:00:00Z',
  };
}

function bundle(id: string, hostname: string) {
  return {
    id,
    mode: 'TEMPLATE',
    manifest: {
      version: '1',
      id,
      mode: 'TEMPLATE',
      hostname,
      created_at: '2026-11-02T10:00:00Z',
      ek_algorithm: 'RSA',
      ek_handle: 0x81010001,
      secure_boot_enabled: true,
      cloned_from: 'tmpl-a',
    },
    tpm_state: { state_dir: `/var/lib/vtpm/bundles/${id}/tpm`, permall_file: 'tpm2-00.permall' },
    ovmf_state: { nvram_file: 'OVMF_VARS.fd' },
    created_at: '2026-11-02T10:00:00Z',
    cloned_from: 'tmpl-a',
  };
}

function ok(payload: unknown): string {
  return JSON.stringify({ code: 200, success: true, payload });
}

async function mockVTPM(page: Page): Promise<VTPMMock> {
  const templates: TemplateWire[] = [template('tmpl-a', 'RSA', true), template('tmpl-b', 'ECC', false)];
  const bundles = [bundle('bundle-1', 'host-one')];
  const mock: VTPMMock = { requests: [], validateAnswers: [] };

  await mockTenantApi(page);

  await page.route('**/api/v1/vtpm/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const path = new URL(request.url()).pathname.replace(/\/+$/, '');
    let body: unknown = null;
    let raw: Buffer | null = null;
    if (method === 'POST') {
      raw = request.postDataBuffer();
      if (!path.endsWith('/bundles/import')) {
        try {
          body = request.postDataJSON();
        } catch {
          body = null;
        }
      }
    }
    mock.requests.push({ method, path, body, raw });

    const fulfill = (payload: unknown) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: ok(payload) });
    const rest = path.slice(path.indexOf('/api/v1/vtpm') + '/api/v1/vtpm'.length);
    const parts = rest.split('/').filter(Boolean).map(decodeURIComponent);

    if (parts[0] === 'templates') {
      if (parts.length === 1 && method === 'GET') return fulfill({ templates });
      if (parts.length === 1 && method === 'POST') {
        const sent = JSON.stringify(body);
        const id = (sent.match(/"id":"([^"]+)"/) ?? [])[1] ?? 'unknown';
        const created = template(id, 'RSA', false);
        templates.push(created);
        return fulfill(created);
      }
      const found = templates.find((t) => t.id === parts[1]);
      if (parts.length === 2 && method === 'GET' && found) return fulfill(found);
      if (parts.length === 2 && method === 'DELETE') {
        const at = templates.findIndex((t) => t.id === parts[1]);
        if (at >= 0) templates.splice(at, 1);
        return fulfill({ success: true, message: 'template deleted' });
      }
      if (parts[2] === 'clone' && method === 'POST') {
        const hostname = (body as { hostname?: string })?.hostname ?? '';
        return fulfill(bundle('bundle-cloned-7', hostname));
      }
    }

    if (parts[0] === 'bundles') {
      if (parts.length === 1 && method === 'GET') return fulfill({ bundles, total: bundles.length });
      if (parts[1] === 'import' && method === 'POST') {
        const imported = bundle('bundle-imported-9', 'host-imported');
        bundles.push(imported);
        return fulfill(imported);
      }
      const id = parts[1];
      if (parts.length === 2 && method === 'GET') return fulfill(bundle(id, 'host-one'));
      if (parts[2] === 'validate' && method === 'POST') {
        return fulfill(mock.validateAnswers.shift() ?? { valid: true });
      }
      if (parts[2] === 'path') return fulfill({ path: `/var/lib/vtpm/bundles/${id}` });
      if (parts[2] === 'tpm-socket') return fulfill({ path: `/run/vtpm/${id}/swtpm.sock` });
      if (parts[2] === 'nvram') return fulfill({ path: `/var/lib/vtpm/bundles/${id}/OVMF_VARS.fd` });
    }

    await route.fulfill({
      status: 404,
      contentType: 'application/json',
      body: JSON.stringify({ code: 404, success: false, error: 'not found', payload: null }),
    });
  });

  return mock;
}

function count(mock: VTPMMock, method: string, suffix: string): number {
  return mock.requests.filter((r) => r.method === method && r.path.endsWith(suffix)).length;
}

function last(mock: VTPMMock, method: string, suffix: string): RecordedRequest | undefined {
  return [...mock.requests].reverse().find((r) => r.method === method && r.path.endsWith(suffix));
}

async function openTemplates(page: Page): Promise<VTPMMock> {
  const mock = await mockVTPM(page);
  await page.goto('/devices/vtpm/templates/');
  await expect(page.getByTestId('vtpm-template-list')).toContainText('tmpl-a');
  return mock;
}

function templateRow(page: Page, id: string) {
  return page.getByTestId('vtpm-template-list').getByRole('row').filter({ hasText: id });
}

async function openBundle(page: Page, id: string): Promise<VTPMMock> {
  const mock = await mockVTPM(page);
  await page.goto('/devices/vtpm/bundles/__placeholder__/');
  // pushState is only router-integrated once the app has hydrated.
  await page.getByText('Loading bundle').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate((target) => window.history.pushState(null, '', target), `/devices/vtpm/bundles/${id}/`);
  await expect(page.getByTestId('vtpm-bundle-detail')).toBeVisible();
  return mock;
}

test.describe('vTPM bundles and templates', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('ListTemplates', async ({ page }) => {
    const mock = await openTemplates(page);
    expect(count(mock, 'GET', '/api/v1/vtpm/templates')).toBeGreaterThanOrEqual(1);
    const list = page.getByTestId('vtpm-template-list');
    await expect(list).toContainText('tmpl-a');
    await expect(list).toContainText('tmpl-b');
    await expect(list).toContainText('ECC');
  });

  test('CreateTemplate', async ({ page }) => {
    const mock = await openTemplates(page);
    const listsBefore = count(mock, 'GET', '/api/v1/vtpm/templates');

    await page.getByRole('button', { name: 'New template' }).click();
    await page.locator('#vt-id').fill('tmpl-new');
    await page.locator('#vt-description').fill('a fresh template');
    await page.locator('#vt-ek-algorithm').selectOption('ECC');
    await page.locator('#vt-secure-boot').check();
    await page.getByRole('button', { name: 'Create template' }).click();

    await expect(page.getByTestId('vtpm-template-list')).toContainText('tmpl-new');
    const create = last(mock, 'POST', '/api/v1/vtpm/templates');
    expect(create).toBeDefined();
    // The body's shape changes with #1590; only its values are asserted here.
    const sent = JSON.stringify(create?.body);
    expect(sent).toContain('tmpl-new');
    expect(sent).toContain('a fresh template');
    expect(count(mock, 'GET', '/api/v1/vtpm/templates')).toBeGreaterThan(listsBefore);
  });

  test('GetTemplate', async ({ page }) => {
    const mock = await openTemplates(page);
    await templateRow(page, 'tmpl-a').getByRole('button', { name: 'Details' }).click();

    const details = page.getByTestId('vtpm-template-details');
    await expect(details).toContainText('/var/lib/vtpm/templates/tmpl-a/tpm');
    await expect(details).toContainText('/var/lib/vtpm/templates/tmpl-a/OVMF_VARS.fd');
    expect(count(mock, 'GET', '/api/v1/vtpm/templates/tmpl-a')).toBe(1);
  });

  test('CloneTemplate', async ({ page }) => {
    const mock = await openTemplates(page);
    await templateRow(page, 'tmpl-a').getByRole('button', { name: 'Clone', exact: true }).click();
    await page.locator('#vt-clone-hostname').fill('web-07');
    await page.getByRole('button', { name: 'Clone to bundle' }).click();

    const result = page.getByTestId('vtpm-clone-result');
    await expect(result).toContainText('bundle-cloned-7');
    await expect(result.getByRole('link', { name: 'bundle-cloned-7' })).toHaveAttribute(
      'href',
      /\/devices\/vtpm\/bundles\/bundle-cloned-7\/?$/
    );
    const clone = last(mock, 'POST', '/api/v1/vtpm/templates/tmpl-a/clone');
    expect(clone?.body).toEqual({ hostname: 'web-07' });
  });

  test('DeleteTemplate', async ({ page }) => {
    const mock = await openTemplates(page);
    await templateRow(page, 'tmpl-b').getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByRole('button', { name: 'Confirm' })).toBeVisible();
    expect(count(mock, 'DELETE', '/api/v1/vtpm/templates/tmpl-b')).toBe(0);

    await page.getByRole('button', { name: 'Confirm' }).click();
    await expect(page.getByTestId('vtpm-template-list')).not.toContainText('tmpl-b');
    expect(count(mock, 'DELETE', '/api/v1/vtpm/templates/tmpl-b')).toBe(1);
    await expect(page.getByTestId('vtpm-template-list')).toContainText('tmpl-a');
  });

  test('ImportBundle', async ({ page }) => {
    const mock = await mockVTPM(page);
    await page.goto('/devices/vtpm/bundles/');
    await expect(page.getByTestId('vtpm-bundle-list')).toContainText('bundle-1');

    const archive = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04]);
    await page.locator('#vb-import-file').setInputFiles({
      name: 'bundle.tar.gz',
      mimeType: 'application/gzip',
      buffer: archive,
    });
    await page.getByRole('button', { name: 'Import bundle' }).click();

    await expect(page.getByTestId('vtpm-import-result')).toContainText('bundle-imported-9');
    const imported = last(mock, 'POST', '/api/v1/vtpm/bundles/import');
    expect(imported?.raw?.equals(archive)).toBe(true);
    await expect(page.getByTestId('vtpm-bundle-list')).toContainText('bundle-imported-9');
  });

  test('GetBundle', async ({ page }) => {
    const mock = await openBundle(page, 'bundle-1');
    await expect(page.getByTestId('vtpm-bundle-detail')).toContainText('host-one');
    await expect(page.getByTestId('vtpm-bundle-detail')).toContainText('RSA');
    expect(count(mock, 'GET', '/api/v1/vtpm/bundles/bundle-1')).toBeGreaterThanOrEqual(1);
  });

  test('ValidateBundle', async ({ page }) => {
    const mock = await openBundle(page, 'bundle-1');
    mock.validateAnswers.push({ valid: true }, { valid: false, errors: ['checksum mismatch'] });

    await page.getByRole('button', { name: 'Validate bundle' }).click();
    const result = page.getByTestId('vtpm-validate-result');
    await expect(result).toContainText(/^\s*Valid/);

    await page.getByRole('button', { name: 'Validate bundle' }).click();
    await expect(result).toContainText('Invalid');
    await expect(result).toContainText('checksum mismatch');
    expect(count(mock, 'POST', '/api/v1/vtpm/bundles/bundle-1/validate')).toBe(2);
  });

  test('GetBundlePath', async ({ page }) => {
    const mock = await openBundle(page, 'bundle-1');
    await page.getByRole('button', { name: 'Get bundle path' }).click();
    await expect(page.getByTestId('vtpm-bundle-path')).toContainText('/var/lib/vtpm/bundles/bundle-1');
    expect(count(mock, 'GET', '/api/v1/vtpm/bundles/bundle-1/path')).toBe(1);
  });

  test('GetTPMSocketPath', async ({ page }) => {
    const mock = await openBundle(page, 'bundle-1');
    await page.getByRole('button', { name: 'Get TPM socket path' }).click();
    await expect(page.getByTestId('vtpm-socket-path')).toContainText('/run/vtpm/bundle-1/swtpm.sock');
    expect(count(mock, 'GET', '/api/v1/vtpm/bundles/bundle-1/tpm-socket')).toBe(1);
  });

  test('GetNVRAMPath', async ({ page }) => {
    const mock = await openBundle(page, 'bundle-1');
    await page.getByRole('button', { name: 'Get NVRAM path' }).click();
    await expect(page.getByTestId('vtpm-nvram-path')).toContainText(
      '/var/lib/vtpm/bundles/bundle-1/OVMF_VARS.fd'
    );
    expect(count(mock, 'GET', '/api/v1/vtpm/bundles/bundle-1/nvram')).toBe(1);
  });
});
