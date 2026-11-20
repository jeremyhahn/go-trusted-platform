/**
 * Real-server spec for the vTPM bundle and template operations (#2071, epic #1665).
 *
 * Covers VTPMService ListTemplates, CreateTemplate, GetTemplate, CloneTemplate,
 * DeleteTemplate, ImportBundle, GetBundle, ValidateBundle, GetBundlePath,
 * GetTPMSocketPath and GetNVRAMPath through the dashboard pages under
 * /devices/vtpm/templates and /devices/vtpm/bundles. State is seeded through the
 * SDK client against the harness server, never through route mocks, and every
 * assertion compares the page with what the server returns.
 */
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

type Wire<T> = { success: boolean; data?: T; error?: { message?: string } };

interface TemplateWire {
  id: string;
  description?: string;
}

interface BundleWire {
  id: string;
  manifest?: { hostname?: string };
}

interface PathWire {
  path: string;
}

function data<T>(response: unknown): T {
  const r = response as Wire<T>;
  expect(r.success, r.error?.message ?? 'SDK call failed').toBe(true);
  return r.data as T;
}

function uniqueId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

test.describe('vTPM templates', () => {
  test('lists the templates the server returns', async ({ adminPage, sdk }) => {
    const id = uniqueId('e2e-tpl-list');
    data<TemplateWire>(
      await sdk.vtpm.createTemplate({ options: { id, description: 'seeded by spec' } })
    );

    await adminPage.goto('/devices/vtpm/templates');
    await expect(adminPage.getByRole('heading', { name: 'vTPM Templates' })).toBeVisible();

    const listed = data<{ templates?: TemplateWire[] }>(await sdk.vtpm.listTemplates());
    const list = adminPage.getByTestId('vtpm-template-list');
    for (const t of listed.templates ?? []) {
      await expect(list).toContainText(t.id);
    }
    await expect(list).toContainText(id);

    await sdk.vtpm.deleteTemplate(id);
  });

  test('creates a template from the form and the server stores it', async ({ adminPage, sdk }) => {
    const id = uniqueId('e2e-tpl-create');
    await adminPage.goto('/devices/vtpm/templates');

    await adminPage.getByLabel('ID').fill(id);
    await adminPage.getByLabel('Description').fill('created in the browser');
    await adminPage.getByRole('button', { name: 'Create template' }).click();

    await expect(adminPage.getByTestId('vtpm-template-list')).toContainText(id);
    const stored = data<TemplateWire>(await sdk.vtpm.getTemplate(id));
    expect(stored.id).toBe(id);
    expect(stored.description).toBe('created in the browser');

    await sdk.vtpm.deleteTemplate(id);
  });

  test('shows the details the server returns for a template', async ({ adminPage, sdk }) => {
    const id = uniqueId('e2e-tpl-get');
    data<TemplateWire>(
      await sdk.vtpm.createTemplate({ options: { id, description: 'details view' } })
    );
    const stored = data<TemplateWire>(await sdk.vtpm.getTemplate(id));

    await adminPage.goto('/devices/vtpm/templates');
    const row = adminPage.getByTestId('vtpm-template-list').getByRole('row').filter({ hasText: id });
    await row.getByRole('button', { name: 'Details' }).click();

    const details = adminPage.getByTestId('vtpm-template-details');
    await expect(details).toContainText(stored.id);
    await expect(details).toContainText(stored.description ?? '');

    await sdk.vtpm.deleteTemplate(id);
  });

  test('clones a template into a bundle the server lists', async ({ adminPage, sdk }) => {
    const id = uniqueId('e2e-tpl-clone');
    const hostname = uniqueId('e2e-host');
    data<TemplateWire>(await sdk.vtpm.createTemplate({ options: { id } }));

    await adminPage.goto('/devices/vtpm/templates');
    const row = adminPage.getByTestId('vtpm-template-list').getByRole('row').filter({ hasText: id });
    await row.getByRole('button', { name: 'Clone' }).click();
    await adminPage.getByLabel('Hostname').fill(hostname);
    await adminPage.getByRole('button', { name: 'Clone to bundle' }).click();

    const result = adminPage.getByTestId('vtpm-clone-result');
    await expect(result).toBeVisible();

    const bundles = data<{ bundles?: BundleWire[] }>(
      await sdk.vtpm.listBundles({ options: { limit: 500, offset: 0 } })
    );
    const cloned = (bundles.bundles ?? []).find((b) => b.manifest?.hostname === hostname);
    expect(cloned, 'server lists the cloned bundle').toBeTruthy();
    await expect(result).toContainText(cloned!.id);

    await sdk.vtpm.deleteBundle(cloned!.id);
    await sdk.vtpm.deleteTemplate(id);
  });

  test('deletes a template after confirmation and the server forgets it', async ({ adminPage, sdk }) => {
    const id = uniqueId('e2e-tpl-delete');
    data<TemplateWire>(await sdk.vtpm.createTemplate({ options: { id } }));

    await adminPage.goto('/devices/vtpm/templates');
    const list = adminPage.getByTestId('vtpm-template-list');
    await list.getByRole('row').filter({ hasText: id }).getByRole('button', { name: 'Delete' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText(`Delete template ${id}?`);
    await dialog.getByRole('button', { name: 'Delete' }).click();

    await expect(list).not.toContainText(id);
    const after = (await sdk.vtpm.getTemplate(id)) as Wire<TemplateWire>;
    expect(after.success).toBe(false);
  });
});

test.describe('vTPM bundles', () => {
  async function seedBundle(sdk: PlatformClient) {
    const templateId = uniqueId('e2e-tpl-bundle');
    const hostname = uniqueId('e2e-bundle-host');
    data<TemplateWire>(await sdk.vtpm.createTemplate({ options: { id: templateId } }));
    const bundle = data<BundleWire>(
      await sdk.vtpm.cloneTemplate({ options: { templateId, hostname } })
    );
    return { templateId, bundle };
  }

  test('lists bundles and opens the detail the server returns', async ({ adminPage, sdk }) => {
    const { templateId, bundle } = await seedBundle(sdk);
    const stored = data<BundleWire>(await sdk.vtpm.getBundle(bundle.id));

    await adminPage.goto('/devices/vtpm/bundles');
    await expect(adminPage.getByRole('heading', { name: 'vTPM Bundles' })).toBeVisible();
    const list = adminPage.getByTestId('vtpm-bundle-list');
    await expect(list).toContainText(bundle.id);
    await list.getByRole('link', { name: bundle.id }).click();

    await expect(adminPage.getByRole('heading', { name: `vTPM bundle ${stored.id}` })).toBeVisible();
    await expect(adminPage.getByTestId('vtpm-bundle-detail')).toContainText(stored.id);

    await sdk.vtpm.deleteBundle(bundle.id);
    await sdk.vtpm.deleteTemplate(templateId);
  });

  test('validates a bundle and shows the server result', async ({ adminPage, sdk }) => {
    const { templateId, bundle } = await seedBundle(sdk);
    const expected = (await sdk.vtpm.validateBundle(bundle.id)) as Wire<{ valid?: boolean }>;

    await adminPage.goto(`/devices/vtpm/bundles/${encodeURIComponent(bundle.id)}`);
    await adminPage.getByRole('button', { name: 'Validate bundle' }).click();

    if (expected.success) {
      await expect(adminPage.getByTestId('vtpm-validate-result')).toBeVisible();
      await expect(adminPage.getByTestId('vtpm-validate-result')).toContainText(
        expected.data?.valid ? /^Valid$/ : /^Invalid/
      );
    } else {
      await expect(adminPage.getByTestId('vtpm-validate-error')).toBeVisible();
    }

    await sdk.vtpm.deleteBundle(bundle.id);
    await sdk.vtpm.deleteTemplate(templateId);
  });

  test('shows the bundle, TPM socket and NVRAM paths the server returns', async ({ adminPage, sdk }) => {
    const { templateId, bundle } = await seedBundle(sdk);
    const bundlePath = data<PathWire>(await sdk.vtpm.getBundlePath(bundle.id));
    const socketPath = data<PathWire>(await sdk.vtpm.getTPMSocketPath(bundle.id));
    const nvramPath = data<PathWire>(await sdk.vtpm.getNVRAMPath(bundle.id));

    await adminPage.goto(`/devices/vtpm/bundles/${encodeURIComponent(bundle.id)}`);
    await adminPage.getByRole('button', { name: 'Get bundle path' }).click();
    await expect(adminPage.getByTestId('vtpm-bundle-path')).toHaveText(bundlePath.path);
    await adminPage.getByRole('button', { name: 'Get TPM socket path' }).click();
    await expect(adminPage.getByTestId('vtpm-socket-path')).toHaveText(socketPath.path);
    await adminPage.getByRole('button', { name: 'Get NVRAM path' }).click();
    await expect(adminPage.getByTestId('vtpm-nvram-path')).toHaveText(nvramPath.path);

    await sdk.vtpm.deleteBundle(bundle.id);
    await sdk.vtpm.deleteTemplate(templateId);
  });

  test('imports a bundle archive and the server lists it', async ({ adminPage, sdk }) => {
    const { templateId, bundle } = await seedBundle(sdk);
    // ExportBundle is streaming plumbing with no SDK method (coverage matrix:
    // not-UI); fetch the archive from the real REST route with the admin session.
    const exported = await adminPage.request.get(
      `/api/v1/vtpm/bundles/${encodeURIComponent(bundle.id)}/export`
    );
    expect(exported.ok(), `export ${exported.status()}`).toBe(true);
    const archive = await exported.body();
    await sdk.vtpm.deleteBundle(bundle.id);

    await adminPage.goto('/devices/vtpm/bundles');
    await adminPage.getByLabel('Archive').setInputFiles({
      name: `${bundle.id}.tar.gz`,
      mimeType: 'application/gzip',
      buffer: archive,
    });
    await adminPage.getByRole('button', { name: 'Import bundle' }).click();

    const result = adminPage.getByTestId('vtpm-import-result');
    await expect(result).toBeVisible();
    const listed = data<{ bundles?: BundleWire[] }>(
      await sdk.vtpm.listBundles({ options: { limit: 500, offset: 0 } })
    );
    const imported = (listed.bundles ?? []).find((b) => b.id === bundle.id);
    expect(imported, 'server lists the imported bundle').toBeTruthy();
    await expect(result).toContainText(imported!.id);

    await sdk.vtpm.deleteBundle(bundle.id);
    await sdk.vtpm.deleteTemplate(templateId);
  });
});
