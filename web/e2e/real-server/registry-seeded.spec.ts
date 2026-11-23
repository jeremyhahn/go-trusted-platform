/**
 * The registry page against the real platformd: #2063 RegistryService List,
 * Inspect and Delete with a real tag, and the two OCI capability gates
 * (List tags on GET /v2/{name:.+}/tags/list, Delete on
 * DELETE /v2/{name:.+}/manifests/{reference}). The image is pushed through
 * /v2 by fixtures/registry-seed.ts, because the SDK has no push; no page.route
 * mocks, every answer comes from the server.
 */
import type { Page, Response } from '@playwright/test';

import { expect, requestFetch, test } from './fixtures';
import { pushTestImage } from './fixtures/registry-seed';
import { unwrapPayload } from './fixtures/wire';

/** Pushes two tags with distinct labels (so distinct manifest digests) to a fresh repository. */
async function seed(adminPage: Page, baseURL: string | undefined): Promise<string> {
  const name = `e2e/reg-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const fetchFn = requestFetch(adminPage.context().request);
  await pushTestImage(fetchFn, baseURL!, name, 'v1', `${name}-v1`);
  await pushTestImage(fetchFn, baseURL!, name, 'v2', `${name}-v2`);
  return name;
}

/** The tags the server holds for name, read through /v2 (empty for an unknown repository). */
async function serverTags(adminPage: Page, baseURL: string | undefined, name: string): Promise<string[]> {
  const res = await requestFetch(adminPage.context().request)(new URL(`/v2/${name}/tags/list`, baseURL).href);
  if (res.status === 404) return [];
  expect(res.ok, `GET /v2/${name}/tags/list answered ${res.status}`).toBe(true);
  const body = (await res.json()) as { tags?: string[] | null };
  return body.tags ?? [];
}

/** Opens the registry page and lists the tags of name, returning the page's own tags/list response. */
async function listTags(page: Page, name: string): Promise<Response> {
  await page.goto('/compute/registry');
  await expect(page.getByTestId('registry-status')).toBeVisible();
  await page.getByRole('textbox', { name: 'Repository' }).fill(name);
  const listed = page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === `/v2/${name}/tags/list`,
  );
  await page.getByRole('button', { name: /list tags/i }).click();
  return listed;
}

test.describe('Registry with a seeded image', () => {
  test('lists the tags the server holds for a pushed repository', async ({ adminPage, baseURL }) => {
    const name = await seed(adminPage, baseURL);
    const res = await listTags(adminPage, name);
    expect(res.ok()).toBe(true);

    await expect(adminPage.getByRole('cell', { name: 'v1', exact: true })).toBeVisible();
    await expect(adminPage.getByRole('cell', { name: 'v2', exact: true })).toBeVisible();
    expect((await serverTags(adminPage, baseURL, name)).sort()).toEqual(['v1', 'v2']);
  });

  test('deletes a tag only after the confirm and the server drops it', async ({ adminPage, baseURL }) => {
    const name = await seed(adminPage, baseURL);
    await listTags(adminPage, name);

    await adminPage.getByRole('button', { name: 'Delete v1' }).click();
    const dialog = adminPage.getByRole('dialog', { name: 'Delete manifest' });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText(`${name}:v1`);
    expect(await serverTags(adminPage, baseURL, name)).toContain('v1');

    const deleted = adminPage.waitForResponse(
      (r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname === `/v2/${name}/manifests/v1`,
    );
    await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
    const res = await deleted;
    expect(res.ok()).toBe(true);
    expect(res.status()).toBe(202);

    await expect(adminPage.getByRole('cell', { name: 'v1', exact: true })).toHaveCount(0);
    await expect(adminPage.getByRole('cell', { name: 'v2', exact: true })).toBeVisible();
    const tags = await serverTags(adminPage, baseURL, name);
    expect(tags).not.toContain('v1');
    expect(tags).toContain('v2');
    await expect(adminPage.getByText('Manifest deleted')).toBeVisible();
  });

  test('cancel keeps the tag', async ({ adminPage, baseURL }) => {
    const name = await seed(adminPage, baseURL);
    await listTags(adminPage, name);

    const deletes: string[] = [];
    adminPage.on('request', (req) => {
      if (req.method() === 'DELETE' && req.url().includes('/v2/')) deletes.push(req.url());
    });

    await adminPage.getByRole('button', { name: 'Delete v2' }).click();
    const dialog = adminPage.getByRole('dialog', { name: 'Delete manifest' });
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();

    expect(deletes).toEqual([]);
    expect((await serverTags(adminPage, baseURL, name)).sort()).toEqual(['v1', 'v2']);
    await expect(adminPage.getByRole('cell', { name: 'v2', exact: true })).toBeVisible();
  });

  test('inspects a pushed tag and shows what the server answers', async ({ adminPage, baseURL }) => {
    const name = await seed(adminPage, baseURL);
    await listTags(adminPage, name);

    const inspected = adminPage.waitForResponse((r) => {
      if (r.request().method() !== 'GET') return false;
      const pathname = new URL(r.url()).pathname;
      return pathname.startsWith('/api/v1/compute/images/') && pathname.endsWith(':v1');
    });
    await adminPage.getByRole('button', { name: 'Inspect v1' }).click();
    const res = await inspected;
    expect(res.ok(), `${res.url()} answered ${res.status()}`).toBe(true);
    const body = unwrapPayload<{
      Artifact?: { Digest?: string; Manifest?: { Layers?: unknown[] } };
      Tags?: string[];
    }>(await res.json());
    const digest = body.Artifact?.Digest ?? '';
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    const layers = body.Artifact?.Manifest?.Layers ?? [];

    const panel = adminPage.getByTestId('registry-inspect-panel');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText(`${name}:v1`);
    await expect(adminPage.getByTestId('registry-inspect-digest')).toHaveText(digest);
    await expect(adminPage.getByTestId('registry-inspect-layers')).toHaveText(String(layers.length));
  });

  test('List tags and Delete follow GET /api/v1/capabilities', async ({ adminPage, baseURL }) => {
    const name = await seed(adminPage, baseURL);
    await listTags(adminPage, name);

    const list = adminPage.getByRole('button', { name: 'List tags' });
    await expect(list).toHaveAttribute('data-capability-op', 'GET /v2/{name:.+}/tags/list');
    await expect(list).toHaveAttribute('data-capability-enabled', 'true');

    const del = adminPage.getByRole('button', { name: 'Delete v1' });
    await expect(del).toHaveAttribute('data-capability-op', 'DELETE /v2/{name:.+}/manifests/{reference}');
    await expect(del).toHaveAttribute('data-capability-enabled', 'true');

    const inspect = adminPage.getByRole('button', { name: 'Inspect v1' });
    await expect(inspect).toHaveAttribute('data-capability-op', 'GET /api/v1/compute/images/{repository:.+}');
    await expect(inspect).toHaveAttribute('data-capability-enabled', 'true');
  });
});
