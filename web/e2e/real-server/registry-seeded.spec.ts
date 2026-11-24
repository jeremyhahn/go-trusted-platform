/**
 * The registry page against the real platformd: #2063 RegistryService List
 * and Delete with a real tag. The image is pushed through /v2 by
 * fixtures/registry-seed.ts, because the SDK has no push; no page.route mocks,
 * every answer comes from the server. Inspect of a real tag is added to this
 * spec once the Inspect control from open PR #2180 is on this branch.
 */
import type { Page, Response } from '@playwright/test';

import { expect, requestFetch, test } from './fixtures';
import { pushTestImage } from './fixtures/registry-seed';

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
});
