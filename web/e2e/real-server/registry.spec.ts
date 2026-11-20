/**
 * Container registry against the real-server harness (#2063, epic #1665):
 * Status, List (tags), Inspect and Delete (manifest). State comes from the
 * server through the SDK; nothing is route-mocked.
 */
import { RegistryService } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

const REPOSITORY = 'e2e/registry';

test.describe('Container registry (real server)', () => {
  test('status view shows what GET /v1/compute/images/status returns', async ({ adminPage, sdk }) => {
    const registry = new RegistryService(sdk.getApiClient());
    const res = await registry.getStatus();

    await adminPage.goto('/compute/registry');
    const card = adminPage.getByTestId('registry-status');
    await expect(card).toBeVisible();
    if (res.success && res.data) {
      await expect(card).toContainText(res.data.ReadOnly ? 'Read-only' : 'Read-write');
      if (res.data.Version) {
        await expect(card).toContainText(res.data.Version);
      }
    } else {
      await expect(card).toContainText('Failed to load status');
    }
  });

  test('list tags shows the tags the server lists for a repository', async ({ adminPage, sdk }) => {
    const registry = new RegistryService(sdk.getApiClient());
    const res = await registry.listTags(REPOSITORY);

    await adminPage.goto('/compute/registry');
    await adminPage.getByLabel('Repository').fill(REPOSITORY);
    await adminPage.getByRole('button', { name: 'List tags' }).click();

    if (!res.success) {
      await expect(adminPage.getByText(/Failed to list tags/)).toBeVisible();
      return;
    }
    const tags = res.data?.tags ?? [];
    if (tags.length === 0) {
      await expect(adminPage.getByText(`${REPOSITORY} has no tags.`)).toBeVisible();
      return;
    }
    for (const tag of tags) {
      await expect(adminPage.getByRole('button', { name: `Inspect ${tag}` })).toBeVisible();
    }
  });

  test('inspect shows the artifact the server returns for a tag', async ({ adminPage, sdk }) => {
    const registry = new RegistryService(sdk.getApiClient());
    const list = await registry.listTags(REPOSITORY);
    const tag = list.data?.tags?.[0];
    test.skip(!tag, 'the harness registry holds no tag to inspect (Push is not-UI plumbing)');

    const detail = await registry.inspect(REPOSITORY, tag as string);
    await adminPage.goto('/compute/registry');
    await adminPage.getByLabel('Repository').fill(REPOSITORY);
    await adminPage.getByRole('button', { name: 'List tags' }).click();
    await adminPage.getByRole('button', { name: `Inspect ${tag}` }).click();

    const panel = adminPage.getByTestId('registry-inspect');
    await expect(panel).toBeVisible();
    if (detail.success && detail.data?.Artifact?.Digest) {
      await expect(panel).toContainText(detail.data.Artifact.Digest);
    } else {
      await expect(panel).toContainText('Failed to inspect');
    }
  });

  test('delete removes the manifest from the server, or is gated off when read-only', async ({ adminPage, sdk }) => {
    const registry = new RegistryService(sdk.getApiClient());
    const status = await registry.getStatus();
    const list = await registry.listTags(REPOSITORY);
    const tag = list.data?.tags?.[0];
    test.skip(!tag, 'the harness registry holds no tag to delete (Push is not-UI plumbing)');

    await adminPage.goto('/compute/registry');
    await adminPage.getByLabel('Repository').fill(REPOSITORY);
    await adminPage.getByRole('button', { name: 'List tags' }).click();
    const del = adminPage.getByRole('button', { name: `Delete ${tag}` });

    if (status.data?.ReadOnly) {
      await expect(del).toBeDisabled();
      await expect(adminPage.getByText(/registry is read-only/).first()).toBeVisible();
      return;
    }
    await del.click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await expect(adminPage.getByText('Manifest deleted')).toBeVisible();

    const after = await registry.listTags(REPOSITORY);
    expect(after.data?.tags ?? []).not.toContain(tag);
  });
});
