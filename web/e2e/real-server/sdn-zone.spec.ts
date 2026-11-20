/**
 * Real-server spec for the SDN network-zone operations (#2065, epic #1665
 * coverage-matrix slice 28): ListNetworkZones, CreateNetworkZone,
 * UpdateNetworkZone and DeleteNetworkZone.
 *
 * State is seeded through the SDK client (`sdk.sdn`) against the harness
 * server, never through route mocks, and every assertion reads what the
 * server returns.
 */
import { test, expect } from './fixtures';

function zoneName(tag: string): string {
  return `e2e-${tag}-${Date.now().toString(36)}`.slice(0, 30);
}

test.describe('SDN network zones against the real server', () => {
  test('lists a zone seeded through the SDK', async ({ adminPage, sdk }) => {
    const name = zoneName('list');
    const created = await sdk.sdn.createNetworkZone({ name, offset: 201, services: ['dns'] });
    expect(created.success).toBe(true);
    expect(created.data?.name).toBe(name);

    const listed = await sdk.sdn.listNetworkZones();
    expect(listed.success).toBe(true);
    expect(listed.data?.zones.map((z) => z.name)).toContain(name);

    await adminPage.goto('/networking/zones');
    await expect(adminPage.getByRole('cell', { name, exact: true })).toBeVisible();

    await sdk.sdn.deleteNetworkZone(name);
  });

  test('creates a zone from the page', async ({ adminPage, sdk }) => {
    const name = zoneName('create');
    await adminPage.goto('/networking/zones');
    await adminPage.getByRole('button', { name: /add zone/i }).click();
    await adminPage.getByLabel(/^name$/i).fill(name);
    await adminPage.getByLabel(/offset/i).fill('202');
    await adminPage.getByRole('button', { name: /^(create|save)/i }).click();

    await expect(adminPage.getByRole('cell', { name, exact: true })).toBeVisible();
    const listed = await sdk.sdn.listNetworkZones();
    const zone = listed.data?.zones.find((z) => z.name === name);
    expect(zone).toBeDefined();
    expect(zone?.offset).toBe(202);

    await sdk.sdn.deleteNetworkZone(name);
  });

  test('updates a zone from the page', async ({ adminPage, sdk }) => {
    const name = zoneName('update');
    await sdk.sdn.createNetworkZone({ name, offset: 203 });

    await adminPage.goto('/networking/zones');
    const row = adminPage.getByRole('row').filter({ hasText: name });
    await row.getByRole('button', { name: /open menu|actions/i }).click();
    await adminPage.getByRole('menuitem', { name: /edit/i }).click();
    await adminPage.getByLabel(/services/i).fill('dns, ntp');
    await adminPage.getByRole('button', { name: /^(save|update)/i }).click();

    await expect
      .poll(async () => {
        const listed = await sdk.sdn.listNetworkZones();
        return listed.data?.zones.find((z) => z.name === name)?.services ?? [];
      })
      .toEqual(['dns', 'ntp']);

    await sdk.sdn.deleteNetworkZone(name);
  });

  test('deletes a zone from the page', async ({ adminPage, sdk }) => {
    const name = zoneName('delete');
    await sdk.sdn.createNetworkZone({ name, offset: 204 });

    await adminPage.goto('/networking/zones');
    const row = adminPage.getByRole('row').filter({ hasText: name });
    await row.getByRole('button', { name: /open menu|actions/i }).click();
    await adminPage.getByRole('menuitem', { name: /delete/i }).click();
    await adminPage.getByRole('button', { name: /^delete/i }).click();

    await expect(adminPage.getByRole('cell', { name, exact: true })).toHaveCount(0);
    const listed = await sdk.sdn.listNetworkZones();
    expect(listed.data?.zones.map((z) => z.name)).not.toContain(name);
  });

  test('the server refuses a duplicate zone name', async ({ sdk }) => {
    const name = zoneName('dup');
    await sdk.sdn.createNetworkZone({ name, offset: 205 });
    const again = await sdk.sdn.createNetworkZone({ name, offset: 206 });
    expect(again.success).toBe(false);
    await sdk.sdn.deleteNetworkZone(name);
  });
});
