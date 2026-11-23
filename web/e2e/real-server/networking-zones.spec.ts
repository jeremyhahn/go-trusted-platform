// Real-server spec for the Network Zones page (/networking/zones), row #2065
// of the UI epic #1665 (coverage-matrix slice 28).
//
// It runs against the real platformd of the real-server harness: no
// page.route and no api-mock. Every assertion reads the server's own answer
// (GET /api/v1/capabilities and GET /api/v1/sdn/zones), so the spec holds
// whether the zone ops are offered or reported not configured. A zone change
// applies at the next daemon restart, so the spec does not assert that a
// deleted zone leaves the list.
import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

const LIST = 'GET /api/v1/sdn/zones';
const CREATE = 'POST /api/v1/sdn/zones';
const UPDATE = 'PUT /api/v1/sdn/zones/{name}';
const REMOVE = 'DELETE /api/v1/sdn/zones/{name}';

const ZONES_PATH = /\/api\/v1\/sdn\/zones$/;

type Cap = { enabled: boolean; reason?: string };

type CapabilitiesSdk = {
  capabilities: {
    list(): Promise<{
      success: boolean;
      data?: { capabilities: { op: string; enabled: boolean; reason?: string }[] } | null;
      error?: unknown;
    }>;
  };
};

function apiResponse(page: Page, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && path.test(new URL(r.url()).pathname),
  );
}

async function json<T>(r: Response): Promise<T> {
  expect(r.ok(), `${r.url()} answered ${r.status()}`).toBeTruthy();
  return unwrapPayload<T>(await r.json());
}

function mutation(page: Page, method: string, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && new URL(r.url()).pathname.endsWith(path),
  );
}

async function capabilityMap(sdk: CapabilitiesSdk): Promise<Map<string, Cap>> {
  const caps = await sdk.capabilities.list();
  expect(caps.success, JSON.stringify(caps.error)).toBeTruthy();
  const out = new Map<string, Cap>();
  for (const c of caps.data?.capabilities ?? []) {
    out.set(c.op, { enabled: c.enabled, reason: c.reason });
  }
  return out;
}

async function expectGated(locator: Locator, cap: Cap | undefined): Promise<void> {
  if (cap?.enabled) {
    await expect(locator).toHaveAttribute('data-capability-enabled', 'true');
    return;
  }
  await expect(locator).toHaveAttribute('data-capability-enabled', 'false');
  await expect(locator).toBeDisabled();
  await expect(locator).toHaveAttribute('title', cap?.reason ?? '');
}

async function expectMenuItemOff(item: Locator, cap: Cap | undefined): Promise<void> {
  await expect(item).toBeDisabled();
  await expect(item).toHaveAttribute('title', cap?.reason ?? '');
}

async function expectUnavailable(page: Page, cap: Cap | undefined): Promise<void> {
  const alert = page.getByTestId('zones-unavailable');
  await expect(alert).toBeVisible();
  if (cap?.reason) {
    await expect(alert).toContainText(cap.reason);
  }
}

test.describe('Network Zones against the real platformd', () => {
  test('lists the zones the server answers, or says the list is not offered', async ({
    adminPage,
    sdk,
  }) => {
    const caps = await capabilityMap(sdk);
    const list = caps.get(LIST);

    if (!list?.enabled) {
      await adminPage.goto('/networking/zones');
      await expect(adminPage.getByRole('heading', { level: 1, name: 'Network Zones' })).toBeVisible();
      await expectUnavailable(adminPage, list);
      return;
    }

    const res = apiResponse(adminPage, ZONES_PATH);
    await adminPage.goto('/networking/zones');
    const { zones } = await json<{ zones: { name: string }[] }>(await res);

    await expect(adminPage.getByRole('heading', { level: 1, name: 'Network Zones' })).toBeVisible();
    for (const zone of zones ?? []) {
      await expect(adminPage.getByRole('cell', { name: zone.name, exact: true })).toBeVisible();
    }
    const total = (zones ?? []).length;
    await expect(
      adminPage.locator('div', { hasText: new RegExp(`^\\s*Total\\s*${total}(\\D|$)`) }).first(),
    ).toBeVisible();
  });

  test('gates Refresh and Create Zone on the server capabilities', async ({ adminPage, sdk }) => {
    const caps = await capabilityMap(sdk);
    const list = caps.get(LIST);

    await adminPage.goto('/networking/zones');
    await expect(adminPage.getByRole('heading', { level: 1, name: 'Network Zones' })).toBeVisible();

    await expectGated(adminPage.locator(`[data-capability-op="${LIST}"]`).first(), list);

    if (list?.enabled) {
      // With the list off the page shows no Create Zone, only the notice.
      await expectGated(
        adminPage.locator(`[data-capability-op="${CREATE}"]`).filter({ hasText: 'Create Zone' }),
        caps.get(CREATE),
      );
    } else {
      await expectUnavailable(adminPage, list);
    }
  });

  test('creates, edits and deletes an owner zone through the dialogs when the server offers them', async ({
    adminPage,
    sdk,
  }) => {
    const caps = await capabilityMap(sdk);
    const list = caps.get(LIST);
    const create = caps.get(CREATE);
    const update = caps.get(UPDATE);
    const remove = caps.get(REMOVE);

    await adminPage.goto('/networking/zones');
    await expect(adminPage.getByRole('heading', { level: 1, name: 'Network Zones' })).toBeVisible();

    if (!list?.enabled) {
      await expectUnavailable(adminPage, list);
      return;
    }

    const createButton = adminPage
      .locator(`[data-capability-op="${CREATE}"]`)
      .filter({ hasText: 'Create Zone' });
    if (!create?.enabled) {
      await expectGated(createButton, create);
      return;
    }

    const worker = test.info().workerIndex;
    const name = `e2e-zone-w${worker}-${Date.now().toString(36)}`.toLowerCase().slice(0, 31);

    // Create.
    await createButton.click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await dialog.locator('#zone-name').fill(name);
    await dialog.locator('#zone-offset').fill(String(90 + (worker % 10)));
    await expect(dialog.locator('#port-class-hypervisor')).toHaveAttribute('data-state', 'checked');
    const created = mutation(adminPage, 'POST', '/api/v1/sdn/zones');
    await expect(dialog.getByRole('button', { name: 'Create Zone' })).toBeEnabled();
    await dialog.getByRole('button', { name: 'Create Zone' }).click();
    const createdRes = await created;
    expect(createdRes.ok(), `create answered ${createdRes.status()}`).toBeTruthy();
    await expect(adminPage.getByText('Zone created', { exact: true }).first()).toBeVisible();

    const listed = await sdk.sdn.listNetworkZones();
    expect(listed.success, JSON.stringify(listed.error)).toBeTruthy();
    expect((listed.data?.zones ?? []).map((z) => z.name)).toContain(name);

    const zonePath = `/api/v1/sdn/zones/${encodeURIComponent(name)}`;
    const row = adminPage.getByRole('row').filter({ hasText: name });

    // Edit.
    const reloaded = apiResponse(adminPage, ZONES_PATH);
    await adminPage.reload();
    await json<{ zones: { name: string }[] }>(await reloaded);
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: 'Open menu' }).click();
    const editItem = adminPage.getByRole('menuitem', { name: 'Edit', exact: true });
    if (!update?.enabled) {
      await expectMenuItemOff(editItem, update);
      await adminPage.keyboard.press('Escape');
    } else {
      await editItem.click();
      const editDialog = adminPage.getByRole('dialog');
      await expect(editDialog).toBeVisible();
      await editDialog.locator('#isolate').click();
      const updated = mutation(adminPage, 'PUT', zonePath);
      await editDialog.getByRole('button', { name: 'Save Changes' }).click();
      const updatedRes = await updated;
      expect(updatedRes.ok(), `update answered ${updatedRes.status()}`).toBeTruthy();
      await expect(adminPage.getByText('Zone updated', { exact: true }).first()).toBeVisible();
      await expect(editDialog).toBeHidden();
    }

    // Delete.
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: 'Open menu' }).click();
    const deleteItem = adminPage.getByRole('menuitem', { name: 'Delete', exact: true });
    if (!remove?.enabled) {
      await expectMenuItemOff(deleteItem, remove);
      await adminPage.keyboard.press('Escape');
      return;
    }
    await deleteItem.click();
    const confirm = adminPage.getByRole('dialog').or(adminPage.getByRole('alertdialog'));
    await expect(confirm).toBeVisible();
    const deleted = mutation(adminPage, 'DELETE', zonePath);
    await confirm.getByRole('button', { name: 'Delete', exact: true }).click();
    const deletedRes = await deleted;
    expect(deletedRes.ok(), `delete answered ${deletedRes.status()}`).toBeTruthy();
    await expect(adminPage.getByText('Zone deleted', { exact: true }).first()).toBeVisible();
  });
});
