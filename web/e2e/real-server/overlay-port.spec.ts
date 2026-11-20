/**
 * Overlay VTEPs page against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/overlay.spec.ts. VNIs are created through the SDK,
 * the VTEP and tunnel tables are held to what the server lists, and every
 * delete is checked against the server afterwards. Mocked cases with no server
 * behaviour behind them (403s for an admin, learned remote MACs and tunnel
 * counters a single harness node never produces) are listed as gaps in the PR
 * body.
 */
import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures';

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

/** The part of the SDK's OverlayService these specs drive. */
interface OverlaySdk {
  overlay: {
    createVNI(req: { config: { vni: number; name?: string } }): Promise<Result<unknown>>;
    listVNIs(): Promise<Result<{ vnis: Array<{ config: { vni: number; name?: string } }> }>>;
    deleteVNI(vni: number): Promise<Result<unknown>>;
    listVTEPs(): Promise<Result<{ vteps: Array<{ nodeId: string; ip: string }> }>>;
    listTunnels(): Promise<Result<{ tunnels: unknown[] }>>;
  };
}

/** A VNI number unlikely to collide across parallel workers (1..16777215). */
function randomVni(): number {
  return 100000 + Math.floor(Math.random() * 16000000);
}

async function openPage(page: Page): Promise<void> {
  await page.goto('/networking/overlays/vteps');
  await expect(page.getByRole('heading', { name: 'Overlay VTEPs' })).toBeVisible();
}

/** Creates a VNI through the SDK and returns its number and name. */
async function seedVni(sdk: OverlaySdk): Promise<{ vni: number; name: string }> {
  const vni = randomVni();
  const name = `e2e-vni-${vni}`;
  const res = await sdk.overlay.createVNI({ config: { vni, name } });
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  return { vni, name };
}

async function serverHasVni(sdk: OverlaySdk, vni: number): Promise<boolean> {
  const res = await sdk.overlay.listVNIs();
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  return (res.data?.vnis ?? []).some((v) => v.config.vni === vni);
}

function countDeletes(page: Page): { count: () => number } {
  let n = 0;
  page.on('request', (req) => {
    if (req.method() === 'DELETE') n++;
  });
  return { count: () => n };
}

test.describe('Overlay VTEPs and tunnels', () => {
  test('ListVTEPs: lists the VTEPs the server holds', async ({ adminPage, sdk }) => {
    const res = await (sdk as OverlaySdk).overlay.listVTEPs();

    await openPage(adminPage);

    const table = adminPage.getByTestId('vteps-table');
    if (!res.success) {
      await expect(adminPage.getByTestId('vteps-list-error')).toBeVisible();
      return;
    }
    const vteps = res.data?.vteps ?? [];
    if (vteps.length === 0) {
      await expect(adminPage.getByText('No VTEPs found')).toBeVisible();
    }
    for (const vtep of vteps) {
      await expect(table.getByRole('cell', { name: vtep.nodeId, exact: true })).toBeVisible();
      await expect(table.getByRole('cell', { name: vtep.ip })).toBeVisible();
    }
  });

  test('GetVTEP: shows one VTEP when selected', async ({ adminPage, sdk }) => {
    const res = await (sdk as OverlaySdk).overlay.listVTEPs();
    const first = res.data?.vteps?.[0];
    test.skip(!first, 'the harness server lists no VTEP');

    await openPage(adminPage);
    await adminPage.getByRole('button', { name: `Details ${first!.nodeId}` }).click();

    await expect(adminPage.getByRole('dialog').getByText(`VTEP ${first!.nodeId}`)).toBeVisible();
  });

  test('DeleteVNI: deletes a VNI after confirmation', async ({ adminPage, sdk }) => {
    const { vni } = await seedVni(sdk);
    const deletes = countDeletes(adminPage);

    await openPage(adminPage);
    await adminPage.getByRole('button', { name: `Delete VNI ${vni}` }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText(`Delete VNI ${vni}?`, { exact: false })).toBeVisible();
    expect(deletes.count()).toBe(0);
    await dialog.getByRole('button', { name: 'Delete' }).click();

    await expect(adminPage.getByRole('button', { name: `Delete VNI ${vni}` })).toHaveCount(0);
    expect(await serverHasVni(sdk, vni)).toBe(false);
  });

  test('DeleteVNI: cancel leaves the VNI in place', async ({ adminPage, sdk }) => {
    const { vni, name } = await seedVni(sdk);
    const deletes = countDeletes(adminPage);

    await openPage(adminPage);
    await adminPage.getByRole('button', { name: `Delete VNI ${vni}` }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

    await expect(adminPage.getByRole('cell', { name })).toBeVisible();
    expect(deletes.count()).toBe(0);
    expect(await serverHasVni(sdk, vni)).toBe(true);
  });

  test('ListTunnels: the tunnel table loads with the server answer', async ({ adminPage, sdk }) => {
    const res = await (sdk as OverlaySdk).overlay.listTunnels();

    await openPage(adminPage);

    if (res.success) {
      await expect(adminPage.getByTestId('tunnels-list-error')).toHaveCount(0);
    } else {
      await expect(adminPage.getByTestId('tunnels-list-error')).toBeVisible();
    }
  });

  test('ForgetMAC: forgets a MAC after confirmation and shows the server answer', async ({ adminPage, sdk }) => {
    const { vni } = await seedVni(sdk);
    const deletes = countDeletes(adminPage);

    await openPage(adminPage);
    await adminPage.getByLabel('MAC address').fill('aa:bb:cc:dd:ee:ff');
    await adminPage.getByLabel('VNI', { exact: true }).fill(String(vni));
    await adminPage.getByRole('button', { name: 'Forget MAC' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText(`Forget MAC aa:bb:cc:dd:ee:ff on VNI ${vni}?`)).toBeVisible();
    expect(deletes.count()).toBe(0);

    const answered: Promise<Response> = adminPage.waitForResponse(
      (r) => r.request().method() === 'DELETE' && /\/macs\b/.test(r.url())
    );
    await dialog.getByRole('button', { name: 'Forget' }).click();
    const response = await answered;

    const url = new URL(response.url());
    expect(url.searchParams.get('mac')).toBe('aa:bb:cc:dd:ee:ff');
    expect(url.searchParams.get('vni')).toBe(String(vni));
    if (response.ok()) {
      await expect(dialog).toBeHidden();
      await expect(adminPage.getByText('Forget MAC failed')).toHaveCount(0);
    } else {
      await expect(adminPage.getByText('Forget MAC failed').first()).toBeVisible();
      await expect(adminPage.getByLabel('MAC address')).toHaveValue('aa:bb:cc:dd:ee:ff');
    }
  });

  test('ForgetMAC: an exponential VNI is read whole', async ({ adminPage }) => {
    await openPage(adminPage);
    await adminPage.getByLabel('MAC address').fill('aa:bb:cc:dd:ee:ff');
    await adminPage.getByLabel('VNI', { exact: true }).fill('1e4');
    await adminPage.getByRole('button', { name: 'Forget MAC' }).click();

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText('Forget MAC aa:bb:cc:dd:ee:ff on VNI 10000?')).toBeVisible();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
  });

  test('ForgetMAC: a fractional VNI is refused before any request', async ({ adminPage }) => {
    const deletes = countDeletes(adminPage);

    await openPage(adminPage);
    await adminPage.getByLabel('MAC address').fill('aa:bb:cc:dd:ee:ff');
    await adminPage.getByLabel('VNI', { exact: true }).fill('5001.9');
    await adminPage.getByRole('button', { name: 'Forget MAC' }).click();

    await expect(
      adminPage.getByText('Enter a MAC address and a whole VNI from 1 to 16777215').first()
    ).toBeVisible();
    await expect(adminPage.getByRole('dialog')).toHaveCount(0);
    expect(deletes.count()).toBe(0);
  });
});
