import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures';

/**
 * VM operations on the VM detail page and the Migrations page (#1727, slice 7
 * of #1665), against the real-server harness (#2035).
 *
 * The VM is the first one the harness server lists. Each operation asserts on
 * the request the console sends and on the server's real answer: a success
 * shows the page's result, a refusal shows none. When the harness lists no VM
 * (no hypervisor), the case asserts the server refuses an unknown VM id and
 * stops there; docs/plans/1665-port-1.md lists that gap.
 */

const COMPUTE = '/api/v1/compute';

function path(url: string): string {
  return new URL(url).pathname;
}

function answer(page: Page, method: string, suffix: string): Promise<Response> {
  return page.waitForResponse((r) => r.request().method() === method && path(r.url()).endsWith(suffix));
}

interface VMLister {
  compute: {
    listVMs(): Promise<{ success: boolean; data?: unknown }>;
    getVM(id: string): Promise<{ success: boolean }>;
  };
}

/** The first VM the server lists, or null after asserting an unknown id is refused. */
async function firstVM(sdk: VMLister): Promise<{ id: string; name: string } | null> {
  const res = await sdk.compute.listVMs().catch(() => ({ success: false, data: undefined }));
  const vm = (res.data as { vms?: Array<{ id: string; name?: string; config?: { name?: string } }> } | undefined)
    ?.vms?.[0];
  if (res.success && vm) return { id: vm.id, name: vm.config?.name ?? vm.name ?? vm.id };
  const unknown = await sdk.compute.getVM('e2e-no-such-vm').catch(() => ({ success: false }));
  expect(unknown.success).toBe(false);
  return null;
}

/** Opens the static-export VM detail page for id and waits for its operations panel. */
async function openVM(page: Page, id: string): Promise<void> {
  const read = page.waitForResponse(
    (r) => r.request().method() === 'GET' && path(r.url()) === `${COMPUTE}/vms/${encodeURIComponent(id)}`
  );
  await page.goto('/compute/vms/__placeholder__/');
  await page.waitForLoadState('networkidle');
  await page.evaluate((i) => window.history.pushState(null, '', `/compute/vms/${i}/`), id);
  expect((await read).ok()).toBe(true);
  await expect(page.getByTestId('vm-operations')).toBeVisible();
}

test.describe('Compute VM operations, real server', () => {
  test('GetVM shows the VM detail', async ({ adminPage, sdk }) => {
    const vm = await firstVM(sdk);
    if (!vm) return;
    await openVM(adminPage, vm.id);
    await expect(adminPage.getByText('Virtual Machine Details')).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: vm.name })).toBeVisible();
  });

  test('SuspendVM and ResumeVM toggle the VM through the server', async ({ adminPage, sdk }) => {
    const vm = await firstVM(sdk);
    if (!vm) return;
    await openVM(adminPage, vm.id);
    const suspend = adminPage.getByRole('button', { name: 'Suspend' });
    const resume = adminPage.getByRole('button', { name: 'Resume' });
    if (await suspend.isVisible()) {
      const res = answer(adminPage, 'POST', `/vms/${vm.id}/suspend`);
      await suspend.click();
      if ((await res).ok()) await expect(resume).toBeVisible();
    } else {
      const res = answer(adminPage, 'POST', `/vms/${vm.id}/resume`);
      await resume.click();
      if ((await res).ok()) await expect(suspend).toBeVisible();
    }
  });

  test('the 5 s refresh keeps VM operations forms and dialogs', async ({ adminPage, sdk }) => {
    const vm = await firstVM(sdk);
    if (!vm) return;
    await openVM(adminPage, vm.id);
    await adminPage.getByLabel('Snapshot name').fill('kept-across-refresh');
    await adminPage.getByLabel('Destination host').fill('dest-node');
    await adminPage.getByRole('button', { name: 'Migrate VM' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('Migrate this VM to dest-node?');
    await answer(adminPage, 'GET', `/vms/${vm.id}`);
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('Migrate this VM to dest-node?');
    await expect(adminPage.getByLabel('Snapshot name')).toHaveValue('kept-across-refresh');
  });

  test('AttestVM sends a nonce and shows the server attestation', async ({ adminPage, sdk }) => {
    const vm = await firstVM(sdk);
    if (!vm) return;
    await openVM(adminPage, vm.id);
    const res = answer(adminPage, 'POST', `/vms/${vm.id}/attest`);
    await adminPage.getByRole('button', { name: 'Attest VM' }).click();
    const a = await res;
    expect((a.request().postDataJSON() as { nonce?: string }).nonce ?? '').not.toBe('');
    const card = adminPage.getByTestId('vm-attestation');
    if (a.ok()) {
      const body = (await a.json()) as { pcrValues?: unknown[] };
      await expect(card).toContainText(`PCR values: ${body.pcrValues?.length ?? 0}`);
    } else {
      await expect(card).toContainText('No attestation collected');
    }
  });

  test('GetVMMetrics shows the server metrics', async ({ adminPage, sdk }) => {
    const vm = await firstVM(sdk);
    if (!vm) return;
    await openVM(adminPage, vm.id);
    const res = answer(adminPage, 'GET', `/vms/${vm.id}/metrics`);
    await adminPage.getByRole('button', { name: 'Load Metrics' }).click();
    const m = await res;
    const card = adminPage.getByTestId('vm-live-metrics');
    const metrics = m.ok() ? ((await m.json()) as { metrics?: { cpuUsagePercent?: number } }).metrics : undefined;
    if (metrics) await expect(card).toContainText(`CPU: ${metrics.cpuUsagePercent}%`);
    else await expect(card).toContainText('No metrics loaded');
  });

  test('AttachDisk, ResizeDisk and DetachDisk use the attached ID', async ({ adminPage, sdk }) => {
    const vm = await firstVM(sdk);
    if (!vm) return;
    await openVM(adminPage, vm.id);
    const result = adminPage.getByTestId('vm-disk-result');
    await adminPage.getByLabel('Disk path').fill('/var/lib/disks/e2e-data.qcow2');
    await adminPage.getByLabel('Size GB', { exact: true }).fill('1');
    const attach = answer(adminPage, 'POST', `/vms/${vm.id}/disks`);
    await adminPage.getByRole('button', { name: 'Attach Disk' }).click();
    const a = await attach;
    expect(a.request().postDataJSON()).toEqual({
      disk: { id: expect.stringMatching(/^disk-[0-9a-f]{16}$/), path: '/var/lib/disks/e2e-data.qcow2', sizeGb: 1 },
    });
    if (!a.ok()) {
      await expect(result).toBeHidden();
      return;
    }
    const id = await adminPage.getByLabel('Disk ID').inputValue();
    await expect(result).toHaveText(`Attached /var/lib/disks/e2e-data.qcow2 as ${id}`);

    await adminPage.getByLabel('New size GB').fill('2');
    const resize = answer(adminPage, 'PATCH', `/vms/${vm.id}/disks/${id}`);
    await adminPage.getByRole('button', { name: 'Resize Disk' }).click();
    const r = await resize;
    expect(r.request().postDataJSON()).toEqual({ newSizeGb: 2 });
    if (r.ok()) await expect(result).toHaveText(`Resized ${id} to 2 GB`);

    await adminPage.getByRole('button', { name: 'Detach Disk' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText(`Detach disk ${id} from this VM?`);
    const detach = answer(adminPage, 'DELETE', `/vms/${vm.id}/disks/${id}`);
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    if ((await detach).ok()) await expect(result).toHaveText(`Detached ${id}`);
  });

  test('DetachDisk sends nothing before confirm, and an unknown disk is not reported detached', async ({
    adminPage,
    sdk,
  }) => {
    const vm = await firstVM(sdk);
    if (!vm) return;
    await openVM(adminPage, vm.id);
    const deletes: string[] = [];
    adminPage.on('request', (r) => {
      if (r.method() === 'DELETE') deletes.push(path(r.url()));
    });
    await adminPage.getByLabel('Disk ID').fill('disk-e2e-none');
    await adminPage.getByRole('button', { name: 'Detach Disk' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('Detach disk disk-e2e-none from this VM?');
    expect(deletes).toEqual([]);
    const detach = answer(adminPage, 'DELETE', `/vms/${vm.id}/disks/disk-e2e-none`);
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    const d = await detach;
    const result = adminPage.getByTestId('vm-disk-result');
    if (d.ok()) await expect(result).toHaveText('Detached disk-e2e-none');
    else await expect(result).toBeHidden();
  });

  test('CreateSnapshot and GetSnapshot show the server snapshot', async ({ adminPage, sdk }) => {
    const vm = await firstVM(sdk);
    if (!vm) return;
    await openVM(adminPage, vm.id);
    await adminPage.getByLabel('Snapshot name').fill('e2e-before-upgrade');
    const create = answer(adminPage, 'POST', `/vms/${vm.id}/snapshots`);
    await adminPage.getByRole('button', { name: 'Take Snapshot' }).click();
    const c = await create;
    expect(c.request().postDataJSON()).toEqual({ config: { name: 'e2e-before-upgrade' } });
    const detail = adminPage.getByTestId('vm-snapshot-detail');
    const snap = c.ok() ? ((await c.json()) as { snapshot?: { id?: string } }).snapshot : undefined;
    if (!snap?.id) {
      await expect(detail).toBeHidden();
      return;
    }
    await expect(detail).toContainText(`e2e-before-upgrade (${snap.id})`);
    await expect(adminPage.getByLabel('Snapshot ID')).toHaveValue(snap.id);

    const get = answer(adminPage, 'GET', `/vms/${vm.id}/snapshots/${snap.id}`);
    await adminPage.getByRole('button', { name: 'Get Snapshot' }).click();
    expect((await get).ok()).toBe(true);
    await expect(detail).toContainText(`(${snap.id})`);
    await sdk.compute.deleteSnapshot({ vmId: vm.id, snapshotId: snap.id }).catch(() => undefined);
  });

  test('MigrateVM asks first, then sends a cold migration', async ({ adminPage, sdk }) => {
    const vm = await firstVM(sdk);
    if (!vm) return;
    await openVM(adminPage, vm.id);
    await adminPage.getByLabel('Destination host').fill('e2e-no-such-host');
    await adminPage.getByRole('button', { name: 'Migrate VM' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('Migrate this VM to e2e-no-such-host?');
    const migrate = answer(adminPage, 'POST', `/vms/${vm.id}/migrate`);
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    const m = await migrate;
    expect(m.request().postDataJSON()).toEqual({ destinationHost: 'e2e-no-such-host', liveMigration: false });
    const result = adminPage.getByTestId('vm-migrate-result');
    if (m.ok()) await expect(result).toHaveText('Migration to e2e-no-such-host started');
    else await expect(result).toBeHidden();
  });
});

test.describe('VM migrations page, real server', () => {
  test('PrepareMigration needs the full spec and sends it', async ({ adminPage }) => {
    await adminPage.goto('/compute/migrations');
    await expect(adminPage.getByRole('heading', { name: 'VM Migrations' })).toBeVisible();
    await adminPage.getByLabel('Guest name').fill('e2e-rx-vm');
    await adminPage.getByLabel('Mode', { exact: true }).selectOption('cold');
    await expect(adminPage.getByRole('button', { name: 'Prepare Migration' })).toBeDisabled();
    await adminPage.getByLabel('Memory MB').fill('512');
    await adminPage.getByLabel('CPUs').fill('1');
    await adminPage.getByLabel('Disk size').fill('1G');
    await adminPage.getByLabel('Boot mode').fill('uefi');
    await adminPage.getByLabel('Arch').selectOption('aarch64');
    await adminPage.getByLabel('Secure boot').check();
    await adminPage.getByLabel('TPM').check();
    const prepare = answer(adminPage, 'POST', '/migrations/prepare');
    await adminPage.getByRole('button', { name: 'Prepare Migration' }).click();
    const p = await prepare;
    expect(p.request().postDataJSON()).toEqual({
      vmName: 'e2e-rx-vm',
      mode: 'cold',
      spec: {
        memoryMb: 512,
        cpus: 1,
        diskSize: '1G',
        bootMode: 'uefi',
        arch: 'aarch64',
        secureBoot: true,
        enableKvm: true,
        tpmEnabled: true,
        networkMode: 'bridge',
      },
    });
    const receiver = adminPage.getByTestId('migration-receiver');
    if (!p.ok()) {
      await expect(receiver).toBeHidden();
      return;
    }
    await expect(receiver).toContainText('Receiver: ');
    await expect(adminPage.getByLabel('Receiver ID')).not.toHaveValue('');
  });

  test('FinalizeMigration asks first and an unknown receiver is not reported committed', async ({ adminPage }) => {
    await adminPage.goto('/compute/migrations');
    await adminPage.getByLabel('Guest name').fill('e2e-rx-vm');
    await adminPage.getByLabel('Receiver ID').fill('rx-e2e-none');
    await adminPage.getByRole('button', { name: 'Commit Migration' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('Register and resume the VM received by rx-e2e-none?');
    const finalize = answer(adminPage, 'POST', '/migrations/rx-e2e-none/finalize');
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    const f = await finalize;
    expect(f.request().postDataJSON()).toEqual({ commit: true });
    expect(f.ok()).toBe(false);
    await expect(adminPage.getByTestId('migration-finalize-result')).toBeHidden();
  });

  test('the sidebar lists the Migrations page', async ({ adminPage }) => {
    await adminPage.goto('/compute/migrations');
    await expect(adminPage.getByRole('link', { name: 'Migrations' })).toBeVisible();
  });
});
