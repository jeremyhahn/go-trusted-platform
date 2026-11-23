import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Compute pages (VMs, containers, snapshots) against the real-server harness
 * (#2035, port of the mocked compute.spec.ts).
 *
 * The harness daemon may run without a compute backend: then the list routes
 * answer the service registry's 503 SERVICE_NOT_CONFIGURED and every page
 * must show its informational state; any other refusal must show as an
 * error. Each case seeds through the SDK, reads the answer the page itself
 * got, and asserts the page shows that answer. Cases with no server
 * behaviour behind them are listed in docs/plans/1665-port-1.md.
 */

interface Answer {
  status: number;
  body: Record<string, unknown>;
}

const NOT_AVAILABLE = /compute is not available on this node/i;

const isPath = (path: string) => (r: Response) => new URL(r.url()).pathname === path;

async function answerOf(res: Response): Promise<Answer> {
  let body: Record<string, unknown> = {};
  try {
    body = (await res.json()) as Record<string, unknown>;
  } catch {
    // no JSON body
  }
  // protorest.WriteSuccess puts vms, containers, snapshots and created
  // resources inside payload: assert on that. An error envelope stays whole,
  // so notConfigured still reads its reason.
  const payload = body.payload;
  if (res.ok() && body.success === true && typeof payload === 'object' && payload !== null && !Array.isArray(payload)) {
    body = unwrapPayload<Record<string, unknown>>(body);
  }
  return { status: res.status(), body };
}

/** Opens path and returns the server's answer to the page's GET of api. */
async function open(page: Page, path: string, api: string): Promise<Answer> {
  const res = page.waitForResponse((r) => r.request().method() === 'GET' && isPath(api)(r));
  await page.goto(path);
  return answerOf(await res);
}

const notConfigured = (a: Answer) => a.status === 503 && a.body.reason === 'SERVICE_NOT_CONFIGURED';

interface Named {
  id?: string;
  config?: { name?: string };
  state?: string;
}

const items = (a: Answer, key: string): Named[] => (Array.isArray(a.body[key]) ? (a.body[key] as Named[]) : []);

/** Asserts the page shows the list answer: not available, error, empty or the rows. */
async function expectListShows(page: Page, a: Answer, key: string, errorText: RegExp, emptyText: RegExp) {
  if (notConfigured(a)) {
    await expect(page.getByText(NOT_AVAILABLE)).toBeVisible();
    await expect(page.getByText(errorText)).not.toBeVisible();
    return;
  }
  if (a.status >= 400) {
    await expect(page.getByText(errorText).first()).toBeVisible();
    await expect(page.getByText(NOT_AVAILABLE)).not.toBeVisible();
    return;
  }
  const rows = items(a, key);
  if (rows.length === 0) {
    await expect(page.getByText(emptyText)).toBeVisible();
    return;
  }
  for (const row of rows.slice(0, 5)) {
    if (row.config?.name) await expect(page.getByText(row.config.name).first()).toBeVisible();
  }
}

const badge = (state: string | undefined, prefix: string) => (state ?? '').replace(prefix, '').toLowerCase();

async function seedVM(sdk: PlatformClient, name: string, start?: boolean): Promise<string | null> {
  const res = await sdk.compute.createVM({
    config: { name, cpu: { cores: 1 }, memory: { sizeMb: 256 }, disks: [], networks: [] },
    ...(start ? { start: true } : {}),
  });
  return res.success && res.data?.vm?.id ? res.data.vm.id : null;
}

async function seedContainer(sdk: PlatformClient, name: string): Promise<string | null> {
  const res = await sdk.compute.createContainer({ config: { name, image: 'busybox:latest' } });
  return res.success && res.data?.container?.id ? res.data.container.id : null;
}

const unique = (prefix: string) => `${prefix}-${Date.now().toString(36)}`;

/** Clicks a row action and asserts the toast for the server's answer to it. */
async function rowAction(page: Page, rowName: string, item: RegExp, method: string, id: string, success: RegExp) {
  const res = page.waitForResponse((r) => r.request().method() === method && r.url().includes(id));
  const actions = page.getByRole('row', { name: new RegExp(rowName, 'i') }).getByRole('button');
  await expect(actions).toBeEnabled();
  await actions.click();
  await page.getByRole('menuitem', { name: item }).click();
  const a = await answerOf(await res);
  if (a.status < 400) {
    await expect(page.getByText(success).first()).toBeVisible({ timeout: 10_000 });
  } else {
    await expect(page.getByText(success)).not.toBeVisible();
    await expect(page.getByText(/error|failed/i).first()).toBeVisible();
  }
  return a;
}

test.describe('Compute, real server', () => {
  test.describe('VMs list', () => {
    test('shows the VM table, or the state of the list answer', async ({ adminPage }) => {
      const a = await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
      await expect(adminPage.getByRole('heading', { name: /virtual machines/i })).toBeVisible();
      if (a.status < 400 && items(a, 'vms').length > 0) {
        for (const col of [/name/i, /status/i, /vcpus/i, /memory/i, /actions/i]) {
          await expect(adminPage.getByRole('columnheader', { name: col })).toBeVisible();
        }
      }
      await expectListShows(adminPage, a, 'vms', /failed to fetch vms/i, /no virtual machines found/i);
    });

    test('shows each VM state as a lowercase badge', async ({ adminPage, sdk }) => {
      const id = await seedVM(sdk, unique('e2e-badge-vm'));
      try {
        const a = await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
        await expectListShows(adminPage, a, 'vms', /failed to fetch vms/i, /no virtual machines found/i);
        for (const vm of items(a, 'vms').slice(0, 5)) {
          const text = badge(vm.state, 'VM_STATE_');
          if (text) await expect(adminPage.locator(`text=${text}`).first()).toBeVisible();
        }
      } finally {
        if (id) await sdk.compute.deleteVM({ id });
      }
    });

    test('shows the empty, not-available or error state the server answers', async ({ adminPage }) => {
      const a = await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
      await expectListShows(adminPage, a, 'vms', /failed to fetch vms/i, /no virtual machines found/i);
      if (a.status >= 400 && !notConfigured(a)) {
        // A refusal without the registry discriminator is an error, not compute-absent.
        await expect(adminPage.getByText(NOT_AVAILABLE)).not.toBeVisible();
      }
    });

    test('filters VMs by the status dropdown', async ({ adminPage, sdk }) => {
      const name = unique('e2e-filter-vm');
      const id = await seedVM(sdk, name);
      try {
        const a = await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
        const vms = items(a, 'vms');
        if (a.status >= 400 || vms.length === 0) {
          await expectListShows(adminPage, a, 'vms', /failed to fetch vms/i, /no virtual machines found/i);
          return;
        }
        await expect(adminPage.getByText(vms[0].config?.name ?? '').first()).toBeVisible();
        await adminPage.getByRole('combobox').click();
        await adminPage.getByRole('option', { name: /stopped/i }).click();
        for (const vm of vms.slice(0, 5)) {
          const row = adminPage.getByRole('row', { name: new RegExp(vm.config?.name ?? '', 'i') });
          if (badge(vm.state, 'VM_STATE_') === 'stopped') await expect(row).toBeVisible();
          else await expect(row).not.toBeVisible();
        }
      } finally {
        if (id) await sdk.compute.deleteVM({ id });
      }
    });
  });

  test.describe('Snapshots availability', () => {
    test('shows the not-available or error state the server answers', async ({ adminPage }) => {
      const a = await open(adminPage, '/compute/snapshots', '/api/v1/compute/vms');
      if (notConfigured(a)) {
        await expect(adminPage.getByText(NOT_AVAILABLE)).toBeVisible();
        await expect(adminPage.getByText(/error loading snapshots/i)).not.toBeVisible();
      } else if (a.status >= 400) {
        await expect(adminPage.getByText(/error loading snapshots/i).first()).toBeVisible();
        await expect(adminPage.getByText(NOT_AVAILABLE)).not.toBeVisible();
      } else {
        await expect(adminPage.getByText(NOT_AVAILABLE)).not.toBeVisible();
      }
    });
  });

  test.describe('VM operations', () => {
    test('opens the create VM dialog', async ({ adminPage }) => {
      const a = await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
      if (notConfigured(a)) {
        await expect(adminPage.getByText(NOT_AVAILABLE)).toBeVisible();
        return;
      }
      await adminPage.getByRole('button', { name: /create vm/i }).click();
      await expect(adminPage.getByRole('dialog')).toBeVisible();
      await expect(adminPage.getByRole('heading', { name: /create.*virtual machine|new vm/i })).toBeVisible();
    });

    test('creates a VM, or shows the server refusing it', async ({ adminPage, sdk }) => {
      const a = await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
      if (notConfigured(a)) {
        await expect(adminPage.getByText(NOT_AVAILABLE)).toBeVisible();
        return;
      }
      const name = unique('e2e-new-vm');
      await adminPage.getByRole('button', { name: /create vm/i }).click();
      await adminPage.fill('input[name="name"]', name);
      const res = adminPage.waitForResponse((r) => r.request().method() === 'POST' && isPath('/api/v1/compute/vms')(r));
      await adminPage.getByRole('button', { name: /create/i }).last().click();
      const created = await answerOf(await res);
      const vm = created.body.vm as Named | undefined;
      try {
        if (created.status < 400) {
          await expect(adminPage.getByText(/virtual machine created successfully/i)).toBeVisible();
          await expect(adminPage.getByText(name).first()).toBeVisible();
          const list = await sdk.compute.listVMs();
          expect(list.data?.vms.some((v) => v.config.name === name)).toBe(true);
        } else {
          await expect(adminPage.getByText(/virtual machine created successfully/i)).not.toBeVisible();
          await expect(adminPage.getByText(/error|failed/i).first()).toBeVisible();
        }
      } finally {
        if (vm?.id) await sdk.compute.deleteVM({ id: vm.id });
      }
    });

    for (const op of [
      { item: /start/i, success: /vm started successfully/i, label: 'starts a stopped VM' },
      // VMTable shows Stop and Reboot only for a running VM: these seed one started.
      { item: /stop/i, success: /vm stopped successfully/i, label: 'stops a VM', start: true },
      { item: /reboot/i, success: /vm rebooted successfully/i, label: 'reboots a VM', start: true },
    ]) {
      test(`${op.label}, or shows the server's refusal`, async ({ adminPage, sdk }) => {
        const name = unique('e2e-op-vm');
        const id = await seedVM(sdk, name, op.start);
        try {
          const a = await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
          if (!id) {
            // No VM could be seeded (no hypervisor): the list shows what the server answers.
            await expectListShows(adminPage, a, 'vms', /failed to fetch vms/i, /no virtual machines found/i);
            await expect(adminPage.getByRole('cell', { name })).toHaveCount(0);
            return;
          }
          await expect(adminPage.getByRole('cell', { name })).toBeVisible();
          if (op.start) {
            const vmState = async () => {
              const res = await sdk.compute.getVM(id).catch(() => null);
              return String(res?.data?.vm?.state ?? '');
            };
            const running = await expect
              .poll(vmState, { timeout: 30_000 })
              .toBe('VM_STATE_RUNNING')
              .then(() => true)
              .catch(() => false);
            if (!running) {
              // The backend did not start the VM: the page offers no Stop or Reboot.
              await adminPage.getByRole('row', { name: new RegExp(name, 'i') }).getByRole('button').click();
              await expect(adminPage.getByRole('menuitem', { name: op.item })).toHaveCount(0);
              return;
            }
            // The list the page loaded predates the start: reload it.
            await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
            await expect(adminPage.getByRole('cell', { name })).toBeVisible();
          }
          await rowAction(adminPage, name, op.item, 'POST', id, op.success);
        } finally {
          if (id) await sdk.compute.deleteVM({ id });
        }
      });
    }

    test('deletes a VM, or shows the server refusing it', async ({ adminPage, sdk }) => {
      const name = unique('e2e-del-vm');
      const id = await seedVM(sdk, name);
      let deleted = false;
      try {
        const a = await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
        if (!id) {
          await expectListShows(adminPage, a, 'vms', /failed to fetch vms/i, /no virtual machines found/i);
          return;
        }
        adminPage.on('dialog', (d) => d.accept());
        await expect(adminPage.getByRole('cell', { name })).toBeVisible();
        const res = await rowAction(adminPage, name, /delete/i, 'DELETE', id, /vm deleted successfully/i);
        if (res.status < 400) {
          deleted = true;
          await expect(adminPage.getByText(name)).not.toBeVisible();
          const list = await sdk.compute.listVMs();
          expect(list.data?.vms.some((v) => v.id === id)).toBe(false);
        }
      } finally {
        if (id && !deleted) await sdk.compute.deleteVM({ id });
      }
    });
  });

  test.describe('Containers', () => {
    test('shows the container list, or the state of the list answer', async ({ adminPage }) => {
      const a = await open(adminPage, '/compute/containers', '/api/v1/compute/containers');
      await expect(adminPage.getByRole('heading', { name: /containers/i }).first()).toBeVisible();
      await expectListShows(adminPage, a, 'containers', /failed to fetch containers/i, /no containers found/i);
    });

    test('shows each container state as a lowercase badge', async ({ adminPage, sdk }) => {
      const id = await seedContainer(sdk, unique('e2e-badge-ctr'));
      try {
        const a = await open(adminPage, '/compute/containers', '/api/v1/compute/containers');
        await expectListShows(adminPage, a, 'containers', /failed to fetch containers/i, /no containers found/i);
        for (const c of items(a, 'containers').slice(0, 5)) {
          const text = badge(c.state, 'CONTAINER_STATE_');
          if (text) await expect(adminPage.locator(`text=${text}`).first()).toBeVisible();
        }
      } finally {
        if (id) await sdk.compute.deleteContainer({ id, force: true });
      }
    });

    for (const op of [
      { item: /start/i, method: 'POST', success: /container started successfully/i, label: 'starts a container' },
      { item: /stop/i, method: 'POST', success: /container stopped successfully/i, label: 'stops a container' },
      { item: /delete/i, method: 'DELETE', success: /container deleted successfully/i, label: 'deletes a container' },
    ]) {
      test(`${op.label}, or shows the server's refusal`, async ({ adminPage, sdk }) => {
        const name = unique('e2e-op-ctr');
        const id = await seedContainer(sdk, name);
        try {
          const a = await open(adminPage, '/compute/containers', '/api/v1/compute/containers');
          if (!id) {
            await expectListShows(adminPage, a, 'containers', /failed to fetch containers/i, /no containers found/i);
            await expect(adminPage.getByRole('cell', { name })).toHaveCount(0);
            return;
          }
          await expect(adminPage.getByRole('cell', { name })).toBeVisible();
          const res = await rowAction(adminPage, name, op.item, op.method, id, op.success);
          if (op.method === 'DELETE' && res.status < 400) {
            const list = await sdk.compute.listContainers();
            expect(list.data?.containers.some((c) => c.id === id)).toBe(false);
          }
        } finally {
          if (id) await sdk.compute.deleteContainer({ id, force: true });
        }
      });
    }
  });

  test.describe('Snapshots', () => {
    test('lists snapshots, or the state of the server answer', async ({ adminPage, sdk }) => {
      const vmId = await seedVM(sdk, unique('e2e-snap-vm'));
      const snapName = unique('e2e-snap');
      let snapId: string | undefined;
      try {
        if (vmId) {
          const snap = await sdk.compute.createSnapshot({ vmId, config: { name: snapName } });
          snapId = snap.data?.snapshot?.id;
        }
        const a = await open(adminPage, '/compute/snapshots', '/api/v1/compute/vms');
        await expect(adminPage.getByRole('heading', { name: /snapshots/i }).first()).toBeVisible();
        if (a.status >= 400) {
          await expect(adminPage.getByText(notConfigured(a) ? NOT_AVAILABLE : /error loading snapshots/i).first()).toBeVisible();
        } else if (items(a, 'vms').length === 0) {
          await expect(adminPage.getByText(/no vms are currently running|no snapshots/i).first()).toBeVisible();
        } else if (snapId) {
          await expect(adminPage.getByText(snapName)).toBeVisible();
        } else {
          await expect(adminPage.getByText(/no snapshots have been created yet|no snapshots/i).first()).toBeVisible();
        }
      } finally {
        if (vmId && snapId) await sdk.compute.deleteSnapshot({ vmId, snapshotId: snapId });
        if (vmId) await sdk.compute.deleteVM({ id: vmId });
      }
    });

    for (const op of [
      { item: /restore/i, method: 'POST', success: /restore.*initiated|restoring/i, label: 'restores from a snapshot' },
      { item: /delete/i, method: 'DELETE', success: /^Snapshot deleted$/, label: 'deletes a snapshot' },
    ]) {
      test(`${op.label}, or shows the server's refusal`, async ({ adminPage, sdk }) => {
        const vmId = await seedVM(sdk, unique('e2e-snapop-vm'));
        const snapName = unique('e2e-snapop');
        let snapId: string | undefined;
        try {
          if (vmId) {
            const snap = await sdk.compute.createSnapshot({ vmId, config: { name: snapName } });
            snapId = snap.data?.snapshot?.id;
          }
          await open(adminPage, '/compute/snapshots', '/api/v1/compute/vms');
          if (!snapId) {
            // No VM or snapshot could be seeded: the seeded name is not listed.
            await expect(adminPage.getByText(snapName)).toHaveCount(0);
            return;
          }
          adminPage.on('dialog', (d) => d.accept());
          await expect(adminPage.getByText(snapName)).toBeVisible();
          await rowAction(adminPage, snapName, op.item, op.method, snapId, op.success);
        } finally {
          if (vmId && snapId) await sdk.compute.deleteSnapshot({ vmId, snapshotId: snapId });
          if (vmId) await sdk.compute.deleteVM({ id: vmId });
        }
      });
    }
  });

  test.describe('Access control', () => {
    test('lets the signed-in tenant admin view the VMs page', async ({ adminPage }) => {
      await open(adminPage, '/compute/vms', '/api/v1/compute/vms');
      await expect(adminPage).toHaveURL(/\/compute\/vms/);
      await expect(adminPage.getByRole('heading', { name: /virtual machines/i })).toBeVisible();
    });

    test('redirects a signed-out visitor to login', async ({ page }) => {
      await page.goto('/compute/vms');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  });
});
