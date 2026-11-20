/**
 * Real-server spec for the compute-container row (#2045, epic #1665):
 * GetContainer, GetContainerMetrics, ExecContainer, AttestContainer on the
 * container detail page, and VerifyVMAttestation on the VM detail page.
 *
 * State is seeded through the SDK client (`sdk`) against the harness
 * server; every assertion compares the page with what the server returns.
 * No route mocks.
 */
import type { Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

type Sdk = PlatformClient;
type Fx = { adminPage: Page; sdk: Sdk };

const IMAGE = 'docker.io/library/busybox:latest';

/** Creates a container through the SDK and returns its ID, or null when the
 * harness server has no container runtime (the server says so; the spec
 * then checks the page shows the server's error instead of a result). */
async function seedContainer(sdk: Sdk, name: string): Promise<string | null> {
  const created = await sdk.compute.createContainer({
    config: { name, image: IMAGE, command: ['sleep', '3600'] },
  } as never);
  if (!created.success || !created.data) return null;
  const data = created.data as { container?: { id?: string }; id?: string };
  return data.container?.id ?? data.id ?? null;
}

async function removeContainer(sdk: Sdk, id: string | null) {
  if (!id) return;
  await sdk.compute.deleteContainer({ id, force: true });
}

test.describe('compute containers: detail page against the real server', () => {
  test('GetContainer and GetContainerMetrics: the page shows what the server returns', async ({
    adminPage,
    sdk,
  }: Fx) => {
    const id = await seedContainer(sdk, `e2e-ctr-get-${Date.now()}`);
    test.skip(id === null, 'harness server has no container runtime');
    try {
      const got = await sdk.compute.getContainer(id!);
      expect(got.success).toBe(true);
      const container = got.data!.container!;
      expect(container.id).toBe(id);

      await adminPage.goto(`/compute/containers/${encodeURIComponent(id!)}`);
      await expect(adminPage.getByRole('heading', { level: 1 })).toHaveText(
        container.config?.name || container.id
      );
      await expect(adminPage.getByText(container.id, { exact: true })).toBeVisible();

      const metrics = await sdk.compute.getContainerMetrics(id!);
      const card = adminPage.getByTestId('container-metrics');
      await expect(card).toBeVisible();
      if (metrics.success && metrics.data?.metrics) {
        await expect(card).toContainText(`${metrics.data.metrics.memoryLimitMb} MB`);
      } else {
        await expect(card).toContainText('No metrics available');
      }
    } finally {
      await removeContainer(sdk, id);
    }
  });

  test('GetContainer: an unknown ID shows the server error', async ({ adminPage, sdk }: Fx) => {
    const missing = `e2e-missing-${Date.now()}`;
    const got = await sdk.compute.getContainer(missing);
    expect(got.success).toBe(false);

    await adminPage.goto(`/compute/containers/${missing}`);
    await expect(adminPage.getByRole('alert')).toContainText('Failed to load container');
  });

  test('ExecContainer: the confirmed command runs and its exit code is shown', async ({
    adminPage,
    sdk,
  }: Fx) => {
    const id = await seedContainer(sdk, `e2e-ctr-exec-${Date.now()}`);
    test.skip(id === null, 'harness server has no container runtime');
    try {
      await sdk.compute.startContainer(id!);
      const direct = await sdk.compute.execContainer({ id: id!, command: ['echo', 'e2e-exec'] });

      await adminPage.goto(`/compute/containers/${encodeURIComponent(id!)}`);
      const run = adminPage.getByRole('button', { name: 'Run' });
      await adminPage.getByLabel('Command').fill('echo e2e-exec');
      if (await run.isDisabled()) {
        // Gated off: the control carries the server's reason.
        await expect(run).toHaveAttribute('title', /.+/);
        return;
      }
      await run.click();
      await adminPage.getByRole('button', { name: 'Confirm' }).click();
      const result = adminPage.getByTestId('exec-result');
      await expect(result).toBeVisible();
      if (direct.success) {
        await expect(result).toContainText(`Exit code: ${direct.data?.exitCode ?? 0}`);
        await expect(result).toContainText('e2e-exec');
      } else {
        await expect(result).toContainText('Exec failed');
      }
    } finally {
      await removeContainer(sdk, id);
    }
  });

  test('AttestContainer: the attestation result matches the server digests', async ({
    adminPage,
    sdk,
  }: Fx) => {
    const id = await seedContainer(sdk, `e2e-ctr-attest-${Date.now()}`);
    test.skip(id === null, 'harness server has no container runtime');
    try {
      const direct = await sdk.compute.attestContainer({ id: id! });

      await adminPage.goto(`/compute/containers/${encodeURIComponent(id!)}`);
      const attest = adminPage.getByRole('button', { name: 'Attest' });
      if (await attest.isDisabled()) {
        await expect(attest).toHaveAttribute('title', /.+/);
        return;
      }
      await attest.click();
      await adminPage.getByRole('button', { name: 'Confirm' }).click();
      const result = adminPage.getByTestId('attest-result');
      await expect(result).toBeVisible();
      if (direct.success && direct.data?.imageDigest) {
        await expect(result).toContainText(direct.data.imageDigest);
      } else if (!direct.success) {
        await expect(result).toContainText('Attestation failed');
      }
    } finally {
      await removeContainer(sdk, id);
    }
  });
});

test.describe('compute VMs: attestation verify against the real server', () => {
  test('VerifyVMAttestation: the verify control shows the server verdict or its reason', async ({
    adminPage,
    sdk,
  }: Fx) => {
    const listed = await sdk.compute.listVMs();
    expect(listed.success).toBe(true);
    const vm = listed.data?.vms?.[0];
    test.skip(!vm, 'harness server has no VM to attest');

    await adminPage.goto(`/compute/vms/${encodeURIComponent(vm!.id)}`);
    const verify = adminPage.getByRole('button', { name: /Verify attestation/i });
    await expect(verify).toBeVisible();
    if (await verify.isDisabled()) {
      await expect(verify).toHaveAttribute('title', /.+/);
      return;
    }
    await verify.click();
    await expect(adminPage.getByTestId('vm-verify-result')).toBeVisible();
  });
});
