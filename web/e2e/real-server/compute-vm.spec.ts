/**
 * Real-server spec for the compute-vm row (#2044, epic #1665).
 *
 * Every operation of the row is seeded and checked through the SDK client
 * against the harness server, and the VM detail page is driven as the
 * seeded admin. No route mocks: assertions are on what the server returns.
 */
import type { Page } from "@playwright/test";
import type { PlatformClient } from "trusted-platform-sdk";
import { test, expect } from "./fixtures";

interface Fixtures {
  adminPage: Page;
  sdk: PlatformClient;
  tenant: { id: string; name: string };
}

const suffix = () => Math.random().toString(36).slice(2, 8);

/** Creates a stopped VM through the SDK and returns its ID. */
async function seedVM(sdk: PlatformClient, tenantName: string): Promise<string> {
  const name = `e2e-${tenantName}-vm-${suffix()}`.toLowerCase();
  const created = await sdk.compute.createVM({
    config: {
      name,
      cpu: { cores: 1 },
      memory: { sizeMb: 256 },
      disks: [{ path: `/tmp/${name}.qcow2`, type: "DISK_TYPE_QCOW2", sizeGb: 1 }],
    },
    start: false,
  } as Parameters<PlatformClient["compute"]["createVM"]>[0]);
  expect(created.success, created.error?.message).toBe(true);
  const data = created.data as { vm?: { id?: string }; id?: string } | undefined;
  const id = data?.vm?.id ?? data?.id;
  expect(id).toBeTruthy();
  return id as string;
}

test.describe("compute VM operations (real server)", () => {
  test("GetVM: the detail page shows the VM the server returns", async ({ adminPage, sdk, tenant }: Fixtures) => {
    const vmId = await seedVM(sdk, tenant.name);
    const got = await sdk.compute.getVM(vmId);
    expect(got.success).toBe(true);

    await adminPage.goto(`/compute/vms/${vmId}`);
    await expect(adminPage.getByText(vmId).first()).toBeVisible();
    await expect(adminPage.getByTestId("vm-operations")).toBeVisible();
  });

  test("SuspendVM and ResumeVM change the state the server reports", async ({ sdk, tenant }: Fixtures) => {
    const vmId = await seedVM(sdk, tenant.name);
    expect((await sdk.compute.startVM(vmId)).success).toBe(true);

    const suspended = await sdk.compute.suspendVM(vmId);
    expect(suspended.success, suspended.error?.message).toBe(true);
    const afterSuspend = await sdk.compute.getVM(vmId);
    expect(JSON.stringify(afterSuspend.data)).toMatch(/suspend|paus/i);

    const resumed = await sdk.compute.resumeVM(vmId);
    expect(resumed.success, resumed.error?.message).toBe(true);
    const afterResume = await sdk.compute.getVM(vmId);
    expect(JSON.stringify(afterResume.data)).toMatch(/running/i);
  });

  test("AttestVM and GetVMMetrics: the detail page shows the server's answers", async ({ adminPage, sdk, tenant }: Fixtures) => {
    const vmId = await seedVM(sdk, tenant.name);
    expect((await sdk.compute.startVM(vmId)).success).toBe(true);

    const metrics = await sdk.compute.getVMMetrics(vmId);
    expect(metrics.success, metrics.error?.message).toBe(true);

    await adminPage.goto(`/compute/vms/${vmId}`);
    await adminPage.getByRole("button", { name: "Load Metrics" }).click();
    await expect(adminPage.getByTestId("vm-live-metrics")).toContainText("CPU:");

    await adminPage.getByRole("button", { name: "Attest VM" }).click();
    const attestation = adminPage.getByTestId("vm-attestation");
    await expect(attestation).not.toContainText("No attestation collected");
  });

  test("AttachDisk, ResizeDisk and DetachDisk through the Disks card", async ({ adminPage, sdk, tenant }: Fixtures) => {
    const vmId = await seedVM(sdk, tenant.name);
    const diskId = `disk-${suffix()}`;

    await adminPage.goto(`/compute/vms/${vmId}`);
    await adminPage.getByLabel("Disk path").fill(`/tmp/${diskId}.qcow2`);
    await adminPage.getByLabel("Size GB", { exact: true }).fill("1");
    await adminPage.getByLabel("Disk ID").fill(diskId);
    await adminPage.getByRole("button", { name: "Attach Disk" }).click();
    await expect(adminPage.getByTestId("vm-disk-result")).toContainText(`as ${diskId}`);

    const attached = await sdk.compute.getVM(vmId);
    expect(JSON.stringify(attached.data)).toContain(diskId);

    await adminPage.getByLabel("New size GB").fill("2");
    await adminPage.getByRole("button", { name: "Resize Disk" }).click();
    await expect(adminPage.getByTestId("vm-disk-result")).toContainText(`Resized ${diskId} to 2 GB`);

    await adminPage.getByRole("button", { name: "Detach Disk" }).click();
    await adminPage.getByRole("button", { name: "Confirm" }).click();
    await expect(adminPage.getByTestId("vm-disk-result")).toContainText(`Detached ${diskId}`);

    const detached = await sdk.compute.getVM(vmId);
    expect(JSON.stringify(detached.data)).not.toContain(diskId);
  });

  test("CreateSnapshot and GetSnapshot: the page shows the snapshot the server stored", async ({ adminPage, sdk, tenant }: Fixtures) => {
    const vmId = await seedVM(sdk, tenant.name);
    const name = `snap-${suffix()}`;

    await adminPage.goto(`/compute/vms/${vmId}`);
    await adminPage.getByLabel("Snapshot name").fill(name);
    await adminPage.getByRole("button", { name: "Take Snapshot" }).click();
    const detail = adminPage.getByTestId("vm-snapshot-detail");
    await expect(detail).toContainText(name);

    const snapshotId = await adminPage.getByLabel("Snapshot ID").inputValue();
    expect(snapshotId).toBeTruthy();
    const got = await sdk.compute.getSnapshot(vmId, snapshotId);
    expect(got.success, got.error?.message).toBe(true);
    expect(JSON.stringify(got.data)).toContain(name);

    await adminPage.getByRole("button", { name: "Get Snapshot" }).click();
    await expect(detail).toContainText(snapshotId);
  });

  test("MigrateVM: live migration is gated off with its reason", async ({ adminPage, sdk, tenant }: Fixtures) => {
    const vmId = await seedVM(sdk, tenant.name);
    await adminPage.goto(`/compute/vms/${vmId}`);
    const live = adminPage.getByRole("checkbox");
    await expect(live).toBeDisabled();
    await expect(adminPage.getByTitle(/Live migration is unavailable/)).toBeVisible();
    await expect(adminPage.getByRole("button", { name: "Migrate VM" })).toBeVisible();
  });

  test("PrepareMigration and FinalizeMigration: an aborted receiver is refused on reuse", async ({ adminPage, sdk, tenant }: Fixtures) => {
    const vmId = await seedVM(sdk, tenant.name);
    const vm = await sdk.compute.getVM(vmId);
    expect(vm.success).toBe(true);

    const prepared = await sdk.compute.prepareMigration({
      vmName: `e2e-${tenant.name}-rx-${suffix()}`.toLowerCase(),
      vmId,
      mode: "cold",
      spec: { memoryMb: 256, cpus: 1 },
    });
    expect(prepared.success, prepared.error?.message).toBe(true);
    const receiverId = (prepared.data as { receiverId?: string } | undefined)?.receiverId;
    expect(receiverId).toBeTruthy();

    const aborted = await sdk.compute.finalizeMigration({ receiverId: receiverId as string, commit: false });
    expect(aborted.success, aborted.error?.message).toBe(true);

    const again = await sdk.compute.finalizeMigration({ receiverId: receiverId as string, commit: true });
    expect(again.success && (again.data as { status?: { success?: boolean } })?.status?.success !== false).toBe(false);

    await adminPage.goto("/compute/migrations");
    await expect(adminPage.getByRole("button", { name: "Prepare Migration" })).toBeVisible();
  });
});
