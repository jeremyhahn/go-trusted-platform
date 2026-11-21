"use client";

/**
 * VM disk operations through the SDK client.
 *
 * AttachDisk, DetachDisk and ResizeDisk go through `client.compute`
 * (`POST`, `DELETE` and `PATCH /api/v1/compute/vms/{id}/disks[/{diskId}]`).
 * The attached disks are read from GetVM (`vm.config.disks`).
 *
 * GetSnapshot is `GET /api/v1/compute/vms/{id}/snapshots/{snapshotId}`, sent on
 * the SDK API client because the SDK ComputeService has no method for it on main.
 */

import { useMemo } from "react";
import {
  usePlatformClient,
  type ApiResponse,
  type DiskConfig,
  type DiskType,
  type DiskBus,
  type Snapshot,
} from "trusted-platform-sdk";

export const DISK_TYPES: DiskType[] = ['DISK_TYPE_QCOW2', 'DISK_TYPE_RAW', 'DISK_TYPE_VDI', 'DISK_TYPE_VMDK'];
export const DISK_BUSES: DiskBus[] = ['DISK_BUS_VIRTIO', 'DISK_BUS_SCSI', 'DISK_BUS_SATA', 'DISK_BUS_NVME', 'DISK_BUS_IDE'];

/** 'DISK_TYPE_QCOW2' -> 'QCOW2', 'DISK_BUS_VIRTIO' -> 'VIRTIO'; undefined -> '-'. */
export function diskEnumLabel(v?: string): string {
  if (!v) return '-';
  return v.replace(/^DISK_(TYPE|BUS)_/, '');
}

export function snapshotPath(vmId: string, snapshotId: string): string {
  return `/v1/compute/vms/${encodeURIComponent(vmId)}/snapshots/${encodeURIComponent(snapshotId)}`;
}

/** A whole number of GB >= 1, from a form string; otherwise null. */
export function parseSizeGb(s: string): number | null {
  const t = s.trim();
  if (!/^\d+$/.test(t)) return null;
  const n = Number(t);
  return Number.isSafeInteger(n) && n >= 1 ? n : null;
}

export function useVMDisks(vmId: string) {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      listDisks: async (): Promise<ApiResponse<DiskConfig[]>> => {
        const res = await client.compute.getVM(vmId);
        return res.success
          ? { success: true, data: res.data?.vm.config?.disks ?? [], error: res.error }
          : { success: false, data: undefined, error: res.error };
      },
      attach: (disk: DiskConfig) => client.compute.attachDisk({ vmId, disk }),
      detach: (diskId: string) => client.compute.detachDisk({ vmId, diskId }),
      resize: (diskId: string, newSizeGb: number) => client.compute.resizeDisk({ vmId, diskId, newSizeGb }),
      getSnapshot: (snapshotId: string) => api.get<{ snapshot: Snapshot }>(snapshotPath(vmId, snapshotId)),
    };
  }, [client, vmId]);
}
