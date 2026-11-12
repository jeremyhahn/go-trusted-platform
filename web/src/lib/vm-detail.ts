import type { VM } from 'trusted-platform-sdk';
import type { VMDetail } from '@/types/infrastructure';
import { vmStatus } from '@/lib/compute-state';

function num(value: number | undefined | null): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

/**
 * toVMDetail maps the GetVM response (a proto VM with a nested config and
 * no snapshots) to the detail page's VMDetail view. Lists the response does
 * not carry start empty; every missing number is 0.
 */
export function toVMDetail(vm: VM): VMDetail {
  const config = vm.config;
  const metrics = vm.metrics;
  const memUsed = num(metrics?.memoryUsedMb);
  const memTotal = memUsed + num(metrics?.memoryAvailableMb);
  const storageMB = (config?.disks ?? []).reduce(
    (sum, disk) => sum + num(disk.sizeGb) * 1024,
    0
  );

  return {
    id: vm.id,
    name: config?.name ?? '',
    description: config?.description,
    status: vmStatus(vm.state),
    vcpus: num(config?.cpu?.cores),
    memoryMB: num(config?.memory?.sizeMb),
    storageMB,
    createdAt: vm.createdAt,
    osType: config?.labels?.os ?? '',
    bootOrder: [],
    snapshots: [],
    disks: [],
    networkInterfaces: [],
    metrics: {
      cpuUsagePercent: num(metrics?.cpuUsagePercent),
      memoryUsagePercent: memTotal > 0 ? (memUsed / memTotal) * 100 : 0,
      diskUsagePercent: 0,
      networkInMbps: 0,
      networkOutMbps: 0,
    },
  };
}
