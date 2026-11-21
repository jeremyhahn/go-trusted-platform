import type { VerifyVMAttestationResponse, VM } from 'trusted-platform-sdk';
import type { VMDetail } from '@/types/infrastructure';
import { vmStatus } from '@/lib/compute-state';

function num(value: unknown): number {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : 0;
  }
  if (typeof value === 'string' && /^\d+$/.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : 0;
  }
  return 0;
}

/**
 * toVMDetail maps the GetVM response (a proto VM with a nested config and
 * no snapshots) to the detail page's VMDetail view. Lists the response does
 * not carry start empty; every missing number is 0. protojson emits uint64
 * fields (memory.sizeMb, disks[].sizeGb, metrics.memoryUsedMb,
 * metrics.memoryAvailableMb) as decimal strings, so num accepts both forms
 * and maps a malformed or out-of-range string to 0.
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


/**
 * VM_PCRS_NOT_APPRAISED is shown under every VM verification verdict: the
 * page sends no expected PCRs (the platform has no trusted reference values
 * for a VM), and VerifyVMAttestation then treats the PCRs as valid.
 */
export const VM_PCRS_NOT_APPRAISED =
  'Boot measurements (PCRs) were not appraised: no reference values were supplied.';

/**
 * vmVerifyHeadline names what a VerifyVMAttestation verdict checked: the
 * quote signature and nonce only. It never claims a full attestation,
 * whatever actualPcrs holds.
 */
export function vmVerifyHeadline(result: VerifyVMAttestationResponse): string {
  return result.verified ? 'Quote signature and nonce verified' : 'Attestation not verified';
}
