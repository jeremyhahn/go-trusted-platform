import { describe, expect, it } from 'vitest';
import type { VerifyVMAttestationResponse, VM } from 'trusted-platform-sdk';
import { toVMDetail, VM_PCRS_NOT_APPRAISED, vmVerifyHeadline } from './vm-detail';

const protoVM = {
  id: 'vm-1',
  config: {
    name: 'build-vm',
    description: 'ci builder',
    cpu: { cores: 4 },
    memory: { sizeMb: 4096 },
    disks: [{ path: '/var/lib/vm/a.qcow2', sizeGb: 10 }, { path: '/var/lib/vm/b.qcow2' }],
    networks: [],
    labels: { os: 'linux' },
  },
  state: 'VM_STATE_RUNNING',
  createdAt: '2026-11-12T00:00:00Z',
  updatedAt: '2026-11-12T00:00:00Z',
  metrics: { cpuUsagePercent: 12 },
} as unknown as VM;

describe('toVMDetail', () => {
  it('maps the nested GetVM config to the detail view', () => {
    const vm = toVMDetail(protoVM);
    expect(vm.id).toBe('vm-1');
    expect(vm.name).toBe('build-vm');
    expect(vm.description).toBe('ci builder');
    expect(vm.vcpus).toBe(4);
    expect(vm.memoryMB).toBe(4096);
    expect(vm.storageMB).toBe(10 * 1024);
    expect(vm.status).toBe('running');
    expect(vm.osType).toBe('linux');
    expect(vm.createdAt).toBe('2026-11-12T00:00:00Z');
  });

  it('initialises the lists the response does not carry', () => {
    const vm = toVMDetail(protoVM);
    expect(vm.snapshots).toEqual([]);
    expect(vm.bootOrder).toEqual([]);
    expect(vm.disks).toEqual([]);
    expect(vm.networkInterfaces).toEqual([]);
  });

  it('fills every missing metric with 0', () => {
    expect(toVMDetail(protoVM).metrics).toEqual({
      cpuUsagePercent: 12,
      memoryUsagePercent: 0,
      diskUsagePercent: 0,
      networkInMbps: 0,
      networkOutMbps: 0,
    });
  });

  it('derives memory usage from used and available MB', () => {
    const vm = toVMDetail({
      ...protoVM,
      metrics: { cpuUsagePercent: 1, memoryUsedMb: 256, memoryAvailableMb: 768 },
    } as unknown as VM);
    expect(vm.metrics.memoryUsagePercent).toBe(25);
  });

  it('maps protojson uint64 strings', () => {
    const vm = toVMDetail({
      ...protoVM,
      config: {
        ...protoVM.config,
        memory: { sizeMb: '4096' },
        disks: [
          { path: 'a', sizeGb: '10' },
          { path: 'b', sizeGb: '2' },
        ],
      },
      metrics: { cpuUsagePercent: 12, memoryUsedMb: '256', memoryAvailableMb: '768' },
    } as unknown as VM);
    expect(vm.memoryMB).toBe(4096);
    expect(vm.storageMB).toBe(12 * 1024);
    expect(vm.metrics.memoryUsagePercent).toBe(25);
  });

  it('maps a malformed integer string to 0', () => {
    for (const sizeMb of ['4e3', '-1', '', ' 42', 'abc', '99999999999999999999']) {
      const vm = toVMDetail({
        ...protoVM,
        config: { ...protoVM.config, memory: { sizeMb } },
      } as unknown as VM);
      expect(vm.memoryMB, sizeMb).toBe(0);
    }
  });

  it('tolerates a VM without config or metrics', () => {
    const vm = toVMDetail({ id: 'vm-2', state: 'VM_STATE_STOPPED' } as unknown as VM);
    expect(vm.name).toBe('');
    expect(vm.vcpus).toBe(0);
    expect(vm.storageMB).toBe(0);
    expect(vm.status).toBe('stopped');
    expect(vm.metrics.cpuUsagePercent).toBe(0);
  });
});

describe('vmVerifyHeadline', () => {
  const ok = { success: true } as unknown as VerifyVMAttestationResponse['status'];

  it('names what was checked, even with unexpected PCR measurements', () => {
    const headline = vmVerifyHeadline({
      status: ok,
      verified: true,
      actualPcrs: [{ index: 0, value: '/////w==' }],
    } as VerifyVMAttestationResponse);
    expect(headline).toBe('Quote signature and nonce verified');
    expect(headline).not.toMatch(/^Attestation verified$/);
  });

  it('reports a failed verification as not verified', () => {
    expect(vmVerifyHeadline({ status: ok, verified: false })).toBe('Attestation not verified');
  });

  it('says the PCRs were not appraised', () => {
    expect(VM_PCRS_NOT_APPRAISED).toMatch(/not appraised/);
  });
});
