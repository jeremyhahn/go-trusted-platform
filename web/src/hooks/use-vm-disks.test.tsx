import type { ReactNode } from 'react';
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { diskEnumLabel, parseSizeGb, snapshotPath, useVMDisks } from './use-vm-disks';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderDisks() {
  return renderHook(() => useVMDisks('vm-1'), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

describe('useVMDisks', () => {
  it('lists the attached disks', async () => {
    stubControlPlane({
      'GET /api/v1/compute/vms/vm-1': ok({
        vm: {
          id: 'vm-1',
          state: 'VM_STATE_RUNNING',
          config: {
            name: 'web-1',
            disks: [
              { id: 'd1', path: '/var/lib/vms/web-1.qcow2', type: 'DISK_TYPE_QCOW2', bus: 'DISK_BUS_VIRTIO', sizeGb: '20' },
            ],
          },
        },
      }),
    });
    const { result } = renderDisks();
    let res: Awaited<ReturnType<typeof result.current.listDisks>> | undefined;
    await act(async () => {
      res = await result.current.listDisks();
    });
    expect(res?.success).toBe(true);
    expect(res?.data).toHaveLength(1);
    expect(res?.data?.[0].id).toBe('d1');
  });

  it('attaches a disk', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/compute/vms/vm-1/disks': ok({ status: { success: true } }),
    });
    const { result } = renderDisks();
    let res: Awaited<ReturnType<typeof result.current.attach>> | undefined;
    await act(async () => {
      res = await result.current.attach({
        path: '/var/lib/vms/data.qcow2',
        type: 'DISK_TYPE_QCOW2',
        bus: 'DISK_BUS_VIRTIO',
        sizeGb: 10,
      });
    });
    expect(res?.success).toBe(true);
    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/compute/vms/vm-1/disks');
    expect(sent[0].body).toEqual({
      disk: { path: '/var/lib/vms/data.qcow2', type: 'DISK_TYPE_QCOW2', bus: 'DISK_BUS_VIRTIO', sizeGb: 10 },
    });
  });

  it('detaches and resizes', async () => {
    const sent = stubControlPlane({
      'DELETE /api/v1/compute/vms/vm-1/disks/d1': ok({ status: { success: true } }),
      'PATCH /api/v1/compute/vms/vm-1/disks/d1': ok({ status: { success: true } }),
    });
    const { result } = renderDisks();
    await act(async () => {
      await result.current.detach('d1');
      await result.current.resize('d1', 40);
    });
    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual([
      'DELETE /api/v1/compute/vms/vm-1/disks/d1',
      'PATCH /api/v1/compute/vms/vm-1/disks/d1',
    ]);
    expect(sent[1].body).toEqual({ newSizeGb: 40 });
  });

  it('surfaces a refused resize', async () => {
    stubControlPlane({
      'PATCH /api/v1/compute/vms/vm-1/disks/d1': refused(400, 'compute: disk can only grow'),
    });
    const { result } = renderDisks();
    let res: Awaited<ReturnType<typeof result.current.resize>> | undefined;
    await act(async () => {
      res = await result.current.resize('d1', 10);
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
    expect(res?.error?.message).toContain('only grow');
  });

  it('reads a snapshot', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/compute/vms/vm-1/snapshots/s%2F1': ok({
        snapshot: {
          id: 's/1',
          vmId: 'vm-1',
          config: { name: 'nightly' },
          createdAt: '2026-11-01T00:00:00Z',
          sizeBytes: '1024',
          vmState: 'VM_STATE_RUNNING',
        },
      }),
    });
    const { result } = renderDisks();
    let res: Awaited<ReturnType<typeof result.current.getSnapshot>> | undefined;
    await act(async () => {
      res = await result.current.getSnapshot('s/1');
    });
    expect(sent[0].path).toBe('/api/v1/compute/vms/vm-1/snapshots/s%2F1');
    expect(res?.data?.snapshot.config.name).toBe('nightly');
  });

  it('labels enums and parses sizes', () => {
    expect(diskEnumLabel('DISK_TYPE_QCOW2')).toBe('QCOW2');
    expect(diskEnumLabel('DISK_BUS_VIRTIO')).toBe('VIRTIO');
    expect(diskEnumLabel(undefined)).toBe('-');
    expect(parseSizeGb('20')).toBe(20);
    expect(parseSizeGb('0')).toBeNull();
    expect(parseSizeGb('1.5')).toBeNull();
    expect(parseSizeGb('x')).toBeNull();
    expect(snapshotPath('a/b', 's1')).toBe('/v1/compute/vms/a%2Fb/snapshots/s1');
  });
});
