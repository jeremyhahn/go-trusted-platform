import { describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useDnsOps, type DnsOpsService } from './use-dns-ops';

function ok<T>(data: T) {
  return Promise.resolve({ success: true, data });
}

function fakeService(overrides: Partial<Record<keyof DnsOpsService, unknown>> = {}) {
  const svc = {
    updateZone: vi.fn(() => ok({ status: { success: true, message: '' }, zone: { id: 1, name: 'z', ttl: 7200, internal: false } })),
    signZone: vi.fn(() => ok({ status: { success: true, message: 'signed' } })),
    getDNSSECStatus: vi.fn(() => ok({ status: { enabled: true, zoneSigned: true, algorithm: 'ECDSAP256SHA256' } })),
    addRecord: vi.fn(() => ok({ status: { success: true, message: '' } })),
    updateRecord: vi.fn(() => ok({ status: { success: true, message: '' } })),
    deleteRecord: vi.fn(() => ok({ status: { success: true, message: '' } })),
    listRecords: vi.fn(() => ok({ records: [{ type: 'RECORD_TYPE_A', a: { name: 'www', value: '192.0.2.1', ttl: 300 } }] })),
    resolve: vi.fn(() => ok({ records: [{ type: 'RECORD_TYPE_A', a: { name: 'h', value: '192.0.2.9', ttl: 60 } }], authoritative: true })),
    register: vi.fn(() => ok({ status: { success: true, message: '' } })),
    ...overrides,
  };
  return svc as unknown as DnsOpsService & Record<keyof DnsOpsService, ReturnType<typeof vi.fn>>;
}

describe('useDnsOps', () => {
  it('passes each operation to its SDK method and returns the server data', async () => {
    const svc = fakeService();
    const { result } = renderHook(() => useDnsOps(svc));
    const out: unknown[] = [];
    await act(async () => {
      out.push(await result.current.updateZone({ name: 'z', ttl: 7200, description: 'd' }));
      out.push(await result.current.listRecords('z', 'A'));
      out.push(await result.current.getDNSSECStatus('z'));
      out.push(await result.current.signZone('z'));
      out.push(await result.current.resolve('h.z', 'A'));
      out.push(await result.current.register('h.z', '192.0.2.9'));
    });
    expect(svc.updateZone).toHaveBeenCalledWith({ name: 'z', ttl: 7200, description: 'd' });
    expect(svc.listRecords).toHaveBeenCalledWith({ zoneName: 'z', type: 'A' });
    expect(svc.getDNSSECStatus).toHaveBeenCalledWith('z');
    expect(svc.signZone).toHaveBeenCalledWith('z');
    expect(svc.resolve).toHaveBeenCalledWith({ fqdn: 'h.z', type: 'A' });
    expect(svc.register).toHaveBeenCalledWith({ fqdn: 'h.z', ip: '192.0.2.9' });
    expect((out[0] as { zone: { ttl: number } }).zone.ttl).toBe(7200);
    expect(out[1]).toEqual([{ type: 'RECORD_TYPE_A', a: { name: 'www', value: '192.0.2.1', ttl: 300 } }]);
    expect(out[2]).toEqual({ enabled: true, zoneSigned: true, algorithm: 'ECDSAP256SHA256' });
    expect((out[4] as { records: unknown[] }).records).toHaveLength(1);
    expect(result.current.error).toBeNull();
  });

  it('omits the type filter when listing every type', async () => {
    const svc = fakeService();
    const { result } = renderHook(() => useDnsOps(svc));
    await act(async () => {
      await result.current.listRecords('z');
    });
    expect(svc.listRecords).toHaveBeenCalledWith({ zoneName: 'z' });
  });

  it('adds, updates and deletes records through the SDK', async () => {
    const svc = fakeService();
    const { result } = renderHook(() => useDnsOps(svc));
    const a = { type: 'A' as const, a: { name: 'www', value: '192.0.2.1', ttl: 300 } };
    const b = { type: 'A' as const, a: { name: 'www', value: '192.0.2.2', ttl: 300 } };
    let added: unknown;
    let deleted: unknown;
    await act(async () => {
      added = await result.current.addRecord('z', a);
      await result.current.updateRecord('z', a, b);
      deleted = await result.current.deleteRecord('z', 'A', 'www');
    });
    expect(added).toBe(true);
    expect(deleted).toBe(true);
    expect(svc.addRecord).toHaveBeenCalledWith({ zoneName: 'z', record: a });
    expect(svc.updateRecord).toHaveBeenCalledWith({ zoneName: 'z', oldRecord: a, newRecord: b });
    expect(svc.deleteRecord).toHaveBeenCalledWith({ zoneName: 'z', type: 'A', name: 'www' });
  });

  it('reports the server error of a failed response and returns null', async () => {
    const svc = fakeService({
      signZone: vi.fn(() => Promise.resolve({ success: false, error: { message: 'no DNSSEC signer configured' } })),
    });
    const { result } = renderHook(() => useDnsOps(svc));
    let out: unknown = 'unset';
    await act(async () => {
      out = await result.current.signZone('z');
    });
    expect(out).toBeNull();
    expect(result.current.error).toBe('no DNSSEC signer configured');
  });

  it('treats a DNSStatus with success false as a failure', async () => {
    const svc = fakeService({
      register: vi.fn(() => ok({ status: { success: false, message: 'zone not found' } })),
    });
    const { result } = renderHook(() => useDnsOps(svc));
    let out: unknown = 'unset';
    await act(async () => {
      out = await result.current.register('h.nowhere', '192.0.2.9');
    });
    expect(out).toBeNull();
    expect(result.current.error).toBe('zone not found');
  });

  it('reports a thrown transport error', async () => {
    const svc = fakeService({ listRecords: vi.fn(() => Promise.reject(new Error('network down'))) });
    const { result } = renderHook(() => useDnsOps(svc));
    let out: unknown = 'unset';
    await act(async () => {
      out = await result.current.listRecords('z');
    });
    expect(out).toBeNull();
    expect(result.current.error).toBe('network down');
  });
});
