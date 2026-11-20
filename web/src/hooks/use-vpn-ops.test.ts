import { cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const service = {
  enrolPeer: vi.fn(),
  revokePeer: vi.fn(),
  getPosturePolicy: vi.fn(),
  setPosturePolicy: vi.fn(),
  deletePosturePolicy: vi.fn(),
};

vi.mock('trusted-platform-sdk', () => ({
  useVPN: () => service,
}));

import { parseZones, useVpnOps } from './use-vpn-ops';

const ok = <T>(data: T) => ({ success: true, data });
const fail = (message: string) => ({ success: false, error: { code: 'INVALID_ARGUMENT', message } });

describe('parseZones', () => {
  it('splits on commas, trims, drops empties and duplicates', () => {
    expect(parseZones(' management, storage,,management ,')).toEqual(['management', 'storage']);
    expect(parseZones('   ')).toEqual([]);
  });
});

describe('useVpnOps', () => {
  beforeEach(() => {
    Object.values(service).forEach((fn) => fn.mockReset());
  });
  afterEach(cleanup);

  it('enrolPeer trims the tenant and device and sends the parsed zones', async () => {
    const peer = { tenantId: 't1', deviceId: 'dev-1', zones: ['mgmt'], enrolledAtUnix: '1' };
    service.enrolPeer.mockResolvedValue(ok({ peer }));
    const { result } = renderHook(() => useVpnOps());

    await expect(
      result.current.enrolPeer({ tenantId: ' t1 ', deviceId: ' dev-1 ', zones: 'mgmt, ' })
    ).resolves.toEqual(peer);
    expect(service.enrolPeer).toHaveBeenCalledWith({ tenantId: 't1', deviceId: 'dev-1', zones: ['mgmt'] });
  });

  it('enrolPeer refuses an empty tenant or device without calling the server', async () => {
    const { result } = renderHook(() => useVpnOps());
    await expect(result.current.enrolPeer({ tenantId: 't1', deviceId: '  ', zones: '' })).rejects.toThrow(
      'Device ID is required'
    );
    await expect(result.current.enrolPeer({ tenantId: '', deviceId: 'd', zones: '' })).rejects.toThrow(
      'Tenant is required'
    );
    expect(service.enrolPeer).not.toHaveBeenCalled();
  });

  it('revokePeer passes the tenant and device and surfaces the server error', async () => {
    service.revokePeer.mockResolvedValue(fail('peer not enrolled'));
    const { result } = renderHook(() => useVpnOps());
    await expect(result.current.revokePeer('t1', 'dev-1')).rejects.toThrow('peer not enrolled');
    expect(service.revokePeer).toHaveBeenCalledWith('t1', 'dev-1');
  });

  it('getPosturePolicy returns the stored policy and fails when none is returned', async () => {
    const policy = { tenantId: 't1', name: 'p', module: 'package vpn.posture\n', updatedAtUnix: '2' };
    service.getPosturePolicy.mockResolvedValueOnce(ok({ policy }));
    const { result } = renderHook(() => useVpnOps());
    await expect(result.current.getPosturePolicy('t1', 'p')).resolves.toEqual(policy);
    expect(service.getPosturePolicy).toHaveBeenCalledWith('t1', 'p');

    service.getPosturePolicy.mockResolvedValueOnce(ok({}));
    await expect(result.current.getPosturePolicy('t1', 'p')).rejects.toThrow('Posture policy p not found');
  });

  it('setPosturePolicy sends only tenant, name and module and surfaces a compile refusal', async () => {
    service.setPosturePolicy.mockResolvedValue(fail('rego_parse_error'));
    const { result } = renderHook(() => useVpnOps());
    await expect(
      result.current.setPosturePolicy({ tenantId: ' t1 ', name: ' p ', module: 'package x', isNew: true })
    ).rejects.toThrow('rego_parse_error');
    expect(service.setPosturePolicy).toHaveBeenCalledWith({ tenantId: 't1', name: 'p', module: 'package x' });
  });

  it('setPosturePolicy refuses an empty module without calling the server', async () => {
    const { result } = renderHook(() => useVpnOps());
    await expect(result.current.setPosturePolicy({ tenantId: 't1', name: 'p', module: ' \n' })).rejects.toThrow(
      'Module is required'
    );
    expect(service.setPosturePolicy).not.toHaveBeenCalled();
  });

  it('deletePosturePolicy passes the tenant and name', async () => {
    service.deletePosturePolicy.mockResolvedValue(ok({}));
    const { result } = renderHook(() => useVpnOps());
    await expect(result.current.deletePosturePolicy('t1', 'p')).resolves.toBeUndefined();
    expect(service.deletePosturePolicy).toHaveBeenCalledWith('t1', 'p');
  });
});
