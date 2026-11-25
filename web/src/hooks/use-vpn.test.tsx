import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useVPN } from '@/hooks';

// #2070: useVPN hands the page the SDK's VPN client; every one of the eight
// VPNService ops goes out with its method, path, query and body.

function renderVPN() {
  return renderHook(() => useVPN(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

// The stub's sent list keeps only the pathname; the query is read from the
// fetch mock's calls.
function sentUrls(): string[] {
  return vi.mocked(fetch).mock.calls.map(([input]) => (input instanceof Request ? input.url : String(input)));
}

function lastQuery(): string {
  const urls = sentUrls();
  return new URL(urls[urls.length - 1]).search;
}

describe('useVPN', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('enrolPeer posts the tenant, device and zones to /vpn/peers', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/vpn/peers': ok({
        peer: { tenantId: 'acme', deviceId: 'laptop-1', zones: ['management'], enrolledAtUnix: '1760300000' },
      }),
    });
    const { result } = renderVPN();
    let res: Awaited<ReturnType<typeof result.current.enrolPeer>> | undefined;
    await act(async () => {
      res = await result.current.enrolPeer({ tenantId: 'acme', deviceId: 'laptop-1', zones: ['management'] });
    });
    expect(res?.success).toBe(true);
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/vpn/peers',
        body: { tenantId: 'acme', deviceId: 'laptop-1', zones: ['management'] },
      },
    ]);
    expect(lastQuery()).toBe('');
  });

  it('enrolPeer with no zones sends an empty zone list', async () => {
    const sent = stubControlPlane({ 'POST /api/v1/vpn/peers': ok({}) });
    const { result } = renderVPN();
    await act(async () => {
      await result.current.enrolPeer({ tenantId: 'acme', deviceId: 'laptop-1' });
    });
    expect(sent).toEqual([
      { method: 'POST', path: '/api/v1/vpn/peers', body: { tenantId: 'acme', deviceId: 'laptop-1', zones: [] } },
    ]);
  });

  it('listPeers reads /vpn/peers with the tenant filter, and with no query when none is given', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/vpn/peers': ok({
        peers: [{ tenantId: 'acme', deviceId: 'laptop-1', zones: ['management'], enrolledAtUnix: '1760300000' }],
      }),
    });
    const { result } = renderVPN();
    await act(async () => {
      await result.current.listPeers('acme');
    });
    expect(lastQuery()).toBe('?tenant_id=acme');
    await act(async () => {
      await result.current.listPeers();
    });
    expect(lastQuery()).toBe('');
    expect(sent).toEqual([
      { method: 'GET', path: '/api/v1/vpn/peers', body: undefined },
      { method: 'GET', path: '/api/v1/vpn/peers', body: undefined },
    ]);
  });

  it('revokePeer deletes the encoded device in its tenant', async () => {
    const sent = stubControlPlane({ 'DELETE /api/v1/vpn/peers/laptop%201': ok({}) });
    const { result } = renderVPN();
    let res: Awaited<ReturnType<typeof result.current.revokePeer>> | undefined;
    await act(async () => {
      res = await result.current.revokePeer('acme', 'laptop 1');
    });
    expect(res?.success).toBe(true);
    expect(sent).toEqual([{ method: 'DELETE', path: '/api/v1/vpn/peers/laptop%201', body: undefined }]);
    expect(lastQuery()).toBe('?tenant_id=acme');
  });

  it('getStatus reads /vpn/status for one gateway, and with no query for an empty gateway', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/vpn/status': ok({ gateways: [] }) });
    const { result } = renderVPN();
    await act(async () => {
      await result.current.getStatus('gw-1');
    });
    expect(lastQuery()).toBe('?gateway_id=gw-1');
    await act(async () => {
      await result.current.getStatus('');
    });
    expect(lastQuery()).toBe('');
    expect(sent).toEqual([
      { method: 'GET', path: '/api/v1/vpn/status', body: undefined },
      { method: 'GET', path: '/api/v1/vpn/status', body: undefined },
    ]);
  });

  it('getPosturePolicy reads one policy by name in its tenant', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/vpn/posture-policies/corp': ok({
        policy: { tenantId: 'acme', name: 'corp', module: 'package vpn.posture\n', updatedAtUnix: '1760300000' },
      }),
    });
    const { result } = renderVPN();
    let res: Awaited<ReturnType<typeof result.current.getPosturePolicy>> | undefined;
    await act(async () => {
      res = await result.current.getPosturePolicy('acme', 'corp');
    });
    expect(res?.data?.policy?.name).toBe('corp');
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/vpn/posture-policies/corp', body: undefined }]);
    expect(lastQuery()).toBe('?tenant_id=acme');
  });

  it('setPosturePolicy puts the tenant, name and module to the named policy', async () => {
    const sent = stubControlPlane({ 'PUT /api/v1/vpn/posture-policies/corp': ok({}) });
    const { result } = renderVPN();
    let res: Awaited<ReturnType<typeof result.current.setPosturePolicy>> | undefined;
    await act(async () => {
      res = await result.current.setPosturePolicy({ tenantId: 'acme', name: 'corp', module: 'package vpn.posture\n' });
    });
    expect(res?.success).toBe(true);
    expect(sent).toEqual([
      {
        method: 'PUT',
        path: '/api/v1/vpn/posture-policies/corp',
        body: { tenantId: 'acme', name: 'corp', module: 'package vpn.posture\n' },
      },
    ]);
  });

  it('setPosturePolicy carries the server refusal', async () => {
    stubControlPlane({ 'PUT /api/v1/vpn/posture-policies/corp': refused(409, 'module does not compile') });
    const { result } = renderVPN();
    let res: Awaited<ReturnType<typeof result.current.setPosturePolicy>> | undefined;
    await act(async () => {
      res = await result.current.setPosturePolicy({ tenantId: 'acme', name: 'corp', module: 'package vpn.posture\n' });
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(409);
    expect(res?.error?.message).toContain('module does not compile');
  });

  it('deletePosturePolicy deletes the named policy in its tenant', async () => {
    const sent = stubControlPlane({ 'DELETE /api/v1/vpn/posture-policies/corp': ok({}) });
    const { result } = renderVPN();
    let res: Awaited<ReturnType<typeof result.current.deletePosturePolicy>> | undefined;
    await act(async () => {
      res = await result.current.deletePosturePolicy('acme', 'corp');
    });
    expect(res?.success).toBe(true);
    expect(sent).toEqual([{ method: 'DELETE', path: '/api/v1/vpn/posture-policies/corp', body: undefined }]);
    expect(lastQuery()).toBe('?tenant_id=acme');
  });

  it('listPosturePolicies reads /vpn/posture-policies with the tenant filter', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/vpn/posture-policies': ok({
        policies: [{ tenantId: 'acme', name: 'corp', module: 'package vpn.posture\n', updatedAtUnix: '1760300000' }],
      }),
    });
    const { result } = renderVPN();
    let res: Awaited<ReturnType<typeof result.current.listPosturePolicies>> | undefined;
    await act(async () => {
      res = await result.current.listPosturePolicies('acme');
    });
    expect(res?.data?.policies?.[0].name).toBe('corp');
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/vpn/posture-policies', body: undefined }]);
    expect(lastQuery()).toBe('?tenant_id=acme');
  });
});
