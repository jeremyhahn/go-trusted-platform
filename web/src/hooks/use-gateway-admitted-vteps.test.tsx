import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, renderHook, waitFor } from '@testing-library/react';
import { PlatformProvider } from 'trusted-platform-sdk';
import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useGatewayAdmittedVTEPs } from './use-gateway-admitted-vteps';

const LIST = '/api/v1/gateway/state/gw-1/admitted-vteps';
const ONE = `${LIST}/192.0.2.10`;

const V1 = {
  vtep: '192.0.2.10',
  device_id: 7,
  host_id: 'host-a',
  serial: 'SN-0001',
  hostname: 'node-a.example.com',
  baseline_source: 'measured',
  verdict_at: '2026-11-20T00:00:00Z',
};
const V2 = { vtep: '2001:db8::2', hostname: 'node-b.example.com' };

function render(gatewayId: string) {
  return renderHook(() => useGatewayAdmittedVTEPs(gatewayId), {
    wrapper: ({ children }) => withControlPlane(children),
  });
}

// The SDK retries a 5xx answer; the refused-list case reads it once.
function renderNoRetry(gatewayId: string) {
  return renderHook(() => useGatewayAdmittedVTEPs(gatewayId), {
    wrapper: ({ children }) => (
      <PlatformProvider config={{ baseUrl: 'https://control-plane.test/api', retry: { maxRetries: 0 } }}>
        <>{children}</>
      </PlatformProvider>
    ),
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useGatewayAdmittedVTEPs', () => {
  it('lists the admitted VTEPs of one gateway through the SDK', async () => {
    const sent = stubControlPlane({ [`GET ${LIST}`]: ok({ admitted_vteps: [V1, V2], total: 2 }) });
    const { result } = render('gw-1');

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.vteps).toEqual([V1, V2]);
    expect(result.current.error).toBeNull();
    expect(sent).toContainEqual({ method: 'GET', path: LIST, body: undefined });
  });

  it('reads one VTEP with get', async () => {
    const sent = stubControlPlane({
      [`GET ${LIST}`]: ok({ admitted_vteps: [V1], total: 1 }),
      [`GET ${ONE}`]: ok(V1),
    });
    const { result } = render('gw-1');
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(result.current.get('192.0.2.10')).resolves.toEqual(V1);
    expect(sent).toContainEqual({ method: 'GET', path: ONE, body: undefined });
  });

  it('rejects get with the HTTP status when the read is refused', async () => {
    stubControlPlane({
      [`GET ${LIST}`]: ok({ admitted_vteps: [V1], total: 1 }),
      [`GET ${ONE}`]: refused(404, 'vtep not admitted'),
    });
    const { result } = render('gw-1');
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(result.current.get('192.0.2.10')).rejects.toThrow('HTTP 404: vtep not admitted');
  });

  it('shows a refused list as error', async () => {
    stubControlPlane({
      [`GET ${LIST}`]: refused(503, 'overlay telemetry is not available for this gateway'),
    });
    const { result } = renderNoRetry('gw-1');

    await waitFor(() =>
      expect(result.current.error).toBe('HTTP 503: overlay telemetry is not available for this gateway')
    );
    expect(result.current.vteps).toEqual([]);
    expect(result.current.isLoading).toBe(false);
  });

  it('sends nothing for an empty gateway id', async () => {
    const sent = stubControlPlane({});
    const { result } = render('');

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(sent.filter((r) => r.path.includes('/gateway/state'))).toEqual([]);
    expect(result.current.vteps).toEqual([]);
  });
});
