import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useBMCCertOps } from './use-bmc-cert-ops';

interface Seen {
  url: string;
  method: string;
  body: unknown;
}

function stubFetch(reply: (url: string) => { status: number; json: unknown }): Seen[] {
  const seen: Seen[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      seen.push({
        url,
        method: init?.method ?? 'GET',
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      const r = reply(url);
      return new Response(JSON.stringify(r.json), { status: r.status });
    })
  );
  return seen;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('useBMCCertOps', () => {
  it('sends enrol and restore to their REST routes', async () => {
    const seen = stubFetch(() => ({ status: 200, json: { payload: { steps: [] } } }));
    const { result } = renderHook(() => useBMCCertOps('7'));
    await act(async () => {
      await result.current.enroll({ replaceCertificate: true, dnsRegister: false });
      await result.current.restoreFactoryCert();
    });
    expect(seen.map((s) => `${s.method} ${s.url}`)).toEqual([
      'POST /api/v1/bmc/7/enroll',
      'POST /api/v1/bmc/7/cert/restore',
    ]);
    expect(seen[0].body).toEqual({ replace_certificate: true, dns_register: false });
  });

  it('returns the enrolment result from the payload envelope', async () => {
    stubFetch(() => ({
      status: 200,
      json: {
        payload: {
          device_id: '42',
          endpoint: 'https://bmc',
          hostname: 'bmc-1',
          pin_spki_sha256: 'abc',
          steps: [{ name: 'replace_certificate', ok: true }],
        },
      },
    }));
    const { result } = renderHook(() => useBMCCertOps('7'));
    let out: unknown;
    await act(async () => {
      out = await result.current.enroll({});
    });
    expect(out).toMatchObject({ device_id: '42', hostname: 'bmc-1' });
    expect(result.current.lastResult).toMatchObject({ operation: 'enroll' });
    expect(result.current.error).toBeNull();
  });

  it('reports the server error of a refused call and returns null', async () => {
    stubFetch(() => ({ status: 503, json: { error: 'bmc enroller not available' } }));
    const { result } = renderHook(() => useBMCCertOps('7'));
    let out: unknown = 'unset';
    await act(async () => {
      out = await result.current.restoreFactoryCert();
    });
    expect(out).toBeNull();
    expect(result.current.error).toBe('bmc enroller not available');
    expect(result.current.busy).toBe(false);
  });

  it('encodes the profile ID as one path segment', async () => {
    const seen = stubFetch(() => ({ status: 200, json: {} }));
    const { result } = renderHook(() => useBMCCertOps('a/b'));
    await act(async () => {
      await result.current.restoreFactoryCert();
    });
    expect(seen[0].url).toBe('/api/v1/bmc/a%2Fb/cert/restore');
  });
});
