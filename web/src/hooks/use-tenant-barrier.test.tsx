import { cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useTenantBarrier } from './use-tenant-barrier';

// #2067: useTenantBarrier reads and drives a tenant's barrier on the server's tenant paths.

function renderBarrier() {
  return renderHook(() => useTenantBarrier(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  }).result.current;
}

describe('useTenantBarrier', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the status on the tenant path, escaping the id', async () => {
    const barrierStatus = { tenantId: 't/1', sealed: true, initialized: true, strategy: 'shamir' };
    const sent = stubControlPlane({
      'GET /api/v1/tenants/t%2F1/barrier': ok({ barrierStatus }),
    });

    const res = await renderBarrier().getStatus('t/1');

    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/tenants/t%2F1/barrier', body: undefined });
    expect(res.success).toBe(true);
    expect(res.data?.barrierStatus).toEqual(barrierStatus);
  });

  it('initializes with the operator passphrase', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/tenants/t1/barrier/init': ok({ status: { code: 0 } }),
    });

    const res = await renderBarrier().init('t1', 'pw');

    expect(res.success).toBe(true);
    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/tenants/t1/barrier/init', body: { passphrase: 'pw' } });
  });

  it('unseals with the key given', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/tenants/t1/barrier/unseal': ok({ status: { code: 0 } }),
    });

    const res = await renderBarrier().unseal('t1', 'a2V5');

    expect(res.success).toBe(true);
    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/tenants/t1/barrier/unseal', body: { key: 'a2V5' } });
  });

  it('seals with an empty body', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/tenants/t1/barrier/seal': ok({ status: { code: 0 } }),
    });

    const res = await renderBarrier().seal('t1');

    expect(res.success).toBe(true);
    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/tenants/t1/barrier/seal', body: {} });
  });
});
