import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, renderHook, waitFor } from '@testing-library/react';
import { PlatformProvider } from 'trusted-platform-sdk';
import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useSDNPolicies, type SDNPolicyFilter } from './use-sdn-policies';

const LIST = '/api/v1/sdn/policies';
const ONE = `${LIST}/pol-1`;

const P1 = {
  id: 'pol-1',
  config: { name: 'web-acl', type: 'POLICY_TYPE_ACL', priority: 100, enabled: true },
  status: 'POLICY_STATUS_ACTIVE',
  hitCount: '5',
};
const P2 = {
  id: 'pol-2',
  config: { name: 'voice-qos', type: 'POLICY_TYPE_QOS', priority: 200, enabled: false },
  status: 'POLICY_STATUS_INACTIVE',
  hitCount: '0',
};

function render(filter?: SDNPolicyFilter) {
  return renderHook(() => useSDNPolicies(filter), {
    wrapper: ({ children }) => withControlPlane(children),
  });
}

// The SDK retries a 5xx answer; the refused-list case reads it once.
function renderNoRetry(filter?: SDNPolicyFilter) {
  return renderHook(() => useSDNPolicies(filter), {
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

describe('useSDNPolicies', () => {
  it('lists the policies through GET /api/v1/sdn/policies', async () => {
    const sent = stubControlPlane({ [`GET ${LIST}`]: ok({ policies: [P1, P2] }) });
    const { result } = render();

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.policies).toEqual([P1, P2]);
    expect(result.current.error).toBeNull();
    expect(result.current.notConfigured).toBe(false);
    expect(sent).toContainEqual({ method: 'GET', path: LIST, body: undefined });
  });

  it('passes the type and target filters', async () => {
    stubControlPlane({ [`GET ${LIST}`]: ok({ policies: [P1] }) });
    const filter = { type: 'POLICY_TYPE_ACL', targetId: 'br-int' };
    const { result } = render(filter);

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    const calls = vi.mocked(globalThis.fetch).mock.calls;
    const urls = calls.map(([input]) => new URL(input instanceof Request ? input.url : String(input)));
    const list = urls.find((u) => u.pathname === LIST);
    expect(list?.searchParams.get('type')).toBe('POLICY_TYPE_ACL');
    expect(list?.searchParams.get('target_id')).toBe('br-int');
  });

  it('shows a refused list as error and marks a 503 as not configured', async () => {
    stubControlPlane({ [`GET ${LIST}`]: refused(503, 'sdn: not configured') });
    const { result } = renderNoRetry();

    await waitFor(() => expect(result.current.error).toBe('HTTP 503: sdn: not configured'));
    expect(result.current.notConfigured).toBe(true);
    expect(result.current.policies).toEqual([]);
    expect(result.current.isLoading).toBe(false);
  });

  it('reads one policy with get', async () => {
    const sent = stubControlPlane({
      [`GET ${LIST}`]: ok({ policies: [P1] }),
      [`GET ${ONE}`]: ok({ policy: P1 }),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(result.current.get('pol-1')).resolves.toEqual(P1);
    expect(sent).toContainEqual({ method: 'GET', path: ONE, body: undefined });
  });

  it('rejects get with the HTTP status', async () => {
    stubControlPlane({
      [`GET ${LIST}`]: ok({ policies: [P1] }),
      [`GET ${ONE}`]: refused(404, 'policy not found'),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(result.current.get('pol-1')).rejects.toThrow('HTTP 404: policy not found');
  });

  it('applies a policy and lists again', async () => {
    const config = { name: 'dns-acl', type: 'POLICY_TYPE_ACL', priority: 50, enabled: true };
    const sent = stubControlPlane({
      [`GET ${LIST}`]: ok({ policies: [P1] }),
      [`POST ${LIST}`]: ok({ policy: { id: 'pol-3', config } }),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await result.current.apply({ policyId: 'pol-3', config });
    expect(sent).toContainEqual({ method: 'POST', path: LIST, body: { policyId: 'pol-3', config } });
    expect(sent.filter((r) => r.method === 'GET' && r.path === LIST)).toHaveLength(2);
  });

  it('deletes a policy and lists again', async () => {
    const sent = stubControlPlane({
      [`GET ${LIST}`]: ok({ policies: [P1] }),
      [`DELETE ${ONE}`]: ok({}),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await result.current.remove('pol-1');
    expect(sent).toContainEqual({ method: 'DELETE', path: ONE, body: undefined });
    expect(sent.filter((r) => r.method === 'GET' && r.path === LIST)).toHaveLength(2);
  });

  it('rejects a refused delete with the HTTP status', async () => {
    stubControlPlane({
      [`GET ${LIST}`]: ok({ policies: [P1] }),
      [`DELETE ${ONE}`]: refused(409, 'policy in use'),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(result.current.remove('pol-1')).rejects.toThrow('HTTP 409: policy in use');
  });
});
