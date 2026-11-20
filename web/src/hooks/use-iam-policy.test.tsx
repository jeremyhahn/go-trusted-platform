import { renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const iam = vi.hoisted(() => ({
  createPolicy: vi.fn(),
  getPolicy: vi.fn(),
}));

const captured = vi.hoisted(() => ({
  mutationFn: undefined as unknown,
  mutationOptions: undefined as unknown,
  apiFn: undefined as unknown,
  apiDeps: undefined as unknown,
  apiData: undefined as unknown,
}));

vi.mock('trusted-platform-sdk', () => ({
  useIAM: () => iam,
  useMutation: (fn: unknown, options: unknown) => {
    captured.mutationFn = fn;
    captured.mutationOptions = options;
    return { mutate: vi.fn(), isLoading: false };
  },
  useApi: (fn: unknown, deps: unknown) => {
    captured.apiFn = fn;
    captured.apiDeps = deps;
    return { data: captured.apiData, isLoading: false, error: null, refetch: vi.fn() };
  },
}));

import { buildPolicyYaml, useCreatePolicy, usePolicyDetail, type PolicyDraft } from './use-iam-policy';

type MutationFn = (draft: PolicyDraft) => Promise<unknown>;
type ApiFn = () => Promise<unknown>;

const draft: PolicyDraft = {
  name: 'allow-read',
  description: 'Allow reads',
  effect: 'allow',
  actions: ' read , write ,, ',
  resources: '*, kv://config/*',
};

afterEach(() => {
  vi.clearAllMocks();
  captured.apiData = undefined;
});

describe('buildPolicyYaml', () => {
  it('renders one rule with trimmed actions and quoted resources', () => {
    expect(buildPolicyYaml('t-1', draft)).toBe(
      [
        'apiVersion: v1',
        'kind: Policy',
        'metadata:',
        '  name: allow-read',
        '  tenant: t-1',
        '  description: Allow reads',
        'spec:',
        '  rules:',
        '    - name: rule-1',
        '      effect: allow',
        '      actions: [read, write]',
        '      resources: ["*", "kv://config/*"]',
      ].join('\n'),
    );
  });
});

describe('useCreatePolicy', () => {
  it('sends the YAML under specYaml, spec and spec_yaml', async () => {
    iam.createPolicy.mockResolvedValue({ success: true, data: {} });
    renderHook(() => useCreatePolicy('t-1'));
    await (captured.mutationFn as MutationFn)(draft);

    const yaml = buildPolicyYaml('t-1', draft);
    expect(iam.createPolicy).toHaveBeenCalledWith({
      tenantId: 't-1',
      name: 'allow-read',
      description: 'Allow reads',
      specYaml: yaml,
      spec: yaml,
      spec_yaml: yaml,
    });
  });

  it('refuses without a tenant and calls no SDK method', async () => {
    renderHook(() => useCreatePolicy(null));
    await expect((captured.mutationFn as MutationFn)(draft)).rejects.toThrow(/tenant/i);
    expect(iam.createPolicy).not.toHaveBeenCalled();
  });

  it('passes the caller options to useMutation', () => {
    const onSuccess = vi.fn();
    renderHook(() => useCreatePolicy('t-1', { onSuccess }));
    expect(captured.mutationOptions).toEqual({ onSuccess });
  });
});

describe('usePolicyDetail', () => {
  it('fetches the named policy for the tenant', async () => {
    iam.getPolicy.mockResolvedValue({ success: true, data: {} });
    renderHook(() => usePolicyDetail('t-1', 'allow-read'));
    await (captured.apiFn as ApiFn)();
    expect(iam.getPolicy).toHaveBeenCalledWith('t-1', 'allow-read');
    expect(captured.apiDeps).toEqual(['t-1', 'allow-read']);
  });

  it('unwraps a nested {policy} response with the snake_case spec', () => {
    captured.apiData = { policy: { description: 'd', priority: 7, spec_yaml: 'kind: Policy' } };
    const { result } = renderHook(() => usePolicyDetail('t-1', 'p'));
    expect(result.current.policy).toEqual({ description: 'd', priority: 7, yaml: 'kind: Policy' });
  });

  it('reads a flat camelCase response', () => {
    captured.apiData = { description: 'flat', specYaml: 'kind: Policy' };
    const { result } = renderHook(() => usePolicyDetail('t-1', 'p'));
    expect(result.current.policy).toEqual({ description: 'flat', priority: 0, yaml: 'kind: Policy' });
  });

  it('is null before the server answers', () => {
    const { result } = renderHook(() => usePolicyDetail('t-1', 'p'));
    expect(result.current.policy).toBeNull();
  });

  it('errors without a tenant and calls no SDK method', async () => {
    renderHook(() => usePolicyDetail(undefined, 'p'));
    await expect((captured.apiFn as ApiFn)()).rejects.toThrow(/tenant/i);
    expect(iam.getPolicy).not.toHaveBeenCalled();
  });
});
