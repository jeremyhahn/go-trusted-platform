import { cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const iam = {
  validatePolicy: vi.fn(),
  testPolicy: vi.fn(),
};

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  useIAM: () => iam,
}));

import { usePolicyTools } from './use-policy-tools';

const REASON = 'the embedded IAM backend does not implement Policy.Validate or Policy.Simulate yet';

/**
 * The embedded IAM backend (go-quicbaas v0.12.0-alpha) lacks Policy.Validate
 * and Policy.Simulate, so the policy tools report themselves unavailable and
 * never call the SDK (#2023 Codex round 2).
 */
describe('usePolicyTools', () => {
  beforeEach(() => {
    iam.validatePolicy.mockReset();
    iam.testPolicy.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it('reports the tools unavailable with the reason', () => {
    const { result } = renderHook(() => usePolicyTools());
    expect(result.current.available).toBe(false);
    expect(result.current.unavailableReason).toBe(REASON);
  });

  it('validate rejects with the reason without calling the SDK', async () => {
    const { result } = renderHook(() => usePolicyTools());
    await expect(
      result.current.validate.mutateAsync({ tenantId: 't-1', specYaml: 'kind: Policy' })
    ).rejects.toMatchObject({ message: REASON });
    expect(iam.validatePolicy).not.toHaveBeenCalled();
  });

  it('test rejects with the reason without calling the SDK', async () => {
    const { result } = renderHook(() => usePolicyTools());
    await expect(
      result.current.test.mutateAsync({ tenantId: 't-1', subjectId: 'u-1', action: 'read', resource: 'r' })
    ).rejects.toMatchObject({ message: REASON });
    expect(iam.testPolicy).not.toHaveBeenCalled();
  });
});
