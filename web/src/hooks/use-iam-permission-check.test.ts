import { describe, expect, it, vi } from 'vitest';
import type { ApiResponse, CheckIAMPermissionResponse } from 'trusted-platform-sdk';
import { checkIAMPermission, permissionDecisionLabel } from './use-iam-permission-check';

type CheckFn = (req: unknown) => Promise<ApiResponse<CheckIAMPermissionResponse>>;

function fakeIAM(response: ApiResponse<CheckIAMPermissionResponse>) {
  const checkPermission = vi.fn<CheckFn>().mockResolvedValue(response);
  return { iam: { checkPermission }, checkPermission };
}

describe('checkIAMPermission', () => {
  it('sends the tenant and the trimmed input to the SDK checkPermission', async () => {
    const { iam, checkPermission } = fakeIAM({
      success: true,
      data: { allowed: true, reason: 'policy p1' } as unknown as CheckIAMPermissionResponse,
    });
    const decision = await checkIAMPermission(iam, 't1', {
      subjectId: ' alice ',
      action: 'read ',
      resource: ' /api/v1/secrets/x',
    });
    expect(checkPermission).toHaveBeenCalledWith({
      tenantId: 't1',
      subjectId: 'alice',
      action: 'read',
      resource: '/api/v1/secrets/x',
    });
    expect(decision).toEqual({ allowed: true, reason: 'policy p1' });
  });

  it('reads a denial from the server response', async () => {
    const { iam } = fakeIAM({
      success: true,
      data: { allowed: false } as unknown as CheckIAMPermissionResponse,
    });
    const decision = await checkIAMPermission(iam, 't1', { subjectId: 'a', action: 'b', resource: 'c' });
    expect(decision.allowed).toBe(false);
  });

  it('throws the server error when the check is refused', async () => {
    const { iam } = fakeIAM({
      success: false,
      error: { message: 'PEP client not configured' },
    } as unknown as ApiResponse<CheckIAMPermissionResponse>);
    await expect(
      checkIAMPermission(iam, 't1', { subjectId: 'a', action: 'b', resource: 'c' }),
    ).rejects.toThrow('PEP client not configured');
  });

  it('refuses without a tenant or a required field and calls no SDK method', async () => {
    const { iam, checkPermission } = fakeIAM({ success: true } as ApiResponse<CheckIAMPermissionResponse>);
    await expect(
      checkIAMPermission(iam, null, { subjectId: 'a', action: 'b', resource: 'c' }),
    ).rejects.toThrow(/tenant/i);
    await expect(
      checkIAMPermission(iam, 't1', { subjectId: ' ', action: 'b', resource: 'c' }),
    ).rejects.toThrow(/subject/i);
    expect(checkPermission).not.toHaveBeenCalled();
  });
});

describe('permissionDecisionLabel', () => {
  it('labels the decision', () => {
    expect(permissionDecisionLabel({ allowed: true })).toBe('Allowed');
    expect(permissionDecisionLabel({ allowed: false, reason: 'no policy' })).toBe('Denied: no policy');
  });
});
