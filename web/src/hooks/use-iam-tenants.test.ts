import { describe, expect, it } from 'vitest';
import type { ApiResponse } from 'trusted-platform-sdk';
import { expectOk, TENANTS_PAGE_SIZE, tenantPageCount } from './use-iam-tenants';

// The REST handler defaults limit to 50, so the tenants screen pages by 50
// and counts its pages from the server's total (#1757).
describe('tenantPageCount', () => {
  it('pages by 50', () => {
    expect(TENANTS_PAGE_SIZE).toBe(50);
  });

  it('counts at least one page', () => {
    expect(tenantPageCount(0, 50)).toBe(1);
    expect(tenantPageCount(undefined, 50)).toBe(1);
  });

  it('rounds a partial page up', () => {
    expect(tenantPageCount(50, 50)).toBe(1);
    expect(tenantPageCount(51, 50)).toBe(2);
    expect(tenantPageCount(60, 50)).toBe(2);
  });
});

// The SDK client leaves throwOnError false: an HTTP error resolves to
// { success: false, error } instead of rejecting (#1757).
describe('expectOk', () => {
  it('returns a successful response unchanged', () => {
    const response = { success: true, data: { id: 'acme' } } as ApiResponse<{ id: string }>;
    expect(expectOk(response, 'Create tenant')).toBe(response);
  });

  it('throws with the server message on an error response', () => {
    const response = {
      success: false,
      error: { code: 'INTERNAL', message: 'tenant store unavailable' },
    } as ApiResponse<unknown>;
    expect(() => expectOk(response, 'Delete tenant')).toThrow('tenant store unavailable');
  });

  it('throws with the operation name when the error has no message', () => {
    const response = { success: false } as ApiResponse<unknown>;
    expect(() => expectOk(response, 'Update tenant')).toThrow('Update tenant failed');
  });
});
