import { describe, expect, it } from 'vitest';
import type { ApiResponse } from 'trusted-platform-sdk';
import { expectOk } from './use-iam-tenants';

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
