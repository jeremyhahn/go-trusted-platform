import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { useTPMCertify } from './use-tpm-certify';

// #2068: Certify and DeleteAK both go through the SDK TPMService; a
// hand-written POST on the API client throws here.

const { certifySpy, deleteSpy } = vi.hoisted(() => ({
  certifySpy: vi.fn(),
  deleteSpy: vi.fn(),
}));

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  usePlatformClient: () => ({
    getApiClient: () => ({
      post: () => {
        throw new Error('hand-written POST /v1/tpm/certify');
      },
    }),
  }),
  useTPM: () => ({ certify: certifySpy, deleteAK: deleteSpy }),
}));

afterEach(() => {
  cleanup();
  certifySpy.mockReset();
  deleteSpy.mockReset();
});

describe('useTPMCertify', () => {
  it('certifies through the SDK TPMService', async () => {
    const answer = { success: true, data: { signatureAlgorithm: 'SHA256-RSASSA' } };
    certifySpy.mockResolvedValue(answer);
    const { result } = renderHook(() => useTPMCertify());

    const input = { keyHandle: 0x81000009, nonce: 'AAEC' };
    let res: unknown;
    await act(async () => {
      res = await result.current.certify(input);
    });

    expect(res).toEqual(answer);
    expect(certifySpy).toHaveBeenCalledTimes(1);
    expect(certifySpy).toHaveBeenCalledWith(input);
  });

  it('evicts an AK through the SDK TPMService', async () => {
    const answer = { success: true, data: {} };
    deleteSpy.mockResolvedValue(answer);
    const { result } = renderHook(() => useTPMCertify());

    const req = { handle: 0x81000010 };
    let res: unknown;
    await act(async () => {
      res = await result.current.deleteAK(req);
    });

    expect(res).toEqual(answer);
    expect(deleteSpy).toHaveBeenCalledTimes(1);
    expect(deleteSpy).toHaveBeenCalledWith(req);
  });
});
