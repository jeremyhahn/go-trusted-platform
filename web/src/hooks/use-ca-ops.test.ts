import { describe, expect, it, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';

const getInfo = vi.fn();
const verifyCertificate = vi.fn();
const signCSR = vi.fn();
const createPlatformClient = vi.fn(() => ({ ca: { signCSR } }));

vi.mock('trusted-platform-sdk', () => ({
  createPlatformClient: (...args: unknown[]) => (createPlatformClient as (...a: unknown[]) => unknown)(...args),
}));

vi.mock('@/hooks', () => ({
  useCA: () => ({ getInfo, verifyCertificate, signCSR }),
  usePlatformClient: () => ({ baseUrl: 'https://ca.test' }),
  useApi: (fn: () => unknown) => {
    fn();
    return { data: { caInfo: { commonName: 'Root CA', defaultValidityDays: 30 } }, isLoading: false, error: null, refetch: vi.fn() };
  },
  useMutation: (fn: (v: unknown) => Promise<unknown>) => ({
    mutate: (v: unknown) => void fn(v),
    mutateAsync: fn,
    reset: vi.fn(),
    data: undefined,
    error: null,
    isLoading: false,
  }),
}));

import {
  normalizeCAInfo,
  pemToVerifyRequest,
  SIGN_CSR_UNAVAILABLE_REASON,
  useCAInfo,
  useSignCSR,
  useVerifyCertificate,
} from './use-ca-ops';

beforeEach(() => {
  getInfo.mockReset();
  verifyCertificate.mockReset();
  signCSR.mockReset();
  createPlatformClient.mockClear();
});

describe('normalizeCAInfo', () => {
  it('reads the camelCase envelope', () => {
    const info = normalizeCAInfo({
      caInfo: {
        commonName: 'Root CA',
        isIntermediate: false,
        defaultAlgorithm: 'ECDSA_P256',
        defaultValidityDays: 365,
        rootCert: { serial: '01', commonName: 'Root CA' },
        intermediates: [{ serial: '02', commonName: 'Int' }],
      },
    });
    expect(info).toMatchObject({
      commonName: 'Root CA',
      isIntermediate: false,
      defaultAlgorithm: 'ECDSA_P256',
      defaultValidityDays: 365,
    });
    expect(info.root?.serial).toBe('01');
    expect(info.intermediates).toHaveLength(1);
  });

  it('reads the snake_case envelope and a bare body', () => {
    expect(normalizeCAInfo({ ca_info: { common_name: 'S', is_intermediate: true, default_validity_days: 7 } })).toMatchObject({
      commonName: 'S',
      isIntermediate: true,
      defaultValidityDays: 7,
    });
    expect(normalizeCAInfo({ commonName: 'Bare' }).commonName).toBe('Bare');
  });

  it('returns empty fields for no data', () => {
    expect(normalizeCAInfo(undefined)).toMatchObject({ commonName: '', intermediates: [], root: undefined });
  });
});

describe('pemToVerifyRequest', () => {
  it('sends the base64 body of the PEM and asks for revocation', () => {
    const pem = '-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n';
    expect(pemToVerifyRequest(pem)).toEqual({ certificateDer: 'AAAABBBB', verifyRevocation: true });
  });
});

describe('useCAInfo', () => {
  it('calls ca.getInfo and returns the normalized info', () => {
    const { result } = renderHook(() => useCAInfo());
    expect(getInfo).toHaveBeenCalledTimes(1);
    expect(result.current.info.commonName).toBe('Root CA');
    expect(result.current.info.defaultValidityDays).toBe(30);
  });
});

describe('useVerifyCertificate', () => {
  it('posts the PEM body through ca.verifyCertificate', async () => {
    verifyCertificate.mockResolvedValue({ valid: true });
    const { result } = renderHook(() => useVerifyCertificate());
    await act(async () => {
      await result.current.verifyAsync('-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----');
    });
    expect(verifyCertificate).toHaveBeenCalledWith({ certificateDer: 'QUJD', verifyRevocation: true });
  });
});

describe('useSignCSR', () => {
  // The server's platform-token middleware takes only DPoP-bound tokens, and
  // the console cannot send a DPoP proof: a bearer-only request always fails.
  it('reports the action unavailable, with the reason', () => {
    const { result } = renderHook(() => useSignCSR());
    expect(result.current.available).toBe(false);
    expect(result.current.reason).toBe(SIGN_CSR_UNAVAILABLE_REASON);
    expect(SIGN_CSR_UNAVAILABLE_REASON).toMatch(/DPoP/);
  });

  it('never sends a request, with or without a token', async () => {
    const { result } = renderHook(() => useSignCSR());
    await act(async () => {
      await expect(result.current.signAsync({ csrPem: ' CSR ', token: ' tok ', validDays: 5 })).rejects.toThrow(
        SIGN_CSR_UNAVAILABLE_REASON,
      );
    });
    expect(createPlatformClient).not.toHaveBeenCalled();
    expect(signCSR).not.toHaveBeenCalled();
  });
});
