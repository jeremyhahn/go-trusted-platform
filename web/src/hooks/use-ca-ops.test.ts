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
  CA_GATED_CONTROLS,
  caOperationReason,
  normalizeCAInfo,
  pemToVerifyRequest,
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
    expect(pemToVerifyRequest(pem)).toEqual({ certificatePem: 'AAAABBBB', verifyRevocation: true });
  });
});

describe('gated CA controls', () => {
  it('lists InitCA, InstallCACertificates and UninstallCACertificates with a reason each', () => {
    expect(CA_GATED_CONTROLS.map((c) => c.operation)).toEqual([
      'InitCA',
      'InstallCACertificates',
      'UninstallCACertificates',
    ]);
    for (const c of CA_GATED_CONTROLS) {
      expect(caOperationReason(c.operation)).toMatch(/^Not available: /);
      expect(caOperationReason(c.operation)).toContain(c.operation);
    }
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
    expect(verifyCertificate).toHaveBeenCalledWith({ certificatePem: 'QUJD', verifyRevocation: true });
  });
});

describe('useSignCSR', () => {
  it('signs with a client that carries the pasted token, never the session client', async () => {
    signCSR.mockResolvedValue({ certificate: { serial: '10' } });
    const { result } = renderHook(() => useSignCSR());
    await act(async () => {
      await result.current.signAsync({ csrPem: ' CSR ', token: ' tok ', validDays: 5 });
    });
    expect(createPlatformClient).toHaveBeenCalledWith({
      baseUrl: 'https://ca.test',
      credentials: 'include',
      headers: { Authorization: 'Bearer tok' },
    });
    expect(signCSR).toHaveBeenCalledWith({ csrPem: 'CSR', validDays: 5 });
  });

  it('omits a validity that is not a positive number', async () => {
    signCSR.mockResolvedValue({});
    const { result } = renderHook(() => useSignCSR());
    await act(async () => {
      await result.current.signAsync({ csrPem: 'CSR', token: 't', validDays: 0 });
    });
    expect(signCSR).toHaveBeenCalledWith({ csrPem: 'CSR' });
  });
});
