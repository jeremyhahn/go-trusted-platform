import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  decodePem,
  ldevidAlgorithmProtoName,
  ldevidRequestBody,
  useLDevID,
  type CreateLDevIDInput,
} from './use-ldevid';

// #2055: CreateLDevID is served on main (POST /api/v1/idevid/ldevid) but the
// SDK IDevIDService has no method for it, so the hook calls the SDK API
// client directly. These tests drive the real SDK client through the
// stubbed fetch.

const ROUTE = 'POST /api/v1/idevid/ldevid';

const issued = ok({
  status: { success: true, message: 'issued' },
  csrPem: btoa('-----BEGIN CERTIFICATE REQUEST-----'),
  certificatePem: btoa('-----BEGIN CERTIFICATE-----'),
  certificate: { serialNumber: '0a' },
});

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

async function create(input: CreateLDevIDInput) {
  const { result } = renderHook(() => useLDevID(), { wrapper });
  let res!: Awaited<ReturnType<ReturnType<typeof useLDevID>['createLDevID']>>;
  await act(async () => {
    res = await result.current.createLDevID(input);
  });
  return res;
}

describe('useLDevID', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('creates an LDevID with the defaults', async () => {
    const sent = stubControlPlane({ [ROUTE]: issued });

    const res = await create({ commonName: ' dev-1 ' });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/idevid/ldevid');
    expect(sent[0].body).toEqual({
      template: { commonName: 'dev-1' },
      algorithm: 'DEVICE_KEY_ALGORITHM_ECDSA_P256',
      handle: 0x81010102,
    });
    expect(res.success).toBe(true);
    expect(decodePem(res.data!.certificatePem)).toBe('-----BEGIN CERTIFICATE-----');
  });

  it('sends every option when set', async () => {
    const sent = stubControlPlane({ [ROUTE]: issued });

    await create({
      commonName: 'dev-1',
      organization: 'Acme',
      algorithm: 'RSA_3072',
      handle: 0x81010110,
      profile: 'ldevid',
      validityDays: 90,
      overwrite: true,
    });

    expect(sent[0].body).toEqual({
      template: { commonName: 'dev-1', organization: 'Acme' },
      algorithm: 'DEVICE_KEY_ALGORITHM_RSA_3072',
      handle: 0x81010110,
      profile: 'ldevid',
      validityDays: 90,
      overwrite: true,
    });
  });

  it('surfaces a taken handle', async () => {
    stubControlPlane({ [ROUTE]: refused(409, 'LDevID key already exists at handle') });

    const res = await create({ commonName: 'dev-1' });

    expect(res.success).toBe(false);
    expect(res.error?.status).toBe(409);
  });

  it('surfaces a refused request', async () => {
    stubControlPlane({ [ROUTE]: refused(400, 'common name is required') });

    const res = await create({ commonName: '' });

    expect(res.success).toBe(false);
    expect(res.error?.status).toBe(400);
  });

  it('builds the body pieces', () => {
    expect(ldevidAlgorithmProtoName('ECDSA_P384')).toBe('DEVICE_KEY_ALGORITHM_ECDSA_P384');
    expect(ldevidRequestBody({ commonName: 'x', profile: '', validityDays: 0, overwrite: false })).toEqual({
      template: { commonName: 'x' },
      algorithm: 'DEVICE_KEY_ALGORITHM_ECDSA_P256',
      handle: 0x81010102,
    });
    expect(decodePem('')).toBe('');
  });
});
