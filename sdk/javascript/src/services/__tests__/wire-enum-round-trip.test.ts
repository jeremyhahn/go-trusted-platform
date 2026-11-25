/**
 * Objects the server returns carry their enums in the server's own spelling
 * (protojson enum names such as RECORD_TYPE_A, or the device and vTPM REST
 * spellings such as "802.1x" and "pre-assigned"). Each test here reads an
 * object through the SDK and sends it straight back, and asserts the enum
 * reaches the write body intact instead of being dropped.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ApiClient } from '../../client/api-client.js';
import { InvalidEnumValueError } from '../../errors/index.js';
import { encodeEnum, encodeOptionalEnum } from '../wire-enum.js';
import { DNSService } from '../dns-service.js';
import { DeviceService } from '../device-service.js';
import { CAService } from '../ca-service.js';
import { TPMService } from '../tpm-service.js';
import { AttestationService } from '../attestation-service.js';
import { IDevIDService } from '../idevid-service.js';
import { VTPMService } from '../vtpm-service.js';
import { PXEService } from '../pxe-service.js';
import { RECORD_TYPE_PROTO_NAMES } from '../../types/dns.js';
import { AUTH_METHOD_WIRE_NAMES } from '../../types/device.js';
import type { DeviceProfile } from '../../types/device.js';
import type { Certificate } from '../../types/ca.js';
import type { GetEKResponse } from '../../types/tpm.js';
import type { AttestationQuote } from '../../types/attestation.js';
import type { DeviceKeyInfo } from '../../types/idevid.js';
import type { VTPMBundle } from '../../types/vtpm.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

/** Serves one GET response and records the write that follows. */
function respondWith(client: ApiClient, data: unknown): void {
  vi.mocked(client.get).mockResolvedValue({ success: true, data });
  vi.mocked(client.post).mockResolvedValue({ success: true, data });
  vi.mocked(client.put).mockResolvedValue({ success: true, data: {} });
}

/** The value, which the test requires to be present. */
function defined<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new TypeError('expected a value, got undefined');
  }
  return value;
}

/** The body of the only call made through `method`. */
function sentBody(method: unknown): Record<string, unknown> {
  const calls = vi.mocked(method as (url: string, body: unknown) => unknown).mock.calls;
  expect(calls).toHaveLength(1);
  return defined(calls[0])[1] as Record<string, unknown>;
}

describe('encodeEnum', () => {
  it('translates a short name to its wire spelling', () => {
    expect(encodeEnum('type', RECORD_TYPE_PROTO_NAMES, 'A')).toBe('RECORD_TYPE_A');
  });

  it('passes a wire spelling through unchanged', () => {
    expect(encodeEnum('type', RECORD_TYPE_PROTO_NAMES, 'RECORD_TYPE_AAAA')).toBe('RECORD_TYPE_AAAA');
    expect(encodeEnum('auth_method', AUTH_METHOD_WIRE_NAMES, '802.1x')).toBe('802.1x');
  });

  it('encodes a short name the map leaves unset as undefined', () => {
    expect(encodeEnum('auth_method', AUTH_METHOD_WIRE_NAMES, 'UNSPECIFIED')).toBeUndefined();
  });

  it('throws a typed error for an unknown value instead of dropping it', () => {
    expect(() => encodeEnum('type', RECORD_TYPE_PROTO_NAMES, 'RECORD_TYPE_BOGUS')).toThrow(InvalidEnumValueError);
    expect(() => encodeEnum('type', RECORD_TYPE_PROTO_NAMES, 'toString')).toThrow(InvalidEnumValueError);
    let caught: unknown;
    try {
      encodeEnum('auth_method', AUTH_METHOD_WIRE_NAMES, 'eap');
    } catch (err) {
      caught = err;
    }
    expect(caught).toMatchObject({ name: 'InvalidEnumValueError', field: 'auth_method', value: 'eap' });
  });

  it('leaves an absent optional value absent', () => {
    expect(encodeOptionalEnum('auth_method', AUTH_METHOD_WIRE_NAMES, undefined)).toBeUndefined();
  });
});

describe('server-returned enums round-trip through the write bodies', () => {
  let client: ApiClient;

  beforeEach(() => {
    client = createMockApiClient();
  });

  it('DNS: a record from listRecords is accepted as both oldRecord and newRecord', async () => {
    const service = new DNSService(client);
    respondWith(client, { records: [{ type: 'RECORD_TYPE_A', a: { address: '10.0.0.5' } }] });

    const listed = await service.listRecords({ zoneName: 'example.internal' });
    const record = defined(defined(listed.data).records[0]);
    await service.updateRecord({ zoneName: 'example.internal', oldRecord: record, newRecord: record });

    expect(sentBody(client.put)).toEqual({
      oldRecord: { type: 'RECORD_TYPE_A', a: { address: '10.0.0.5' } },
      newRecord: { type: 'RECORD_TYPE_A', a: { address: '10.0.0.5' } },
    });
  });

  it('device: a profile from listProfiles keeps its 802.1X auth method on update', async () => {
    const service = new DeviceService(client);
    const stored = {
      id: '7',
      name: 'p1',
      role: 'worker',
      networks: { trusted: { vlan: 20, auth_method: '802.1x' } },
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z',
    } as unknown as DeviceProfile;
    respondWith(client, { profiles: [stored], pagination: {} });

    const listed = await service.listProfiles();
    await service.updateProfile({ profile: defined(defined(listed.data).profiles[0]) });

    expect(sentBody(client.put)).toMatchObject({ networks: { trusted: { vlan: 20, auth_method: '802.1x' } } });
  });

  it('CA: a certificate key algorithm from getCertificate is sent back on reissue', async () => {
    const service = new CAService(client);
    const cert = { keyAlgorithm: 'KEY_ALGORITHM_ECDSA_P384' } as unknown as Certificate;
    respondWith(client, { certificate: cert, timestamp: '' });

    const got = await service.getCertificate('01');
    vi.mocked(client.post).mockClear();
    await service.issueCertificate({ subject: { commonName: 'node1' }, keyAlgorithm: defined(got.data).certificate.keyAlgorithm });

    expect(sentBody(client.post)).toMatchObject({ request: { keyAlgorithm: 'KEY_ALGORITHM_ECDSA_P384' } });
  });

  it('TPM: the algorithm getEK returns is sent back in createEK attributes', async () => {
    const service = new TPMService(client);
    const ek = { publicKey: '', handle: 0x81010001, algorithm: 'KEY_ALGORITHM_RSA_2048' } as unknown as GetEKResponse;
    respondWith(client, ek);

    const got = await service.getEK();
    vi.mocked(client.post).mockClear();
    await service.createEK({ attributes: { cn: 'ek', algorithm: defined(got.data).algorithm } });

    expect(sentBody(client.post)).toMatchObject({ attributes: { algorithm: 'KEY_ALGORITHM_RSA_2048' } });
  });

  it('attestation: the PCR values getQuote returns verify as expectedPcrs', async () => {
    const service = new AttestationService(client);
    const quote = {
      quoteData: 'q',
      signature: 's',
      signatureAlgorithm: 'ECDSA-SHA256',
      nonce: 'n',
      pcrValues: [{ index: 7, value: 'AA==', algorithm: 'ATTESTATION_HASH_ALGORITHM_SHA256' }],
    } as unknown as AttestationQuote;
    respondWith(client, { status: 'ATTESTATION_STATUS_SUCCESS', quote });

    const got = await service.getQuote({ nonce: 'n' } as never);
    vi.mocked(client.post).mockClear();
    const returned = defined(defined(got.data).quote);
    await service.verifyQuote({ quote: returned, akPublicKeyPem: 'pem', expectedNonce: 'n', expectedPcrs: returned.pcrValues });

    expect(sentBody(client.post)).toMatchObject({
      expectedPcrs: [{ index: 7, algorithm: 'ATTESTATION_HASH_ALGORITHM_SHA256' }],
    });
  });

  it('IDevID: the key algorithm getIDevIDInfo returns is sent back to generateIDevID', async () => {
    const service = new IDevIDService(client);
    const keyInfo = { algorithm: 'DEVICE_KEY_ALGORITHM_ECDSA_P256' } as unknown as DeviceKeyInfo;
    respondWith(client, { keyInfo });

    const got = await service.getIDevIDInfo();
    vi.mocked(client.post).mockClear();
    await service.generateIDevID({ config: { algorithm: defined(got.data).keyInfo.algorithm } });

    expect(sentBody(client.post)).toEqual({ config: { algorithm: 'DEVICE_KEY_ALGORITHM_ECDSA_P256' } });
  });

  it('vTPM: the bundle mode getBundle returns is sent back to createBundle', async () => {
    const service = new VTPMService(client);
    const bundle = { mode: 'pre-assigned', manifest: { ekAlgorithm: 'ECC' } } as unknown as VTPMBundle;
    respondWith(client, { bundle });

    const got = await service.getBundle('b1');
    vi.mocked(client.post).mockClear();
    const returned = defined(got.data).bundle;
    await service.createBundle({ options: { mode: returned.mode, ekAlgorithm: returned.manifest.ekAlgorithm } });

    // createBundle posts a serialized body so a uint64 device profile ID stays exact.
    expect(JSON.parse(sentBody(client.post) as unknown as string)).toEqual({ mode: 'pre-assigned', ek_algorithm: 'ECC' });
  });

  it('PXE: the state getDevice returns is sent back to updateState', async () => {
    const service = new PXEService(client);
    respondWith(client, { device: { id: 'd1', macAddress: 'aa:bb', state: 'PROVISIONING_STATE_ENROLLED' } });

    const got = await service.getDevice('d1');
    await service.updateState({ deviceId: 'd1', state: defined(got.data).device.state });

    expect(sentBody(client.put)).toMatchObject({ state: 'PROVISIONING_STATE_ENROLLED' });
  });
});
