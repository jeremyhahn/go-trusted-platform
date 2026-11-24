/**
 * Unit tests for the ceremony service routes (/api/v1/ceremony on the
 * webservice, pkg/webservice/v1/rest/ceremony).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CeremonyService } from '../ceremony-service.js';
import { CeremonyService as IndexedCeremonyService } from '../index.js';
import { CeremonyService as RootCeremonyService } from '../../index.js';
import type {
  CeremonyInitOfficer,
  CeremonyInitRequest,
  CeremonyInitResponse,
  CeremonyStatusResponse,
  CeremonyClaimCertBeginRequest,
  CeremonyClaimCertCompleteRequest,
  CeremonyClaimShareBeginRequest,
  CeremonyClaimShareCompleteRequest,
  CeremonySignCSRRequest,
} from '../../index.js';
import type { ApiClient } from '../../client/api-client.js';

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

describe('CeremonyService', () => {
  let service: CeremonyService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new CeremonyService(mockClient);
  });

  it('is exported from the services index and the package root', () => {
    expect(IndexedCeremonyService).toBe(CeremonyService);
    expect(RootCeremonyService).toBe(CeremonyService);
  });

  it('init posts the request to /v1/ceremony/init', async () => {
    const reply: CeremonyInitResponse = {
      ceremonyId: 'cer-1',
      state: 'CEREMONY_STATE_IN_PROGRESS',
      initializedAt: '2026-11-21T00:00:00Z',
      adminCertPem: 'CERT',
      adminKeyPem: 'KEY',
      spkiPin: 'PIN',
    };
    const response = { success: true, data: reply };
    vi.mocked(mockClient.post).mockResolvedValue(response);
    const officers: CeremonyInitOfficer[] = [
      { username: 'alice', csrPem: 'CSR-A' },
      { username: 'bob', csrPem: 'CSR-B' },
    ];
    const request: CeremonyInitRequest = {
      soPin: '1234',
      userPin: '5678',
      threshold: '3-of-5',
      hostname: 'ca.example',
      sans: ['ca.example'],
      credentialSealStrategy: 'tpm',
      officers,
    };

    const result = await service.init(request);

    expect(result).toBe(response);
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/ceremony/init', request);
  });

  it('status gets /v1/ceremony/status', async () => {
    const reply: CeremonyStatusResponse = {
      ceremonyId: 'cer-1',
      state: 'CEREMONY_STATE_COMPLETE',
      threshold: '3-of-5',
      officersEnrolled: 5,
      officersRequired: 5,
      initializedAt: '2026-11-21T00:00:00Z',
    };
    const response = { success: true, data: reply };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.status();

    expect(result).toBe(response);
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/ceremony/status');
  });

  const posts: Array<{ name: string; path: string; call: (s: CeremonyService) => Promise<unknown>; body: unknown }> =
    (() => {
      const certBegin: CeremonyClaimCertBeginRequest = {
        username: 'alice',
        authenticatorType: 'CEREMONY_AUTHENTICATOR_TYPE_PIV',
        slot: '9a',
        credentialId: 'cred-1',
      };
      const certComplete: CeremonyClaimCertCompleteRequest = { username: 'alice', nonce: 'n1', signature: 'sig' };
      const shareBegin: CeremonyClaimShareBeginRequest = { username: 'alice' };
      const shareComplete: CeremonyClaimShareCompleteRequest = { username: 'alice', nonce: 'n2', signature: 'c2ln' };
      const sign: CeremonySignCSRRequest = {
        username: 'alice',
        soPin: '1234',
        csrPem: 'CSR',
        role: 'CEREMONY_OFFICER_ROLE_ADMIN',
      };
      return [
        { name: 'claimCertBegin', path: '/v1/ceremony/claim-cert/begin', call: (s) => s.claimCertBegin(certBegin), body: certBegin },
        { name: 'claimCertComplete', path: '/v1/ceremony/claim-cert/complete', call: (s) => s.claimCertComplete(certComplete), body: certComplete },
        { name: 'claimShareBegin', path: '/v1/ceremony/claim-share/begin', call: (s) => s.claimShareBegin(shareBegin), body: shareBegin },
        { name: 'claimShareComplete', path: '/v1/ceremony/claim-share/complete', call: (s) => s.claimShareComplete(shareComplete), body: shareComplete },
        { name: 'signCSR', path: '/v1/ceremony/sign-csr', call: (s) => s.signCSR(sign), body: sign },
      ];
    })();

  for (const probe of posts) {
    it(`${probe.name} posts its request to ${probe.path}`, async () => {
      const response = { success: true, data: {} };
      vi.mocked(mockClient.post).mockResolvedValue(response);

      const result = await probe.call(service);

      expect(result).toBe(response);
      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith(probe.path, probe.body);
    });
  }
});
