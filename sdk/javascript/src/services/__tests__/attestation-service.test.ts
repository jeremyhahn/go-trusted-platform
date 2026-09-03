/**
 * Unit tests pinning AttestationService's URLs to the documented REST
 * contract in docs/attestation/api.md.
 *
 * These exist because the client and server had silently drifted apart:
 * the service posted to `/collect/host`, `/collect/vm`, `/collect/container`
 * and `/manifests`, while the server (and the docs) serve `/host`,
 * `/vm/{id}`, `/container/{id}` and `/manifests/build`. Every collection
 * call therefore 404'd in the console with "the requested API endpoint does
 * not exist", and nothing in the suite noticed.
 *
 * The VM and container routes take their identifier from the PATH — the
 * server overwrites any body value with `mux.Vars(req)["id"]` — so the id
 * must be in the URL, not only in the payload.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AttestationService } from '../attestation-service.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn().mockResolvedValue({ success: true }),
    post: vi.fn().mockResolvedValue({ success: true }),
    put: vi.fn().mockResolvedValue({ success: true }),
    patch: vi.fn().mockResolvedValue({ success: true }),
    delete: vi.fn().mockResolvedValue({ success: true }),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

describe('AttestationService REST contract', () => {
  let client: ApiClient;
  let service: AttestationService;

  beforeEach(() => {
    client = createMockApiClient();
    service = new AttestationService(client);
  });

  it('collects host attestation from /attestation/host', async () => {
    await service.collectHostAttestation({ config: {}, nonce: 'bm9uY2U=' } as never);
    const [url] = (client.post as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/v1/attestation/host');
    expect(url).not.toContain('/collect/');
  });

  it('puts the VM id in the path, because the server reads it from mux vars', async () => {
    await service.collectVMAttestation({ vmId: 'vm-42', config: {}, nonce: 'bm9uY2U=' } as never);
    const [url] = (client.post as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/v1/attestation/vm/vm-42');
  });

  it('puts the container id in the path', async () => {
    await service.collectContainerAttestation({ containerId: 'ctr-7' } as never);
    const [url] = (client.post as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/v1/attestation/container/ctr-7');
  });

  it('encodes identifiers that would otherwise break out of the path segment', async () => {
    await service.collectVMAttestation({ vmId: 'a/b?c', config: {}, nonce: 'bm9uY2U=' } as never);
    const [url] = (client.post as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/v1/attestation/vm/a%2Fb%3Fc');
  });

  it('builds manifests at /manifests/build, not the list route', async () => {
    await service.buildManifest({} as never);
    const [url] = (client.post as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/v1/attestation/manifests/build');
  });

  it('still lists and verifies manifests at their documented routes', async () => {
    await service.listManifests();
    const [listUrl] = (client.get as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(listUrl).toContain('/v1/attestation/manifests');

    await service.verifyManifest({} as never);
    const [verifyUrl] = (client.post as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(verifyUrl).toBe('/v1/attestation/manifests/verify');
  });
});
