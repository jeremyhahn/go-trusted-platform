/**
 * Unit tests for the compute request wire shapes.
 *
 * The daemon decodes every compute request with protojson against the
 * ComputeService request message: a field the message does not have is a
 * 400, and an enum takes only its proto-canonical name. These pin the shapes
 * the service sends: list filters named after the message's fields, the short
 * PCR bank translated, and the disk and snapshot config wrapped in the field
 * that carries them.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ComputeService, listQuery, protoEnumName } from '../compute-service.js';
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

/** The query of the first GET the service sent. */
function sentQuery(mockClient: ApiClient): URLSearchParams {
  const url = String(vi.mocked(mockClient.get).mock.calls[0]?.[0]);
  return new URL(url, 'https://api.example.com').searchParams;
}

/** The body of the first POST the service sent. */
function postedBody(mockClient: ApiClient): unknown {
  return vi.mocked(mockClient.post).mock.calls[0]?.[1];
}

describe('protoEnumName', () => {
  it('prefixes a short enum value', () => {
    expect(protoEnumName('VM_STATE_', 'RUNNING')).toBe('VM_STATE_RUNNING');
  });

  it('leaves an already-canonical value untouched rather than double-prefixing', () => {
    expect(protoEnumName('VM_STATE_', 'VM_STATE_RUNNING')).toBe('VM_STATE_RUNNING');
  });
});

describe('listQuery', () => {
  it('names every filter after a field of the list request message', () => {
    expect(
      listQuery({
        labels: { env: 'prod' },
        states: ['CONTAINER_STATE_RUNNING', 'CONTAINER_STATE_EXITED'],
        page: 2,
        pageSize: 10,
      })
    ).toEqual({
      states: ['CONTAINER_STATE_RUNNING', 'CONTAINER_STATE_EXITED'],
      'pagination.page': 2,
      'pagination.pageSize': 10,
      'selector.matchLabels.env': 'prod',
    });
  });

  it('sends no filter when the caller supplied none', () => {
    const query = listQuery();

    expect(Object.values(query).every((value) => value === undefined)).toBe(true);
  });
});

describe('ComputeService wire shapes', () => {
  let service: ComputeService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    service = new ComputeService(mockClient);
  });

  it('lists VMs with one states parameter per state and the selector by label', async () => {
    await service.listVMs({
      states: ['VM_STATE_RUNNING', 'VM_STATE_STOPPED'],
      pageSize: 5,
      labels: { tier: 'web' },
    });

    const query = sentQuery(mockClient);
    expect(query.getAll('states')).toEqual(['VM_STATE_RUNNING', 'VM_STATE_STOPPED']);
    expect(query.get('pagination.pageSize')).toBe('5');
    expect(query.get('selector.matchLabels.tier')).toBe('web');
    expect(query.has('limit')).toBe(false);
  });

  it('lists containers with container state names', async () => {
    await service.listContainers({ states: ['CONTAINER_STATE_EXITED'] });

    expect(sentQuery(mockClient).getAll('states')).toEqual(['CONTAINER_STATE_EXITED']);
  });

  it('wraps an attached disk in the disk field', async () => {
    await service.attachDisk({ vmId: 'vm-1', disk: { path: '/data/d.qcow2', sizeGb: 20 } });

    expect(postedBody(mockClient)).toEqual({ disk: { path: '/data/d.qcow2', sizeGb: 20 } });
  });

  it('wraps a snapshot config in the config field', async () => {
    await service.createSnapshot({ vmId: 'vm-1', config: { name: 'nightly', memorySnapshot: true } });

    expect(postedBody(mockClient)).toEqual({ config: { name: 'nightly', memorySnapshot: true } });
  });

  it('sends the proto-canonical PCR bank when attesting a VM', async () => {
    await service.attestVM({ vmId: 'vm-1', nonce: 'bm9uY2U=', pcrBank: 'SHA256' });

    expect((postedBody(mockClient) as { pcrBank?: string }).pcrBank).toBe('PCR_BANK_SHA256');
  });

  it('omits the PCR bank when the caller supplied none', async () => {
    await service.attestVM({ vmId: 'vm-1', nonce: 'bm9uY2U=' });

    expect((postedBody(mockClient) as { pcrBank?: string }).pcrBank).toBeUndefined();
  });

  it('posts a container attestation to the container attest path with an empty body', async () => {
    await service.attestContainer({ id: 'ctr 1' });

    expect(String(vi.mocked(mockClient.post).mock.calls[0]?.[0])).toContain('/containers/ctr%201/attest');
    // The daemon's container attestation takes no caller nonce, PCR selection
    // or bank, so the SDK posts none.
    expect(postedBody(mockClient)).toEqual({});
  });
});
