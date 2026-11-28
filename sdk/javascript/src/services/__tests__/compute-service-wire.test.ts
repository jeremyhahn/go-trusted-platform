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

  it('suspends and resumes a VM with an empty body on its encoded path', async () => {
    await service.suspendVM('vm/1');
    await service.resumeVM('vm/1');

    const calls = vi.mocked(mockClient.post).mock.calls;
    expect(String(calls[0]?.[0])).toMatch(/\/v1\/compute\/vms\/vm%2F1\/suspend$/);
    expect(calls[0]?.[1]).toEqual({});
    expect(String(calls[1]?.[0])).toMatch(/\/v1\/compute\/vms\/vm%2F1\/resume$/);
    expect(calls[1]?.[1]).toEqual({});
  });

  it('passes request options through on migrateVM', async () => {
    const options = { timeout: 7200000, retry: { enabled: false } };
    await service.migrateVM(
      { vmId: 'vm-1', destinationHost: 'destination.example.test', liveMigration: true },
      options
    );
    await service.migrateVM({ vmId: 'vm-1', destinationHost: 'destination.example.test', liveMigration: true });

    const calls = vi.mocked(mockClient.post).mock.calls;
    expect(String(calls[0]?.[0])).toMatch(/\/v1\/compute\/vms\/vm-1\/migrate$/);
    expect(calls[0]?.[1]).toEqual({
      destinationHost: 'destination.example.test',
      liveMigration: true,
      bandwidthLimitMbps: undefined,
    });
    expect(calls[0]?.[2]).toEqual(options);
    expect(calls[1]?.[2]).toBeUndefined();
  });

  it('reads one snapshot on GET /vms/{id}/snapshots/{snapshotId}', async () => {
    await service.getSnapshot({ vmId: 'vm-1', snapshotId: 's/1' });

    const url = String(vi.mocked(mockClient.get).mock.calls[0]?.[0]);
    expect(url).toMatch(/\/v1\/compute\/vms\/vm-1\/snapshots\/s%2F1$/);
  });

  it('prepares a migration receiver on POST /migrations/prepare', async () => {
    await service.prepareMigration({
      vmId: 'vm-1',
      vmName: 'web-1',
      mode: 'live',
      spec: { memoryMb: 2048, cpus: 2, arch: 'x86_64' },
    });

    const url = String(vi.mocked(mockClient.post).mock.calls[0]?.[0]);
    expect(url).toMatch(/\/v1\/compute\/migrations\/prepare$/);
    expect(postedBody(mockClient)).toEqual({
      vmId: 'vm-1',
      vmName: 'web-1',
      mode: 'live',
      spec: { memoryMb: 2048, cpus: 2, arch: 'x86_64' },
    });
  });

  it('omits the spec when the caller supplied none', async () => {
    await service.prepareMigration({ vmId: 'vm-1', vmName: 'web-1', mode: 'cold' });

    expect((postedBody(mockClient) as { spec?: unknown }).spec).toBeUndefined();
  });

  it('finalizes a receiver on its encoded path with only the commit flag in the body', async () => {
    await service.finalizeMigration({ receiverId: 'rx/1', commit: false });

    const url = String(vi.mocked(mockClient.post).mock.calls[0]?.[0]);
    expect(url).toMatch(/\/v1\/compute\/migrations\/rx%2F1\/finalize$/);
    expect(postedBody(mockClient)).toEqual({ commit: false });
  });
});
