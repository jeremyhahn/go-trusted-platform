/**
 * Unit tests for every public method of the Compute service, with a mocked
 * transport: each test pins the HTTP method, the path, the query and the body
 * the service sends, and that a transport failure reaches the caller.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ComputeService } from './compute-service.js';
import type { ApiClient } from '../client/api-client.js';
import type {
  AttachDiskRequest,
  AttestVMRequest,
  CreateContainerRequest,
  CreateSnapshotRequest,
  CreateVMRequest,
  ExecContainerRequest,
  MigrateVMRequest,
  VerifyVMAttestationRequest,
} from '../types/compute.js';

type HttpMethod = 'get' | 'post' | 'patch' | 'delete';

interface Case {
  name: string;
  call: (service: ComputeService) => Promise<unknown>;
  method: HttpMethod;
  path: string;
  query?: Array<[string, string]>;
  body?: unknown;
}

const BASE = 'https://api.example.com';

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
    baseUrl: BASE,
  } as unknown as ApiClient;
}

const createVMRequest = { name: 'vm-a', tenantId: 't1' } as unknown as CreateVMRequest;
const attachDiskRequest = {
  vmId: 'vm/1',
  disk: { name: 'data', sizeGb: 20 },
} as unknown as AttachDiskRequest;
const createSnapshotRequest = {
  vmId: 'vm/1',
  config: { name: 'snap-a', description: 'before upgrade' },
} as unknown as CreateSnapshotRequest;
const migrateVMRequest: MigrateVMRequest = {
  vmId: 'vm/1',
  destinationHost: 'host-b',
  liveMigration: true,
  bandwidthLimitMbps: 500,
} as MigrateVMRequest;
const attestVMRequest = {
  vmId: 'vm/1',
  nonce: 'bm9uY2U=',
  pcrIndices: [0, 7],
  pcrBank: 'SHA256',
} as unknown as AttestVMRequest;
const verifyRequest = {
  vmId: 'vm/1',
  quote: 'cXVvdGU=',
  expectedPcrs: { '0': 'aa' },
} as unknown as VerifyVMAttestationRequest;
const createContainerRequest = {
  name: 'ctr-a',
  image: 'registry.local/app:1',
} as unknown as CreateContainerRequest;
const execRequest = {
  id: 'ctr/1',
  command: ['ls', '-l'],
  tty: false,
} as unknown as ExecContainerRequest;

const cases: Case[] = [
  // VM operations
  {
    name: 'listVMs',
    call: (s) =>
      s.listVMs({ labels: { env: 'prod' }, states: ['VM_STATE_RUNNING'], page: 2, pageSize: 10 }),
    method: 'get',
    path: '/v1/compute/vms',
    query: [
      ['states', 'VM_STATE_RUNNING'],
      ['pagination.page', '2'],
      ['pagination.pageSize', '10'],
      ['selector.matchLabels.env', 'prod'],
    ],
  },
  { name: 'getVM', call: (s) => s.getVM('vm/1'), method: 'get', path: '/v1/compute/vms/vm%2F1' },
  {
    name: 'createVM',
    call: (s) => s.createVM(createVMRequest),
    method: 'post',
    path: '/v1/compute/vms',
    body: createVMRequest,
  },
  {
    name: 'deleteVM',
    call: (s) => s.deleteVM({ id: 'vm/1', deleteDisks: true }),
    method: 'delete',
    path: '/v1/compute/vms/vm%2F1',
    query: [['deleteDisks', 'true']],
  },
  {
    name: 'startVM',
    call: (s) => s.startVM('vm/1'),
    method: 'post',
    path: '/v1/compute/vms/vm%2F1/start',
    body: {},
  },
  {
    name: 'stopVM',
    call: (s) => s.stopVM({ id: 'vm/1', force: true, timeoutSeconds: 30 }),
    method: 'post',
    path: '/v1/compute/vms/vm%2F1/stop',
    body: { force: true, timeoutSeconds: 30 },
  },
  {
    name: 'rebootVM',
    call: (s) => s.rebootVM({ id: 'vm/1', force: false }),
    method: 'post',
    path: '/v1/compute/vms/vm%2F1/reboot',
    body: { force: false },
  },
  {
    name: 'migrateVM',
    call: (s) => s.migrateVM(migrateVMRequest),
    method: 'post',
    path: '/v1/compute/vms/vm%2F1/migrate',
    body: { destinationHost: 'host-b', liveMigration: true, bandwidthLimitMbps: 500 },
  },
  {
    name: 'attestVM',
    call: (s) => s.attestVM(attestVMRequest),
    method: 'post',
    path: '/v1/compute/vms/vm%2F1/attest',
    body: { nonce: 'bm9uY2U=', pcrIndices: [0, 7], pcrBank: 'PCR_BANK_SHA256' },
  },
  {
    name: 'verifyVMAttestation',
    call: (s) => s.verifyVMAttestation(verifyRequest),
    method: 'post',
    path: '/v1/compute/vms/vm%2F1/attest/verify',
    body: verifyRequest,
  },
  {
    name: 'getVMMetrics',
    call: (s) => s.getVMMetrics('vm/1'),
    method: 'get',
    path: '/v1/compute/vms/vm%2F1/metrics',
  },
  // VM disk operations
  {
    name: 'attachDisk',
    call: (s) => s.attachDisk(attachDiskRequest),
    method: 'post',
    path: '/v1/compute/vms/vm%2F1/disks',
    body: { disk: { name: 'data', sizeGb: 20 } },
  },
  {
    name: 'detachDisk',
    call: (s) => s.detachDisk({ vmId: 'vm/1', diskId: 'd/2' }),
    method: 'delete',
    path: '/v1/compute/vms/vm%2F1/disks/d%2F2',
  },
  {
    name: 'resizeDisk',
    call: (s) => s.resizeDisk({ vmId: 'vm/1', diskId: 'd/2', newSizeGb: 40 }),
    method: 'patch',
    path: '/v1/compute/vms/vm%2F1/disks/d%2F2',
    body: { newSizeGb: 40 },
  },
  // VM snapshot operations
  {
    name: 'listSnapshots',
    call: (s) => s.listSnapshots('vm/1'),
    method: 'get',
    path: '/v1/compute/vms/vm%2F1/snapshots',
  },
  {
    name: 'createSnapshot',
    call: (s) => s.createSnapshot(createSnapshotRequest),
    method: 'post',
    path: '/v1/compute/vms/vm%2F1/snapshots',
    body: { config: { name: 'snap-a', description: 'before upgrade' } },
  },
  {
    name: 'deleteSnapshot',
    call: (s) => s.deleteSnapshot({ vmId: 'vm/1', snapshotId: 's/3' }),
    method: 'delete',
    path: '/v1/compute/vms/vm%2F1/snapshots/s%2F3',
  },
  {
    name: 'restoreSnapshot',
    call: (s) => s.restoreSnapshot({ vmId: 'vm/1', snapshotId: 's/3' }),
    method: 'post',
    path: '/v1/compute/vms/vm%2F1/snapshots/s%2F3/restore',
    body: {},
  },
  // Container operations
  {
    name: 'listContainers',
    call: (s) =>
      s.listContainers({
        labels: { app: 'web' },
        states: ['CONTAINER_STATE_RUNNING', 'CONTAINER_STATE_EXITED'],
        page: 1,
        pageSize: 5,
      }),
    method: 'get',
    path: '/v1/compute/containers',
    query: [
      ['states', 'CONTAINER_STATE_RUNNING'],
      ['states', 'CONTAINER_STATE_EXITED'],
      ['pagination.page', '1'],
      ['pagination.pageSize', '5'],
      ['selector.matchLabels.app', 'web'],
    ],
  },
  {
    name: 'getContainer',
    call: (s) => s.getContainer('ctr/1'),
    method: 'get',
    path: '/v1/compute/containers/ctr%2F1',
  },
  {
    name: 'createContainer',
    call: (s) => s.createContainer(createContainerRequest),
    method: 'post',
    path: '/v1/compute/containers',
    body: createContainerRequest,
  },
  {
    name: 'deleteContainer',
    call: (s) => s.deleteContainer({ id: 'ctr/1', force: true, deleteVolumes: false }),
    method: 'delete',
    path: '/v1/compute/containers/ctr%2F1',
    query: [
      ['force', 'true'],
      ['deleteVolumes', 'false'],
    ],
  },
  {
    name: 'startContainer',
    call: (s) => s.startContainer('ctr/1'),
    method: 'post',
    path: '/v1/compute/containers/ctr%2F1/start',
    body: {},
  },
  {
    name: 'stopContainer',
    call: (s) => s.stopContainer({ id: 'ctr/1', timeoutSeconds: 10 }),
    method: 'post',
    path: '/v1/compute/containers/ctr%2F1/stop',
    body: { timeoutSeconds: 10 },
  },
  {
    name: 'execContainer',
    call: (s) => s.execContainer(execRequest),
    method: 'post',
    path: '/v1/compute/containers/ctr%2F1/exec',
    body: execRequest,
  },
  {
    name: 'getContainerMetrics',
    call: (s) => s.getContainerMetrics('ctr/1'),
    method: 'get',
    path: '/v1/compute/containers/ctr%2F1/metrics',
  },
];

const ALL_METHODS: HttpMethod[] = ['get', 'post', 'patch', 'delete'];

describe('ComputeService', () => {
  let service: ComputeService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new ComputeService(mockClient);
  });

  it('covers every public method of the service', () => {
    const methods = Object.getOwnPropertyNames(ComputeService.prototype)
      .filter((name) => name !== 'constructor')
      .sort();

    expect(cases.map((c) => c.name).sort()).toEqual(methods);
  });

  describe.each(cases)('$name', (c) => {
    it(`sends ${c.method.toUpperCase()} ${c.path} with its query and body`, async () => {
      const response = { data: { ok: c.name }, status: 200 };
      vi.mocked(mockClient[c.method]).mockResolvedValueOnce(response as never);

      await expect(c.call(service)).resolves.toBe(response);

      const send = vi.mocked(mockClient[c.method]);
      expect(send).toHaveBeenCalledTimes(1);
      for (const other of ALL_METHODS.filter((m) => m !== c.method)) {
        expect(vi.mocked(mockClient[other])).not.toHaveBeenCalled();
      }

      const args = send.mock.calls[0] as unknown[];
      const url = new URL(String(args[0]), BASE);
      expect(url.pathname).toBe(c.path);
      expect([...url.searchParams.entries()]).toEqual(c.query ?? []);

      if (c.method === 'post' || c.method === 'patch') {
        expect(args).toHaveLength(2);
        expect(args[1]).toEqual(c.body);
      } else {
        expect(args).toHaveLength(1);
      }
    });

    it('passes a transport failure through to the caller', async () => {
      const failure = new Error(`${c.name} failed: 503`);
      vi.mocked(mockClient[c.method]).mockRejectedValueOnce(failure);

      await expect(c.call(service)).rejects.toBe(failure);
    });
  });

  describe('optional filters', () => {
    it('listVMs without a request sends no query', async () => {
      vi.mocked(mockClient.get).mockResolvedValueOnce({ data: {}, status: 200 } as never);

      await service.listVMs();

      expect(vi.mocked(mockClient.get)).toHaveBeenCalledWith('/v1/compute/vms');
    });

    it('listContainers without a request sends no query', async () => {
      vi.mocked(mockClient.get).mockResolvedValueOnce({ data: {}, status: 200 } as never);

      await service.listContainers();

      expect(vi.mocked(mockClient.get)).toHaveBeenCalledWith('/v1/compute/containers');
    });

    it('deleteVM without deleteDisks sends no query', async () => {
      vi.mocked(mockClient.delete).mockResolvedValueOnce({ data: {}, status: 200 } as never);

      await service.deleteVM({ id: 'vm-1' });

      expect(vi.mocked(mockClient.delete)).toHaveBeenCalledWith('/v1/compute/vms/vm-1');
    });

    it('deleteContainer without flags sends no query', async () => {
      vi.mocked(mockClient.delete).mockResolvedValueOnce({ data: {}, status: 200 } as never);

      await service.deleteContainer({ id: 'ctr-1' });

      expect(vi.mocked(mockClient.delete)).toHaveBeenCalledWith('/v1/compute/containers/ctr-1');
    });

    it('attestVM without a PCR bank leaves the bank unset', async () => {
      vi.mocked(mockClient.post).mockResolvedValueOnce({ data: {}, status: 200 } as never);

      await service.attestVM({ vmId: 'vm-1', nonce: 'bg==' } as unknown as AttestVMRequest);

      const body = vi.mocked(mockClient.post).mock.calls[0]?.[1] as Record<string, unknown>;
      expect(body.pcrBank).toBeUndefined();
    });
  });
});
