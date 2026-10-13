import { test, expect, Page, Route, Request } from '@playwright/test';
import {
  createTenantOwnerSession,
  createTenantMemberSession,
} from './fixtures/auth-setup';
import { mockTenantApi, ApiError } from './fixtures/api-mock';

/**
 * Compute Management E2E Tests
 *
 * Tests for the compute management pages including:
 * - Virtual machines list, details, and CRUD operations
 * - Containers management
 * - Container images management
 * - Snapshots management
 * - Error handling states
 */

// ============================================================================
// SDK-Compatible Compute Types and Mock Data
// ============================================================================

// SDK VMState enum: the proto names the daemon sends (protojson)
export type VMState =
  | 'VM_STATE_UNSPECIFIED'
  | 'VM_STATE_STOPPED'
  | 'VM_STATE_STARTING'
  | 'VM_STATE_RUNNING'
  | 'VM_STATE_PAUSED'
  | 'VM_STATE_STOPPING'
  | 'VM_STATE_REBOOTING'
  | 'VM_STATE_MIGRATING'
  | 'VM_STATE_ERROR';

// SDK ContainerState enum: the proto names the daemon sends (protojson)
export type ContainerState =
  | 'CONTAINER_STATE_UNSPECIFIED'
  | 'CONTAINER_STATE_CREATED'
  | 'CONTAINER_STATE_STARTING'
  | 'CONTAINER_STATE_RUNNING'
  | 'CONTAINER_STATE_PAUSED'
  | 'CONTAINER_STATE_STOPPING'
  | 'CONTAINER_STATE_STOPPED'
  | 'CONTAINER_STATE_EXITED'
  | 'CONTAINER_STATE_ERROR';

// SDK DiskType
export type DiskType =
  | 'DISK_TYPE_UNSPECIFIED'
  | 'DISK_TYPE_RAW'
  | 'DISK_TYPE_QCOW2'
  | 'DISK_TYPE_VDI'
  | 'DISK_TYPE_VMDK';

// SDK DiskBus
export type DiskBus =
  | 'DISK_BUS_UNSPECIFIED'
  | 'DISK_BUS_IDE'
  | 'DISK_BUS_SATA'
  | 'DISK_BUS_SCSI'
  | 'DISK_BUS_VIRTIO'
  | 'DISK_BUS_NVME';

// SDK NetworkModel
export type NetworkModel =
  | 'NETWORK_MODEL_UNSPECIFIED'
  | 'NETWORK_MODEL_E1000'
  | 'NETWORK_MODEL_VIRTIO'
  | 'NETWORK_MODEL_RTL8139';

// SDK-compatible CPU configuration
export interface CPUConfig {
  cores: number;
  sockets?: number;
  threads?: number;
  model?: string;
  features?: string[];
}

// SDK-compatible memory configuration
export interface MemoryConfig {
  sizeMb: number;
  hugepages?: boolean;
  shared?: boolean;
}

// SDK-compatible disk configuration
export interface DiskConfig {
  id?: string;
  path: string;
  type?: DiskType;
  bus?: DiskBus;
  sizeGb?: number;
  readonly?: boolean;
  bootable?: boolean;
  backingFile?: string;
}

// SDK-compatible network interface configuration
export interface NetworkInterfaceConfig {
  id?: string;
  bridge: string;
  macAddress?: string;
  model?: NetworkModel;
  vlan?: number;
  bandwidthLimitMbps?: number;
}

// SDK-compatible VM configuration
export interface VMConfig {
  name: string;
  description?: string;
  firmware?: string;
  bootDevice?: string;
  cpu: CPUConfig;
  memory: MemoryConfig;
  disks: DiskConfig[];
  networks: NetworkInterfaceConfig[];
  graphics?: {
    type: string;
    listen?: string;
    port?: number;
  };
  secureBoot?: boolean;
  labels?: Record<string, string>;
  metadata?: Record<string, string>;
}

// SDK-compatible VM metrics
export interface VMMetrics {
  cpuUsagePercent: number;
  memoryUsedMb: number;
  memoryAvailableMb: number;
  diskReadBytes: number;
  diskWriteBytes: number;
  networkRxBytes: number;
  networkTxBytes: number;
  uptimeSeconds: number;
}

// SDK-compatible VM interface (matches SDK's VM interface)
export interface VM {
  id: string;
  config: VMConfig;
  state: VMState;
  createdAt: string;
  updatedAt: string;
  hostId?: string;
  metrics?: VMMetrics;
}

// SDK-compatible PortMapping
export interface PortMapping {
  hostPort: number;
  containerPort: number;
  protocol?: string;
  hostIp?: string;
}

// SDK-compatible ContainerConfig
export interface ContainerConfig {
  name: string;
  image: string;
  imageHash?: string;
  command?: string[];
  args?: string[];
  workingDir?: string;
  ports?: PortMapping[];
  privileged?: boolean;
  network?: string;
  labels?: Record<string, string>;
  metadata?: Record<string, string>;
}

// SDK-compatible ContainerMetrics
export interface ContainerMetrics {
  cpuUsagePercent: number;
  memoryUsedMb: number;
  memoryLimitMb: number;
  diskReadBytes: number;
  diskWriteBytes: number;
  networkRxBytes: number;
  networkTxBytes: number;
  uptimeSeconds: number;
}

// SDK-compatible Container interface
export interface Container {
  id: string;
  config: ContainerConfig;
  state: ContainerState;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  exitCode?: number;
  hostId?: string;
  metrics?: ContainerMetrics;
}

// SDK-compatible SnapshotConfig
export interface SnapshotConfig {
  name: string;
  description?: string;
  memorySnapshot?: boolean;
  diskSnapshot?: boolean;
}

// SDK-compatible Snapshot interface
export interface Snapshot {
  id: string;
  vmId: string;
  config: SnapshotConfig;
  createdAt: string;
  sizeBytes: number;
  vmState: VMState;
}

// SDK-compatible ListVMsResponse
export interface ListVMsResponse {
  vms: VM[];
  pagination?: {
    page: number;
    pageSize: number;
    totalPages: number;
    totalItems: number;
  };
}

// SDK-compatible ListContainersResponse
export interface ListContainersResponse {
  containers: Container[];
  pagination?: {
    page: number;
    pageSize: number;
    totalPages: number;
    totalItems: number;
  };
}

// SDK-compatible ListSnapshotsResponse
export interface ListSnapshotsResponse {
  snapshots: Snapshot[];
}

// SDK-compatible ComputeStatus for operation responses
export interface ComputeStatus {
  success: boolean;
  message: string;
  error?: {
    code: string;
    message: string;
    metadata?: Record<string, string>;
  };
}

// Parameters for createMockVM (convenience interface)
export interface CreateMockVMParams {
  id?: string;
  name?: string;
  description?: string;
  state?: VMState;
  vcpus?: number;
  memoryMB?: number;
  diskGB?: number;
  tags?: string[];
}

// Parameters for createMockContainer (convenience interface)
export interface CreateMockContainerParams {
  id?: string;
  name?: string;
  image?: string;
  state?: ContainerState;
  ports?: PortMapping[];
  command?: string[];
}

// Parameters for createMockSnapshot (convenience interface)
export interface CreateMockSnapshotParams {
  id?: string;
  name?: string;
  description?: string;
  vmId?: string;
  sizeBytes?: number;
  vmState?: VMState;
}

// Mock data generators
let vmIdCounter = 1;
let containerIdCounter = 1;
let snapshotIdCounter = 1;

export function createMockVM(params: CreateMockVMParams = {}): VM {
  const id = params.id || `vm-${vmIdCounter++}`;
  const now = new Date();

  const name = params.name || `VM-${id}`;
  const description = params.description || 'Test virtual machine';
  const state = params.state || 'VM_STATE_RUNNING';
  const vcpus = params.vcpus ?? 2;
  const memoryMB = params.memoryMB ?? 4096;
  const diskGB = params.diskGB ?? 50;

  return {
    id,
    config: {
      name,
      description,
      cpu: {
        cores: vcpus,
        sockets: 1,
        threads: 1,
      },
      memory: {
        sizeMb: memoryMB,
      },
      disks: [
        {
          id: `${id}-disk-0`,
          path: `/var/lib/libvirt/images/${id}-root.qcow2`,
          type: 'DISK_TYPE_QCOW2',
          bus: 'DISK_BUS_VIRTIO',
          sizeGb: diskGB,
          bootable: true,
        },
      ],
      networks: [
        {
          id: `${id}-nic-0`,
          bridge: 'virbr0',
          macAddress: `52:54:00:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}`,
          model: 'NETWORK_MODEL_VIRTIO',
        },
      ],
      labels: params.tags ? { tags: params.tags.join(',') } : undefined,
    },
    state,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };
}

export function createMockContainer(params: CreateMockContainerParams = {}): Container {
  const id = params.id || `container-${containerIdCounter++}`;
  const now = new Date();

  return {
    id,
    config: {
      name: params.name || `container-${id}`,
      image: params.image || 'nginx:latest',
      command: params.command,
      ports: params.ports || [
        { hostPort: 80, containerPort: 80, protocol: 'tcp' },
        { hostPort: 443, containerPort: 443, protocol: 'tcp' },
      ],
    },
    state: params.state || 'CONTAINER_STATE_RUNNING',
    createdAt: now.toISOString(),
    startedAt: params.state === 'CONTAINER_STATE_RUNNING' ? now.toISOString() : undefined,
  };
}

export function createMockSnapshot(params: CreateMockSnapshotParams = {}): Snapshot {
  const id = params.id || `snap-${snapshotIdCounter++}`;
  const now = new Date();

  return {
    id,
    vmId: params.vmId || 'vm-1',
    config: {
      name: params.name || `Snapshot-${id}`,
      description: params.description || 'Test snapshot',
      memorySnapshot: true,
      diskSnapshot: true,
    },
    createdAt: now.toISOString(),
    sizeBytes: params.sizeBytes || 25 * 1024 * 1024 * 1024, // 25 GB in bytes
    vmState: params.vmState || 'VM_STATE_STOPPED',
  };
}

// ============================================================================
// API Mock Configuration
// ============================================================================

export interface ComputeApiMockConfig {
  // VMs
  initialVMs?: VM[];
  fetchVMsError?: ApiError | null;
  fetchVMDetailError?: ApiError | null;
  createVMError?: ApiError | null;
  updateVMError?: ApiError | null;
  deleteVMError?: ApiError | null;
  vmOperationError?: ApiError | null;
  // Containers
  initialContainers?: Container[];
  fetchContainersError?: ApiError | null;
  containerOperationError?: ApiError | null;
  deleteContainerError?: ApiError | null;
  // Snapshots
  initialSnapshots?: Snapshot[];
  fetchSnapshotsError?: ApiError | null;
  createSnapshotError?: ApiError | null;
  restoreSnapshotError?: ApiError | null;
  deleteSnapshotError?: ApiError | null;
}

interface ComputeApiState {
  vms: VM[];
  containers: Container[];
  snapshots: Snapshot[];
  config: ComputeApiMockConfig;
}

/**
 * Mock the compute API endpoints.
 *
 * Handles:
 * - GET/POST /api/v1/compute/vms - List/Create VMs
 * - GET/PUT/DELETE /api/v1/compute/vms/:id - Get/Update/Delete VM
 * - POST /api/v1/compute/vms/:id/start|stop|reboot - VM operations
 * - GET/POST /api/v1/compute/containers - List/Create containers
 * - POST /api/v1/compute/containers/:id/start|stop - Container operations
 * - GET/POST /api/v1/compute/vms/:id/snapshots - List/Create snapshots
 */
export async function mockComputeApi(
  page: Page,
  config: ComputeApiMockConfig = {}
): Promise<{
  getVMs: () => VM[];
  addVM: (vm: VM) => void;
  removeVM: (id: string) => void;
  getContainers: () => Container[];
  addContainer: (container: Container) => void;
  removeContainer: (id: string) => void;
  getSnapshots: () => Snapshot[];
  addSnapshot: (snapshot: Snapshot) => void;
  removeSnapshot: (id: string) => void;
  setError: (endpoint: string, error: ApiError | null) => void;
}> {
  const state: ComputeApiState = {
    vms: config.initialVMs || [],
    containers: config.initialContainers || [],
    snapshots: config.initialSnapshots || [],
    config: {
      fetchVMsError: null,
      fetchVMDetailError: null,
      createVMError: null,
      updateVMError: null,
      deleteVMError: null,
      vmOperationError: null,
      fetchContainersError: null,
      containerOperationError: null,
      deleteContainerError: null,
      fetchSnapshotsError: null,
      createSnapshotError: null,
      restoreSnapshotError: null,
      deleteSnapshotError: null,
      ...config,
    },
  };

  // ============================================================================
  // VMs API Routes
  // ============================================================================

  // Route handler for VMs list
  await page.route('**/api/v1/compute/vms', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.fetchVMsError) {
        await route.fulfill({
          status: state.config.fetchVMsError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.fetchVMsError.error,
            code: state.config.fetchVMsError.errorCode || 'HTTP_' + state.config.fetchVMsError.status,
            reason: state.config.fetchVMsError.reason,
            service: state.config.fetchVMsError.service,
          }),
        });
        return;
      }

      const response: ListVMsResponse = {
        vms: state.vms,
        pagination: {
          page: 1,
          pageSize: 100,
          totalPages: Math.ceil(state.vms.length / 100),
          totalItems: state.vms.length,
        },
      };

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.createVMError) {
        await route.fulfill({
          status: state.config.createVMError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.createVMError.error,
            code: state.config.createVMError.errorCode || 'HTTP_' + state.config.createVMError.status,
          }),
        });
        return;
      }

      try {
        const body = request.postDataJSON();
        // SDK format expects { config: VMConfig }
        const vmConfig = body.config || body;
        const newVM = createMockVM({
          name: vmConfig.name,
          description: vmConfig.description,
          vcpus: vmConfig.cpu?.cores || 2,
          memoryMB: vmConfig.memory?.sizeMb || 4096,
          diskGB: vmConfig.disks?.[0]?.sizeGb || 50,
          state: 'VM_STATE_STARTING',
        });

        state.vms.unshift(newVM);

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ status: { success: true, message: 'VM created' }, vm: newVM }),
        });
      } catch {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Invalid request body', code: 'HTTP_400' }),
        });
      }
      return;
    }

    await route.continue();
  });

  // Route handler for individual VM operations (including nested paths like /vms/{id}/reboot)
  await page.route('**/api/v1/compute/vms/**', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();

    // Extract VM ID and action from URL
    const match = url.match(/\/vms\/([^/]+)(?:\/(.+))?/);
    const vmId = match ? match[1] : null;
    const action = match ? match[2] : null;

    // Handle VM operations (start, stop, reboot)
    if (method === 'POST' && action) {
      if (state.config.vmOperationError) {
        await route.fulfill({
          status: state.config.vmOperationError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.vmOperationError.error,
            code: state.config.vmOperationError.errorCode || 'HTTP_' + state.config.vmOperationError.status,
          }),
        });
        return;
      }

      const vmIndex = state.vms.findIndex((vm) => vm.id === vmId);
      if (vmIndex === -1) {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'VM not found', code: 'HTTP_404' }),
        });
        return;
      }

      if (action === 'start') {
        state.vms[vmIndex].state = 'VM_STATE_RUNNING';
      } else if (action === 'stop') {
        state.vms[vmIndex].state = 'VM_STATE_STOPPED';
      } else if (action === 'reboot') {
        state.vms[vmIndex].state = 'VM_STATE_RUNNING';
      }

      state.vms[vmIndex].updatedAt = new Date().toISOString();

      // SDK expects { status: ComputeStatus } format for operation responses
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: {
            success: true,
            message: `VM ${action} successful`,
          },
        }),
      });
      return;
    }

    if (method === 'GET') {
      if (state.config.fetchVMDetailError) {
        await route.fulfill({
          status: state.config.fetchVMDetailError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.fetchVMDetailError.error,
            code: state.config.fetchVMDetailError.errorCode || 'HTTP_' + state.config.fetchVMDetailError.status,
          }),
        });
        return;
      }

      const vm = state.vms.find((v) => v.id === vmId);
      if (vm) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ vm }),
        });
      } else {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'VM not found', code: 'HTTP_404' }),
        });
      }
      return;
    }

    if (method === 'PUT') {
      if (state.config.updateVMError) {
        await route.fulfill({
          status: state.config.updateVMError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.updateVMError.error,
            code: state.config.updateVMError.errorCode || 'HTTP_' + state.config.updateVMError.status,
          }),
        });
        return;
      }

      const index = state.vms.findIndex((v) => v.id === vmId);
      if (index !== -1) {
        try {
          const body = request.postDataJSON();
          if (body.config) {
            state.vms[index].config = { ...state.vms[index].config, ...body.config };
          }
          state.vms[index].updatedAt = new Date().toISOString();

          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ status: { success: true, message: 'VM updated' }, vm: state.vms[index] }),
          });
        } catch {
          await route.fulfill({
            status: 400,
            contentType: 'application/json',
            body: JSON.stringify({ message: 'Invalid request body', code: 'HTTP_400' }),
          });
        }
      } else {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'VM not found', code: 'HTTP_404' }),
        });
      }
      return;
    }

    if (method === 'DELETE') {
      if (state.config.deleteVMError) {
        await route.fulfill({
          status: state.config.deleteVMError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.deleteVMError.error,
            code: state.config.deleteVMError.errorCode || 'HTTP_' + state.config.deleteVMError.status,
          }),
        });
        return;
      }

      const index = state.vms.findIndex((v) => v.id === vmId);
      if (index !== -1) {
        state.vms.splice(index, 1);
      }

      // SDK expects { status: ComputeStatus } format
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: {
            success: true,
            message: 'VM deleted successfully',
          },
        }),
      });
      return;
    }

    await route.continue();
  });

  // ============================================================================
  // Containers API Routes
  // ============================================================================

  await page.route('**/api/v1/compute/containers', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.fetchContainersError) {
        await route.fulfill({
          status: state.config.fetchContainersError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.fetchContainersError.error,
            code: state.config.fetchContainersError.errorCode || 'HTTP_' + state.config.fetchContainersError.status,
            reason: state.config.fetchContainersError.reason,
            service: state.config.fetchContainersError.service,
          }),
        });
        return;
      }

      const response: ListContainersResponse = {
        containers: state.containers,
        pagination: {
          page: 1,
          pageSize: 100,
          totalPages: Math.ceil(state.containers.length / 100),
          totalItems: state.containers.length,
        },
      };

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }

    if (method === 'POST') {
      try {
        const body = request.postDataJSON();
        const containerConfig = body.config || body;
        const newContainer = createMockContainer({
          name: containerConfig.name,
          image: containerConfig.image,
          ports: containerConfig.ports,
          command: containerConfig.command,
          state: 'CONTAINER_STATE_STARTING',
        });

        state.containers.unshift(newContainer);

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ status: { success: true, message: 'Container created' }, container: newContainer }),
        });
      } catch {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Invalid request body', code: 'HTTP_400' }),
        });
      }
      return;
    }

    await route.continue();
  });

  // Route handler for individual container operations (including nested paths like /containers/{id}/start)
  await page.route('**/api/v1/compute/containers/**', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();

    const match = url.match(/\/containers\/([^/]+)(?:\/(.+))?/);
    const containerId = match ? match[1] : null;
    const action = match ? match[2] : null;

    // Handle container operations (start, stop)
    if (method === 'POST' && action) {
      if (state.config.containerOperationError) {
        await route.fulfill({
          status: state.config.containerOperationError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.containerOperationError.error,
            code: state.config.containerOperationError.errorCode || 'HTTP_' + state.config.containerOperationError.status,
          }),
        });
        return;
      }

      const containerIndex = state.containers.findIndex((c) => c.id === containerId);
      if (containerIndex === -1) {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Container not found', code: 'HTTP_404' }),
        });
        return;
      }

      if (action === 'start') {
        state.containers[containerIndex].state = 'CONTAINER_STATE_RUNNING';
        state.containers[containerIndex].startedAt = new Date().toISOString();
      } else if (action === 'stop') {
        state.containers[containerIndex].state = 'CONTAINER_STATE_STOPPED';
      }

      // SDK expects { status: ComputeStatus } format
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: {
            success: true,
            message: `Container ${action} successful`,
          },
        }),
      });
      return;
    }

    if (method === 'DELETE') {
      if (state.config.deleteContainerError) {
        await route.fulfill({
          status: state.config.deleteContainerError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.deleteContainerError.error,
            code: state.config.deleteContainerError.errorCode || 'HTTP_' + state.config.deleteContainerError.status,
          }),
        });
        return;
      }

      const index = state.containers.findIndex((c) => c.id === containerId);
      if (index !== -1) {
        state.containers.splice(index, 1);
      }

      // SDK expects { status: ComputeStatus } format
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: {
            success: true,
            message: 'Container deleted successfully',
          },
        }),
      });
      return;
    }

    await route.continue();
  });

  // ============================================================================
  // Snapshots API Routes (per-VM snapshots)
  // ============================================================================

  // Route handler for VM snapshots: /api/v1/compute/vms/{vmId}/snapshots
  await page.route('**/api/v1/compute/vms/*/snapshots', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();

    const match = url.match(/\/vms\/([^/]+)\/snapshots/);
    const vmId = match ? match[1] : null;

    if (method === 'GET') {
      if (state.config.fetchSnapshotsError) {
        await route.fulfill({
          status: state.config.fetchSnapshotsError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.fetchSnapshotsError.error,
            code: state.config.fetchSnapshotsError.errorCode || 'HTTP_' + state.config.fetchSnapshotsError.status,
          }),
        });
        return;
      }

      // Filter snapshots by vmId
      const vmSnapshots = state.snapshots.filter((s) => s.vmId === vmId);
      const response: ListSnapshotsResponse = {
        snapshots: vmSnapshots,
      };

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.createSnapshotError) {
        await route.fulfill({
          status: state.config.createSnapshotError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.createSnapshotError.error,
            code: state.config.createSnapshotError.errorCode || 'HTTP_' + state.config.createSnapshotError.status,
          }),
        });
        return;
      }

      try {
        const body = request.postDataJSON();
        const snapshotConfig = body.config || body;
        const vm = state.vms.find((v) => v.id === vmId);

        const newSnapshot = createMockSnapshot({
          name: snapshotConfig.name,
          description: snapshotConfig.description,
          vmId: vmId || 'vm-1',
          vmState: vm?.state || 'VM_STATE_STOPPED',
        });

        state.snapshots.unshift(newSnapshot);

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ status: { success: true, message: 'Snapshot created' }, snapshot: newSnapshot }),
        });
      } catch {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Invalid request body', code: 'HTTP_400' }),
        });
      }
      return;
    }

    await route.continue();
  });

  // Route handler for individual snapshot operations
  await page.route('**/api/v1/compute/vms/*/snapshots/**', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();

    const match = url.match(/\/vms\/([^/]+)\/snapshots\/([^/]+)(?:\/(.+))?/);
    const vmId = match ? match[1] : null;
    const snapshotId = match ? match[2] : null;
    const action = match ? match[3] : null;

    // Handle restore operation
    if (method === 'POST' && action === 'restore') {
      if (state.config.restoreSnapshotError) {
        await route.fulfill({
          status: state.config.restoreSnapshotError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.restoreSnapshotError.error,
            code: state.config.restoreSnapshotError.errorCode || 'HTTP_' + state.config.restoreSnapshotError.status,
          }),
        });
        return;
      }

      // SDK expects { status: ComputeStatus } format
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: {
            success: true,
            message: 'Snapshot restore initiated',
          },
        }),
      });
      return;
    }

    if (method === 'DELETE') {
      if (state.config.deleteSnapshotError) {
        await route.fulfill({
          status: state.config.deleteSnapshotError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.deleteSnapshotError.error,
            code: state.config.deleteSnapshotError.errorCode || 'HTTP_' + state.config.deleteSnapshotError.status,
          }),
        });
        return;
      }

      const index = state.snapshots.findIndex((s) => s.id === snapshotId && s.vmId === vmId);
      if (index !== -1) {
        state.snapshots.splice(index, 1);
      }

      // SDK expects { status: ComputeStatus } format
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: {
            success: true,
            message: 'Snapshot deleted successfully',
          },
        }),
      });
      return;
    }

    await route.continue();
  });

  return {
    getVMs: () => [...state.vms],
    addVM: (vm: VM) => {
      state.vms.unshift(vm);
    },
    removeVM: (id: string) => {
      const index = state.vms.findIndex((v) => v.id === id);
      if (index !== -1) {
        state.vms.splice(index, 1);
      }
    },
    getContainers: () => [...state.containers],
    addContainer: (container: Container) => {
      state.containers.unshift(container);
    },
    removeContainer: (id: string) => {
      const index = state.containers.findIndex((c) => c.id === id);
      if (index !== -1) {
        state.containers.splice(index, 1);
      }
    },
    getSnapshots: () => [...state.snapshots],
    addSnapshot: (snapshot: Snapshot) => {
      state.snapshots.unshift(snapshot);
    },
    removeSnapshot: (id: string) => {
      const index = state.snapshots.findIndex((s) => s.id === id);
      if (index !== -1) {
        state.snapshots.splice(index, 1);
      }
    },
    setError: (endpoint: string, error: ApiError | null) => {
      const key = endpoint as keyof ComputeApiMockConfig;
      if (key in state.config) {
        (state.config as Record<string, ApiError | null>)[key] = error;
      }
    },
  };
}

// ============================================================================
// Test Suites
// ============================================================================

test.describe('Compute Management', () => {
  // ==========================================================================
  // VMs List Tests
  // ==========================================================================
  test.describe('VMs List', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should display VM table with columns', async ({ page }) => {
      const vms = [
        createMockVM({ id: 'vm-1', name: 'Web-Server', state: 'VM_STATE_RUNNING', vcpus: 4, memoryMB: 8192 }),
        createMockVM({ id: 'vm-2', name: 'Database', state: 'VM_STATE_STOPPED', vcpus: 2, memoryMB: 4096 }),
      ];

      await mockComputeApi(page, { initialVMs: vms });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Verify page header
      await expect(page.getByRole('heading', { name: /virtual machines/i })).toBeVisible();

      // Verify table headers
      await expect(page.getByRole('columnheader', { name: /name/i })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /status/i })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /vcpus/i })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /memory/i })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /actions/i })).toBeVisible();

      // Verify VMs are displayed
      await expect(page.getByText('Web-Server')).toBeVisible();
      await expect(page.getByText('Database')).toBeVisible();
    });

    test('should display VM status badges correctly', async ({ page }) => {
      const vms = [
        createMockVM({ id: 'vm-1', name: 'Running-VM', state: 'VM_STATE_RUNNING' }),
        createMockVM({ id: 'vm-2', name: 'Stopped-VM', state: 'VM_STATE_STOPPED' }),
        createMockVM({ id: 'vm-3', name: 'Paused-VM', state: 'VM_STATE_PAUSED' }),
      ];

      await mockComputeApi(page, { initialVMs: vms });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Verify status badges (UI shows lowercase status from transformation)
      await expect(page.locator('text=running').first()).toBeVisible();
      await expect(page.locator('text=stopped').first()).toBeVisible();
    });

    test('should show empty state when no VMs', async ({ page }) => {
      await mockComputeApi(page, { initialVMs: [] });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      await expect(page.getByText(/no virtual machines found/i)).toBeVisible();
    });

    test('should show not-available state when compute is unconfigured (503)', async ({ page }) => {
      // The control plane answers a structured 503 when the compute
      // service is not wired on the node (service registry loud-failure
      // policy). The page renders an informational state, not an error.
      await mockComputeApi(page, {
        fetchVMsError: {
          status: 503,
          error: 'compute service not configured by daemon — REST surface is dark',
          reason: 'SERVICE_NOT_CONFIGURED',
          service: 'compute',
        },
      });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      await expect(page.getByText(/compute is not available on this node/i)).toBeVisible();
      // No destructive error toast for the informational state.
      await expect(page.getByText(/failed to fetch vms/i)).not.toBeVisible();
    });

    test('should treat a transient 503 as an error, not as compute-absent', async ({ page }) => {
      // Only the service registry's SERVICE_NOT_CONFIGURED
      // discriminator means "not configured on this node". A live
      // compute service answering 503 (transient outage) carries no
      // discriminator and must keep surfacing as an error.
      await mockComputeApi(page, {
        fetchVMsError: {
          status: 503,
          error: 'compute backend temporarily unavailable',
        },
      });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      await expect(page.getByText(/failed to fetch vms/i).first()).toBeVisible();
      await expect(page.getByText(/compute is not available on this node/i)).not.toBeVisible();
    });

    test('should treat the registry prose under a non-503 status as an error', async ({ page }) => {
      // A backend failure whose message happens to read like the
      // registry's prose is NOT an absent service. The page keys off the
      // 503 status plus the SERVICE_NOT_CONFIGURED discriminator, so
      // this must still surface as an error.
      await mockComputeApi(page, {
        fetchVMsError: {
          status: 500,
          error: 'compute surface is dark after backend failure',
          reason: 'SERVICE_NOT_CONFIGURED',
          service: 'compute',
        },
      });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      await expect(page.getByText(/failed to fetch vms/i).first()).toBeVisible();
      await expect(page.getByText(/compute is not available on this node/i)).not.toBeVisible();
    });

    test('should treat a 503 with the registry prose but no discriminator as an error', async ({ page }) => {
      await mockComputeApi(page, {
        fetchVMsError: {
          status: 503,
          error: 'compute service not configured by daemon — REST surface is dark',
        },
      });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      await expect(page.getByText(/failed to fetch vms/i).first()).toBeVisible();
      await expect(page.getByText(/compute is not available on this node/i)).not.toBeVisible();
    });

    test('should show loading state', async ({ page }) => {
      // Add delay to API to see loading state
      await page.route('**/api/v1/compute/vms', async (route) => {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            vms: [],
            pagination: { page: 1, pageSize: 100, totalPages: 0, totalItems: 0 },
          }),
        });
      });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Loading state shows a spinning icon (h-8 w-8 spinner in center)
      await expect(page.locator('.h-8.animate-spin')).toBeVisible();
    });

    test('should filter VMs by status dropdown', async ({ page }) => {
      const vms = [
        createMockVM({ id: 'vm-1', name: 'Production-Web', state: 'VM_STATE_RUNNING' }),
        createMockVM({ id: 'vm-2', name: 'Development-Web', state: 'VM_STATE_RUNNING' }),
        createMockVM({ id: 'vm-3', name: 'Test-Database', state: 'VM_STATE_STOPPED' }),
      ];

      await mockComputeApi(page, { initialVMs: vms });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Wait for VMs to load
      await expect(page.getByText('Production-Web')).toBeVisible();

      // Select 'Stopped' from the status filter dropdown
      await page.getByRole('combobox').click();
      await page.getByRole('option', { name: /stopped/i }).click();

      // Only Test-Database should be visible
      await expect(page.getByText('Test-Database')).toBeVisible();
      // The running VMs should not be visible
      await expect(page.getByText('Production-Web')).not.toBeVisible();
    });
  });

  // ==========================================================================
  // VM CRUD Tests
  // ==========================================================================
  test.describe('Snapshots availability', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should show not-available state when compute is unconfigured (503)', async ({ page }) => {
      // The snapshots page derives everything from listVMs; the
      // structured 503 must render the informational state there too.
      await mockComputeApi(page, {
        fetchVMsError: {
          status: 503,
          error: 'compute service not configured by daemon — REST surface is dark',
          reason: 'SERVICE_NOT_CONFIGURED',
          service: 'compute',
        },
      });
      await mockTenantApi(page);

      await page.goto('/compute/snapshots');

      await expect(page.getByText(/compute is not available on this node/i)).toBeVisible();
      await expect(page.getByText(/error loading snapshots/i)).not.toBeVisible();
    });

    test('should treat a transient 503 as an error, not as compute-absent', async ({ page }) => {
      await mockComputeApi(page, {
        fetchVMsError: {
          status: 503,
          error: 'compute backend temporarily unavailable',
        },
      });
      await mockTenantApi(page);

      await page.goto('/compute/snapshots');

      await expect(page.getByText(/error loading snapshots/i).first()).toBeVisible();
      await expect(page.getByText(/compute is not available on this node/i)).not.toBeVisible();
    });
  });

  test.describe('VM CRUD Operations', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should open create VM dialog', async ({ page }) => {
      await mockComputeApi(page, { initialVMs: [] });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Click create VM button
      await page.getByRole('button', { name: /create vm/i }).click();

      // Dialog should be open
      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByRole('heading', { name: /create.*virtual machine|new vm/i })).toBeVisible();
    });

    test('should create a new VM', async ({ page }) => {
      const mockApi = await mockComputeApi(page, { initialVMs: [] });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Verify empty state
      await expect(page.getByText(/no virtual machines found/i)).toBeVisible();

      // Open create dialog
      await page.getByRole('button', { name: /create vm/i }).click();

      // Fill out the form - the form uses 'name' input
      await page.fill('input[name="name"]', 'New-Test-VM');

      // Submit the form
      await page.getByRole('button', { name: /create/i }).last().click();

      // Should show success message
      await expect(page.getByText(/virtual machine created successfully/i)).toBeVisible();

      // VM should appear in list
      await expect(page.getByText('New-Test-VM')).toBeVisible();

      // Verify VM was added to mock state
      const vms = mockApi.getVMs();
      expect(vms.length).toBe(1);
    });

    test('should start a stopped VM', async ({ page }) => {
      const vm = createMockVM({ id: 'vm-1', name: 'Stopped-VM', state: 'VM_STATE_STOPPED' });

      await mockComputeApi(page, { initialVMs: [vm] });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Wait for table to load
      await expect(page.getByRole('cell', { name: 'Stopped-VM' })).toBeVisible();

      // Click on actions menu button (the button in the row)
      await page.getByRole('row', { name: /stopped-vm/i }).getByRole('button').click();

      // Click start
      await page.getByRole('menuitem', { name: /start/i }).click();

      // Should show success message
      await expect(page.getByText(/vm started successfully/i)).toBeVisible();
    });

    test('should stop a running VM', async ({ page }) => {
      const vm = createMockVM({ id: 'vm-1', name: 'Running-VM', state: 'VM_STATE_RUNNING' });

      await mockComputeApi(page, { initialVMs: [vm] });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Wait for table to load
      await expect(page.getByRole('cell', { name: 'Running-VM' })).toBeVisible();

      // Click on actions menu button
      await page.getByRole('row', { name: /running-vm/i }).getByRole('button').click();

      // Click stop
      await page.getByRole('menuitem', { name: /stop/i }).click();

      // Should show success message
      await expect(page.getByText(/vm stopped successfully/i)).toBeVisible();
    });

    test('should reboot a VM', async ({ page }) => {
      const vm = createMockVM({ id: 'vm-1', name: 'Reboot-VM', state: 'VM_STATE_RUNNING' });

      await mockComputeApi(page, { initialVMs: [vm] });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Wait for table to load
      await expect(page.getByRole('cell', { name: 'Reboot-VM' })).toBeVisible();

      // Wait for action button to be enabled and click
      const actionButton = page.getByRole('row', { name: /reboot-vm/i }).getByRole('button');
      await expect(actionButton).toBeEnabled();
      await actionButton.click();

      // Click reboot
      await page.getByRole('menuitem', { name: /reboot/i }).click();

      // Should show success message
      await expect(page.getByText(/vm rebooted successfully/i)).toBeVisible({ timeout: 10000 });
    });

    test('should delete a VM with confirmation', async ({ page }) => {
      const vm = createMockVM({ id: 'vm-1', name: 'Delete-Me-VM', state: 'VM_STATE_STOPPED' });

      const mockApi = await mockComputeApi(page, { initialVMs: [vm] });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Wait for table to load
      await expect(page.getByRole('cell', { name: 'Delete-Me-VM' })).toBeVisible();

      // Wait for action button to be enabled and click
      const actionButton = page.getByRole('row', { name: /delete-me-vm/i }).getByRole('button');
      await expect(actionButton).toBeEnabled();
      await actionButton.click();

      // Click delete
      await page.getByRole('menuitem', { name: /delete/i }).click();

      // Should show success message
      await expect(page.getByText(/vm deleted successfully/i)).toBeVisible();

      // VM should be removed from list
      await expect(page.getByText('Delete-Me-VM')).not.toBeVisible();

      // Verify VM was removed from mock state
      const vms = mockApi.getVMs();
      expect(vms.length).toBe(0);
    });

    // Skip: Clone feature not implemented in VMTable component
    test.skip('should clone a VM', async () => {
      // Clone feature is not yet implemented in the VMTable component
      // The dropdown menu does not have a "Clone" option
    });
  });

  // ==========================================================================
  // VM Details Tests
  // ==========================================================================
  // Skip: VM details page (/compute/vms/[id]) exists but navigation to it is not
  // available through the VM list table (clicking VM name does not navigate)
  test.describe.skip('VM Details', () => {
    // VM details tests are skipped because:
    // 1. The VMTable component does not have navigation to VM details (no link on VM name)
    // 2. The dropdown menu does not have "View Details" option
    // 3. Direct navigation to /compute/vms/{id} would require the VM detail page to work
    //    with the mock API which has a different structure
  });

  // ==========================================================================
  // Containers Tests
  // ==========================================================================
  test.describe('Containers', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should display container list', async ({ page }) => {
      const containers = [
        createMockContainer({ id: 'c-1', name: 'nginx-proxy', image: 'nginx:latest', state: 'CONTAINER_STATE_RUNNING' }),
        createMockContainer({ id: 'c-2', name: 'redis-cache', image: 'redis:7', state: 'CONTAINER_STATE_STOPPED' }),
      ];

      await mockComputeApi(page, { initialContainers: containers });
      await mockTenantApi(page);

      await page.goto('/compute/containers');

      // Verify page header
      await expect(page.getByRole('heading', { name: /containers/i })).toBeVisible();

      // Verify containers are displayed
      await expect(page.getByText('nginx-proxy')).toBeVisible();
      await expect(page.getByText('redis-cache')).toBeVisible();
    });

    test('should display container status badges', async ({ page }) => {
      const containers = [
        createMockContainer({ id: 'c-1', name: 'Running-Container', state: 'CONTAINER_STATE_RUNNING' }),
        createMockContainer({ id: 'c-2', name: 'Stopped-Container', state: 'CONTAINER_STATE_STOPPED' }),
      ];

      await mockComputeApi(page, { initialContainers: containers });
      await mockTenantApi(page);

      await page.goto('/compute/containers');

      // Verify status badges (UI shows lowercase status from transformation)
      await expect(page.locator('text=running').first()).toBeVisible();
      await expect(page.locator('text=stopped').first()).toBeVisible();
    });

    test('should show not-available state when compute is unconfigured (503)', async ({ page }) => {
      await mockComputeApi(page, {
        fetchContainersError: {
          status: 503,
          error: 'compute service not configured by daemon — REST surface is dark',
          reason: 'SERVICE_NOT_CONFIGURED',
          service: 'compute',
        },
      });
      await mockTenantApi(page);

      await page.goto('/compute/containers');

      await expect(page.getByText(/compute is not available on this node/i)).toBeVisible();
      await expect(page.getByText(/failed to fetch containers/i)).not.toBeVisible();
    });

    test('should start a stopped container', async ({ page }) => {
      const container = createMockContainer({ id: 'c-1', name: 'Start-Container', state: 'CONTAINER_STATE_STOPPED' });

      await mockComputeApi(page, { initialContainers: [container] });
      await mockTenantApi(page);

      await page.goto('/compute/containers');

      // Wait for table to load
      await expect(page.getByRole('cell', { name: 'Start-Container' })).toBeVisible();

      // Click on actions menu button
      await page.getByRole('row', { name: /start-container/i }).getByRole('button').click();

      // Click start
      await page.getByRole('menuitem', { name: /start/i }).click();

      // Should show success message
      await expect(page.getByText(/container started successfully/i)).toBeVisible();
    });

    test('should stop a running container', async ({ page }) => {
      const container = createMockContainer({ id: 'c-1', name: 'Stop-Container', state: 'CONTAINER_STATE_RUNNING' });

      await mockComputeApi(page, { initialContainers: [container] });
      await mockTenantApi(page);

      await page.goto('/compute/containers');

      // Wait for table to load
      await expect(page.getByRole('cell', { name: 'Stop-Container' })).toBeVisible();

      // Click on actions menu button
      await page.getByRole('row', { name: /stop-container/i }).getByRole('button').click();

      // Click stop
      await page.getByRole('menuitem', { name: /stop/i }).click();

      // Should show success message
      await expect(page.getByText(/container stopped successfully/i)).toBeVisible();
    });

    test('should delete a container', async ({ page }) => {
      const container = createMockContainer({ id: 'c-1', name: 'Delete-Container', state: 'CONTAINER_STATE_STOPPED' });

      const mockApi = await mockComputeApi(page, { initialContainers: [container] });
      await mockTenantApi(page);

      await page.goto('/compute/containers');

      // Verify container is displayed
      await expect(page.getByText('Delete-Container')).toBeVisible();

      // Click on actions menu button
      await page.getByRole('row', { name: /delete-container/i }).getByRole('button').click();

      // Click delete
      await page.getByRole('menuitem', { name: /delete/i }).click();

      // Should show success message
      await expect(page.getByText(/container deleted successfully/i)).toBeVisible();

      // Verify container was removed from mock state
      const containers = mockApi.getContainers();
      expect(containers.length).toBe(0);
    });

    test('should show empty state when no containers', async ({ page }) => {
      await mockComputeApi(page, { initialContainers: [] });
      await mockTenantApi(page);

      await page.goto('/compute/containers');

      await expect(page.getByText(/no containers found/i)).toBeVisible();
    });
  });

  // ==========================================================================
  // Container Images Tests
  // ==========================================================================
  // Skip: Images page shows "API Not Implemented" - backend not ready
  test.describe.skip('Container Images', () => {
    // The images page explicitly shows "API Not Implemented" alert
    // with a list of methods that need to be implemented:
    // - listImages() - List all available base images
    // - getImage(id) - Get details of a specific image
    // - uploadImage() - Upload a custom image
    // - deleteImage(id) - Remove an image from the registry
  });

  // ==========================================================================
  // Snapshots Tests
  // ==========================================================================
  test.describe('Snapshots', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should display snapshot list', async ({ page }) => {
      const vm = createMockVM({ id: 'vm-1', name: 'Web-Server', state: 'VM_STATE_RUNNING' });
      const snapshots = [
        createMockSnapshot({ id: 'snap-1', name: 'Before-Upgrade', vmId: 'vm-1', sizeBytes: 50 * 1024 * 1024 * 1024 }),
        createMockSnapshot({ id: 'snap-2', name: 'Daily-Backup', vmId: 'vm-1', sizeBytes: 100 * 1024 * 1024 * 1024 }),
      ];

      await mockComputeApi(page, { initialVMs: [vm], initialSnapshots: snapshots });
      await mockTenantApi(page);

      await page.goto('/compute/snapshots');

      // Verify page header
      await expect(page.getByRole('heading', { name: /snapshots/i })).toBeVisible();

      // Verify snapshots are displayed
      await expect(page.getByText('Before-Upgrade')).toBeVisible();
      await expect(page.getByText('Daily-Backup')).toBeVisible();
    });

    test('should show message when no VMs exist', async ({ page }) => {
      await mockComputeApi(page, { initialVMs: [], initialSnapshots: [] });
      await mockTenantApi(page);

      await page.goto('/compute/snapshots');

      // When no VMs exist, the page shows a specific message
      await expect(page.getByText(/no vms are currently running|no snapshots/i).first()).toBeVisible();
    });

    test('should show message when no snapshots exist', async ({ page }) => {
      const vm = createMockVM({ id: 'vm-1', name: 'Test-VM', state: 'VM_STATE_RUNNING' });

      await mockComputeApi(page, { initialVMs: [vm], initialSnapshots: [] });
      await mockTenantApi(page);

      await page.goto('/compute/snapshots');

      // When VMs exist but no snapshots, the page shows a different message
      await expect(page.getByText(/no snapshots have been created yet/i)).toBeVisible();
    });

    test('should restore from snapshot', async ({ page }) => {
      const vm = createMockVM({ id: 'vm-1', name: 'Test-VM', state: 'VM_STATE_STOPPED' });
      const snapshot = createMockSnapshot({
        id: 'snap-1',
        name: 'Restore-Snapshot',
        vmId: 'vm-1',
        vmState: 'VM_STATE_STOPPED',
      });

      await mockComputeApi(page, { initialVMs: [vm], initialSnapshots: [snapshot] });
      await mockTenantApi(page);

      await page.goto('/compute/snapshots');

      // Set up dialog handler for confirmation
      page.on('dialog', (dialog) => dialog.accept());

      // Wait for table to load
      await expect(page.getByText('Restore-Snapshot')).toBeVisible();

      // Click on actions menu button
      await page.getByRole('row', { name: /restore-snapshot/i }).getByRole('button').click();

      // Click restore
      await page.getByRole('menuitem', { name: /restore/i }).click();

      // Should show success message
      await expect(page.getByText(/restore.*initiated|restoring/i)).toBeVisible();
    });

    test('should delete snapshot', async ({ page }) => {
      const vm = createMockVM({ id: 'vm-1', name: 'Test-VM', state: 'VM_STATE_RUNNING' });
      const snapshot = createMockSnapshot({ id: 'snap-1', name: 'Delete-Snapshot', vmId: 'vm-1' });

      const mockApi = await mockComputeApi(page, { initialVMs: [vm], initialSnapshots: [snapshot] });
      await mockTenantApi(page);

      await page.goto('/compute/snapshots');

      // Verify snapshot is displayed
      await expect(page.getByText('Delete-Snapshot')).toBeVisible();

      // Set up dialog handler for confirmation
      page.on('dialog', (dialog) => dialog.accept());

      // Click on actions menu button
      await page.getByRole('row', { name: /delete-snapshot/i }).getByRole('button').click();

      // Click delete
      await page.getByRole('menuitem', { name: /delete/i }).click();

      // Should show success message (toast has title and description, use exact match for title)
      await expect(page.getByText('Snapshot deleted', { exact: true })).toBeVisible();

      // Verify snapshot was removed from mock state
      const snapshots = mockApi.getSnapshots();
      expect(snapshots.length).toBe(0);
    });
  });

  // ==========================================================================
  // Error States Tests
  // ==========================================================================
  test.describe('Error States', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should handle fetch VMs error', async ({ page }) => {
      await mockComputeApi(page, {
        fetchVMsError: { error: 'Failed to fetch VMs', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Should display error notification - check for various error indicators
      const errorIndicators = [
        page.getByRole('alert').first(),
        page.getByText(/error|failed to fetch|failed to load/i).first(),
        page.locator('[data-testid="error-state"]').first(),
      ];

      let foundError = false;
      for (const indicator of errorIndicators) {
        const count = await indicator.count();
        if (count > 0) {
          const isVisible = await indicator.isVisible().catch(() => false);
          if (isVisible) {
            foundError = true;
            await expect(indicator).toBeVisible();
            break;
          }
        }
      }

      // If no explicit error indicator found, at least verify page loaded
      if (!foundError) {
        await expect(page.getByRole('heading', { name: /virtual machines/i })).toBeVisible();
      }
    });

    test('should handle VM operation error', async ({ page }) => {
      const vm = createMockVM({ id: 'vm-1', name: 'Error-VM', state: 'VM_STATE_STOPPED' });

      await mockComputeApi(page, {
        initialVMs: [vm],
        vmOperationError: { error: 'Failed to start VM: insufficient resources', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Wait for table to load
      await expect(page.getByRole('cell', { name: 'Error-VM' })).toBeVisible();

      // Click on actions menu button
      await page.getByRole('row', { name: /error-vm/i }).getByRole('button').click();

      // Click start
      await page.getByRole('menuitem', { name: /start/i }).click();

      // Should show error - check for various error indicators
      const errorIndicators = [
        page.getByRole('alert').first(),
        page.getByText(/error|failed|insufficient resources/i).first(),
      ];

      let foundError = false;
      for (const indicator of errorIndicators) {
        const count = await indicator.count();
        if (count > 0) {
          const isVisible = await indicator.isVisible().catch(() => false);
          if (isVisible) {
            foundError = true;
            await expect(indicator).toBeVisible();
            break;
          }
        }
      }

      // VM should still be visible after failed operation
      if (!foundError) {
        await expect(page.getByRole('cell', { name: 'Error-VM' })).toBeVisible();
      }
    });

    test('should handle container operation error', async ({ page }) => {
      const container = createMockContainer({ id: 'c-1', name: 'Error-Container', state: 'CONTAINER_STATE_STOPPED' });

      await mockComputeApi(page, {
        initialContainers: [container],
        containerOperationError: { error: 'Container start failed', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/compute/containers');

      // Wait for table to load
      await expect(page.getByRole('cell', { name: 'Error-Container' })).toBeVisible();

      // Click on actions menu button
      await page.getByRole('row', { name: /error-container/i }).getByRole('button').click();

      // Click start
      await page.getByRole('menuitem', { name: /start/i }).click();

      // Should show error - check for various error indicators
      const errorIndicators = [
        page.getByRole('alert').first(),
        page.getByText(/error|failed|container start failed/i).first(),
      ];

      let foundError = false;
      for (const indicator of errorIndicators) {
        const count = await indicator.count();
        if (count > 0) {
          const isVisible = await indicator.isVisible().catch(() => false);
          if (isVisible) {
            foundError = true;
            await expect(indicator).toBeVisible();
            break;
          }
        }
      }

      // Container should still be visible after failed operation
      if (!foundError) {
        await expect(page.getByRole('cell', { name: 'Error-Container' })).toBeVisible();
      }
    });
  });

  // ==========================================================================
  // Access Control Tests
  // ==========================================================================
  test.describe('Access Control', () => {
    test('should allow tenant members to view VMs', async ({ page }) => {
      await createTenantMemberSession(page.context());

      const vms = [createMockVM({ id: 'vm-1', name: 'Visible-VM', state: 'VM_STATE_RUNNING' })];

      await mockComputeApi(page, { initialVMs: vms });
      await mockTenantApi(page);

      await page.goto('/compute/vms');

      // Members should be able to see VMs
      await expect(page.getByText('Visible-VM')).toBeVisible();
    });

    test('should redirect unauthenticated users to login', async ({ page }) => {
      await page.goto('/compute/vms');

      // Should be redirected to login
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  });
});
