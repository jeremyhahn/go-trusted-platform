/**
 * Compute Service
 *
 * Provides operations for VM and container lifecycle management.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  CreateVMRequest,
  StopVMRequest,
  RebootVMRequest,
  DeleteVMRequest,
  ListVMsRequest,
  AttachDiskRequest,
  DetachDiskRequest,
  ResizeDiskRequest,
  CreateSnapshotRequest,
  RestoreSnapshotRequest,
  DeleteSnapshotRequest,
  MigrateVMRequest,
  CreateContainerRequest,
  StopContainerRequest,
  DeleteContainerRequest,
  ListContainersRequest,
  ExecContainerRequest,
  AttestVMRequest,
  VerifyVMAttestationRequest,
  CreateVMResponse,
  StartVMResponse,
  StopVMResponse,
  RebootVMResponse,
  DeleteVMResponse,
  GetVMResponse,
  ListVMsResponse,
  VMMetricsResponse,
  AttachDiskResponse,
  DetachDiskResponse,
  ResizeDiskResponse,
  CreateSnapshotResponse,
  RestoreSnapshotResponse,
  DeleteSnapshotResponse,
  ListSnapshotsResponse,
  MigrateVMResponse,
  CreateContainerResponse,
  StartContainerResponse,
  StopContainerResponse,
  DeleteContainerResponse,
  GetContainerResponse,
  ListContainersResponse,
  ContainerMetricsResponse,
  ExecContainerResponse,
  AttestVMResponse,
  VerifyVMAttestationResponse,
} from '../types/compute.js';

/**
 * Compute Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create and start a VM
 * const vm = await client.compute.createVM({
 *   config: {
 *     name: 'my-vm',
 *     cpu: { cores: 2 },
 *     memory: { sizeMb: 4096 },
 *     disks: [{ path: '/data/vm-001.qcow2', type: 'QCOW2', sizeGb: 100 }],
 *     networks: [{ bridge: 'br0' }],
 *   },
 *   start: true,
 * });
 *
 * // Execute command in container
 * const result = await client.compute.execContainer({
 *   id: 'container-id',
 *   command: ['ls', '-la'],
 * });
 * ```
 */
export class ComputeService extends BaseService {
  /**
   * Creates a new Compute service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/compute');
  }

  // =========================================================================
  // VM Operations
  // =========================================================================

  /**
   * Create a VM
   *
   * @param request - VM creation request
   * @returns Created VM
   */
  async createVM(request: CreateVMRequest): Promise<ApiResponse<CreateVMResponse>> {
    return this.client.post<CreateVMResponse>(this.buildUrl('/vms'), request);
  }

  /**
   * Start a VM
   *
   * @param id - VM identifier
   * @returns Start result
   */
  async startVM(id: string): Promise<ApiResponse<StartVMResponse>> {
    return this.client.post<StartVMResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(id)}/start`),
      {}
    );
  }

  /**
   * Stop a VM
   *
   * @param request - Stop request
   * @returns Stop result
   */
  async stopVM(request: StopVMRequest): Promise<ApiResponse<StopVMResponse>> {
    return this.client.post<StopVMResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.id)}/stop`),
      { force: request.force, timeoutSeconds: request.timeoutSeconds }
    );
  }

  /**
   * Reboot a VM
   *
   * @param request - Reboot request
   * @returns Reboot result
   */
  async rebootVM(request: RebootVMRequest): Promise<ApiResponse<RebootVMResponse>> {
    return this.client.post<RebootVMResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.id)}/reboot`),
      { force: request.force }
    );
  }

  /**
   * Delete a VM
   *
   * @param request - Delete request
   * @returns Delete result
   */
  async deleteVM(request: DeleteVMRequest): Promise<ApiResponse<DeleteVMResponse>> {
    return this.client.delete<DeleteVMResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.id)}`, {
        filters: { deleteDisks: request.deleteDisks?.toString() },
      })
    );
  }

  /**
   * Get VM by ID
   *
   * @param id - VM identifier
   * @returns VM information
   */
  async getVM(id: string): Promise<ApiResponse<GetVMResponse>> {
    return this.client.get<GetVMResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * List VMs
   *
   * @param request - List request with filters
   * @returns List of VMs
   */
  async listVMs(request?: ListVMsRequest): Promise<ApiResponse<ListVMsResponse>> {
    const filters: Record<string, string | undefined> = {};
    if (request?.labels !== undefined) {
      Object.entries(request.labels).forEach(([k, v]) => {
        filters[`label_${k}`] = v;
      });
    }
    if (request?.states !== undefined) {
      filters.states = request.states.join(',');
    }
    return this.client.get<ListVMsResponse>(this.buildUrl('/vms', {
      page: request?.page,
      limit: request?.pageSize,
      filters,
    }));
  }

  /**
   * Get VM metrics
   *
   * @param id - VM identifier
   * @returns VM metrics
   */
  async getVMMetrics(id: string): Promise<ApiResponse<VMMetricsResponse>> {
    return this.client.get<VMMetricsResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(id)}/metrics`)
    );
  }

  // =========================================================================
  // VM Disk Operations
  // =========================================================================

  /**
   * Attach disk to VM
   *
   * @param request - Attach request
   * @returns Attach result
   */
  async attachDisk(request: AttachDiskRequest): Promise<ApiResponse<AttachDiskResponse>> {
    return this.client.post<AttachDiskResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.vmId)}/disks`),
      request.disk
    );
  }

  /**
   * Detach disk from VM
   *
   * @param request - Detach request
   * @returns Detach result
   */
  async detachDisk(request: DetachDiskRequest): Promise<ApiResponse<DetachDiskResponse>> {
    return this.client.delete<DetachDiskResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.vmId)}/disks/${this.encodePathSegment(request.diskId)}`)
    );
  }

  /**
   * Resize VM disk
   *
   * @param request - Resize request
   * @returns Resize result
   */
  async resizeDisk(request: ResizeDiskRequest): Promise<ApiResponse<ResizeDiskResponse>> {
    return this.client.patch<ResizeDiskResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.vmId)}/disks/${this.encodePathSegment(request.diskId)}`),
      { newSizeGb: request.newSizeGb }
    );
  }

  // =========================================================================
  // VM Snapshot Operations
  // =========================================================================

  /**
   * Create VM snapshot
   *
   * @param request - Snapshot creation request
   * @returns Created snapshot
   */
  async createSnapshot(request: CreateSnapshotRequest): Promise<ApiResponse<CreateSnapshotResponse>> {
    return this.client.post<CreateSnapshotResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.vmId)}/snapshots`),
      request.config
    );
  }

  /**
   * Restore VM from snapshot
   *
   * @param request - Restore request
   * @returns Restore result
   */
  async restoreSnapshot(request: RestoreSnapshotRequest): Promise<ApiResponse<RestoreSnapshotResponse>> {
    return this.client.post<RestoreSnapshotResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.vmId)}/snapshots/${this.encodePathSegment(request.snapshotId)}/restore`),
      {}
    );
  }

  /**
   * Delete VM snapshot
   *
   * @param request - Delete request
   * @returns Delete result
   */
  async deleteSnapshot(request: DeleteSnapshotRequest): Promise<ApiResponse<DeleteSnapshotResponse>> {
    return this.client.delete<DeleteSnapshotResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.vmId)}/snapshots/${this.encodePathSegment(request.snapshotId)}`)
    );
  }

  /**
   * List VM snapshots
   *
   * @param vmId - VM identifier
   * @returns List of snapshots
   */
  async listSnapshots(vmId: string): Promise<ApiResponse<ListSnapshotsResponse>> {
    return this.client.get<ListSnapshotsResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(vmId)}/snapshots`)
    );
  }

  // =========================================================================
  // VM Migration
  // =========================================================================

  /**
   * Migrate VM to another host
   *
   * @param request - Migration request
   * @returns Migration result
   */
  async migrateVM(request: MigrateVMRequest): Promise<ApiResponse<MigrateVMResponse>> {
    return this.client.post<MigrateVMResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.vmId)}/migrate`),
      {
        destinationHost: request.destinationHost,
        liveMigration: request.liveMigration,
        bandwidthLimitMbps: request.bandwidthLimitMbps,
      }
    );
  }

  // =========================================================================
  // VM Attestation
  // =========================================================================

  /**
   * Attest VM
   *
   * @param request - Attestation request
   * @returns Attestation result
   */
  async attestVM(request: AttestVMRequest): Promise<ApiResponse<AttestVMResponse>> {
    return this.client.post<AttestVMResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.vmId)}/attest`),
      { nonce: request.nonce, pcrIndices: request.pcrIndices, pcrBank: request.pcrBank }
    );
  }

  /**
   * Verify VM attestation
   *
   * @param request - Verification request
   * @returns Verification result
   */
  async verifyVMAttestation(request: VerifyVMAttestationRequest): Promise<ApiResponse<VerifyVMAttestationResponse>> {
    return this.client.post<VerifyVMAttestationResponse>(
      this.buildUrl(`/vms/${this.encodePathSegment(request.vmId)}/attest/verify`),
      request
    );
  }

  // =========================================================================
  // Container Operations
  // =========================================================================

  /**
   * Create a container
   *
   * @param request - Container creation request
   * @returns Created container
   */
  async createContainer(request: CreateContainerRequest): Promise<ApiResponse<CreateContainerResponse>> {
    return this.client.post<CreateContainerResponse>(this.buildUrl('/containers'), request);
  }

  /**
   * Start a container
   *
   * @param id - Container identifier
   * @returns Start result
   */
  async startContainer(id: string): Promise<ApiResponse<StartContainerResponse>> {
    return this.client.post<StartContainerResponse>(
      this.buildUrl(`/containers/${this.encodePathSegment(id)}/start`),
      {}
    );
  }

  /**
   * Stop a container
   *
   * @param request - Stop request
   * @returns Stop result
   */
  async stopContainer(request: StopContainerRequest): Promise<ApiResponse<StopContainerResponse>> {
    return this.client.post<StopContainerResponse>(
      this.buildUrl(`/containers/${this.encodePathSegment(request.id)}/stop`),
      { timeoutSeconds: request.timeoutSeconds }
    );
  }

  /**
   * Delete a container
   *
   * @param request - Delete request
   * @returns Delete result
   */
  async deleteContainer(request: DeleteContainerRequest): Promise<ApiResponse<DeleteContainerResponse>> {
    return this.client.delete<DeleteContainerResponse>(
      this.buildUrl(`/containers/${this.encodePathSegment(request.id)}`, {
        filters: {
          force: request.force?.toString(),
          deleteVolumes: request.deleteVolumes?.toString(),
        },
      })
    );
  }

  /**
   * Get container by ID
   *
   * @param id - Container identifier
   * @returns Container information
   */
  async getContainer(id: string): Promise<ApiResponse<GetContainerResponse>> {
    return this.client.get<GetContainerResponse>(
      this.buildUrl(`/containers/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * List containers
   *
   * @param request - List request with filters
   * @returns List of containers
   */
  async listContainers(request?: ListContainersRequest): Promise<ApiResponse<ListContainersResponse>> {
    const filters: Record<string, string | undefined> = {};
    if (request?.labels !== undefined) {
      Object.entries(request.labels).forEach(([k, v]) => {
        filters[`label_${k}`] = v;
      });
    }
    if (request?.states !== undefined) {
      filters.states = request.states.join(',');
    }
    return this.client.get<ListContainersResponse>(this.buildUrl('/containers', {
      page: request?.page,
      limit: request?.pageSize,
      filters,
    }));
  }

  /**
   * Get container metrics
   *
   * @param id - Container identifier
   * @returns Container metrics
   */
  async getContainerMetrics(id: string): Promise<ApiResponse<ContainerMetricsResponse>> {
    return this.client.get<ContainerMetricsResponse>(
      this.buildUrl(`/containers/${this.encodePathSegment(id)}/metrics`)
    );
  }

  /**
   * Execute command in container
   *
   * @param request - Exec request
   * @returns Exec result
   */
  async execContainer(request: ExecContainerRequest): Promise<ApiResponse<ExecContainerResponse>> {
    return this.client.post<ExecContainerResponse>(
      this.buildUrl(`/containers/${this.encodePathSegment(request.id)}/exec`),
      request
    );
  }
}
