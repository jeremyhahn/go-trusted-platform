/**
 * Compute Service Types
 *
 * Types for VM and container lifecycle management.
 * Based on pkg/api/grpc/proto/compute.proto
 */

import type { TPMVersion, PCRBank, PCRValue } from './tpm.js';

// =============================================================================
// Enums
//
// Each enum is the proto enum's value name, the spelling the daemon writes in
// every compute response (protojson) and the only one it accepts in a request.
// =============================================================================

/**
 * VM state
 */
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

/**
 * Firmware type
 */
export type FirmwareType =
  | 'FIRMWARE_TYPE_UNSPECIFIED'
  | 'FIRMWARE_TYPE_BIOS'
  | 'FIRMWARE_TYPE_UEFI'
  | 'FIRMWARE_TYPE_UEFI_SECURE_BOOT';

/**
 * Boot device
 */
export type BootDevice =
  | 'BOOT_DEVICE_UNSPECIFIED'
  | 'BOOT_DEVICE_DISK'
  | 'BOOT_DEVICE_CDROM'
  | 'BOOT_DEVICE_NETWORK';

/**
 * Disk type
 */
export type DiskType =
  | 'DISK_TYPE_UNSPECIFIED'
  | 'DISK_TYPE_RAW'
  | 'DISK_TYPE_QCOW2'
  | 'DISK_TYPE_VDI'
  | 'DISK_TYPE_VMDK';

/**
 * Disk bus
 */
export type DiskBus =
  | 'DISK_BUS_UNSPECIFIED'
  | 'DISK_BUS_IDE'
  | 'DISK_BUS_SATA'
  | 'DISK_BUS_SCSI'
  | 'DISK_BUS_VIRTIO'
  | 'DISK_BUS_NVME';

/**
 * Network model
 */
export type NetworkModel =
  | 'NETWORK_MODEL_UNSPECIFIED'
  | 'NETWORK_MODEL_E1000'
  | 'NETWORK_MODEL_VIRTIO'
  | 'NETWORK_MODEL_RTL8139';

/**
 * Graphics type
 */
export type GraphicsType =
  | 'GRAPHICS_TYPE_UNSPECIFIED'
  | 'GRAPHICS_TYPE_NONE'
  | 'GRAPHICS_TYPE_VNC'
  | 'GRAPHICS_TYPE_SPICE'
  | 'GRAPHICS_TYPE_SDL';

/**
 * Container state
 */
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

/**
 * Container restart policy
 */
export type RestartPolicy =
  | 'RESTART_POLICY_UNSPECIFIED'
  | 'RESTART_POLICY_NO'
  | 'RESTART_POLICY_ON_FAILURE'
  | 'RESTART_POLICY_ALWAYS'
  | 'RESTART_POLICY_UNLESS_STOPPED';

// =============================================================================
// Configuration Types
// =============================================================================

/**
 * CPU configuration
 */
export interface CPUConfig {
  /** Number of cores */
  cores: number;
  /** Number of sockets */
  sockets?: number;
  /** Threads per core */
  threads?: number;
  /** CPU model */
  model?: string;
  /** CPU features */
  features?: string[];
}

/**
 * Memory configuration
 */
export interface MemoryConfig {
  /** Size in MB */
  sizeMb: number;
  /** Use huge pages */
  hugepages?: boolean;
  /** Shared memory */
  shared?: boolean;
}

/**
 * Disk configuration
 */
export interface DiskConfig {
  /** Disk ID */
  id?: string;
  /** Disk path */
  path: string;
  /** Disk type */
  type?: DiskType;
  /** Disk bus */
  bus?: DiskBus;
  /** Size in GB */
  sizeGb?: number;
  /** Read-only */
  readonly?: boolean;
  /** Bootable */
  bootable?: boolean;
  /** Backing file path */
  backingFile?: string;
}

/**
 * Network interface configuration
 */
export interface NetworkInterfaceConfig {
  /** Interface ID */
  id?: string;
  /** Bridge name */
  bridge: string;
  /** MAC address */
  macAddress?: string;
  /** Network model */
  model?: NetworkModel;
  /** VLAN ID */
  vlan?: number;
  /** Bandwidth limit in Mbps */
  bandwidthLimitMbps?: number;
}

/**
 * Graphics configuration
 */
export interface GraphicsConfig {
  /** Graphics type */
  type: GraphicsType;
  /** Listen address */
  listen?: string;
  /** Port */
  port?: number;
  /** Password */
  password?: string;
  /** Keymap */
  keymap?: string;
}

/**
 * TPM configuration for VMs
 */
export interface VMTPMConfig {
  /** Enable TPM */
  enabled: boolean;
  /** TPM version */
  version?: TPMVersion;
  /** Device path */
  devicePath?: string;
  /** Emulated TPM */
  emulated?: boolean;
  /** State directory */
  stateDir?: string;
}

/**
 * VM configuration
 */
export interface VMConfig {
  /** VM name */
  name: string;
  /** Description */
  description?: string;
  /** Firmware type */
  firmware?: FirmwareType;
  /** Boot device */
  bootDevice?: BootDevice;
  /** CPU configuration */
  cpu: CPUConfig;
  /** Memory configuration */
  memory: MemoryConfig;
  /** Disk configurations */
  disks: DiskConfig[];
  /** Network configurations */
  networks: NetworkInterfaceConfig[];
  /** Graphics configuration */
  graphics?: GraphicsConfig;
  /** TPM configuration */
  tpm?: VMTPMConfig;
  /** Enable Secure Boot */
  secureBoot?: boolean;
  /** UEFI NVRAM vars (base64) */
  nvram?: string;
  /** Labels */
  labels?: Record<string, string>;
  /** Metadata */
  metadata?: Record<string, string>;
}

/**
 * Resource limits
 */
export interface ResourceLimits {
  /** Max memory in MB */
  maxMemoryMb?: number;
  /** Max CPUs */
  maxCpus?: number;
  /** Max disk in GB */
  maxDiskGb?: number;
  /** Max instances */
  maxInstances?: number;
}

/**
 * Volume mount for containers
 */
export interface VolumeMount {
  /** Source path */
  source: string;
  /** Destination path */
  destination: string;
  /** Read-only */
  readonly?: boolean;
  /** Mount type (bind, volume, tmpfs) */
  type?: string;
  /** Mount options */
  options?: Record<string, string>;
}

/**
 * Port mapping for containers
 */
export interface PortMapping {
  /** Host port */
  hostPort: number;
  /** Container port */
  containerPort: number;
  /** Protocol (tcp, udp) */
  protocol?: string;
  /** Host IP */
  hostIp?: string;
}

/**
 * Environment variable
 */
export interface EnvVar {
  /** Variable name */
  name: string;
  /** Variable value */
  value?: string;
  /** Value reference (secret, configmap) */
  valueFrom?: string;
}

/**
 * Container configuration
 */
export interface ContainerConfig {
  /** Container name */
  name: string;
  /** Image name */
  image: string;
  /** Image hash */
  imageHash?: string;
  /** Command */
  command?: string[];
  /** Arguments */
  args?: string[];
  /** Environment variables */
  env?: EnvVar[];
  /** Working directory */
  workingDir?: string;
  /** Volume mounts */
  volumes?: VolumeMount[];
  /** Port mappings */
  ports?: PortMapping[];
  /** Privileged mode */
  privileged?: boolean;
  /** Capabilities */
  capabilities?: string[];
  /** Resource limits */
  resources?: ResourceLimits;
  /** Restart policy */
  restartPolicy?: RestartPolicy;
  /** TPM access */
  tpmAccess?: boolean;
  /** Network name */
  network?: string;
  /** Labels */
  labels?: Record<string, string>;
  /** Metadata */
  metadata?: Record<string, string>;
}

/**
 * Snapshot configuration
 */
export interface SnapshotConfig {
  /** Snapshot name */
  name: string;
  /** Description */
  description?: string;
  /** Include memory */
  memorySnapshot?: boolean;
  /** Include disk */
  diskSnapshot?: boolean;
}

// =============================================================================
// Data Types
// =============================================================================

/**
 * VM metrics
 */
export interface VMMetrics {
  /** CPU usage percentage */
  cpuUsagePercent: number;
  /** Memory used in MB */
  memoryUsedMb: number;
  /** Memory available in MB */
  memoryAvailableMb: number;
  /** Disk read bytes */
  diskReadBytes: number;
  /** Disk write bytes */
  diskWriteBytes: number;
  /** Network RX bytes */
  networkRxBytes: number;
  /** Network TX bytes */
  networkTxBytes: number;
  /** Uptime in seconds */
  uptimeSeconds: number;
}

/**
 * VM information
 */
export interface VM {
  /** VM ID */
  id: string;
  /** Configuration */
  config: VMConfig;
  /** Current state */
  state: VMState;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
  /** Host ID */
  hostId?: string;
  /** Metrics */
  metrics?: VMMetrics;
}

/**
 * Snapshot information
 */
export interface Snapshot {
  /** Snapshot ID */
  id: string;
  /** VM ID */
  vmId: string;
  /** Configuration */
  config: SnapshotConfig;
  /** Creation timestamp */
  createdAt: string;
  /** Size in bytes */
  sizeBytes: number;
  /** VM state at snapshot */
  vmState: VMState;
}

/**
 * Container metrics
 */
export interface ContainerMetrics {
  /** CPU usage percentage */
  cpuUsagePercent: number;
  /** Memory used in MB */
  memoryUsedMb: number;
  /** Memory limit in MB */
  memoryLimitMb: number;
  /** Disk read bytes */
  diskReadBytes: number;
  /** Disk write bytes */
  diskWriteBytes: number;
  /** Network RX bytes */
  networkRxBytes: number;
  /** Network TX bytes */
  networkTxBytes: number;
  /** Uptime in seconds */
  uptimeSeconds: number;
}

/**
 * Container information
 */
export interface Container {
  /** Container ID */
  id: string;
  /** Configuration */
  config: ContainerConfig;
  /** Current state */
  state: ContainerState;
  /** Creation timestamp */
  createdAt: string;
  /** Start timestamp */
  startedAt?: string;
  /** Finish timestamp */
  finishedAt?: string;
  /** Exit code */
  exitCode?: number;
  /** Host ID */
  hostId?: string;
  /** Metrics */
  metrics?: ContainerMetrics;
}

/**
 * Log entry
 */
export interface LogEntry {
  /** Timestamp */
  timestamp: string;
  /** Log level */
  level: string;
  /** Message */
  message: string;
  /** Source */
  source?: string;
  /** Metadata */
  metadata?: Record<string, string>;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Create VM request
 */
export interface CreateVMRequest {
  /** VM configuration */
  config: VMConfig;
  /** Start after creation */
  start?: boolean;
}

/**
 * Start VM request
 */
export interface StartVMRequest {
  /** VM ID */
  id: string;
}

/**
 * Stop VM request
 */
export interface StopVMRequest {
  /** VM ID */
  id: string;
  /** Force stop */
  force?: boolean;
  /** Timeout in seconds */
  timeoutSeconds?: number;
}

/**
 * Reboot VM request
 */
export interface RebootVMRequest {
  /** VM ID */
  id: string;
  /** Force reboot */
  force?: boolean;
}

/**
 * Delete VM request
 */
export interface DeleteVMRequest {
  /** VM ID */
  id: string;
  /** Delete disks */
  deleteDisks?: boolean;
}

/**
 * Get VM request
 */
export interface GetVMRequest {
  /** VM ID */
  id: string;
}

/**
 * List VMs request
 */
export interface ListVMsRequest {
  /** Label selector */
  labels?: Record<string, string>;
  /** Filter by states */
  states?: VMState[];
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Attach disk request
 */
export interface AttachDiskRequest {
  /** VM ID */
  vmId: string;
  /** Disk configuration */
  disk: DiskConfig;
}

/**
 * Detach disk request
 */
export interface DetachDiskRequest {
  /** VM ID */
  vmId: string;
  /** Disk ID */
  diskId: string;
}

/**
 * Resize disk request
 */
export interface ResizeDiskRequest {
  /** VM ID */
  vmId: string;
  /** Disk ID */
  diskId: string;
  /** New size in GB */
  newSizeGb: number;
}

/**
 * Create snapshot request
 */
export interface CreateSnapshotRequest {
  /** VM ID */
  vmId: string;
  /** Snapshot configuration */
  config: SnapshotConfig;
}

/**
 * Restore snapshot request
 */
export interface RestoreSnapshotRequest {
  /** VM ID */
  vmId: string;
  /** Snapshot ID */
  snapshotId: string;
}

/**
 * Delete snapshot request
 */
export interface DeleteSnapshotRequest {
  /** VM ID */
  vmId: string;
  /** Snapshot ID */
  snapshotId: string;
}

/**
 * List snapshots request
 */
export interface ListSnapshotsRequest {
  /** VM ID */
  vmId: string;
}

/**
 * Migrate VM request
 */
export interface MigrateVMRequest {
  /** VM ID */
  vmId: string;
  /** Destination host */
  destinationHost: string;
  /** Live migration */
  liveMigration?: boolean;
  /** Bandwidth limit in Mbps */
  bandwidthLimitMbps?: number;
}

/**
 * Create container request
 */
export interface CreateContainerRequest {
  /** Container configuration */
  config: ContainerConfig;
  /** Start after creation */
  start?: boolean;
}

/**
 * Start container request
 */
export interface StartContainerRequest {
  /** Container ID */
  id: string;
}

/**
 * Stop container request
 */
export interface StopContainerRequest {
  /** Container ID */
  id: string;
  /** Timeout in seconds */
  timeoutSeconds?: number;
}

/**
 * Delete container request
 */
export interface DeleteContainerRequest {
  /** Container ID */
  id: string;
  /** Force delete */
  force?: boolean;
  /** Delete volumes */
  deleteVolumes?: boolean;
}

/**
 * Get container request
 */
export interface GetContainerRequest {
  /** Container ID */
  id: string;
}

/**
 * List containers request
 */
export interface ListContainersRequest {
  /** Label selector */
  labels?: Record<string, string>;
  /** Filter by states */
  states?: ContainerState[];
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Exec container request
 */
export interface ExecContainerRequest {
  /** Container ID */
  id: string;
  /** Command */
  command: string[];
  /** Environment variables */
  env?: EnvVar[];
  /** Working directory */
  workingDir?: string;
  /** Allocate TTY */
  tty?: boolean;
}

/**
 * Attest VM request
 */
export interface AttestVMRequest {
  /** VM ID */
  vmId: string;
  /** Nonce (base64) */
  nonce: string;
  /** PCR indices */
  pcrIndices?: number[];
  /** PCR bank */
  pcrBank?: PCRBank;
}

/**
 * Request to attest a container
 */
export interface AttestContainerRequest {
  /** Container ID */
  id: string;
}

/**
 * Verify VM attestation request
 */
export interface VerifyVMAttestationRequest {
  /** VM ID */
  vmId: string;
  /** Quote (base64) */
  quote: string;
  /** Signature (base64) */
  signature: string;
  /** Nonce (base64) */
  nonce: string;
  /** Expected PCR values */
  expectedPcrs?: PCRValue[];
  /**
   * Signature scheme the quote declares (AttestVMResponse.signatureAlgorithm,
   * e.g. "SHA256-RSAPSS"). The quote is verified under it alone; an absent
   * or unknown scheme fails verification.
   */
  signatureAlgorithm: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface ComputeStatus {
  /** Whether succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details */
  error?: {
    code: string;
    message: string;
    metadata?: Record<string, string>;
  };
}

/**
 * Create VM response
 */
export interface CreateVMResponse {
  /** Operation status */
  status: ComputeStatus;
  /** Created VM */
  vm?: VM;
}

/**
 * Start VM response
 */
export interface StartVMResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Stop VM response
 */
export interface StopVMResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Reboot VM response
 */
export interface RebootVMResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Delete VM response
 */
export interface DeleteVMResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Get VM response
 */
export interface GetVMResponse {
  /** VM */
  vm: VM;
}

/**
 * List VMs response
 */
export interface ListVMsResponse {
  /** VMs */
  vms: VM[];
  /** Pagination info */
  pagination?: {
    page: number;
    pageSize: number;
    totalPages: number;
    totalItems: number;
  };
}

/**
 * VM metrics response
 */
export interface VMMetricsResponse {
  /** Metrics */
  metrics: VMMetrics;
}

/**
 * Attach disk response
 */
export interface AttachDiskResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Detach disk response
 */
export interface DetachDiskResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Resize disk response
 */
export interface ResizeDiskResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Create snapshot response
 */
export interface CreateSnapshotResponse {
  /** Operation status */
  status: ComputeStatus;
  /** Created snapshot */
  snapshot?: Snapshot;
}

/**
 * Restore snapshot response
 */
export interface RestoreSnapshotResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Delete snapshot response
 */
export interface DeleteSnapshotResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * List snapshots response
 */
export interface ListSnapshotsResponse {
  /** Snapshots */
  snapshots: Snapshot[];
}

/**
 * Migrate VM response
 */
export interface MigrateVMResponse {
  /** Operation status */
  status: ComputeStatus;
}

/** Suspend VM response */
export interface SuspendVMResponse {
  /** Operation status */
  status: ComputeStatus;
}

/** Resume VM response */
export interface ResumeVMResponse {
  /** Operation status */
  status: ComputeStatus;
}

/** Get snapshot response */
export interface GetSnapshotResponse {
  /** Snapshot */
  snapshot: Snapshot;
}

/** Prepare migration request (run on the destination host) */
/** The source guest's configuration a migration receiver needs (proto VMMigrationSpec) */
export interface VMMigrationSpec {
  /** Memory in MB */
  memoryMb: number;
  /** Number of vCPUs */
  cpus: number;
  /** Disk size, e.g. "20G" */
  diskSize?: string;
  /** Boot mode */
  bootMode?: string;
  /** Secure Boot enabled */
  secureBoot?: boolean;
  /** KVM acceleration enabled */
  enableKvm?: boolean;
  /** vTPM enabled */
  tpmEnabled?: boolean;
  /** Network mode */
  networkMode?: string;
  /** MAC address */
  macAddress?: string;
  /** Source guest arch: "x86_64" or "aarch64"; empty means x86_64 */
  arch?: string;
}

export interface PrepareMigrationRequest {
  /** Source instance ID (informational) */
  vmId?: string;
  /** Guest name */
  vmName: string;
  /** Migration mode */
  mode: 'cold' | 'live';
  /** VM migration spec (required: the daemon refuses a request without one) */
  spec: VMMigrationSpec;
}

/** Prepare migration response */
export interface PrepareMigrationResponse {
  /** Operation status */
  status: ComputeStatus;
  /** Receiver token passed to FinalizeMigration */
  receiverId?: string;
  /** TCP port the receiver listens on */
  port?: number;
  /** Host name the source pins in the migration TLS credentials */
  tlsHostname?: string;
}

/** Finalize migration request */
export interface FinalizeMigrationRequest {
  /** Receiver ID from PrepareMigration */
  receiverId: string;
  /** true registers and resumes the received VM, false aborts */
  commit: boolean;
}

/** Finalize migration response */
export interface FinalizeMigrationResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Create container response
 */
export interface CreateContainerResponse {
  /** Operation status */
  status: ComputeStatus;
  /** Created container */
  container?: Container;
}

/**
 * Start container response
 */
export interface StartContainerResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Stop container response
 */
export interface StopContainerResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Delete container response
 */
export interface DeleteContainerResponse {
  /** Operation status */
  status: ComputeStatus;
}

/**
 * Get container response
 */
export interface GetContainerResponse {
  /** Container */
  container: Container;
}

/**
 * List containers response
 */
export interface ListContainersResponse {
  /** Containers */
  containers: Container[];
  /** Pagination info */
  pagination?: {
    page: number;
    pageSize: number;
    totalPages: number;
    totalItems: number;
  };
}

/**
 * Container metrics response
 */
export interface ContainerMetricsResponse {
  /** Metrics */
  metrics: ContainerMetrics;
}

/**
 * Exec container response
 */
export interface ExecContainerResponse {
  /** Operation status */
  status: ComputeStatus;
  /** Exit code */
  exitCode: number;
  /** Stdout (base64) */
  stdout?: string;
  /** Stderr (base64) */
  stderr?: string;
}

/**
 * Attest VM response
 */
export interface AttestVMResponse {
  /** Operation status */
  status: ComputeStatus;
  /** Quote (base64) */
  quote?: string;
  /** Signature (base64) */
  signature?: string;
  /** PCR values */
  pcrValues?: PCRValue[];
  /** Event log (base64) */
  eventLog?: string;
  /** AK public key (base64) */
  akPublic?: string;
  /**
   * x509.SignatureAlgorithm name of the scheme the AK signed the quote under
   * (e.g. "SHA256-RSAPSS"); the signature itself is bare bytes. Send it back
   * as VerifyVMAttestationRequest.signatureAlgorithm.
   */
  signatureAlgorithm?: string;
}

/**
 * Response from attesting a container
 */
export interface AttestContainerResponse {
  /** Operation status */
  status: ComputeStatus;
  /** Quote (base64) */
  quote?: string;
  /** Signature (base64) */
  signature?: string;
  /** PCR values */
  pcrValues?: PCRValue[];
  /** Event log (base64) */
  eventLog?: string;
  /** AK public key (base64) */
  akPublic?: string;
  /** Container ID */
  containerId?: string;
  /** Container name */
  containerName?: string;
  /** Image digest (base64) */
  imageDigest?: string;
  /** Config digest (base64) */
  configDigest?: string;
  /** Whether the server verified the quote */
  verified?: boolean;
  /** Attestation time (RFC 3339) */
  timestamp?: string;
}

/**
 * Verify VM attestation response
 */
export interface VerifyVMAttestationResponse {
  /** Operation status */
  status: ComputeStatus;
  /** Whether verified */
  verified: boolean;
  /** Verification message */
  message?: string;
  /** Actual PCR values */
  actualPcrs?: PCRValue[];
}
