/**
 * Tenant Service Types
 *
 * Types for multi-tenant platform operations: lifecycle, quotas, keys and barriers.
 * Based on pkg/api/grpc/proto/tenant.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Tenant state
 */
export type TenantState =
  | 'UNSPECIFIED'
  | 'PENDING'
  | 'ACTIVE'
  | 'SUSPENDED'
  | 'DELETING'
  | 'DELETED';

// =============================================================================
// Data Types
// =============================================================================

/**
 * Compute quota
 */
export interface ComputeQuota {
  /** Maximum VMs */
  maxVms?: number;
  /** Maximum containers */
  maxContainers?: number;
  /** Maximum vCPUs */
  maxVcpus?: number;
  /** Maximum memory in MB */
  maxMemoryMb?: number;
}

/**
 * Network quota
 */
export interface NetworkQuota {
  /** Maximum bridges */
  maxBridges?: number;
  /** Maximum ports */
  maxPorts?: number;
  /** Maximum bandwidth in Mbps */
  maxBandwidthMbps?: number;
}

/**
 * Storage quota
 */
export interface StorageQuota {
  /** Maximum volumes in GB */
  maxVolumesGb?: number;
  /** Maximum snapshots */
  maxSnapshots?: number;
}

/**
 * Tenant information
 */
export interface Tenant {
  /** Tenant ID */
  id: string;
  /** Tenant name */
  name: string;
  /** Display name */
  displayName?: string;
  /** Tenant state */
  state: TenantState;
  /** DEK path */
  dekPath?: string;
  /** Compute quota */
  computeQuota?: ComputeQuota;
  /** Network quota */
  networkQuota?: NetworkQuota;
  /** Storage quota */
  storageQuota?: StorageQuota;
  /** Labels */
  labels?: Record<string, string>;
  /** Annotations */
  annotations?: Record<string, string>;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
}

/**
 * Tenant usage information
 */
export interface TenantUsage {
  /** Tenant ID */
  tenantId: string;
  /** VMs count */
  vms: number;
  /** Containers count */
  containers: number;
  /** vCPUs count */
  vcpus: number;
  /** Memory used in MB */
  memoryMb: number;
  /** Disk used in GB */
  diskGb: number;
  /** Bridges count */
  bridges: number;
  /** Ports count */
  ports: number;
  /** Bandwidth used in Mbps */
  bandwidthMbps: number;
  /** Volumes count */
  volumes: number;
  /** Snapshots count */
  snapshots: number;
  /** Measurement timestamp */
  timestamp: string;
}

/**
 * DEK re-encryption progress
 */
export interface DEKReencryptionProgress {
  /** Whether in progress */
  inProgress: boolean;
  /** Total keys */
  totalKeys: number;
  /** Processed keys */
  processedKeys: number;
  /** Failed keys */
  failedKeys: number;
  /** Start timestamp */
  startedAt?: string;
  /** Estimated completion timestamp */
  estimatedCompletion?: string;
}

/**
 * Tenant DEK status
 */
export interface TenantDEKStatus {
  /** Tenant ID */
  tenantId: string;
  /** DEK path */
  path: string;
  /** DEK version */
  version: number;
  /** Algorithm */
  algorithm: string;
  /** Status */
  status: string;
  /** Is default DEK */
  isDefault: boolean;
  /** Creation timestamp */
  createdAt: string;
  /** Last rotation timestamp */
  rotatedAt?: string;
  /** Usage count */
  usageCount: number;
  /** Bytes used */
  bytesUsed: number;
  /** Max usage count */
  maxUsageCount: number;
  /** Max bytes used */
  maxBytesUsed: number;
  /** Warning percentage */
  warningPercent: number;
  /** Usage percentage */
  usagePercent: number;
  /** Needs rotation */
  needsRotation: boolean;
  /** Re-encryption progress */
  reencryptProgress?: DEKReencryptionProgress;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Label selector for filtering
 */
export interface TenantLabelSelector {
  /** Match labels */
  matchLabels?: Record<string, string>;
  /** Match expressions */
  matchExpressions?: Array<{
    key: string;
    operator: 'In' | 'NotIn' | 'Exists' | 'DoesNotExist';
    values?: string[];
  }>;
}

/**
 * List tenants request
 */
export interface ListTenantsRequest {
  /** Limit */
  limit?: number;
  /** Offset */
  offset?: number;
  /** Label selector */
  selector?: TenantLabelSelector;
}

/**
 * Get tenant request
 */
export interface GetTenantRequest {
  /** Tenant ID */
  tenantId: string;
}

/**
 * Get tenant by name request
 */
export interface GetTenantByNameRequest {
  /** Tenant name */
  name: string;
}

/**
 * Create tenant request
 */
export interface CreateTenantRequest {
  /** Tenant name */
  name: string;
  /** Display name */
  displayName?: string;
  /** Labels */
  labels?: Record<string, string>;
  /** Annotations */
  annotations?: Record<string, string>;
  /** Compute quota */
  computeQuota?: ComputeQuota;
  /** Network quota */
  networkQuota?: NetworkQuota;
  /** Storage quota */
  storageQuota?: StorageQuota;
}

/**
 * Update tenant request
 */
export interface UpdateTenantRequest {
  /** Tenant ID */
  tenantId: string;
  /** Updated display name */
  displayName?: string;
  /** Updated labels */
  labels?: Record<string, string>;
  /** Updated annotations */
  annotations?: Record<string, string>;
}

/**
 * Delete tenant request
 */
export interface DeleteTenantRequest {
  /** Tenant ID */
  tenantId: string;
}

/**
 * Suspend tenant request
 */
export interface SuspendTenantRequest {
  /** Tenant ID */
  tenantId: string;
}

/**
 * Resume tenant request
 */
export interface ResumeTenantRequest {
  /** Tenant ID */
  tenantId: string;
}

/**
 * Get quotas request
 */
export interface GetQuotasRequest {
  /** Tenant ID */
  tenantId: string;
}

/**
 * Update quotas request
 */
export interface UpdateQuotasRequest {
  /** Tenant ID */
  tenantId: string;
  /** Compute quota */
  compute?: ComputeQuota;
  /** Network quota */
  network?: NetworkQuota;
  /** Storage quota */
  storage?: StorageQuota;
}

/**
 * Get usage request
 */
export interface GetUsageRequest {
  /** Tenant ID */
  tenantId: string;
}

/**
 * Check quota request
 */
export interface CheckQuotaRequest {
  /** Tenant ID */
  tenantId: string;
  /** Resource type */
  resource: string;
  /** Requested amount */
  amount: number;
}

/**
 * Sync tenants request
 */
export interface SyncTenantsRequest {}

/**
 * Rotate tenant DEK request
 */
export interface RotateTenantDEKRequest {
  /** Tenant ID */
  tenantId: string;
  /** Run in background */
  background?: boolean;
}

/**
 * Get tenant DEK status request
 */
export interface GetTenantDEKStatusRequest {
  /** Tenant ID */
  tenantId: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface TenantStatus {
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
 * Pagination response
 */
export interface TenantPaginationResponse {
  /** Current page */
  page: number;
  /** Page size */
  pageSize: number;
  /** Total pages */
  totalPages: number;
  /** Total items */
  totalItems: number;
}

/**
 * List tenants response
 */
export interface ListTenantsResponse {
  /** Tenants */
  tenants: Tenant[];
  /** Total count */
  total: number;
  /** Pagination info */
  pagination?: TenantPaginationResponse;
}

/**
 * Get tenant response
 */
export interface GetTenantResponse {
  /** Tenant */
  tenant: Tenant;
}

/**
 * Get tenant by name response
 */
export interface GetTenantByNameResponse {
  /** Tenant */
  tenant: Tenant;
}

/**
 * Create tenant response
 */
export interface CreateTenantResponse {
  /** Operation status */
  status: TenantStatus;
  /** Created tenant */
  tenant?: Tenant;
}

/**
 * Update tenant response
 */
export interface UpdateTenantResponse {
  /** Operation status */
  status: TenantStatus;
  /** Updated tenant */
  tenant?: Tenant;
}

/**
 * Delete tenant response
 */
export interface DeleteTenantResponse {
  /** Operation status */
  status: TenantStatus;
}

/**
 * Suspend tenant response
 */
export interface SuspendTenantResponse {
  /** Operation status */
  status: TenantStatus;
}

/**
 * Resume tenant response
 */
export interface ResumeTenantResponse {
  /** Operation status */
  status: TenantStatus;
}

/**
 * Get quotas response
 */
export interface GetQuotasResponse {
  /** Tenant ID */
  tenantId: string;
  /** Compute quota */
  compute?: ComputeQuota;
  /** Network quota */
  network?: NetworkQuota;
  /** Storage quota */
  storage?: StorageQuota;
}

/**
 * Update quotas response
 */
export interface UpdateQuotasResponse {
  /** Operation status */
  status: TenantStatus;
}

/**
 * Get usage response
 */
export interface GetUsageResponse {
  /** Usage information */
  usage: TenantUsage;
}

/**
 * Check quota response
 */
export interface CheckQuotaResponse {
  /** Tenant ID */
  tenantId: string;
  /** Resource type */
  resource: string;
  /** Requested amount */
  amount: number;
  /** Whether available */
  available: boolean;
  /** Message */
  message?: string;
}

/**
 * Sync tenants response
 */
export interface SyncTenantsResponse {
  /** Operation status */
  status: TenantStatus;
}

/**
 * Rotate tenant DEK response
 */
export interface RotateTenantDEKResponse {
  /** Tenant ID */
  tenantId: string;
  /** Old version */
  oldVersion: number;
  /** New version */
  newVersion: number;
  /** Timestamp */
  timestamp: string;
}

/**
 * Get tenant DEK status response
 */
export interface GetTenantDEKStatusResponse {
  /** DEK status */
  dekStatus: TenantDEKStatus;
}
