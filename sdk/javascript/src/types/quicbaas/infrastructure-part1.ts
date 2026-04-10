/**
 * QuicBaaS Infrastructure Types - Part 1
 *
 * Types for Cluster, Health, Operations, Cache, and ParameterStore services.
 */

import type { PaginationParams, PaginationMeta, Timestamps } from '../common.js';

// =============================================================================
// Common Types
// =============================================================================

/**
 * Operation status enum
 */
export type QuicBaaSOperationStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

/**
 * Node state enum
 */
export type NodeState = 'healthy' | 'unhealthy' | 'joining' | 'leaving' | 'unknown';

/**
 * Node role in the cluster
 */
export type NodeRole = 'leader' | 'follower' | 'candidate' | 'learner';

// =============================================================================
// Cluster Service Types
// =============================================================================

/**
 * Cluster node information
 */
export interface ClusterNode {
  /** Node identifier */
  nodeId: string;
  /** Node address (host:port) */
  address: string;
  /** Node role in the cluster */
  role: NodeRole;
  /** Current state of the node */
  state: NodeState;
  /** Node version */
  version: string;
  /** Last heartbeat timestamp (ISO 8601) */
  lastHeartbeat: string;
  /** Node metadata */
  metadata?: Record<string, string>;
}

/**
 * Cluster status response
 */
export interface ClusterStatusResponse {
  /** Cluster identifier */
  clusterId: string;
  /** Cluster name */
  name: string;
  /** Total number of nodes */
  nodeCount: number;
  /** Number of healthy nodes */
  healthyNodes: number;
  /** Current leader node ID */
  leaderId: string;
  /** Cluster term (Raft term) */
  term: number;
  /** Cluster state */
  state: 'healthy' | 'degraded' | 'critical';
  /** Cluster formation time (ISO 8601) */
  formedAt: string;
  /** Cluster version */
  version: string;
}

/**
 * Get cluster nodes response
 */
export interface GetNodesResponse {
  /** List of cluster nodes */
  nodes: ClusterNode[];
  /** Pagination metadata */
  pagination?: PaginationMeta;
}

/**
 * Add node request
 */
export interface AddNodeRequest {
  /** Node address (host:port) */
  address: string;
  /** Optional node identifier */
  nodeId?: string;
  /** Initial role for the node */
  role?: NodeRole;
  /** Node metadata */
  metadata?: Record<string, string>;
}

/**
 * Add node response
 */
export interface AddNodeResponse {
  /** Added node information */
  node: ClusterNode;
  /** Message */
  message: string;
}

/**
 * Remove node request
 */
export interface RemoveNodeRequest {
  /** Node identifier to remove */
  nodeId: string;
  /** Force removal even if node is unhealthy */
  force?: boolean;
}

/**
 * Remove node response
 */
export interface RemoveNodeResponse {
  /** Removed node ID */
  nodeId: string;
  /** Operation success message */
  message: string;
}

/**
 * Get leader response
 */
export interface GetLeaderResponse {
  /** Leader node information */
  leader: ClusterNode;
  /** Current term */
  term: number;
}

/**
 * Transfer leadership request
 */
export interface TransferLeadershipRequest {
  /** Target node ID for leadership */
  targetNodeId: string;
  /** Timeout in seconds */
  timeout?: number;
}

/**
 * Transfer leadership response
 */
export interface TransferLeadershipResponse {
  /** New leader node ID */
  newLeaderId: string;
  /** Previous leader node ID */
  previousLeaderId: string;
  /** New term */
  term: number;
  /** Operation message */
  message: string;
}

// =============================================================================
// Health Service Types
// =============================================================================

/**
 * Ping response
 */
export interface PingResponse {
  /** Response message */
  message: string;
  /** Server timestamp (ISO 8601) */
  timestamp: string;
  /** Server version */
  version: string;
}

/**
 * Liveness check response
 */
export interface LivenessResponse {
  /** Whether the service is alive */
  alive: boolean;
  /** Check timestamp (ISO 8601) */
  timestamp: string;
}

/**
 * Readiness check response
 */
export interface ReadinessResponse {
  /** Whether the service is ready */
  ready: boolean;
  /** Individual check results */
  checks: ReadinessCheck[];
  /** Check timestamp (ISO 8601) */
  timestamp: string;
}

/**
 * Individual readiness check
 */
export interface ReadinessCheck {
  /** Check name */
  name: string;
  /** Check status */
  status: 'pass' | 'fail' | 'warn';
  /** Optional message */
  message?: string;
  /** Check duration in milliseconds */
  durationMs: number;
}

/**
 * Metrics response
 */
export interface MetricsResponse {
  /** Metrics in Prometheus format or structured */
  metrics: MetricEntry[];
  /** Collection timestamp (ISO 8601) */
  timestamp: string;
}

/**
 * Single metric entry
 */
export interface MetricEntry {
  /** Metric name */
  name: string;
  /** Metric type */
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
  /** Metric value */
  value: number;
  /** Metric labels */
  labels?: Record<string, string>;
  /** Help text */
  help?: string;
}

// =============================================================================
// Operations Service Types
// =============================================================================

/**
 * Migration request
 */
export interface MigrateRequest {
  /** Migration target version */
  targetVersion: string;
  /** Dry run (validate without executing) */
  dryRun?: boolean;
  /** Force migration even if validation fails */
  force?: boolean;
}

/**
 * Migration response
 */
export interface MigrateResponse {
  /** Operation ID for tracking */
  operationId: string;
  /** Current version */
  fromVersion: string;
  /** Target version */
  toVersion: string;
  /** Operation status */
  status: QuicBaaSOperationStatus;
  /** Operation message */
  message: string;
}

/**
 * Upgrade request
 */
export interface UpgradeRequest {
  /** Target version */
  targetVersion: string;
  /** Rolling upgrade strategy */
  strategy?: 'rolling' | 'immediate';
  /** Backup before upgrade */
  backup?: boolean;
}

/**
 * Upgrade response
 */
export interface UpgradeResponse {
  /** Operation ID for tracking */
  operationId: string;
  /** Current version */
  fromVersion: string;
  /** Target version */
  toVersion: string;
  /** Operation status */
  status: QuicBaaSOperationStatus;
  /** Operation message */
  message: string;
}

/**
 * Rebalance request
 */
export interface RebalanceRequest {
  /** Target nodes for rebalancing */
  targetNodes?: string[];
  /** Force rebalance even if cluster is busy */
  force?: boolean;
  /** Maximum concurrent operations */
  maxConcurrent?: number;
}

/**
 * Rebalance response
 */
export interface RebalanceResponse {
  /** Operation ID for tracking */
  operationId: string;
  /** Number of partitions to rebalance */
  partitionsToRebalance: number;
  /** Operation status */
  status: QuicBaaSOperationStatus;
  /** Operation message */
  message: string;
}

/**
 * Compact request
 */
export interface CompactRequest {
  /** Target collections/tables to compact */
  targets?: string[];
  /** Full compaction (vs incremental) */
  full?: boolean;
  /** Force compaction */
  force?: boolean;
}

/**
 * Compact response
 */
export interface CompactResponse {
  /** Operation ID for tracking */
  operationId: string;
  /** Targets being compacted */
  targets: string[];
  /** Operation status */
  status: QuicBaaSOperationStatus;
  /** Estimated space savings in bytes */
  estimatedSavingsBytes?: number;
  /** Operation message */
  message: string;
}

/**
 * Operation status request
 */
export interface GetOperationStatusRequest {
  /** Operation ID */
  operationId: string;
}

/**
 * Operation status response
 */
export interface OperationStatusResponse {
  /** Operation ID */
  operationId: string;
  /** Operation type */
  type: 'migrate' | 'upgrade' | 'rebalance' | 'compact';
  /** Operation status */
  status: QuicBaaSOperationStatus;
  /** Progress percentage (0-100) */
  progress: number;
  /** Start time (ISO 8601) */
  startedAt: string;
  /** End time (ISO 8601) if completed */
  completedAt?: string;
  /** Error message if failed */
  error?: string;
  /** Operation details */
  details?: Record<string, unknown>;
}

/**
 * Cancel operation request
 */
export interface CancelOperationRequest {
  /** Operation ID to cancel */
  operationId: string;
  /** Force cancellation */
  force?: boolean;
}

/**
 * Cancel operation response
 */
export interface CancelOperationResponse {
  /** Operation ID */
  operationId: string;
  /** Whether cancellation was successful */
  cancelled: boolean;
  /** Operation message */
  message: string;
}

// =============================================================================
// Cache Service Types
// =============================================================================

/**
 * Cache get request
 */
export interface CacheGetRequest {
  /** Cache key */
  key: string;
  /** Cache namespace */
  namespace?: string;
}

/**
 * Cache get response
 */
export interface CacheGetResponse {
  /** Cache key */
  key: string;
  /** Cached value (base64 encoded for binary) */
  value: string;
  /** Value type hint */
  valueType: 'string' | 'json' | 'binary';
  /** Whether the key was found */
  found: boolean;
  /** Time to live in seconds (remaining) */
  ttlSeconds?: number;
  /** Creation timestamp (ISO 8601) */
  createdAt?: string;
}

/**
 * Cache put request
 */
export interface CachePutRequest {
  /** Cache key */
  key: string;
  /** Value to cache (base64 encoded for binary) */
  value: string;
  /** Value type hint */
  valueType?: 'string' | 'json' | 'binary';
  /** Cache namespace */
  namespace?: string;
  /** Time to live in seconds */
  ttlSeconds?: number;
  /** Overwrite if exists */
  overwrite?: boolean;
}

/**
 * Cache put response
 */
export interface CachePutResponse {
  /** Cache key */
  key: string;
  /** Whether the key was created (vs updated) */
  created: boolean;
  /** Expiration timestamp (ISO 8601) */
  expiresAt?: string;
}

/**
 * Cache delete request
 */
export interface CacheDeleteRequest {
  /** Cache key */
  key: string;
  /** Cache namespace */
  namespace?: string;
}

/**
 * Cache delete response
 */
export interface CacheDeleteResponse {
  /** Cache key */
  key: string;
  /** Whether the key was deleted */
  deleted: boolean;
}

/**
 * Cache clear request
 */
export interface CacheClearRequest {
  /** Cache namespace to clear (all if not specified) */
  namespace?: string;
  /** Pattern to match keys (glob-style) */
  pattern?: string;
}

/**
 * Cache clear response
 */
export interface CacheClearResponse {
  /** Number of keys cleared */
  clearedCount: number;
  /** Operation message */
  message: string;
}

/**
 * Cache stats response
 */
export interface CacheStatsResponse {
  /** Total number of keys */
  totalKeys: number;
  /** Total size in bytes */
  totalSizeBytes: number;
  /** Cache hit count */
  hits: number;
  /** Cache miss count */
  misses: number;
  /** Hit ratio (0-1) */
  hitRatio: number;
  /** Eviction count */
  evictions: number;
  /** Stats per namespace */
  namespaceStats?: NamespaceStats[];
  /** Collection timestamp (ISO 8601) */
  collectedAt: string;
}

/**
 * Namespace-specific stats
 */
export interface NamespaceStats {
  /** Namespace name */
  namespace: string;
  /** Number of keys */
  keyCount: number;
  /** Size in bytes */
  sizeBytes: number;
}

/**
 * Set TTL request
 */
export interface SetTTLRequest {
  /** Cache key */
  key: string;
  /** Cache namespace */
  namespace?: string;
  /** New TTL in seconds */
  ttlSeconds: number;
}

/**
 * Set TTL response
 */
export interface SetTTLResponse {
  /** Cache key */
  key: string;
  /** New expiration timestamp (ISO 8601) */
  expiresAt: string;
  /** Operation success */
  updated: boolean;
}

// =============================================================================
// ParameterStore Service Types
// =============================================================================

/**
 * Parameter type enum
 */
export type ParameterType = 'string' | 'stringList' | 'secureString';

/**
 * Parameter entity
 */
export interface Parameter extends Timestamps {
  /** Parameter name (path) */
  name: string;
  /** Parameter type */
  type: ParameterType;
  /** Parameter value */
  value: string;
  /** Parameter description */
  description?: string;
  /** Version number */
  version: number;
  /** Last modified by */
  lastModifiedBy?: string;
  /** Key ID for encrypted parameters */
  keyId?: string;
  /** Parameter tags */
  tags?: Record<string, string>;
}

/**
 * Get parameter request
 */
export interface GetParameterRequest {
  /** Parameter name (path) */
  name: string;
  /** Specific version to retrieve */
  version?: number;
  /** Decrypt secure strings */
  withDecryption?: boolean;
}

/**
 * Get parameter response
 */
export interface GetParameterResponse {
  /** Parameter */
  parameter: Parameter;
}

/**
 * Put parameter request
 */
export interface PutParameterRequest {
  /** Parameter name (path) */
  name: string;
  /** Parameter value */
  value: string;
  /** Parameter type */
  type?: ParameterType;
  /** Parameter description */
  description?: string;
  /** Key ID for encryption (secureString type) */
  keyId?: string;
  /** Overwrite existing parameter */
  overwrite?: boolean;
  /** Parameter tags */
  tags?: Record<string, string>;
}

/**
 * Put parameter response
 */
export interface PutParameterResponse {
  /** Parameter name */
  name: string;
  /** New version number */
  version: number;
  /** Whether a new parameter was created */
  created: boolean;
}

/**
 * Delete parameter request
 */
export interface DeleteParameterRequest {
  /** Parameter name (path) */
  name: string;
}

/**
 * Delete parameter response
 */
export interface DeleteParameterResponse {
  /** Deleted parameter name */
  name: string;
  /** Operation success */
  deleted: boolean;
}

/**
 * List parameters request
 */
export interface ListParametersRequest extends PaginationParams {
  /** Filter by path prefix */
  pathPrefix?: string;
  /** Filter by parameter type */
  type?: ParameterType;
  /** Filter by tags */
  tags?: Record<string, string>;
}

/**
 * List parameters response
 */
export interface ListParametersResponse {
  /** List of parameters (metadata only, no values) */
  parameters: ParameterMetadata[];
  /** Pagination metadata */
  pagination?: PaginationMeta;
}

/**
 * Parameter metadata (without value)
 */
export interface ParameterMetadata extends Timestamps {
  /** Parameter name (path) */
  name: string;
  /** Parameter type */
  type: ParameterType;
  /** Parameter description */
  description?: string;
  /** Version number */
  version: number;
  /** Last modified by */
  lastModifiedBy?: string;
  /** Key ID for encrypted parameters */
  keyId?: string;
}

/**
 * Get parameters by path request
 */
export interface GetParametersByPathRequest extends PaginationParams {
  /** Path prefix */
  path: string;
  /** Recursive lookup */
  recursive?: boolean;
  /** Decrypt secure strings */
  withDecryption?: boolean;
  /** Maximum depth for recursive lookup */
  maxDepth?: number;
}

/**
 * Get parameters by path response
 */
export interface GetParametersByPathResponse {
  /** Parameters at the path */
  parameters: Parameter[];
  /** Pagination metadata */
  pagination?: PaginationMeta;
}
