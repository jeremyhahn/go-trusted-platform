/**
 * QuicBaaS Infrastructure Types - Part 2
 *
 * Types for QuicBaaS infrastructure services including scheduler, object storage,
 * object storage admin, object transfer, and IAM operations.
 */

// =============================================================================
// Common Types
// =============================================================================

/**
 * Pagination parameters for list requests
 */
export interface QuicBaaSPaginationParams {
  /** Page number (1-indexed) */
  page?: number;
  /** Number of items per page */
  pageSize?: number;
  /** Cursor for cursor-based pagination */
  cursor?: string;
}

/**
 * Pagination metadata in list responses
 */
export interface QuicBaaSPaginationMeta {
  /** Current page number */
  page: number;
  /** Page size */
  pageSize: number;
  /** Total number of items */
  totalItems: number;
  /** Total number of pages */
  totalPages: number;
  /** Next page cursor */
  nextCursor?: string;
}

/**
 * Operation status
 */
export interface QuicBaaSOperationResult {
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

// =============================================================================
// Scheduler Types
// =============================================================================

/**
 * Job status
 */
export type JobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'paused' | 'cancelled';

/**
 * Job priority
 */
export type JobPriority = 'low' | 'normal' | 'high' | 'critical';

/**
 * Schedule type for recurring jobs
 */
export type ScheduleType = 'once' | 'cron' | 'interval' | 'fixed_rate';

/**
 * Job schedule configuration
 */
export interface JobSchedule {
  /** Schedule type */
  type: ScheduleType;
  /** Cron expression (for cron type) */
  cronExpression?: string;
  /** Interval in seconds (for interval type) */
  intervalSeconds?: number;
  /** Fixed rate in seconds (for fixed_rate type) */
  rateSeconds?: number;
  /** Start time (ISO 8601) */
  startTime?: string;
  /** End time (ISO 8601) */
  endTime?: string;
  /** Timezone */
  timezone?: string;
}

/**
 * Job retry configuration
 */
export interface JobRetryConfig {
  /** Maximum retry attempts */
  maxAttempts: number;
  /** Initial retry delay in seconds */
  initialDelaySeconds: number;
  /** Maximum retry delay in seconds */
  maxDelaySeconds: number;
  /** Backoff multiplier */
  backoffMultiplier: number;
  /** Retryable error codes */
  retryableErrors?: string[];
}

/**
 * Job execution context
 */
export interface JobExecutionContext {
  /** Execution ID */
  executionId: string;
  /** Attempt number */
  attemptNumber: number;
  /** Started at (ISO 8601) */
  startedAt: string;
  /** Completed at (ISO 8601) */
  completedAt?: string;
  /** Duration in milliseconds */
  durationMs?: number;
  /** Exit code */
  exitCode?: number;
  /** Output data */
  output?: string;
  /** Error message */
  errorMessage?: string;
}

/**
 * Scheduled job
 */
export interface ScheduledJob {
  /** Job ID */
  id: string;
  /** Job name */
  name: string;
  /** Description */
  description?: string;
  /** Job type/handler */
  type: string;
  /** Job status */
  status: JobStatus;
  /** Priority */
  priority: JobPriority;
  /** Schedule configuration */
  schedule: JobSchedule;
  /** Retry configuration */
  retryConfig?: JobRetryConfig;
  /** Job payload data */
  payload?: Record<string, unknown>;
  /** Labels/tags */
  labels?: Record<string, string>;
  /** Last execution context */
  lastExecution?: JobExecutionContext;
  /** Next scheduled run (ISO 8601) */
  nextRun?: string;
  /** Total execution count */
  executionCount: number;
  /** Success count */
  successCount: number;
  /** Failure count */
  failureCount: number;
  /** Created at (ISO 8601) */
  createdAt: string;
  /** Updated at (ISO 8601) */
  updatedAt: string;
}

/**
 * Create job request
 */
export interface CreateJobRequest {
  /** Job name */
  name: string;
  /** Description */
  description?: string;
  /** Job type/handler */
  type: string;
  /** Priority */
  priority?: JobPriority;
  /** Schedule configuration */
  schedule: JobSchedule;
  /** Retry configuration */
  retryConfig?: JobRetryConfig;
  /** Job payload data */
  payload?: Record<string, unknown>;
  /** Labels/tags */
  labels?: Record<string, string>;
}

/**
 * Create job response
 */
export interface CreateJobResponse {
  /** Created job */
  job: ScheduledJob;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Get job request
 */
export interface GetJobRequest {
  /** Job ID */
  jobId: string;
}

/**
 * Get job response
 */
export interface GetJobResponse {
  /** Job */
  job: ScheduledJob;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Update job request
 */
export interface UpdateJobRequest {
  /** Job ID */
  jobId: string;
  /** Updated name */
  name?: string;
  /** Updated description */
  description?: string;
  /** Updated priority */
  priority?: JobPriority;
  /** Updated schedule */
  schedule?: JobSchedule;
  /** Updated retry config */
  retryConfig?: JobRetryConfig;
  /** Updated payload */
  payload?: Record<string, unknown>;
  /** Updated labels */
  labels?: Record<string, string>;
}

/**
 * Update job response
 */
export interface UpdateJobResponse {
  /** Updated job */
  job: ScheduledJob;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete job request
 */
export interface DeleteJobRequest {
  /** Job ID */
  jobId: string;
  /** Force delete even if running */
  force?: boolean;
}

/**
 * Delete job response
 */
export interface DeleteJobResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List jobs request
 */
export interface ListJobsRequest extends QuicBaaSPaginationParams {
  /** Filter by status */
  status?: JobStatus;
  /** Filter by type */
  type?: string;
  /** Filter by priority */
  priority?: JobPriority;
  /** Filter by label key-value pairs */
  labels?: Record<string, string>;
}

/**
 * List jobs response
 */
export interface ListJobsResponse {
  /** Jobs */
  jobs: ScheduledJob[];
  /** Pagination */
  pagination?: QuicBaaSPaginationMeta;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Pause job request
 */
export interface PauseJobRequest {
  /** Job ID */
  jobId: string;
}

/**
 * Pause job response
 */
export interface PauseJobResponse {
  /** Updated job */
  job: ScheduledJob;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Resume job request
 */
export interface ResumeJobRequest {
  /** Job ID */
  jobId: string;
}

/**
 * Resume job response
 */
export interface ResumeJobResponse {
  /** Updated job */
  job: ScheduledJob;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Trigger job request
 */
export interface TriggerJobRequest {
  /** Job ID */
  jobId: string;
  /** Override payload for this execution */
  payloadOverride?: Record<string, unknown>;
}

/**
 * Trigger job response
 */
export interface TriggerJobResponse {
  /** Execution context */
  execution: JobExecutionContext;
  /** Response timestamp */
  timestamp: string;
}

// =============================================================================
// Object Storage Types
// =============================================================================

/**
 * Storage class for objects
 */
export type StorageClass = 'standard' | 'infrequent_access' | 'archive' | 'deep_archive';

/**
 * Object metadata
 */
export interface ObjectMetadata {
  /** Content type */
  contentType?: string;
  /** Content encoding */
  contentEncoding?: string;
  /** Content language */
  contentLanguage?: string;
  /** Cache control */
  cacheControl?: string;
  /** Content disposition */
  contentDisposition?: string;
  /** Custom metadata */
  custom?: Record<string, string>;
}

/**
 * Stored object
 */
export interface StoredObject {
  /** Object key */
  key: string;
  /** Bucket name */
  bucket: string;
  /** Size in bytes */
  size: number;
  /** ETag/checksum */
  etag: string;
  /** Content type */
  contentType?: string;
  /** Storage class */
  storageClass: StorageClass;
  /** Object metadata */
  metadata?: ObjectMetadata;
  /** Version ID */
  versionId?: string;
  /** Last modified (ISO 8601) */
  lastModified: string;
  /** Expiration time (ISO 8601) */
  expiresAt?: string;
}

/**
 * Put object request
 */
export interface PutObjectRequest {
  /** Bucket name */
  bucket: string;
  /** Object key */
  key: string;
  /** Object content (base64 encoded) */
  content: string;
  /** Content type */
  contentType?: string;
  /** Storage class */
  storageClass?: StorageClass;
  /** Object metadata */
  metadata?: ObjectMetadata;
  /** Expected ETag for conditional writes */
  ifMatch?: string;
  /** Write only if object doesn't exist */
  ifNoneMatch?: boolean;
}

/**
 * Put object response
 */
export interface PutObjectResponse {
  /** Object key */
  key: string;
  /** Bucket name */
  bucket: string;
  /** ETag */
  etag: string;
  /** Version ID */
  versionId?: string;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Get object request
 */
export interface GetObjectRequest {
  /** Bucket name */
  bucket: string;
  /** Object key */
  key: string;
  /** Version ID */
  versionId?: string;
  /** Range header for partial content */
  range?: string;
  /** Conditional: if modified since (ISO 8601) */
  ifModifiedSince?: string;
  /** Conditional: if none match ETag */
  ifNoneMatch?: string;
}

/**
 * Get object response
 */
export interface GetObjectResponse {
  /** Object */
  object: StoredObject;
  /** Object content (base64 encoded) */
  content: string;
  /** Content range (for partial responses) */
  contentRange?: string;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete object request
 */
export interface DeleteObjectRequest {
  /** Bucket name */
  bucket: string;
  /** Object key */
  key: string;
  /** Version ID */
  versionId?: string;
}

/**
 * Delete object response
 */
export interface DeleteObjectResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Deleted version ID */
  versionId?: string;
  /** Delete marker created */
  deleteMarker?: boolean;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List objects request
 */
export interface ListObjectsRequest extends QuicBaaSPaginationParams {
  /** Bucket name */
  bucket: string;
  /** Key prefix filter */
  prefix?: string;
  /** Delimiter for hierarchical listing */
  delimiter?: string;
  /** Start after key */
  startAfter?: string;
  /** Maximum keys to return */
  maxKeys?: number;
}

/**
 * List objects response
 */
export interface ListObjectsResponse {
  /** Objects */
  objects: StoredObject[];
  /** Common prefixes (directories) */
  commonPrefixes?: string[];
  /** Pagination */
  pagination?: QuicBaaSPaginationMeta;
  /** Is truncated */
  isTruncated: boolean;
  /** Next continuation token */
  nextContinuationToken?: string;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Head object request
 */
export interface HeadObjectRequest {
  /** Bucket name */
  bucket: string;
  /** Object key */
  key: string;
  /** Version ID */
  versionId?: string;
}

/**
 * Head object response
 */
export interface HeadObjectResponse {
  /** Object metadata (without content) */
  object: StoredObject;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Copy object request
 */
export interface CopyObjectRequest {
  /** Source bucket */
  sourceBucket: string;
  /** Source key */
  sourceKey: string;
  /** Source version ID */
  sourceVersionId?: string;
  /** Destination bucket */
  destinationBucket: string;
  /** Destination key */
  destinationKey: string;
  /** New metadata (replaces source metadata) */
  metadata?: ObjectMetadata;
  /** New storage class */
  storageClass?: StorageClass;
}

/**
 * Copy object response
 */
export interface CopyObjectResponse {
  /** Destination key */
  key: string;
  /** Destination bucket */
  bucket: string;
  /** ETag */
  etag: string;
  /** Version ID */
  versionId?: string;
  /** Response timestamp */
  timestamp: string;
}

// =============================================================================
// Object Storage Admin Types
// =============================================================================

/**
 * Bucket versioning status
 */
export type VersioningStatus = 'disabled' | 'enabled' | 'suspended';

/**
 * Bucket configuration
 */
export interface BucketConfig {
  /** Default storage class */
  defaultStorageClass?: StorageClass;
  /** Versioning status */
  versioning?: VersioningStatus;
  /** Object lock enabled */
  objectLockEnabled?: boolean;
  /** Encryption enabled */
  encryptionEnabled?: boolean;
  /** KMS key ID for encryption */
  kmsKeyId?: string;
}

/**
 * Storage bucket
 */
export interface StorageBucket {
  /** Bucket name */
  name: string;
  /** Region */
  region?: string;
  /** Bucket configuration */
  config: BucketConfig;
  /** Object count */
  objectCount: number;
  /** Total size in bytes */
  totalSizeBytes: number;
  /** Created at (ISO 8601) */
  createdAt: string;
  /** Updated at (ISO 8601) */
  updatedAt: string;
}

/**
 * Bucket policy statement
 */
export interface BucketPolicyStatement {
  /** Statement ID */
  sid?: string;
  /** Effect (allow/deny) */
  effect: 'allow' | 'deny';
  /** Principals */
  principals: string[];
  /** Actions */
  actions: string[];
  /** Resources */
  resources: string[];
  /** Conditions */
  conditions?: Record<string, Record<string, string[]>>;
}

/**
 * Bucket policy
 */
export interface BucketPolicy {
  /** Policy version */
  version: string;
  /** Policy statements */
  statements: BucketPolicyStatement[];
}

/**
 * Create bucket request
 */
export interface CreateBucketRequest {
  /** Bucket name */
  name: string;
  /** Region */
  region?: string;
  /** Bucket configuration */
  config?: BucketConfig;
}

/**
 * Create bucket response
 */
export interface CreateBucketResponse {
  /** Created bucket */
  bucket: StorageBucket;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete bucket request
 */
export interface DeleteBucketRequest {
  /** Bucket name */
  name: string;
  /** Force delete even if not empty */
  force?: boolean;
}

/**
 * Delete bucket response
 */
export interface DeleteBucketResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List buckets request
 */
export interface ListBucketsRequest extends QuicBaaSPaginationParams {
  /** Filter by region */
  region?: string;
}

/**
 * List buckets response
 */
export interface ListBucketsResponse {
  /** Buckets */
  buckets: StorageBucket[];
  /** Pagination */
  pagination?: QuicBaaSPaginationMeta;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Get bucket policy request
 */
export interface GetBucketPolicyRequest {
  /** Bucket name */
  bucket: string;
}

/**
 * Get bucket policy response
 */
export interface GetBucketPolicyResponse {
  /** Bucket name */
  bucket: string;
  /** Bucket policy */
  policy: BucketPolicy;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Set bucket policy request
 */
export interface SetBucketPolicyRequest {
  /** Bucket name */
  bucket: string;
  /** Bucket policy */
  policy: BucketPolicy;
}

/**
 * Set bucket policy response
 */
export interface SetBucketPolicyResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Response timestamp */
  timestamp: string;
}

// =============================================================================
// Object Transfer Types
// =============================================================================

/**
 * Transfer status
 */
export type TransferStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';

/**
 * Transfer direction
 */
export type TransferDirection = 'upload' | 'download' | 'peer_to_peer';

/**
 * Transfer endpoint
 */
export interface TransferEndpoint {
  /** Node ID */
  nodeId: string;
  /** Node address */
  address: string;
  /** Bucket name */
  bucket: string;
  /** Object key */
  key: string;
}

/**
 * Transfer progress
 */
export interface TransferProgress {
  /** Bytes transferred */
  bytesTransferred: number;
  /** Total bytes */
  totalBytes: number;
  /** Transfer rate in bytes per second */
  bytesPerSecond: number;
  /** Estimated time remaining in seconds */
  estimatedSecondsRemaining?: number;
  /** Percentage complete */
  percentComplete: number;
}

/**
 * Data transfer
 */
export interface DataTransfer {
  /** Transfer ID */
  id: string;
  /** Transfer status */
  status: TransferStatus;
  /** Transfer direction */
  direction: TransferDirection;
  /** Source endpoint */
  source: TransferEndpoint;
  /** Destination endpoint */
  destination: TransferEndpoint;
  /** Transfer progress */
  progress: TransferProgress;
  /** Error message */
  errorMessage?: string;
  /** Retry count */
  retryCount: number;
  /** Maximum retries */
  maxRetries: number;
  /** Started at (ISO 8601) */
  startedAt?: string;
  /** Completed at (ISO 8601) */
  completedAt?: string;
  /** Created at (ISO 8601) */
  createdAt: string;
  /** Updated at (ISO 8601) */
  updatedAt: string;
}

/**
 * Initiate transfer request
 */
export interface InitiateTransferRequest {
  /** Transfer direction */
  direction: TransferDirection;
  /** Source endpoint */
  source: TransferEndpoint;
  /** Destination endpoint */
  destination: TransferEndpoint;
  /** Maximum retries */
  maxRetries?: number;
  /** Priority */
  priority?: 'low' | 'normal' | 'high';
}

/**
 * Initiate transfer response
 */
export interface InitiateTransferResponse {
  /** Created transfer */
  transfer: DataTransfer;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Get transfer status request
 */
export interface GetTransferStatusRequest {
  /** Transfer ID */
  transferId: string;
}

/**
 * Get transfer status response
 */
export interface GetTransferStatusResponse {
  /** Transfer */
  transfer: DataTransfer;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Cancel transfer request
 */
export interface CancelTransferRequest {
  /** Transfer ID */
  transferId: string;
}

/**
 * Cancel transfer response
 */
export interface CancelTransferResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List transfers request
 */
export interface ListTransfersRequest extends QuicBaaSPaginationParams {
  /** Filter by status */
  status?: TransferStatus;
  /** Filter by direction */
  direction?: TransferDirection;
  /** Filter by source node ID */
  sourceNodeId?: string;
  /** Filter by destination node ID */
  destinationNodeId?: string;
}

/**
 * List transfers response
 */
export interface ListTransfersResponse {
  /** Transfers */
  transfers: DataTransfer[];
  /** Pagination */
  pagination?: QuicBaaSPaginationMeta;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

// =============================================================================
// QuicBaaS IAM Types
// =============================================================================

/**
 * QuicBaaS IAM user
 */
export interface QuicBaaSUser {
  /** User ID */
  id: string;
  /** Username */
  username: string;
  /** Email */
  email?: string;
  /** Display name */
  displayName?: string;
  /** User status */
  status: 'active' | 'inactive' | 'suspended';
  /** Assigned groups */
  groups: string[];
  /** Assigned policies */
  policies: string[];
  /** API keys count */
  apiKeysCount: number;
  /** User attributes */
  attributes?: Record<string, string>;
  /** Last login (ISO 8601) */
  lastLogin?: string;
  /** Created at (ISO 8601) */
  createdAt: string;
  /** Updated at (ISO 8601) */
  updatedAt: string;
}

/**
 * QuicBaaS IAM group
 */
export interface QuicBaaSGroup {
  /** Group ID */
  id: string;
  /** Group name */
  name: string;
  /** Description */
  description?: string;
  /** Member user IDs */
  members: string[];
  /** Attached policy IDs */
  policies: string[];
  /** Created at (ISO 8601) */
  createdAt: string;
  /** Updated at (ISO 8601) */
  updatedAt: string;
}

/**
 * QuicBaaS IAM policy
 */
export interface QuicBaaSPolicy {
  /** Policy ID */
  id: string;
  /** Policy name */
  name: string;
  /** Description */
  description?: string;
  /** Policy document (JSON) */
  document: string;
  /** Policy version */
  version: string;
  /** Is default policy */
  isDefault: boolean;
  /** Attached users count */
  attachedUsersCount: number;
  /** Attached groups count */
  attachedGroupsCount: number;
  /** Created at (ISO 8601) */
  createdAt: string;
  /** Updated at (ISO 8601) */
  updatedAt: string;
}

/**
 * Create QuicBaaS user request
 */
export interface CreateQuicBaaSUserRequest {
  /** Username */
  username: string;
  /** Email */
  email?: string;
  /** Display name */
  displayName?: string;
  /** Initial groups */
  groups?: string[];
  /** Initial policies */
  policies?: string[];
  /** User attributes */
  attributes?: Record<string, string>;
}

/**
 * Create QuicBaaS user response
 */
export interface CreateQuicBaaSUserResponse {
  /** Created user */
  user: QuicBaaSUser;
  /** Initial access key (only returned on creation) */
  accessKey?: {
    accessKeyId: string;
    secretAccessKey: string;
  };
  /** Response timestamp */
  timestamp: string;
}

/**
 * Get QuicBaaS user request
 */
export interface GetQuicBaaSUserRequest {
  /** User ID */
  userId: string;
}

/**
 * Get QuicBaaS user response
 */
export interface GetQuicBaaSUserResponse {
  /** User */
  user: QuicBaaSUser;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Update QuicBaaS user request
 */
export interface UpdateQuicBaaSUserRequest {
  /** User ID */
  userId: string;
  /** Updated email */
  email?: string;
  /** Updated display name */
  displayName?: string;
  /** Updated status */
  status?: 'active' | 'inactive' | 'suspended';
  /** Updated attributes */
  attributes?: Record<string, string>;
}

/**
 * Update QuicBaaS user response
 */
export interface UpdateQuicBaaSUserResponse {
  /** Updated user */
  user: QuicBaaSUser;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete QuicBaaS user request
 */
export interface DeleteQuicBaaSUserRequest {
  /** User ID */
  userId: string;
}

/**
 * Delete QuicBaaS user response
 */
export interface DeleteQuicBaaSUserResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List QuicBaaS users request
 */
export interface ListQuicBaaSUsersRequest extends QuicBaaSPaginationParams {
  /** Filter by status */
  status?: 'active' | 'inactive' | 'suspended';
  /** Filter by group */
  groupId?: string;
}

/**
 * List QuicBaaS users response
 */
export interface ListQuicBaaSUsersResponse {
  /** Users */
  users: QuicBaaSUser[];
  /** Pagination */
  pagination?: QuicBaaSPaginationMeta;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Create QuicBaaS group request
 */
export interface CreateQuicBaaSGroupRequest {
  /** Group name */
  name: string;
  /** Description */
  description?: string;
  /** Initial member user IDs */
  members?: string[];
  /** Initial policy IDs */
  policies?: string[];
}

/**
 * Create QuicBaaS group response
 */
export interface CreateQuicBaaSGroupResponse {
  /** Created group */
  group: QuicBaaSGroup;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Add user to group request
 */
export interface AddUserToGroupRequest {
  /** Group ID */
  groupId: string;
  /** User ID */
  userId: string;
}

/**
 * Add user to group response
 */
export interface AddUserToGroupResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Remove user from group request
 */
export interface RemoveUserFromGroupRequest {
  /** Group ID */
  groupId: string;
  /** User ID */
  userId: string;
}

/**
 * Remove user from group response
 */
export interface RemoveUserFromGroupResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Create QuicBaaS policy request
 */
export interface CreateQuicBaaSPolicyRequest {
  /** Policy name */
  name: string;
  /** Description */
  description?: string;
  /** Policy document (JSON) */
  document: string;
}

/**
 * Create QuicBaaS policy response
 */
export interface CreateQuicBaaSPolicyResponse {
  /** Created policy */
  policy: QuicBaaSPolicy;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Attach policy request
 */
export interface AttachPolicyRequest {
  /** Policy ID */
  policyId: string;
  /** Target type */
  targetType: 'user' | 'group';
  /** Target ID (user ID or group ID) */
  targetId: string;
}

/**
 * Attach policy response
 */
export interface AttachPolicyResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Detach policy request
 */
export interface DetachPolicyRequest {
  /** Policy ID */
  policyId: string;
  /** Target type */
  targetType: 'user' | 'group';
  /** Target ID (user ID or group ID) */
  targetId: string;
}

/**
 * Detach policy response
 */
export interface DetachPolicyResponse {
  /** Operation status */
  status: QuicBaaSOperationResult;
  /** Response timestamp */
  timestamp: string;
}
