/**
 * QuicBaaS Core Data Types
 *
 * Types for QuicBaaS core data operations including key-value CRUD,
 * batch operations, transactions, queries, time-series, and backup/restore.
 */

// =============================================================================
// Common Enums
// =============================================================================

/**
 * Consistency level for read/write operations
 */
export type ConsistencyLevel =
  | 'UNSPECIFIED'
  | 'EVENTUAL'
  | 'STRONG'
  | 'BOUNDED_STALENESS'
  | 'SESSION';

/**
 * Transaction isolation level
 */
export type IsolationLevel =
  | 'UNSPECIFIED'
  | 'READ_UNCOMMITTED'
  | 'READ_COMMITTED'
  | 'REPEATABLE_READ'
  | 'SERIALIZABLE';

/**
 * Transaction state
 */
export type TransactionState =
  | 'UNSPECIFIED'
  | 'ACTIVE'
  | 'PREPARED'
  | 'COMMITTED'
  | 'ROLLED_BACK'
  | 'ABORTED';

/**
 * Index type for secondary indexes
 */
export type IndexType =
  | 'UNSPECIFIED'
  | 'BTREE'
  | 'HASH'
  | 'FULLTEXT'
  | 'GEO'
  | 'INVERTED';

/**
 * Index state
 */
export type IndexState =
  | 'UNSPECIFIED'
  | 'CREATING'
  | 'READY'
  | 'UPDATING'
  | 'DELETING'
  | 'ERROR';

/**
 * Query operator for filtering
 */
export type QueryOperator =
  | 'EQ'
  | 'NE'
  | 'GT'
  | 'GTE'
  | 'LT'
  | 'LTE'
  | 'IN'
  | 'NOT_IN'
  | 'CONTAINS'
  | 'STARTS_WITH'
  | 'ENDS_WITH'
  | 'REGEX'
  | 'EXISTS'
  | 'IS_NULL';

/**
 * Sort order
 */
export type SortOrder = 'ASC' | 'DESC';

/**
 * Time-series aggregation function
 */
export type AggregationFunction =
  | 'UNSPECIFIED'
  | 'COUNT'
  | 'SUM'
  | 'AVG'
  | 'MIN'
  | 'MAX'
  | 'FIRST'
  | 'LAST'
  | 'STDDEV'
  | 'VARIANCE'
  | 'PERCENTILE';

/**
 * Time-series time bucket
 */
export type TimeBucket =
  | 'UNSPECIFIED'
  | 'SECOND'
  | 'MINUTE'
  | 'HOUR'
  | 'DAY'
  | 'WEEK'
  | 'MONTH'
  | 'YEAR';

/**
 * Backup state
 */
export type BackupState =
  | 'UNSPECIFIED'
  | 'PENDING'
  | 'IN_PROGRESS'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

/**
 * Backup type
 */
export type BackupType =
  | 'UNSPECIFIED'
  | 'FULL'
  | 'INCREMENTAL'
  | 'DIFFERENTIAL';

/**
 * Watch event type
 */
export type WatchEventType =
  | 'UNSPECIFIED'
  | 'PUT'
  | 'DELETE'
  | 'EXPIRE';

// =============================================================================
// Common Data Types
// =============================================================================

/**
 * Key-value pair
 */
export interface KeyValue {
  /** Key */
  key: string;
  /** Value (base64 encoded for binary data) */
  value: string;
  /** Version number */
  version: number;
  /** Creation timestamp (unix epoch ms) */
  createdAt: number;
  /** Last modification timestamp (unix epoch ms) */
  modifiedAt: number;
  /** Expiration timestamp (unix epoch ms), 0 for no expiration */
  expiresAt?: number;
  /** Custom metadata */
  metadata?: Record<string, string>;
}

/**
 * Operation status
 */
export interface QuicBaaSStatus {
  /** Whether the operation succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details if failed */
  error?: {
    code: string;
    message: string;
    details?: Record<string, string>;
  };
}

/**
 * Watch event
 */
export interface WatchEvent {
  /** Event type */
  type: WatchEventType;
  /** Key-value pair */
  kv: KeyValue;
  /** Previous key-value pair (for updates) */
  prevKv?: KeyValue;
}

// =============================================================================
// KV Service Types
// =============================================================================

/**
 * Get request
 */
export interface KVGetRequest {
  /** Key to retrieve */
  key: string;
  /** Consistency level */
  consistency?: ConsistencyLevel;
  /** Specific version to retrieve (0 for latest) */
  version?: number;
}

/**
 * Get response
 */
export interface KVGetResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Key-value pair */
  kv?: KeyValue;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Put request
 */
export interface KVPutRequest {
  /** Key to store */
  key: string;
  /** Value to store (base64 encoded for binary data) */
  value: string;
  /** TTL in seconds (0 for no expiration) */
  ttl?: number;
  /** Custom metadata */
  metadata?: Record<string, string>;
  /** Only put if key does not exist */
  ifNotExists?: boolean;
  /** Only put if current version matches */
  ifVersion?: number;
}

/**
 * Put response
 */
export interface KVPutResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Key */
  key: string;
  /** New version number */
  version: number;
  /** Previous key-value pair (if existed) */
  prevKv?: KeyValue;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Delete request
 */
export interface KVDeleteRequest {
  /** Key to delete */
  key: string;
  /** Only delete if current version matches */
  ifVersion?: number;
}

/**
 * Delete response
 */
export interface KVDeleteResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Key */
  key: string;
  /** Whether the key was deleted */
  deleted: boolean;
  /** Previous key-value pair */
  prevKv?: KeyValue;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * List request
 */
export interface KVListRequest {
  /** Key prefix to filter */
  prefix?: string;
  /** Start key (inclusive) */
  startKey?: string;
  /** End key (exclusive) */
  endKey?: string;
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
  /** Include values in response */
  includeValues?: boolean;
  /** Consistency level */
  consistency?: ConsistencyLevel;
}

/**
 * List response
 */
export interface KVListResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Key-value pairs */
  kvs: KeyValue[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Total count (if available) */
  totalCount?: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Watch request
 */
export interface KVWatchRequest {
  /** Key to watch (exact match) */
  key?: string;
  /** Key prefix to watch */
  prefix?: string;
  /** Start revision to watch from */
  startRevision?: number;
  /** Filter by event types */
  eventTypes?: WatchEventType[];
}

/**
 * Watch response (streamed)
 */
export interface KVWatchResponse {
  /** Watch ID */
  watchId: string;
  /** Events */
  events: WatchEvent[];
  /** Current revision */
  revision: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

// =============================================================================
// Batch Service Types
// =============================================================================

/**
 * Batch get request
 */
export interface BatchGetRequest {
  /** Keys to retrieve */
  keys: string[];
  /** Consistency level */
  consistency?: ConsistencyLevel;
}

/**
 * Batch get response
 */
export interface BatchGetResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Key-value pairs (in same order as requested keys) */
  kvs: (KeyValue | null)[];
  /** Number of keys found */
  foundCount: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Batch put item
 */
export interface BatchPutItem {
  /** Key to store */
  key: string;
  /** Value to store (base64 encoded for binary data) */
  value: string;
  /** TTL in seconds (0 for no expiration) */
  ttl?: number;
  /** Custom metadata */
  metadata?: Record<string, string>;
}

/**
 * Batch put request
 */
export interface BatchPutRequest {
  /** Items to store */
  items: BatchPutItem[];
  /** Fail entire batch on first error */
  atomic?: boolean;
}

/**
 * Batch put result
 */
export interface BatchPutResult {
  /** Key */
  key: string;
  /** Success flag */
  success: boolean;
  /** New version number */
  version?: number;
  /** Error message if failed */
  error?: string;
}

/**
 * Batch put response
 */
export interface BatchPutResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Results for each item */
  results: BatchPutResult[];
  /** Number of successful puts */
  successCount: number;
  /** Number of failed puts */
  failedCount: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Batch delete request
 */
export interface BatchDeleteRequest {
  /** Keys to delete */
  keys: string[];
  /** Fail entire batch on first error */
  atomic?: boolean;
}

/**
 * Batch delete result
 */
export interface BatchDeleteResult {
  /** Key */
  key: string;
  /** Success flag */
  success: boolean;
  /** Whether the key was deleted */
  deleted?: boolean;
  /** Error message if failed */
  error?: string;
}

/**
 * Batch delete response
 */
export interface BatchDeleteResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Results for each key */
  results: BatchDeleteResult[];
  /** Number of successful deletes */
  successCount: number;
  /** Number of failed deletes */
  failedCount: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

// =============================================================================
// Transaction Service Types
// =============================================================================

/**
 * Begin transaction request
 */
export interface BeginTransactionRequest {
  /** Isolation level */
  isolationLevel?: IsolationLevel;
  /** Transaction timeout in seconds */
  timeout?: number;
  /** Read-only transaction */
  readOnly?: boolean;
}

/**
 * Begin transaction response
 */
export interface BeginTransactionResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Transaction ID */
  transactionId: string;
  /** Transaction state */
  state: TransactionState;
  /** Expiration timestamp (unix epoch ms) */
  expiresAt: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Transaction operation
 */
export interface TransactionOperation {
  /** Operation type */
  type: 'GET' | 'PUT' | 'DELETE';
  /** Key */
  key: string;
  /** Value (for PUT operations) */
  value?: string;
  /** TTL in seconds (for PUT operations) */
  ttl?: number;
  /** Metadata (for PUT operations) */
  metadata?: Record<string, string>;
}

/**
 * Commit transaction request
 */
export interface CommitTransactionRequest {
  /** Transaction ID */
  transactionId: string;
  /** Operations to execute */
  operations?: TransactionOperation[];
}

/**
 * Commit transaction response
 */
export interface CommitTransactionResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Transaction ID */
  transactionId: string;
  /** Transaction state */
  state: TransactionState;
  /** Commit revision */
  revision: number;
  /** Results for GET operations */
  results?: (KeyValue | null)[];
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Rollback transaction request
 */
export interface RollbackTransactionRequest {
  /** Transaction ID */
  transactionId: string;
}

/**
 * Rollback transaction response
 */
export interface RollbackTransactionResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Transaction ID */
  transactionId: string;
  /** Transaction state */
  state: TransactionState;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Compare condition for CAS operations
 */
export interface CompareCondition {
  /** Key to compare */
  key: string;
  /** Comparison target */
  target: 'VERSION' | 'VALUE' | 'CREATE_REVISION' | 'MOD_REVISION';
  /** Comparison operator */
  operator: 'EQ' | 'NE' | 'GT' | 'LT';
  /** Value to compare against (base64 for VALUE target) */
  value: string | number;
}

/**
 * Compare and swap request
 */
export interface CompareAndSwapRequest {
  /** Conditions that must all be true */
  conditions: CompareCondition[];
  /** Operations to execute if conditions are met */
  onSuccess: TransactionOperation[];
  /** Operations to execute if conditions are not met */
  onFailure?: TransactionOperation[];
}

/**
 * Compare and swap response
 */
export interface CompareAndSwapResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Whether the conditions were satisfied */
  succeeded: boolean;
  /** Results from executed operations */
  results?: (KeyValue | null)[];
  /** Revision after operation */
  revision: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

// =============================================================================
// Query Service Types
// =============================================================================

/**
 * Query filter condition
 */
export interface QueryFilter {
  /** Field name (dot notation for nested fields) */
  field: string;
  /** Operator */
  operator: QueryOperator;
  /** Value to compare (base64 for binary) */
  value: string | number | boolean | string[] | number[];
}

/**
 * Query sort specification
 */
export interface QuerySort {
  /** Field name (dot notation for nested fields) */
  field: string;
  /** Sort order */
  order: SortOrder;
}

/**
 * Query projection
 */
export interface QueryProjection {
  /** Fields to include */
  include?: string[];
  /** Fields to exclude */
  exclude?: string[];
}

/**
 * Query request
 */
export interface QueryRequest {
  /** Key prefix to query */
  prefix?: string;
  /** Filter conditions (AND logic) */
  filters?: QueryFilter[];
  /** Sort specifications */
  sorts?: QuerySort[];
  /** Field projection */
  projection?: QueryProjection;
  /** Maximum number of results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
  /** Cursor for cursor-based pagination */
  cursor?: string;
  /** Consistency level */
  consistency?: ConsistencyLevel;
}

/**
 * Query result item
 */
export interface QueryResultItem {
  /** Key */
  key: string;
  /** Value (base64 encoded) */
  value: string;
  /** Version */
  version: number;
  /** Score (for relevance-based queries) */
  score?: number;
}

/**
 * Query response
 */
export interface QueryResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Query results */
  items: QueryResultItem[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Total count (if available) */
  totalCount?: number;
  /** Query execution time in ms */
  executionTimeMs: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Index field specification
 */
export interface IndexField {
  /** Field name (dot notation for nested fields) */
  field: string;
  /** Sort order for this field */
  order?: SortOrder;
}

/**
 * Create index request
 */
export interface CreateIndexRequest {
  /** Index name */
  name: string;
  /** Key prefix this index applies to */
  prefix: string;
  /** Index type */
  type: IndexType;
  /** Fields to index */
  fields: IndexField[];
  /** Whether to build index in background */
  background?: boolean;
  /** Unique constraint */
  unique?: boolean;
  /** Sparse index (only index documents with the field) */
  sparse?: boolean;
}

/**
 * Index metadata
 */
export interface IndexMetadata {
  /** Index name */
  name: string;
  /** Key prefix */
  prefix: string;
  /** Index type */
  type: IndexType;
  /** Indexed fields */
  fields: IndexField[];
  /** Index state */
  state: IndexState;
  /** Unique constraint */
  unique: boolean;
  /** Sparse index */
  sparse: boolean;
  /** Creation timestamp (unix epoch ms) */
  createdAt: number;
  /** Last update timestamp (unix epoch ms) */
  updatedAt: number;
  /** Number of indexed entries */
  entryCount?: number;
  /** Index size in bytes */
  sizeBytes?: number;
}

/**
 * Create index response
 */
export interface CreateIndexResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Index metadata */
  index: IndexMetadata;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Delete index request
 */
export interface DeleteIndexRequest {
  /** Index name */
  name: string;
}

/**
 * Delete index response
 */
export interface DeleteIndexResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Index name */
  name: string;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * List indexes request
 */
export interface ListIndexesRequest {
  /** Key prefix to filter indexes */
  prefix?: string;
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
}

/**
 * List indexes response
 */
export interface ListIndexesResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Indexes */
  indexes: IndexMetadata[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

// =============================================================================
// Time-Series Service Types
// =============================================================================

/**
 * Time-series data point
 */
export interface TimeSeriesDataPoint {
  /** Timestamp (unix epoch ms) */
  timestamp: number;
  /** Value */
  value: number;
  /** Tags */
  tags?: Record<string, string>;
}

/**
 * Insert time-series request
 */
export interface TimeSeriesInsertRequest {
  /** Metric name */
  metric: string;
  /** Data points to insert */
  dataPoints: TimeSeriesDataPoint[];
  /** Retention period in seconds (0 for default) */
  retention?: number;
}

/**
 * Insert time-series response
 */
export interface TimeSeriesInsertResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Metric name */
  metric: string;
  /** Number of points inserted */
  insertedCount: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Time-series query request
 */
export interface TimeSeriesQueryRequest {
  /** Metric name */
  metric: string;
  /** Start time (unix epoch ms) */
  startTime: number;
  /** End time (unix epoch ms) */
  endTime: number;
  /** Tag filters */
  tags?: Record<string, string>;
  /** Maximum number of results */
  limit?: number;
  /** Sort order (by timestamp) */
  order?: SortOrder;
}

/**
 * Time-series query response
 */
export interface TimeSeriesQueryResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Metric name */
  metric: string;
  /** Data points */
  dataPoints: TimeSeriesDataPoint[];
  /** Whether there are more results */
  hasMore: boolean;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Aggregation specification
 */
export interface AggregationSpec {
  /** Aggregation function */
  function: AggregationFunction;
  /** Field to aggregate (defaults to value) */
  field?: string;
  /** Percentile value (for PERCENTILE function) */
  percentile?: number;
}

/**
 * Time-series aggregate request
 */
export interface TimeSeriesAggregateRequest {
  /** Metric name */
  metric: string;
  /** Start time (unix epoch ms) */
  startTime: number;
  /** End time (unix epoch ms) */
  endTime: number;
  /** Time bucket for grouping */
  bucket: TimeBucket;
  /** Bucket size multiplier (e.g., 5 for 5-minute buckets) */
  bucketSize?: number;
  /** Aggregations to compute */
  aggregations: AggregationSpec[];
  /** Tag filters */
  tags?: Record<string, string>;
  /** Group by tags */
  groupBy?: string[];
  /** Fill missing buckets */
  fill?: 'NONE' | 'NULL' | 'ZERO' | 'PREVIOUS' | 'LINEAR';
}

/**
 * Aggregation result
 */
export interface AggregationResult {
  /** Bucket start timestamp (unix epoch ms) */
  bucketStart: number;
  /** Bucket end timestamp (unix epoch ms) */
  bucketEnd: number;
  /** Aggregation values */
  values: Record<string, number | null>;
  /** Group tags (if grouped) */
  groupTags?: Record<string, string>;
}

/**
 * Time-series aggregate response
 */
export interface TimeSeriesAggregateResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Metric name */
  metric: string;
  /** Aggregation results */
  results: AggregationResult[];
  /** Query execution time in ms */
  executionTimeMs: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Time-series delete range request
 */
export interface TimeSeriesDeleteRangeRequest {
  /** Metric name */
  metric: string;
  /** Start time (unix epoch ms) */
  startTime: number;
  /** End time (unix epoch ms) */
  endTime: number;
  /** Tag filters (only delete matching) */
  tags?: Record<string, string>;
}

/**
 * Time-series delete range response
 */
export interface TimeSeriesDeleteRangeResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Metric name */
  metric: string;
  /** Number of points deleted */
  deletedCount: number;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

// =============================================================================
// Backup Service Types
// =============================================================================

/**
 * Backup metadata
 */
export interface BackupMetadata {
  /** Backup ID */
  backupId: string;
  /** Backup name */
  name: string;
  /** Backup type */
  type: BackupType;
  /** Backup state */
  state: BackupState;
  /** Backup size in bytes */
  sizeBytes: number;
  /** Number of keys backed up */
  keyCount: number;
  /** Start timestamp (unix epoch ms) */
  startedAt: number;
  /** Completion timestamp (unix epoch ms) */
  completedAt?: number;
  /** Base backup ID (for incremental/differential) */
  baseBackupId?: string;
  /** Storage location */
  location: string;
  /** Backup checksum */
  checksum?: string;
  /** Custom tags */
  tags?: Record<string, string>;
  /** Error message if failed */
  error?: string;
}

/**
 * Create backup request
 */
export interface CreateBackupRequest {
  /** Backup name */
  name: string;
  /** Backup type */
  type?: BackupType;
  /** Base backup ID (required for incremental/differential) */
  baseBackupId?: string;
  /** Key prefixes to include (empty for all) */
  prefixes?: string[];
  /** Storage location (e.g., s3://bucket/path) */
  location?: string;
  /** Compression enabled */
  compression?: boolean;
  /** Encryption key ID */
  encryptionKeyId?: string;
  /** Custom tags */
  tags?: Record<string, string>;
}

/**
 * Create backup response
 */
export interface CreateBackupResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Backup metadata */
  backup: BackupMetadata;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Restore backup request
 */
export interface RestoreBackupRequest {
  /** Backup ID to restore */
  backupId: string;
  /** Target key prefix (optional, for restoring to different location) */
  targetPrefix?: string;
  /** Overwrite existing keys */
  overwrite?: boolean;
  /** Decryption key ID (if backup was encrypted) */
  decryptionKeyId?: string;
}

/**
 * Restore progress
 */
export interface RestoreProgress {
  /** Restore state */
  state: BackupState;
  /** Total keys to restore */
  totalKeys: number;
  /** Keys restored so far */
  restoredKeys: number;
  /** Percentage complete */
  percentComplete: number;
  /** Estimated time remaining in seconds */
  estimatedTimeRemaining?: number;
}

/**
 * Restore backup response
 */
export interface RestoreBackupResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Restore ID */
  restoreId: string;
  /** Backup ID being restored */
  backupId: string;
  /** Restore progress */
  progress: RestoreProgress;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * List backups request
 */
export interface ListBackupsRequest {
  /** Filter by backup type */
  type?: BackupType;
  /** Filter by state */
  state?: BackupState;
  /** Start time filter (unix epoch ms) */
  startTime?: number;
  /** End time filter (unix epoch ms) */
  endTime?: number;
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
}

/**
 * List backups response
 */
export interface ListBackupsResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Backups */
  backups: BackupMetadata[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Delete backup request
 */
export interface DeleteBackupRequest {
  /** Backup ID to delete */
  backupId: string;
  /** Force delete even if other backups depend on this */
  force?: boolean;
}

/**
 * Delete backup response
 */
export interface DeleteBackupResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Backup ID deleted */
  backupId: string;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}

/**
 * Get backup status request
 */
export interface GetBackupStatusRequest {
  /** Backup ID */
  backupId: string;
}

/**
 * Backup progress
 */
export interface BackupProgress {
  /** Backup state */
  state: BackupState;
  /** Total keys to backup */
  totalKeys: number;
  /** Keys backed up so far */
  backedUpKeys: number;
  /** Bytes written */
  bytesWritten: number;
  /** Percentage complete */
  percentComplete: number;
  /** Estimated time remaining in seconds */
  estimatedTimeRemaining?: number;
}

/**
 * Get backup status response
 */
export interface GetBackupStatusResponse {
  /** Operation status */
  status: QuicBaaSStatus;
  /** Backup metadata */
  backup: BackupMetadata;
  /** Backup progress (if in progress) */
  progress?: BackupProgress;
  /** Timestamp (unix epoch ms) */
  timestamp: number;
}
