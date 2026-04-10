/**
 * Storage service types for Object Storage, KV Store, Time Series, Vector DB, and Backups
 */

// Object Storage Types (S3-like)
export interface StorageObject {
  id: string;
  bucket: string;
  key: string;
  size: number;
  contentType: string;
  etag: string;
  lastModified: string;
  storageClass: 'standard' | 'infrequent' | 'archive';
  metadata?: Record<string, string>;
}

export interface StorageBucket {
  id: string;
  name: string;
  region: string;
  createdAt: string;
  objectCount: number;
  totalSize: number;
  versioning: boolean;
  encryption: boolean;
}

export interface ObjectUploadInput {
  bucket: string;
  key: string;
  contentType: string;
  metadata?: Record<string, string>;
  storageClass?: 'standard' | 'infrequent' | 'archive';
}

export interface ObjectFilters {
  bucket?: string;
  prefix?: string;
  search?: string;
}

// Key-Value Store Types
export interface KVEntry {
  id: string;
  namespace: string;
  key: string;
  value: string;
  valueType: 'string' | 'json' | 'binary';
  ttl?: number;
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface KVNamespace {
  id: string;
  name: string;
  description?: string;
  entryCount: number;
  totalSize: number;
  createdAt: string;
}

export interface KVSetInput {
  namespace: string;
  key: string;
  value: string;
  valueType?: 'string' | 'json' | 'binary';
  ttl?: number;
}

export interface KVFilters {
  namespace?: string;
  prefix?: string;
  search?: string;
}

// Time Series Database Types
export interface TimeSeriesMetric {
  id: string;
  name: string;
  description?: string;
  unit: string;
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
  labels: Record<string, string>;
  retention: string;
  createdAt: string;
}

export interface TimeSeriesDataPoint {
  timestamp: string;
  value: number;
  labels?: Record<string, string>;
}

export interface TimeSeriesQuery {
  metric: string;
  startTime: string;
  endTime: string;
  step?: string;
  aggregation?: 'avg' | 'sum' | 'min' | 'max' | 'count';
  labels?: Record<string, string>;
}

export interface TimeSeriesResult {
  metric: TimeSeriesMetric;
  dataPoints: TimeSeriesDataPoint[];
}

export interface TimeSeriesFilters {
  search?: string;
  type?: 'counter' | 'gauge' | 'histogram' | 'summary';
}

// Vector Database Types
export interface VectorCollection {
  id: string;
  name: string;
  description?: string;
  dimensions: number;
  distanceMetric: 'cosine' | 'euclidean' | 'dot_product';
  vectorCount: number;
  indexType: 'flat' | 'hnsw' | 'ivf';
  createdAt: string;
  updatedAt: string;
}

export interface VectorEntry {
  id: string;
  collectionId: string;
  vector: number[];
  metadata?: Record<string, unknown>;
  createdAt: string;
}

export interface VectorSearchInput {
  collection: string;
  vector: number[];
  topK: number;
  filter?: Record<string, unknown>;
  includeMetadata?: boolean;
}

export interface VectorSearchResult {
  id: string;
  score: number;
  metadata?: Record<string, unknown>;
}

export interface VectorCollectionInput {
  name: string;
  description?: string;
  dimensions: number;
  distanceMetric: 'cosine' | 'euclidean' | 'dot_product';
  indexType?: 'flat' | 'hnsw' | 'ivf';
}

export interface VectorFilters {
  search?: string;
}

// Backup & Restore Types
export interface Backup {
  id: string;
  name: string;
  description?: string;
  type: 'full' | 'incremental' | 'differential';
  status: 'pending' | 'running' | 'completed' | 'failed';
  source: string;
  destination: string;
  size?: number;
  startedAt: string;
  completedAt?: string;
  retentionDays: number;
  encrypted: boolean;
}

export interface BackupSchedule {
  id: string;
  name: string;
  enabled: boolean;
  cronExpression: string;
  type: 'full' | 'incremental' | 'differential';
  source: string;
  destination: string;
  retentionDays: number;
  encrypted: boolean;
  lastRunAt?: string;
  nextRunAt?: string;
}

export interface BackupCreateInput {
  name: string;
  description?: string;
  type: 'full' | 'incremental' | 'differential';
  source: string;
  destination: string;
  retentionDays?: number;
  encrypted?: boolean;
}

export interface RestoreInput {
  backupId: string;
  destination: string;
  overwrite?: boolean;
}

export interface BackupFilters {
  status?: 'pending' | 'running' | 'completed' | 'failed';
  type?: 'full' | 'incremental' | 'differential';
  search?: string;
}

// Storage Statistics
export interface StorageStats {
  objects: {
    bucketCount: number;
    objectCount: number;
    totalSize: number;
  };
  kv: {
    namespaceCount: number;
    entryCount: number;
    totalSize: number;
  };
  timeseries: {
    metricCount: number;
    dataPointCount: number;
    retentionDays: number;
  };
  vector: {
    collectionCount: number;
    vectorCount: number;
    totalDimensions: number;
  };
  backup: {
    totalBackups: number;
    activeSchedules: number;
    lastBackupAt?: string;
  };
}
