import { test, expect, Page, Route, Request } from '@playwright/test';
import {
  createTenantOwnerSession,
  createTenantMemberSession,
} from './fixtures/auth-setup';
import { mockTenantApi, ApiError } from './fixtures/api-mock';

/**
 * Storage E2E Tests
 *
 * Tests for all storage management pages including:
 * - Key-Value Store (/storage/kv)
 * - Object Storage (/storage/objects)
 * - Vector Database (/storage/vector)
 * - Time Series (/storage/timeseries)
 * - Backup Management (/storage/backup)
 *
 * Types are aligned with the trusted-platform-sdk QuicBaaS types.
 */

// ============================================================================
// Type Definitions - Aligned with SDK types from trusted-platform-sdk
// ============================================================================

// QuicBaaS Status type used in SDK responses
export interface QuicBaaSStatus {
  success: boolean;
  message: string;
  error?: {
    code: string;
    message: string;
    details?: Record<string, string>;
  };
}

// KV Types - from quicbaas/core-data.d.ts
export interface KeyValue {
  key: string;
  value: string;
  version: number;
  createdAt: number; // unix epoch ms
  modifiedAt: number; // unix epoch ms
  expiresAt?: number; // unix epoch ms
  metadata?: Record<string, string>;
}

export interface KVListResponse {
  status: QuicBaaSStatus;
  kvs: KeyValue[];
  nextCursor?: string;
  hasMore: boolean;
  totalCount?: number;
  timestamp: number;
}

export interface KVPutResponse {
  status: QuicBaaSStatus;
  key: string;
  version: number;
  prevKv?: KeyValue;
  timestamp: number;
}

export interface KVDeleteResponse {
  status: QuicBaaSStatus;
  key: string;
  deleted: boolean;
  prevKv?: KeyValue;
  timestamp: number;
}

// Storage Class type - from quicbaas/infrastructure-part2.d.ts
export type StorageClass = 'standard' | 'infrequent_access' | 'archive' | 'deep_archive';
export type VersioningStatus = 'disabled' | 'enabled' | 'suspended';

// Bucket Config - from quicbaas/infrastructure-part2.d.ts
export interface BucketConfig {
  defaultStorageClass?: StorageClass;
  versioning?: VersioningStatus;
  objectLockEnabled?: boolean;
  encryptionEnabled?: boolean;
  kmsKeyId?: string;
}

// Object Storage Types - from quicbaas/infrastructure-part2.d.ts
export interface StorageBucket {
  name: string;
  region?: string;
  config: BucketConfig;
  objectCount: number;
  totalSizeBytes: number;
  createdAt: string; // ISO 8601
  updatedAt: string; // ISO 8601
}

export interface ObjectMetadata {
  contentType?: string;
  contentEncoding?: string;
  contentLanguage?: string;
  cacheControl?: string;
  contentDisposition?: string;
  custom?: Record<string, string>;
}

export interface StoredObject {
  key: string;
  bucket: string;
  size: number;
  etag: string;
  contentType?: string;
  storageClass: StorageClass;
  metadata?: ObjectMetadata;
  versionId?: string;
  lastModified: string; // ISO 8601
  expiresAt?: string;
}

export interface ListBucketsResponse {
  buckets: StorageBucket[];
  pagination?: {
    page: number;
    pageSize: number;
    totalItems: number;
    totalPages: number;
    nextCursor?: string;
  };
  total: number;
  timestamp: string;
}

export interface CreateBucketResponse {
  bucket: StorageBucket;
  timestamp: string;
}

export interface DeleteBucketResponse {
  status: {
    success: boolean;
    message: string;
    error?: { code: string; message: string; metadata?: Record<string, string> };
  };
  timestamp: string;
}

export interface ListObjectsResponse {
  objects: StoredObject[];
  commonPrefixes?: string[];
  pagination?: {
    page: number;
    pageSize: number;
    totalItems: number;
    totalPages: number;
    nextCursor?: string;
  };
  isTruncated: boolean;
  nextContinuationToken?: string;
  timestamp: string;
}

export interface PutObjectResponse {
  key: string;
  bucket: string;
  etag: string;
  versionId?: string;
  timestamp: string;
}

export interface DeleteObjectResponse {
  status: {
    success: boolean;
    message: string;
    error?: { code: string; message: string; metadata?: Record<string, string> };
  };
  versionId?: string;
  deleteMarker?: boolean;
  timestamp: string;
}

export interface GetObjectResponse {
  object: StoredObject;
  content: string; // base64 encoded
  contentRange?: string;
  timestamp: string;
}

// Vector Types - from quicbaas/ai-ml.d.ts
export type DistanceMetric = 'COSINE' | 'EUCLIDEAN' | 'DOT_PRODUCT' | 'MANHATTAN';

export interface AIMLStatus {
  success: boolean;
  message: string;
  error?: {
    code: string;
    message: string;
    metadata?: Record<string, string>;
  };
}

export interface VectorNamespace {
  name: string;
  vectorCount: number;
  dimension: number;
  metric: DistanceMetric;
  createdAt: number; // unix epoch
  updatedAt: number; // unix epoch
}

export interface VectorSearchResult {
  id: string;
  score: number;
  values?: number[];
  metadata?: Record<string, unknown>;
}

export interface ListNamespacesResponse {
  status: AIMLStatus;
  namespaces: VectorNamespace[];
  nextCursor?: string;
  hasMore: boolean;
  totalCount: number;
  timestamp: number;
}

export interface CreateNamespaceResponse {
  status: AIMLStatus;
  namespace: VectorNamespace;
  timestamp: number;
}

export interface DeleteNamespaceResponse {
  status: AIMLStatus;
  name: string;
  timestamp: number;
}

export interface VectorSearchResponse {
  status: AIMLStatus;
  results: VectorSearchResult[];
  queryTimeMs: number;
  timestamp: number;
}

// Time Series Types - from quicbaas/core-data.d.ts
export interface TimeSeriesDataPoint {
  timestamp: number; // unix epoch ms
  value: number;
  tags?: Record<string, string>;
}

export interface TimeSeriesQueryResponse {
  status: QuicBaaSStatus;
  metric: string;
  dataPoints: TimeSeriesDataPoint[];
  hasMore: boolean;
  timestamp: number;
}

export interface AggregationResult {
  bucketStart: number;
  bucketEnd: number;
  values: Record<string, number | null>;
  groupTags?: Record<string, string>;
}

export interface TimeSeriesAggregateResponse {
  status: QuicBaaSStatus;
  metric: string;
  results: AggregationResult[];
  executionTimeMs: number;
  timestamp: number;
}

export interface TimeSeriesDeleteRangeResponse {
  status: QuicBaaSStatus;
  metric: string;
  deletedCount: number;
  timestamp: number;
}

// Backup Types - from quicbaas/core-data.d.ts
export type BackupState = 'UNSPECIFIED' | 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type BackupType = 'UNSPECIFIED' | 'FULL' | 'INCREMENTAL' | 'DIFFERENTIAL';

export interface BackupMetadata {
  backupId: string;
  name: string;
  type: BackupType;
  state: BackupState;
  sizeBytes: number;
  keyCount: number;
  startedAt: number; // unix epoch ms
  completedAt?: number; // unix epoch ms
  baseBackupId?: string;
  location: string;
  checksum?: string;
  tags?: Record<string, string>;
  error?: string;
}

export interface ListBackupsResponse {
  status: QuicBaaSStatus;
  backups: BackupMetadata[];
  nextCursor?: string;
  hasMore: boolean;
  timestamp: number;
}

export interface CreateBackupResponse {
  status: QuicBaaSStatus;
  backup: BackupMetadata;
  timestamp: number;
}

export interface DeleteBackupResponse {
  status: QuicBaaSStatus;
  backupId: string;
  timestamp: number;
}

export interface RestoreBackupResponse {
  status: QuicBaaSStatus;
  restoreId: string;
  backupId: string;
  progress: {
    state: BackupState;
    totalKeys: number;
    restoredKeys: number;
    percentComplete: number;
    estimatedTimeRemaining?: number;
  };
  timestamp: number;
}

// ============================================================================
// Mock Data Generators - Aligned with SDK types
// ============================================================================

let idCounter = 1;

// KV Mock Data
export function createMockKVEntry(overrides: Partial<KeyValue> = {}): KeyValue {
  const id = idCounter++;
  const now = Date.now();
  return {
    key: `namespace/key-${id}`,
    value: btoa(`value-${id}`), // Base64 encoded
    version: 1,
    createdAt: now,
    modifiedAt: now,
    ...overrides,
  };
}

// Object Storage Mock Data
export function createMockBucket(overrides: Partial<StorageBucket> = {}): StorageBucket {
  const id = idCounter++;
  const now = new Date().toISOString();
  return {
    name: `bucket-${id}`,
    region: 'us-east-1',
    objectCount: Math.floor(Math.random() * 100),
    totalSizeBytes: Math.floor(Math.random() * 1024 * 1024 * 100),
    config: {
      versioning: 'enabled',
      encryptionEnabled: true,
      defaultStorageClass: 'standard',
    },
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

export function createMockObject(bucket: string, overrides: Partial<StoredObject> = {}): StoredObject {
  const id = idCounter++;
  return {
    bucket,
    key: `path/to/file-${id}.txt`,
    size: Math.floor(Math.random() * 1024 * 1024),
    contentType: 'text/plain',
    storageClass: 'standard',
    lastModified: new Date().toISOString(),
    etag: `"etag-${id}"`,
    ...overrides,
  };
}

// Vector Mock Data
export function createMockVectorNamespace(overrides: Partial<VectorNamespace> = {}): VectorNamespace {
  const id = idCounter++;
  const now = Math.floor(Date.now() / 1000);
  return {
    name: `embeddings-${id}`,
    dimension: 384,
    metric: 'COSINE',
    vectorCount: Math.floor(Math.random() * 10000),
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

// Backup Mock Data
export function createMockBackup(overrides: Partial<BackupMetadata> = {}): BackupMetadata {
  const id = idCounter++;
  const now = Date.now();
  return {
    backupId: `backup-${id}`,
    name: `Backup-${id}`,
    type: 'FULL',
    state: 'COMPLETED',
    location: `s3://backups/backup-${id}`,
    sizeBytes: Math.floor(Math.random() * 1024 * 1024 * 1024),
    keyCount: Math.floor(Math.random() * 100000),
    startedAt: now - 3600000,
    completedAt: now,
    ...overrides,
  };
}

// ============================================================================
// API Mock Functions - Aligned with SDK response types
// ============================================================================

export interface KVApiMockConfig {
  initialEntries?: KeyValue[];
  fetchError?: ApiError | null;
  putError?: ApiError | null;
  deleteError?: ApiError | null;
}

export async function mockKVApi(
  page: Page,
  config: KVApiMockConfig = {}
): Promise<{
  getEntries: () => KeyValue[];
  addEntry: (entry: KeyValue) => void;
  clearEntries: () => void;
  setError: (endpoint: 'fetch' | 'put' | 'delete', error: ApiError | null) => void;
}> {
  const state = {
    entries: config.initialEntries || [],
    config: {
      fetchError: config.fetchError || null,
      putError: config.putError || null,
      deleteError: config.deleteError || null,
    },
  };

  // QuicBaaS KV API routes - matches /api/v1/quicbaas/kv endpoints
  await page.route('**/api/v1/quicbaas/kv', async (route: Route, request: Request) => {
    // Handle GET (list) requests
    if (request.method() === 'GET') {
      if (state.config.fetchError) {
        await route.fulfill({
          status: state.config.fetchError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.fetchError.error, error: { code: state.config.fetchError.errorCode || 'HTTP_' + state.config.fetchError.status, message: state.config.fetchError.error } },
            kvs: [],
            hasMore: false,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      const response: KVListResponse = {
        status: { success: true, message: 'OK' },
        kvs: state.entries,
        hasMore: false,
        totalCount: state.entries.length,
        timestamp: Date.now(),
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }
    // Handle POST (put) requests
    if (request.method() === 'POST') {
      if (state.config.putError) {
        await route.fulfill({
          status: state.config.putError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.putError.error, error: { code: state.config.putError.errorCode || 'HTTP_' + state.config.putError.status, message: state.config.putError.error } },
            key: '',
            version: 0,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const now = Date.now();
        const existingIndex = state.entries.findIndex((e) => e.key === body.key);
        let newVersion = 1;
        if (existingIndex !== -1) {
          newVersion = state.entries[existingIndex].version + 1;
          state.entries[existingIndex] = {
            ...state.entries[existingIndex],
            value: body.value,
            modifiedAt: now,
            version: newVersion,
            expiresAt: body.ttl ? now + body.ttl * 1000 : undefined,
          };
        } else {
          const newEntry: KeyValue = {
            key: body.key,
            value: body.value,
            version: 1,
            createdAt: now,
            modifiedAt: now,
            expiresAt: body.ttl ? now + body.ttl * 1000 : undefined,
            metadata: body.metadata,
          };
          state.entries.unshift(newEntry);
        }
        const response: KVPutResponse = {
          status: { success: true, message: 'OK' },
          key: body.key,
          version: newVersion,
          timestamp: now,
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({
          status: 400,
          body: JSON.stringify({
            status: { success: false, message: 'Invalid request', error: { code: 'HTTP_400', message: 'Invalid request' } },
            key: '',
            version: 0,
            timestamp: Date.now(),
          }),
        });
      }
      return;
    }
    await route.continue();
  });

  // Handle DELETE requests - /api/v1/quicbaas/kv/{key}
  await page.route('**/api/v1/quicbaas/kv/**', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'DELETE') {
      if (state.config.deleteError) {
        await route.fulfill({
          status: state.config.deleteError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.deleteError.error, error: { code: state.config.deleteError.errorCode || 'HTTP_' + state.config.deleteError.status, message: state.config.deleteError.error } },
            key: '',
            deleted: false,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      try {
        // Extract key from URL path (everything after /kv/)
        const url = new URL(request.url());
        const pathParts = url.pathname.split('/api/v1/quicbaas/kv/');
        const key = pathParts[1] ? decodeURIComponent(pathParts[1]) : '';
        const index = state.entries.findIndex((e) => e.key === key);
        let deleted = false;
        if (index !== -1) {
          state.entries.splice(index, 1);
          deleted = true;
        }
        const response: KVDeleteResponse = {
          status: { success: true, message: 'OK' },
          key,
          deleted,
          timestamp: Date.now(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({
          status: 400,
          body: JSON.stringify({
            status: { success: false, message: 'Invalid request', error: { code: 'HTTP_400', message: 'Invalid request' } },
            key: '',
            deleted: false,
            timestamp: Date.now(),
          }),
        });
      }
    } else {
      await route.continue();
    }
  });

  return {
    getEntries: () => [...state.entries],
    addEntry: (entry: KeyValue) => state.entries.unshift(entry),
    clearEntries: () => { state.entries = []; },
    setError: (endpoint, error) => {
      if (endpoint === 'fetch') state.config.fetchError = error;
      else if (endpoint === 'put') state.config.putError = error;
      else if (endpoint === 'delete') state.config.deleteError = error;
    },
  };
}

export interface ObjectStorageApiMockConfig {
  initialBuckets?: StorageBucket[];
  initialObjects?: Record<string, StoredObject[]>;
  listBucketsError?: ApiError | null;
  listObjectsError?: ApiError | null;
  createBucketError?: ApiError | null;
  deleteBucketError?: ApiError | null;
  putObjectError?: ApiError | null;
  deleteObjectError?: ApiError | null;
}

export async function mockObjectStorageApi(
  page: Page,
  config: ObjectStorageApiMockConfig = {}
): Promise<{
  getBuckets: () => StorageBucket[];
  getObjects: (bucket: string) => StoredObject[];
  addBucket: (bucket: StorageBucket) => void;
  addObject: (bucket: string, object: StoredObject) => void;
}> {
  const state = {
    buckets: config.initialBuckets || [],
    objects: config.initialObjects || {},
    config: {
      listBucketsError: config.listBucketsError || null,
      listObjectsError: config.listObjectsError || null,
      createBucketError: config.createBucketError || null,
      deleteBucketError: config.deleteBucketError || null,
      putObjectError: config.putObjectError || null,
      deleteObjectError: config.deleteObjectError || null,
    },
  };

  // List buckets - GET /api/v1/quicbaas/storage/buckets
  await page.route('**/api/v1/quicbaas/storage/buckets', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'GET') {
      if (state.config.listBucketsError) {
        await route.fulfill({
          status: state.config.listBucketsError.status,
          contentType: 'application/json',
          body: JSON.stringify({ message: state.config.listBucketsError.error, code: state.config.listBucketsError.errorCode || 'HTTP_' + state.config.listBucketsError.status }),
        });
        return;
      }
      const response: ListBucketsResponse = {
        buckets: state.buckets,
        total: state.buckets.length,
        timestamp: new Date().toISOString(),
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }
    // Create bucket - POST /api/v1/quicbaas/storage/buckets
    if (request.method() === 'POST') {
      if (state.config.createBucketError) {
        await route.fulfill({
          status: state.config.createBucketError.status,
          contentType: 'application/json',
          body: JSON.stringify({ message: state.config.createBucketError.error, code: state.config.createBucketError.errorCode || 'HTTP_' + state.config.createBucketError.status }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const newBucket = createMockBucket({ name: body.name, region: body.region, config: body.config });
        state.buckets.push(newBucket);
        state.objects[body.name] = [];
        const response: CreateBucketResponse = {
          bucket: newBucket,
          timestamp: new Date().toISOString(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });

  // Delete bucket - DELETE /api/v1/quicbaas/storage/buckets/{name}
  await page.route('**/api/v1/quicbaas/storage/buckets/*', async (route: Route) => {
    const request = route.request();
    const url = request.url();

    // Skip if this is the objects endpoint
    if (url.includes('/objects')) {
      await route.continue();
      return;
    }

    if (request.method() === 'DELETE') {
      if (state.config.deleteBucketError) {
        await route.fulfill({
          status: state.config.deleteBucketError.status,
          contentType: 'application/json',
          body: JSON.stringify({ message: state.config.deleteBucketError.error, code: state.config.deleteBucketError.errorCode || 'HTTP_' + state.config.deleteBucketError.status }),
        });
        return;
      }
      const match = url.match(/\/buckets\/([^/?]+)$/);
      const bucketName = match ? match[1] : null;
      if (bucketName) {
        const index = state.buckets.findIndex((b) => b.name === bucketName);
        if (index !== -1) {
          state.buckets.splice(index, 1);
          delete state.objects[bucketName];
        }
      }
      const response: DeleteBucketResponse = {
        status: { success: true, message: 'Bucket deleted' },
        timestamp: new Date().toISOString(),
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }
    await route.continue();
  });

  // List objects - GET /api/v1/quicbaas/storage/buckets/{bucket}/objects
  await page.route('**/api/v1/quicbaas/storage/buckets/*/objects', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'GET') {
      if (state.config.listObjectsError) {
        await route.fulfill({
          status: state.config.listObjectsError.status,
          contentType: 'application/json',
          body: JSON.stringify({ message: state.config.listObjectsError.error, code: state.config.listObjectsError.errorCode || 'HTTP_' + state.config.listObjectsError.status }),
        });
        return;
      }
      const url = request.url();
      const match = url.match(/\/buckets\/([^/]+)\/objects/);
      const bucketName = match ? match[1] : '';
      const bucketObjects = state.objects[bucketName] || [];
      const response: ListObjectsResponse = {
        objects: bucketObjects,
        isTruncated: false,
        timestamp: new Date().toISOString(),
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }
    // Put object - POST /api/v1/quicbaas/storage/buckets/{bucket}/objects
    if (request.method() === 'POST') {
      if (state.config.putObjectError) {
        await route.fulfill({
          status: state.config.putObjectError.status,
          contentType: 'application/json',
          body: JSON.stringify({ message: state.config.putObjectError.error, code: state.config.putObjectError.errorCode || 'HTTP_' + state.config.putObjectError.status }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const url = request.url();
        const match = url.match(/\/buckets\/([^/]+)\/objects/);
        const bucketName = match ? match[1] : body.bucket;
        const newObject = createMockObject(bucketName, {
          key: body.key,
          contentType: body.contentType,
          storageClass: body.storageClass || 'standard',
        });
        if (!state.objects[bucketName]) {
          state.objects[bucketName] = [];
        }
        state.objects[bucketName].push(newObject);
        const response: PutObjectResponse = {
          key: newObject.key,
          bucket: bucketName,
          etag: newObject.etag,
          timestamp: new Date().toISOString(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });

  // Get object (for download) - GET /api/v1/quicbaas/storage/buckets/{bucket}/objects/{key}
  await page.route('**/api/v1/quicbaas/storage/buckets/*/objects/**', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'GET') {
      const url = request.url();
      const match = url.match(/\/buckets\/([^/]+)\/objects\/(.+)/);
      if (match) {
        const bucketName = match[1];
        const objectKey = decodeURIComponent(match[2]);
        const bucketObjects = state.objects[bucketName] || [];
        const obj = bucketObjects.find((o) => o.key === objectKey);
        if (obj) {
          const response: GetObjectResponse = {
            object: obj,
            content: btoa('file content'),
            timestamp: new Date().toISOString(),
          };
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(response),
          });
          return;
        }
        await route.fulfill({ status: 404, body: JSON.stringify({ message: 'Object not found', code: 'HTTP_404' }) });
        return;
      }
    }
    await route.continue();
  });

  // Delete object - DELETE /api/v1/quicbaas/storage/buckets/{bucket}/objects/{key}
  await page.route('**/api/v1/quicbaas/storage/object/delete', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'POST') {
      if (state.config.deleteObjectError) {
        await route.fulfill({
          status: state.config.deleteObjectError.status,
          contentType: 'application/json',
          body: JSON.stringify({ message: state.config.deleteObjectError.error, code: state.config.deleteObjectError.errorCode || 'HTTP_' + state.config.deleteObjectError.status }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const bucketObjects = state.objects[body.bucket] || [];
        const index = bucketObjects.findIndex((o) => o.key === body.key);
        if (index !== -1) {
          bucketObjects.splice(index, 1);
        }
        const response: DeleteObjectResponse = {
          status: { success: true, message: 'Object deleted' },
          timestamp: new Date().toISOString(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });

  return {
    getBuckets: () => [...state.buckets],
    getObjects: (bucket: string) => [...(state.objects[bucket] || [])],
    addBucket: (bucket: StorageBucket) => {
      state.buckets.push(bucket);
      if (!state.objects[bucket.name]) {
        state.objects[bucket.name] = [];
      }
    },
    addObject: (bucket: string, object: StoredObject) => {
      if (!state.objects[bucket]) {
        state.objects[bucket] = [];
      }
      state.objects[bucket].push(object);
    },
  };
}

export interface VectorApiMockConfig {
  initialNamespaces?: VectorNamespace[];
  fetchError?: ApiError | null;
  createError?: ApiError | null;
  deleteError?: ApiError | null;
  searchError?: ApiError | null;
}

export async function mockVectorApi(
  page: Page,
  config: VectorApiMockConfig = {}
): Promise<{
  getNamespaces: () => VectorNamespace[];
  addNamespace: (ns: VectorNamespace) => void;
}> {
  const state = {
    namespaces: config.initialNamespaces || [],
    config: {
      fetchError: config.fetchError || null,
      createError: config.createError || null,
      deleteError: config.deleteError || null,
      searchError: config.searchError || null,
    },
  };

  // List namespaces - GET /api/v1/quicbaas/vector/namespaces
  await page.route('**/api/v1/quicbaas/vector/namespaces', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'GET') {
      if (state.config.fetchError) {
        await route.fulfill({
          status: state.config.fetchError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.fetchError.error, error: { code: state.config.fetchError.errorCode || 'HTTP_' + state.config.fetchError.status, message: state.config.fetchError.error } },
            namespaces: [],
            hasMore: false,
            totalCount: 0,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      const response: ListNamespacesResponse = {
        status: { success: true, message: 'OK' },
        namespaces: state.namespaces,
        hasMore: false,
        totalCount: state.namespaces.length,
        timestamp: Date.now(),
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }
    await route.continue();
  });

  // Create namespace - POST /api/v1/quicbaas/vector/namespace
  await page.route('**/api/v1/quicbaas/vector/namespace', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'POST') {
      if (state.config.createError) {
        await route.fulfill({
          status: state.config.createError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.createError.error, error: { code: state.config.createError.errorCode || 'HTTP_' + state.config.createError.status, message: state.config.createError.error } },
            namespace: null,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const newNs = createMockVectorNamespace({
          name: body.name,
          dimension: body.dimension,
          metric: body.metric || 'COSINE',
          vectorCount: 0,
        });
        state.namespaces.push(newNs);
        const response: CreateNamespaceResponse = {
          status: { success: true, message: 'OK' },
          namespace: newNs,
          timestamp: Date.now(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });

  // Delete namespace - POST /api/v1/quicbaas/vector/namespace/delete
  await page.route('**/api/v1/quicbaas/vector/namespace/delete', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'POST') {
      if (state.config.deleteError) {
        await route.fulfill({
          status: state.config.deleteError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.deleteError.error, error: { code: state.config.deleteError.errorCode || 'HTTP_' + state.config.deleteError.status, message: state.config.deleteError.error } },
            name: '',
            timestamp: Date.now(),
          }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const index = state.namespaces.findIndex((ns) => ns.name === body.name);
        if (index !== -1) {
          state.namespaces.splice(index, 1);
        }
        const response: DeleteNamespaceResponse = {
          status: { success: true, message: 'OK' },
          name: body.name,
          timestamp: Date.now(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });

  // Search - POST /api/v1/quicbaas/vector/search
  await page.route('**/api/v1/quicbaas/vector/search', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'POST') {
      if (state.config.searchError) {
        await route.fulfill({
          status: state.config.searchError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.searchError.error, error: { code: state.config.searchError.errorCode || 'HTTP_' + state.config.searchError.status, message: state.config.searchError.error } },
            results: [],
            queryTimeMs: 0,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const topK = body.topK || 10;
        const results: VectorSearchResult[] = Array.from({ length: Math.min(topK, 5) }, (_, i) => ({
          id: `result-${i + 1}`,
          score: 1 - (i * 0.1),
          metadata: { label: `Item ${i + 1}` },
        }));
        const response: VectorSearchResponse = {
          status: { success: true, message: 'OK' },
          results,
          queryTimeMs: 15,
          timestamp: Date.now(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });

  return {
    getNamespaces: () => [...state.namespaces],
    addNamespace: (ns: VectorNamespace) => state.namespaces.push(ns),
  };
}

export interface TimeSeriesApiMockConfig {
  queryError?: ApiError | null;
  aggregateError?: ApiError | null;
  deleteError?: ApiError | null;
}

export async function mockTimeSeriesApi(
  page: Page,
  config: TimeSeriesApiMockConfig = {}
): Promise<void> {
  // Query time series - POST /api/v1/quicbaas/timeseries/query
  await page.route('**/api/v1/quicbaas/timeseries/query', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'POST') {
      if (config.queryError) {
        await route.fulfill({
          status: config.queryError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: config.queryError.error, error: { code: config.queryError.errorCode || 'HTTP_' + config.queryError.status, message: config.queryError.error } },
            metric: '',
            dataPoints: [],
            hasMore: false,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        // Generate sample data points
        const dataPoints: TimeSeriesDataPoint[] = Array.from({ length: 24 }, (_, i) => ({
          timestamp: Date.now() - (23 - i) * 3600000,
          value: Math.random() * 100,
        }));
        const response: TimeSeriesQueryResponse = {
          status: { success: true, message: 'OK' },
          metric: body.metric || 'cpu.usage',
          dataPoints,
          hasMore: false,
          timestamp: Date.now(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });

  // Aggregate time series - POST /api/v1/quicbaas/timeseries/aggregate
  await page.route('**/api/v1/quicbaas/timeseries/aggregate', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'POST') {
      if (config.aggregateError) {
        await route.fulfill({
          status: config.aggregateError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: config.aggregateError.error, error: { code: config.aggregateError.errorCode || 'HTTP_' + config.aggregateError.status, message: config.aggregateError.error } },
            metric: '',
            results: [],
            executionTimeMs: 0,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const results: AggregationResult[] = Array.from({ length: 24 }, (_, i) => ({
          bucketStart: Date.now() - (23 - i) * 3600000,
          bucketEnd: Date.now() - (22 - i) * 3600000,
          values: { AVG: Math.random() * 100 },
        }));
        const response: TimeSeriesAggregateResponse = {
          status: { success: true, message: 'OK' },
          metric: body.metric || 'cpu.usage',
          results,
          executionTimeMs: 15,
          timestamp: Date.now(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });

  // Delete range - POST /api/v1/quicbaas/timeseries/delete
  await page.route('**/api/v1/quicbaas/timeseries/delete', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'POST') {
      if (config.deleteError) {
        await route.fulfill({
          status: config.deleteError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: config.deleteError.error, error: { code: config.deleteError.errorCode || 'HTTP_' + config.deleteError.status, message: config.deleteError.error } },
            metric: '',
            deletedCount: 0,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const response: TimeSeriesDeleteRangeResponse = {
          status: { success: true, message: 'OK' },
          metric: body.metric || 'cpu.usage',
          deletedCount: 1000,
          timestamp: Date.now(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });
}

export interface BackupApiMockConfig {
  initialBackups?: BackupMetadata[];
  listError?: ApiError | null;
  createError?: ApiError | null;
  deleteError?: ApiError | null;
  restoreError?: ApiError | null;
}

export async function mockBackupApi(
  page: Page,
  config: BackupApiMockConfig = {}
): Promise<{
  getBackups: () => BackupMetadata[];
  addBackup: (backup: BackupMetadata) => void;
}> {
  const state = {
    backups: config.initialBackups || [],
    config: {
      listError: config.listError || null,
      createError: config.createError || null,
      deleteError: config.deleteError || null,
      restoreError: config.restoreError || null,
    },
  };

  // List backups - GET /api/v1/quicbaas/backups
  await page.route('**/api/v1/quicbaas/backups', async (route: Route) => {
    const request = route.request();
    if (request.method() === 'GET') {
      if (state.config.listError) {
        await route.fulfill({
          status: state.config.listError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.listError.error, error: { code: state.config.listError.errorCode || 'HTTP_' + state.config.listError.status, message: state.config.listError.error } },
            backups: [],
            hasMore: false,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      const response: ListBackupsResponse = {
        status: { success: true, message: 'OK' },
        backups: state.backups,
        hasMore: false,
        timestamp: Date.now(),
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }
    // Create backup - POST /api/v1/quicbaas/backups
    if (request.method() === 'POST') {
      if (state.config.createError) {
        await route.fulfill({
          status: state.config.createError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.createError.error, error: { code: state.config.createError.errorCode || 'HTTP_' + state.config.createError.status, message: state.config.createError.error } },
            backup: null,
            timestamp: Date.now(),
          }),
        });
        return;
      }
      try {
        const body = request.postDataJSON();
        const newBackup = createMockBackup({
          name: body.name,
          type: body.type || 'FULL',
          location: body.location,
          state: 'PENDING',
        });
        state.backups.unshift(newBackup);
        const response: CreateBackupResponse = {
          status: { success: true, message: 'OK' },
          backup: newBackup,
          timestamp: Date.now(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
      } catch {
        await route.fulfill({ status: 400, body: JSON.stringify({ message: 'Invalid request', code: 'HTTP_400' }) });
      }
      return;
    }
    await route.continue();
  });

  // Delete backup - DELETE /api/v1/quicbaas/backups/{backupId}
  await page.route('**/api/v1/quicbaas/backups/*', async (route: Route) => {
    const request = route.request();
    const url = request.url();

    // Handle restore endpoint separately
    if (url.includes('/restore')) {
      if (request.method() === 'POST') {
        if (state.config.restoreError) {
          await route.fulfill({
            status: state.config.restoreError.status,
            contentType: 'application/json',
            body: JSON.stringify({
              status: { success: false, message: state.config.restoreError.error, error: { code: state.config.restoreError.errorCode || 'HTTP_' + state.config.restoreError.status, message: state.config.restoreError.error } },
              restoreId: '',
              backupId: '',
              progress: { state: 'FAILED', totalKeys: 0, restoredKeys: 0, percentComplete: 0 },
              timestamp: Date.now(),
            }),
          });
          return;
        }
        const match = url.match(/\/backups\/([^/]+)\/restore/);
        const backupId = match ? match[1] : '';
        const response: RestoreBackupResponse = {
          status: { success: true, message: 'OK' },
          restoreId: `restore-${Date.now()}`,
          backupId,
          progress: {
            state: 'IN_PROGRESS',
            totalKeys: 50000,
            restoredKeys: 0,
            percentComplete: 0,
          },
          timestamp: Date.now(),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(response),
        });
        return;
      }
      await route.continue();
      return;
    }

    if (request.method() === 'DELETE') {
      if (state.config.deleteError) {
        await route.fulfill({
          status: state.config.deleteError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: false, message: state.config.deleteError.error, error: { code: state.config.deleteError.errorCode || 'HTTP_' + state.config.deleteError.status, message: state.config.deleteError.error } },
            backupId: '',
            timestamp: Date.now(),
          }),
        });
        return;
      }
      const match = url.match(/\/backups\/([^/?]+)$/);
      const backupId = match ? match[1] : null;
      if (backupId) {
        const index = state.backups.findIndex((b) => b.backupId === backupId);
        if (index !== -1) {
          state.backups.splice(index, 1);
        }
      }
      const response: DeleteBackupResponse = {
        status: { success: true, message: 'OK' },
        backupId: backupId || '',
        timestamp: Date.now(),
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }
    await route.continue();
  });

  return {
    getBackups: () => [...state.backups],
    addBackup: (backup: BackupMetadata) => state.backups.unshift(backup),
  };
}

// ============================================================================
// Test Suites
// ============================================================================

// SKIPPED: Storage pages not yet implemented in the UI
// These tests are ready to be enabled once the storage UI components are built
test.describe.skip('Storage - Key-Value Store', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test.describe('KV List', () => {
    test('should display KV entries table', async ({ page }) => {
      const entries = [
        createMockKVEntry({ key: 'config/app-settings' }),
        createMockKVEntry({ key: 'cache/user-123' }),
      ];

      await mockKVApi(page, { initialEntries: entries });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      await expect(page.getByRole('heading', { name: /key-value store/i })).toBeVisible();
      await expect(page.getByText('config/app-settings')).toBeVisible();
      await expect(page.getByText('cache/user-123')).toBeVisible();
    });

    test('should display empty state when no entries', async ({ page }) => {
      await mockKVApi(page, { initialEntries: [] });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      await expect(page.getByText(/no entries found/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /add your first entry/i })).toBeVisible();
    });

    test('should filter entries by prefix', async ({ page }) => {
      const entries = [
        createMockKVEntry({ key: 'config/setting-1' }),
        createMockKVEntry({ key: 'cache/user-1' }),
        createMockKVEntry({ key: 'config/setting-2' }),
      ];

      await mockKVApi(page, { initialEntries: entries });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      // Wait for entries to load
      await expect(page.getByText('config/setting-1')).toBeVisible();

      // Enter prefix filter
      await page.fill('input[placeholder*="prefix"]', 'config/');

      // Should trigger API call with prefix filter
      await expect(page.getByText('config/setting-1')).toBeVisible();
    });

    test('should show loading state', async ({ page }) => {
      await page.route('**/api/v1/quicbaas/kv', async (route) => {
        await new Promise((resolve) => setTimeout(resolve, 500));
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            status: { success: true, message: 'OK' },
            kvs: [],
            hasMore: false,
            timestamp: Date.now(),
          }),
        });
      });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      // Table should show loading state
      await expect(page.locator('.animate-spin').first()).toBeVisible();
    });
  });

  test.describe('KV CRUD Operations', () => {
    test('should open add entry dialog', async ({ page }) => {
      await mockKVApi(page, { initialEntries: [] });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      await page.getByRole('button', { name: /add entry/i }).click();

      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByRole('heading', { name: /add new entry/i })).toBeVisible();
    });

    test('should create new KV entry', async ({ page }) => {
      const mockApi = await mockKVApi(page, { initialEntries: [] });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      // Open dialog
      await page.getByRole('button', { name: /add entry/i }).click();

      // Fill form
      await page.fill('input#key', 'test/my-key');
      await page.fill('textarea#value', 'my-value');

      // Submit
      await page.getByRole('button', { name: /save entry/i }).click();

      // Should show success
      await expect(page.getByText(/entry created|saved successfully/i)).toBeVisible();

      // Verify entry was added
      const entries = mockApi.getEntries();
      expect(entries.length).toBe(1);
    });

    test('should validate key is required', async ({ page }) => {
      await mockKVApi(page, { initialEntries: [] });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      // Open dialog
      await page.getByRole('button', { name: /add entry/i }).click();

      // Try to submit without key
      await page.getByRole('button', { name: /save entry/i }).click();

      // Should show validation error
      await expect(page.getByText(/key is required/i)).toBeVisible();
    });

    test('should edit existing entry', async ({ page }) => {
      const entries = [createMockKVEntry({ key: 'test/edit-me' })];

      await mockKVApi(page, { initialEntries: entries });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      // Open actions menu
      await page.locator('button').filter({ hasText: /more/i }).first().click();

      // Click edit
      await page.getByRole('menuitem', { name: /edit/i }).click();

      // Dialog should show edit mode
      await expect(page.getByRole('heading', { name: /edit entry/i })).toBeVisible();

      // Key should be disabled in edit mode
      await expect(page.locator('input#key')).toBeDisabled();
    });

    test('should delete entry with confirmation', async ({ page }) => {
      const entries = [createMockKVEntry({ key: 'test/delete-me' })];

      const mockApi = await mockKVApi(page, { initialEntries: entries });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      // Set up dialog handler
      page.on('dialog', (dialog) => dialog.accept());

      // Open actions menu
      await page.locator('button').filter({ hasText: /more/i }).first().click();

      // Click delete
      await page.getByRole('menuitem', { name: /delete/i }).click();

      // Should show success
      await expect(page.getByText(/deleted successfully/i)).toBeVisible();

      // Verify entry was removed
      const remaining = mockApi.getEntries();
      expect(remaining.length).toBe(0);
    });

    test('should set TTL on entry', async ({ page }) => {
      await mockKVApi(page, { initialEntries: [] });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      // Open dialog
      await page.getByRole('button', { name: /add entry/i }).click();

      // Fill form with TTL
      await page.fill('input#key', 'test/expiring-key');
      await page.fill('textarea#value', 'temp-value');
      await page.fill('input#ttl', '3600');

      // Submit
      await page.getByRole('button', { name: /save entry/i }).click();

      // Should show success
      await expect(page.getByText(/saved successfully/i)).toBeVisible();
    });

    test('should select value type', async ({ page }) => {
      await mockKVApi(page, { initialEntries: [] });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      // Open dialog
      await page.getByRole('button', { name: /add entry/i }).click();

      // Select JSON type
      await page.locator('[role="combobox"]').filter({ hasText: /string/i }).click();
      await page.getByRole('option', { name: /json/i }).click();

      // Placeholder should change
      await expect(page.locator('textarea#value')).toHaveAttribute('placeholder', /key.*value/i);
    });
  });

  test.describe('KV Error States', () => {
    test('should handle fetch error', async ({ page }) => {
      await mockKVApi(page, {
        fetchError: { error: 'Failed to fetch entries', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      await expect(page.getByText(/error loading entries/i)).toBeVisible();
    });

    test('should handle create error', async ({ page }) => {
      await mockKVApi(page, {
        initialEntries: [],
        putError: { error: 'Key already exists', status: 409 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      // Open dialog and submit
      await page.getByRole('button', { name: /add entry/i }).click();
      await page.fill('input#key', 'existing/key');
      await page.fill('textarea#value', 'value');
      await page.getByRole('button', { name: /save entry/i }).click();

      await expect(page.getByText(/error saving entry/i)).toBeVisible();
    });

    test('should handle delete error', async ({ page }) => {
      const entries = [createMockKVEntry({ key: 'test/protected-key' })];

      await mockKVApi(page, {
        initialEntries: entries,
        deleteError: { error: 'Cannot delete protected key', status: 403 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/kv');

      page.on('dialog', (dialog) => dialog.accept());

      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /delete/i }).click();

      await expect(page.getByText(/error deleting entry/i)).toBeVisible();
    });
  });
});

// SKIPPED: Storage pages not yet implemented in the UI
test.describe.skip('Storage - Object Storage', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test.describe('Buckets', () => {
    test('should display buckets list', async ({ page }) => {
      const buckets = [
        createMockBucket({ name: 'production-assets' }),
        createMockBucket({ name: 'backup-data' }),
      ];

      await mockObjectStorageApi(page, { initialBuckets: buckets });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      await expect(page.getByRole('heading', { name: /object storage/i })).toBeVisible();
      await expect(page.getByText('production-assets')).toBeVisible();
      await expect(page.getByText('backup-data')).toBeVisible();
    });

    test('should create new bucket', async ({ page }) => {
      const mockApi = await mockObjectStorageApi(page, { initialBuckets: [] });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      // Open create bucket dialog
      await page.getByRole('button', { name: /create bucket/i }).click();

      // Fill form
      await page.fill('input#bucketName', 'my-new-bucket');
      await page.fill('input#region', 'us-west-2');

      // Submit
      await page.getByRole('button', { name: /create bucket/i }).last().click();

      // Should show success
      await expect(page.getByText(/bucket created/i)).toBeVisible();

      // Verify bucket was added
      const buckets = mockApi.getBuckets();
      expect(buckets.length).toBe(1);
    });

    test('should validate bucket name is required', async ({ page }) => {
      await mockObjectStorageApi(page, { initialBuckets: [] });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      await page.getByRole('button', { name: /create bucket/i }).click();
      await page.getByRole('button', { name: /create bucket/i }).last().click();

      await expect(page.getByText(/bucket name is required/i)).toBeVisible();
    });

    test('should delete bucket with confirmation', async ({ page }) => {
      const buckets = [createMockBucket({ name: 'delete-me-bucket' })];

      const mockApi = await mockObjectStorageApi(page, { initialBuckets: buckets });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      page.on('dialog', (dialog) => dialog.accept());

      // Click delete button on bucket
      await page.locator('button').filter({ has: page.locator('svg.text-destructive') }).first().click();

      await expect(page.getByText(/bucket deleted/i)).toBeVisible();

      const remaining = mockApi.getBuckets();
      expect(remaining.length).toBe(0);
    });

    test('should select bucket to view objects', async ({ page }) => {
      const buckets = [
        createMockBucket({ name: 'bucket-1' }),
        createMockBucket({ name: 'bucket-2' }),
      ];

      await mockObjectStorageApi(page, { initialBuckets: buckets });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      // Click on bucket to select it
      await page.getByText('bucket-2').click();

      // Should show selected bucket in description
      await expect(page.getByText(/bucket-2/i)).toBeVisible();
    });
  });

  test.describe('Objects', () => {
    test('should display objects in selected bucket', async ({ page }) => {
      const buckets = [createMockBucket({ name: 'my-bucket' })];
      const objects: Record<string, StoredObject[]> = {
        'my-bucket': [
          createMockObject('my-bucket', { key: 'file1.txt' }),
          createMockObject('my-bucket', { key: 'folder/file2.pdf' }),
        ],
      };

      await mockObjectStorageApi(page, { initialBuckets: buckets, initialObjects: objects });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      // Wait for bucket to be auto-selected
      await expect(page.getByText('file1.txt')).toBeVisible();
      await expect(page.getByText('folder/file2.pdf')).toBeVisible();
    });

    test('should show empty state when bucket has no objects', async ({ page }) => {
      const buckets = [createMockBucket({ name: 'empty-bucket' })];

      await mockObjectStorageApi(page, { initialBuckets: buckets, initialObjects: { 'empty-bucket': [] } });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      await expect(page.getByText(/no objects found/i)).toBeVisible();
    });

    test('should open upload dialog', async ({ page }) => {
      const buckets = [createMockBucket({ name: 'upload-bucket' })];

      await mockObjectStorageApi(page, { initialBuckets: buckets });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      await page.getByRole('button', { name: /upload object/i }).click();

      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByRole('heading', { name: /upload object/i })).toBeVisible();
    });

    test('should delete object with confirmation', async ({ page }) => {
      const buckets = [createMockBucket({ name: 'my-bucket' })];
      const objects: Record<string, StoredObject[]> = {
        'my-bucket': [createMockObject('my-bucket', { key: 'delete-me.txt' })],
      };

      const mockApi = await mockObjectStorageApi(page, { initialBuckets: buckets, initialObjects: objects });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      page.on('dialog', (dialog) => dialog.accept());

      // Open actions menu
      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /delete/i }).click();

      await expect(page.getByText(/object deleted/i)).toBeVisible();

      const remaining = mockApi.getObjects('my-bucket');
      expect(remaining.length).toBe(0);
    });

    test('should download object', async ({ page }) => {
      const buckets = [createMockBucket({ name: 'my-bucket' })];
      const objects: Record<string, StoredObject[]> = {
        'my-bucket': [createMockObject('my-bucket', { key: 'download-me.txt' })],
      };

      await mockObjectStorageApi(page, { initialBuckets: buckets, initialObjects: objects });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      // Open actions menu
      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /download/i }).click();

      await expect(page.getByText(/download started/i)).toBeVisible();
    });
  });

  test.describe('Object Storage Error States', () => {
    test('should handle list buckets error', async ({ page }) => {
      await mockObjectStorageApi(page, {
        listBucketsError: { error: 'Failed to list buckets', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      await expect(page.getByText(/error loading buckets/i)).toBeVisible();
    });

    test('should handle create bucket error', async ({ page }) => {
      await mockObjectStorageApi(page, {
        initialBuckets: [],
        createBucketError: { error: 'Bucket name already exists', status: 409 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/objects');

      await page.getByRole('button', { name: /create bucket/i }).click();
      await page.fill('input#bucketName', 'existing-bucket');
      await page.getByRole('button', { name: /create bucket/i }).last().click();

      await expect(page.getByText(/error creating bucket/i)).toBeVisible();
    });
  });
});

// SKIPPED: Storage pages not yet implemented in the UI
test.describe.skip('Storage - Vector Database', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test.describe('Collections', () => {
    test('should display collections list', async ({ page }) => {
      const namespaces = [
        createMockVectorNamespace({ name: 'documents', dimension: 768, metric: 'COSINE' }),
        createMockVectorNamespace({ name: 'images', dimension: 512, metric: 'EUCLIDEAN' }),
      ];

      await mockVectorApi(page, { initialNamespaces: namespaces });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      await expect(page.getByRole('heading', { name: /vector database/i })).toBeVisible();
      await expect(page.getByText('documents')).toBeVisible();
      await expect(page.getByText('images')).toBeVisible();
    });

    test('should display empty state when no collections', async ({ page }) => {
      await mockVectorApi(page, { initialNamespaces: [] });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      await expect(page.getByText(/no collections found/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /create your first collection/i })).toBeVisible();
    });

    test('should create new collection', async ({ page }) => {
      const mockApi = await mockVectorApi(page, { initialNamespaces: [] });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      // Open dialog
      await page.getByRole('button', { name: /create collection/i }).click();

      // Fill form
      await page.fill('input#name', 'my-embeddings');

      // Select dimensions
      await page.locator('[role="combobox"]').filter({ hasText: /384/i }).click();
      await page.getByRole('option', { name: /768/i }).click();

      // Select metric
      await page.locator('[role="combobox"]').filter({ hasText: /cosine/i }).click();
      await page.getByRole('option', { name: /euclidean/i }).click();

      // Submit
      await page.getByRole('button', { name: /create collection/i }).last().click();

      await expect(page.getByText(/collection created/i)).toBeVisible();

      const namespaces = mockApi.getNamespaces();
      expect(namespaces.length).toBe(1);
    });

    test('should validate collection name is required', async ({ page }) => {
      await mockVectorApi(page, { initialNamespaces: [] });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      await page.getByRole('button', { name: /create collection/i }).click();
      await page.getByRole('button', { name: /create collection/i }).last().click();

      await expect(page.getByText(/collection name is required/i)).toBeVisible();
    });

    test('should delete collection with confirmation', async ({ page }) => {
      const namespaces = [createMockVectorNamespace({ name: 'delete-me' })];

      const mockApi = await mockVectorApi(page, { initialNamespaces: namespaces });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      page.on('dialog', (dialog) => dialog.accept());

      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /delete/i }).click();

      await expect(page.getByText(/collection deleted/i)).toBeVisible();

      const remaining = mockApi.getNamespaces();
      expect(remaining.length).toBe(0);
    });
  });

  test.describe('Vector Search', () => {
    test('should open search dialog', async ({ page }) => {
      const namespaces = [createMockVectorNamespace({ name: 'searchable' })];

      await mockVectorApi(page, { initialNamespaces: namespaces });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      await page.getByRole('button', { name: /search vectors/i }).click();

      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByRole('heading', { name: /similarity search/i })).toBeVisible();
    });

    test('should perform vector search', async ({ page }) => {
      const namespaces = [createMockVectorNamespace({ name: 'searchable' })];

      await mockVectorApi(page, { initialNamespaces: namespaces });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      // Open search from collection actions
      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /search vectors/i }).click();

      // Enter vector
      await page.fill('textarea#vector', '[0.1, 0.2, 0.3]');

      // Search
      await page.getByRole('button', { name: /^search$/i }).click();

      // Should show results
      await expect(page.getByText(/search completed/i)).toBeVisible();
      await expect(page.getByText(/results/i)).toBeVisible();
    });

    test('should validate vector format', async ({ page }) => {
      const namespaces = [createMockVectorNamespace({ name: 'searchable' })];

      await mockVectorApi(page, { initialNamespaces: namespaces });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      await page.getByRole('button', { name: /search vectors/i }).click();

      // Select collection
      await page.locator('[role="combobox"]').first().click();
      await page.getByRole('option', { name: /searchable/i }).click();

      // Enter invalid vector
      await page.fill('textarea#vector', 'not a valid vector');

      await page.getByRole('button', { name: /^search$/i }).click();

      await expect(page.getByText(/vector must be a valid json array/i)).toBeVisible();
    });
  });

  test.describe('Vector Database Error States', () => {
    test('should handle fetch error', async ({ page }) => {
      await mockVectorApi(page, {
        fetchError: { error: 'Failed to fetch collections', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      await expect(page.getByText(/error loading collections/i)).toBeVisible();
    });

    test('should handle create error', async ({ page }) => {
      await mockVectorApi(page, {
        initialNamespaces: [],
        createError: { error: 'Collection already exists', status: 409 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/vector');

      await page.getByRole('button', { name: /create collection/i }).click();
      await page.fill('input#name', 'existing-collection');
      await page.getByRole('button', { name: /create collection/i }).last().click();

      await expect(page.getByText(/error creating collection/i)).toBeVisible();
    });
  });
});

// SKIPPED: Storage pages not yet implemented in the UI
test.describe.skip('Storage - Time Series', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test.describe('Metrics List', () => {
    test('should display sample metrics', async ({ page }) => {
      await mockTimeSeriesApi(page);
      await mockTenantApi(page);

      await page.goto('/storage/timeseries');

      await expect(page.getByRole('heading', { name: /time series database/i })).toBeVisible();
      // Should show sample metrics
      await expect(page.getByText('cpu.usage')).toBeVisible();
      await expect(page.getByText('memory.used')).toBeVisible();
    });

    test('should display metric type badges', async ({ page }) => {
      await mockTimeSeriesApi(page);
      await mockTenantApi(page);

      await page.goto('/storage/timeseries');

      await expect(page.getByText('gauge').first()).toBeVisible();
      await expect(page.getByText('counter').first()).toBeVisible();
    });

    test('should display statistics cards', async ({ page }) => {
      await mockTimeSeriesApi(page);
      await mockTenantApi(page);

      await page.goto('/storage/timeseries');

      await expect(page.getByText('Total Metrics')).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Counters' })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Gauges' })).toBeVisible();
    });
  });

  test.describe('Time Series Query', () => {
    test('should open query dialog', async ({ page }) => {
      await mockTimeSeriesApi(page);
      await mockTenantApi(page);

      await page.goto('/storage/timeseries');

      await page.getByRole('button', { name: /query data/i }).click();

      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByRole('heading', { name: /query time series data/i })).toBeVisible();
    });

    test('should query with time range', async ({ page }) => {
      await mockTimeSeriesApi(page);
      await mockTenantApi(page);

      await page.goto('/storage/timeseries');

      await page.getByRole('button', { name: /query data/i }).click();

      // Fill metric name
      await page.fill('input#queryMetric', 'cpu.usage');

      // Run query
      await page.getByRole('button', { name: /run query/i }).click();

      // Should show results
      await expect(page.getByText(/completed/i)).toBeVisible();
    });

    test('should select aggregation function', async ({ page }) => {
      await mockTimeSeriesApi(page);
      await mockTenantApi(page);

      await page.goto('/storage/timeseries');

      await page.getByRole('button', { name: /query data/i }).click();

      // Select aggregation
      await page.locator('[role="combobox"]').filter({ hasText: /average/i }).click();
      await page.getByRole('option', { name: /sum/i }).click();

      // Select time bucket
      await page.locator('[role="combobox"]').filter({ hasText: /hour/i }).click();
      await page.getByRole('option', { name: /day/i }).click();
    });

    test('should query from metric row action', async ({ page }) => {
      await mockTimeSeriesApi(page);
      await mockTenantApi(page);

      await page.goto('/storage/timeseries');

      // Open actions menu
      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /query data/i }).click();

      // Dialog should open with metric pre-filled
      await expect(page.getByRole('dialog')).toBeVisible();
    });
  });

  test.describe('Time Series Delete', () => {
    test('should delete metric data with confirmation', async ({ page }) => {
      await mockTimeSeriesApi(page);
      await mockTenantApi(page);

      await page.goto('/storage/timeseries');

      page.on('dialog', (dialog) => dialog.accept());

      // Open actions menu
      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /delete data/i }).click();

      await expect(page.getByText(/data deleted/i)).toBeVisible();
    });
  });

  test.describe('Time Series Error States', () => {
    test('should handle query error', async ({ page }) => {
      await mockTimeSeriesApi(page, {
        queryError: { error: 'Query timeout', status: 504 },
        aggregateError: { error: 'Query timeout', status: 504 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/timeseries');

      await page.getByRole('button', { name: /query data/i }).click();
      await page.fill('input#queryMetric', 'cpu.usage');
      await page.getByRole('button', { name: /run query/i }).click();

      await expect(page.getByText(/failed/i)).toBeVisible();
    });
  });
});

// SKIPPED: Storage pages not yet implemented in the UI
test.describe.skip('Storage - Backup Management', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test.describe('Backup List', () => {
    test('should display backups list', async ({ page }) => {
      const backups = [
        createMockBackup({ name: 'Daily Backup', type: 'FULL', state: 'COMPLETED' }),
        createMockBackup({ name: 'Weekly Backup', type: 'INCREMENTAL', state: 'COMPLETED' }),
      ];

      await mockBackupApi(page, { initialBackups: backups });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await expect(page.getByRole('heading', { name: /backup & restore/i })).toBeVisible();
      await expect(page.getByText('Daily Backup')).toBeVisible();
      await expect(page.getByText('Weekly Backup')).toBeVisible();
    });

    test('should display empty state when no backups', async ({ page }) => {
      await mockBackupApi(page, { initialBackups: [] });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await expect(page.getByText(/no backups found/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /create your first backup/i })).toBeVisible();
    });

    test('should display backup status badges', async ({ page }) => {
      const backups = [
        createMockBackup({ name: 'Completed', state: 'COMPLETED' }),
        createMockBackup({ name: 'Running', state: 'IN_PROGRESS' }),
        createMockBackup({ name: 'Failed', state: 'FAILED' }),
      ];

      await mockBackupApi(page, { initialBackups: backups });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await expect(page.getByText('completed').first()).toBeVisible();
      await expect(page.getByText('running').first()).toBeVisible();
      await expect(page.getByText('failed').first()).toBeVisible();
    });

    test('should display backup type badges', async ({ page }) => {
      const backups = [
        createMockBackup({ name: 'Full', type: 'FULL' }),
        createMockBackup({ name: 'Incremental', type: 'INCREMENTAL' }),
        createMockBackup({ name: 'Differential', type: 'DIFFERENTIAL' }),
      ];

      await mockBackupApi(page, { initialBackups: backups });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await expect(page.getByText('full').first()).toBeVisible();
      await expect(page.getByText('incremental').first()).toBeVisible();
      await expect(page.getByText('differential').first()).toBeVisible();
    });

    test('should display statistics cards', async ({ page }) => {
      const backups = [
        createMockBackup({ state: 'COMPLETED' }),
        createMockBackup({ state: 'COMPLETED' }),
        createMockBackup({ state: 'FAILED' }),
        createMockBackup({ state: 'IN_PROGRESS' }),
      ];

      await mockBackupApi(page, { initialBackups: backups });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await expect(page.getByText('Total Backups')).toBeVisible();
      await expect(page.getByText('Completed')).toBeVisible();
      await expect(page.getByText('Failed')).toBeVisible();
      await expect(page.getByText('In Progress')).toBeVisible();
    });
  });

  test.describe('Create Backup', () => {
    test('should open create backup dialog', async ({ page }) => {
      await mockBackupApi(page, { initialBackups: [] });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await page.getByRole('button', { name: /create backup/i }).click();

      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByRole('heading', { name: /create new backup/i })).toBeVisible();
    });

    test('should create new backup', async ({ page }) => {
      const mockApi = await mockBackupApi(page, { initialBackups: [] });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      // Open dialog
      await page.getByRole('button', { name: /create backup/i }).click();

      // Fill form
      await page.fill('input#backupName', 'My Test Backup');
      await page.fill('input#backupDescription', 'Test backup description');

      // Select type
      await page.locator('[role="combobox"]').filter({ hasText: /full/i }).click();
      await page.getByRole('option', { name: /incremental/i }).click();

      // Submit
      await page.getByRole('button', { name: /start backup/i }).click();

      await expect(page.getByText(/backup started/i)).toBeVisible();

      const backups = mockApi.getBackups();
      expect(backups.length).toBe(1);
    });

    test('should validate backup name is required', async ({ page }) => {
      await mockBackupApi(page, { initialBackups: [] });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await page.getByRole('button', { name: /create backup/i }).click();
      await page.getByRole('button', { name: /start backup/i }).click();

      await expect(page.getByText(/backup name is required/i)).toBeVisible();
    });
  });

  test.describe('Restore Backup', () => {
    test('should open restore dialog for completed backup', async ({ page }) => {
      const backups = [createMockBackup({ name: 'Restorable', state: 'COMPLETED' })];

      await mockBackupApi(page, { initialBackups: backups });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      // Open actions menu
      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /restore/i }).click();

      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByRole('heading', { name: /restore backup/i })).toBeVisible();
    });

    test('should restore from backup', async ({ page }) => {
      const backups = [createMockBackup({ name: 'Restorable', state: 'COMPLETED' })];

      await mockBackupApi(page, { initialBackups: backups });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      // Open actions menu and restore
      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /restore/i }).click();

      // Optionally enter target prefix
      await page.fill('input#restoreDestination', 'restored/');

      // Submit
      await page.getByRole('button', { name: /start restore/i }).click();

      await expect(page.getByText(/restore started/i)).toBeVisible();
    });

    test('should disable restore for non-completed backups', async ({ page }) => {
      const backups = [createMockBackup({ name: 'In Progress', state: 'IN_PROGRESS' })];

      await mockBackupApi(page, { initialBackups: backups });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      // Open actions menu
      await page.locator('button').filter({ hasText: /more/i }).first().click();

      // Restore should be disabled
      const restoreItem = page.getByRole('menuitem', { name: /restore/i });
      await expect(restoreItem).toHaveAttribute('aria-disabled', 'true');
    });
  });

  test.describe('Delete Backup', () => {
    test('should delete backup with confirmation', async ({ page }) => {
      const backups = [createMockBackup({ name: 'Delete Me' })];

      const mockApi = await mockBackupApi(page, { initialBackups: backups });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      page.on('dialog', (dialog) => dialog.accept());

      // Open actions menu
      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /delete/i }).click();

      await expect(page.getByText(/backup deleted/i)).toBeVisible();

      const remaining = mockApi.getBackups();
      expect(remaining.length).toBe(0);
    });
  });

  test.describe('Backup Error States', () => {
    test('should handle list error', async ({ page }) => {
      await mockBackupApi(page, {
        listError: { error: 'Failed to list backups', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await expect(page.getByText(/error loading backups/i)).toBeVisible();
    });

    test('should handle create error', async ({ page }) => {
      await mockBackupApi(page, {
        initialBackups: [],
        createError: { error: 'Storage limit exceeded', status: 507 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await page.getByRole('button', { name: /create backup/i }).click();
      await page.fill('input#backupName', 'Test Backup');
      await page.getByRole('button', { name: /start backup/i }).click();

      await expect(page.getByText(/error creating backup/i)).toBeVisible();
    });

    test('should handle restore error', async ({ page }) => {
      const backups = [createMockBackup({ name: 'Restorable', state: 'COMPLETED' })];

      await mockBackupApi(page, {
        initialBackups: backups,
        restoreError: { error: 'Target location not writable', status: 403 },
      });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      await page.locator('button').filter({ hasText: /more/i }).first().click();
      await page.getByRole('menuitem', { name: /restore/i }).click();
      await page.getByRole('button', { name: /start restore/i }).click();

      await expect(page.getByText(/error restoring backup/i)).toBeVisible();
    });
  });

  test.describe('Backup Schedules Tab', () => {
    test('should display schedules tab', async ({ page }) => {
      await mockBackupApi(page, { initialBackups: [] });
      await mockTenantApi(page);

      await page.goto('/storage/backup');

      // Click schedules tab
      await page.getByRole('tab', { name: /schedules/i }).click();

      // Should show coming soon message
      await expect(page.getByText(/coming soon/i)).toBeVisible();
    });
  });
});

// SKIPPED: Storage pages not yet implemented in the UI
test.describe.skip('Storage - Access Control', () => {
  test('should allow tenant members to view storage pages', async ({ page }) => {
    await createTenantMemberSession(page.context());

    await mockKVApi(page, { initialEntries: [] });
    await mockTenantApi(page);

    await page.goto('/storage/kv');

    await expect(page.getByRole('heading', { name: /key-value store/i })).toBeVisible();
  });

  test('should redirect unauthenticated users to login', async ({ page }) => {
    await page.goto('/storage/kv');

    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });
});
