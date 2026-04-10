/**
 * QuicBaaS Services Index
 *
 * Exports all 28 QuicBaaS service classes for the Trusted Platform SDK.
 */

// =============================================================================
// Core Data Services (6 services)
// =============================================================================

export { KVService } from './kv-service.js';
export { BatchService } from './batch-service.js';
export { TransactionService } from './transaction-service.js';
export { QueryService } from './query-service.js';
export { TimeSeriesService } from './timeseries-service.js';
export { BackupService } from './backup-service.js';

// =============================================================================
// AI/ML Services (3 services)
// =============================================================================

export { VectorService } from './vector-service.js';
export { EmbeddingService } from './embedding-service.js';
export { OllamaService } from './ollama-service.js';

// =============================================================================
// Security Services (9 services)
// =============================================================================

// Part 1
export { QuicBaaSAuthService } from './auth-service.js';
export { QuicBaaSKMSService } from './quicbaas-kms-service.js';
export { QuicBaaSSecretsService } from './secrets-service.js';
export { QuicBaaSCryptoService } from './crypto-service.js';
export { QuicBaaSDynamicSecretsService } from './dynamic-secrets-service.js';

// Part 2
export { CertificateService } from './certificate-service.js';
export { SealService } from './seal-service.js';
export { RBACService } from './rbac-service.js';
export { ClusterDEKService } from './cluster-dek-service.js';

// =============================================================================
// Infrastructure Services (9 services)
// =============================================================================

// Part 1
export { ClusterService } from './cluster-service.js';
export { HealthService } from './health-service.js';
export { OperationsService } from './operations-service.js';
export { CacheService } from './cache-service.js';
export { ParameterStoreService } from './parameter-store-service.js';

// Part 2
export { SchedulerService } from './scheduler-service.js';
export { ObjectStorageService } from './object-storage-service.js';
export { ObjectStorageAdminService } from './object-storage-admin-service.js';
export { ObjectTransferService } from './object-transfer-service.js';

// =============================================================================
// Identity Services (1 service)
// =============================================================================

export { QuicBaaSIAMService } from './quicbaas-iam-service.js';
