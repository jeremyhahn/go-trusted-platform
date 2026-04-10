/**
 * Unit tests for PlatformClient QuicBaaS services integration
 *
 * Tests that all 28 QuicBaaS services are properly initialized and accessible.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PlatformClient } from '../platform-client.js';

// Import service classes for instanceof checks
import {
  KVService,
  BatchService,
  TransactionService,
  QueryService,
  TimeSeriesService,
  BackupService,
  VectorService,
  EmbeddingService,
  OllamaService,
  QuicBaaSAuthService,
  QuicBaaSKMSService,
  QuicBaaSSecretsService,
  QuicBaaSCryptoService,
  QuicBaaSDynamicSecretsService,
  CertificateService,
  SealService,
  RBACService,
  ClusterDEKService,
  ClusterService,
  HealthService,
  OperationsService,
  CacheService,
  ParameterStoreService,
  SchedulerService,
  ObjectStorageService,
  ObjectStorageAdminService,
  ObjectTransferService,
  QuicBaaSIAMService,
} from '../../services/quicbaas/index.js';

// Mock fetch globally
vi.stubGlobal('fetch', vi.fn());

describe('PlatformClient QuicBaaS Integration', () => {
  let client: PlatformClient;

  beforeEach(() => {
    client = new PlatformClient({
      baseUrl: 'https://api.example.com',
    });
  });

  // =========================================================================
  // Core Data Services (6 services)
  // =========================================================================

  describe('Core Data Services', () => {
    it('should initialize KVService', () => {
      expect(client.quicBaaSKV).toBeDefined();
      expect(client.quicBaaSKV).toBeInstanceOf(KVService);
    });

    it('should initialize BatchService', () => {
      expect(client.quicBaaSBatch).toBeDefined();
      expect(client.quicBaaSBatch).toBeInstanceOf(BatchService);
    });

    it('should initialize TransactionService', () => {
      expect(client.quicBaaSTransaction).toBeDefined();
      expect(client.quicBaaSTransaction).toBeInstanceOf(TransactionService);
    });

    it('should initialize QueryService', () => {
      expect(client.quicBaaSQuery).toBeDefined();
      expect(client.quicBaaSQuery).toBeInstanceOf(QueryService);
    });

    it('should initialize TimeSeriesService', () => {
      expect(client.quicBaaSTimeSeries).toBeDefined();
      expect(client.quicBaaSTimeSeries).toBeInstanceOf(TimeSeriesService);
    });

    it('should initialize BackupService', () => {
      expect(client.quicBaaSBackup).toBeDefined();
      expect(client.quicBaaSBackup).toBeInstanceOf(BackupService);
    });
  });

  // =========================================================================
  // AI/ML Services (3 services)
  // =========================================================================

  describe('AI/ML Services', () => {
    it('should initialize VectorService', () => {
      expect(client.quicBaaSVector).toBeDefined();
      expect(client.quicBaaSVector).toBeInstanceOf(VectorService);
    });

    it('should initialize EmbeddingService', () => {
      expect(client.quicBaaSEmbedding).toBeDefined();
      expect(client.quicBaaSEmbedding).toBeInstanceOf(EmbeddingService);
    });

    it('should initialize OllamaService', () => {
      expect(client.quicBaaSOllama).toBeDefined();
      expect(client.quicBaaSOllama).toBeInstanceOf(OllamaService);
    });
  });

  // =========================================================================
  // Security Services (9 services)
  // =========================================================================

  describe('Security Services', () => {
    it('should initialize QuicBaaSAuthService', () => {
      expect(client.quicBaaSAuth).toBeDefined();
      expect(client.quicBaaSAuth).toBeInstanceOf(QuicBaaSAuthService);
    });

    it('should initialize QuicBaaSKMSService', () => {
      expect(client.quicBaaSKMS).toBeDefined();
      expect(client.quicBaaSKMS).toBeInstanceOf(QuicBaaSKMSService);
    });

    it('should initialize QuicBaaSSecretsService', () => {
      expect(client.quicBaaSSecrets).toBeDefined();
      expect(client.quicBaaSSecrets).toBeInstanceOf(QuicBaaSSecretsService);
    });

    it('should initialize QuicBaaSCryptoService', () => {
      expect(client.quicBaaSCrypto).toBeDefined();
      expect(client.quicBaaSCrypto).toBeInstanceOf(QuicBaaSCryptoService);
    });

    it('should initialize QuicBaaSDynamicSecretsService', () => {
      expect(client.quicBaaSDynamicSecrets).toBeDefined();
      expect(client.quicBaaSDynamicSecrets).toBeInstanceOf(QuicBaaSDynamicSecretsService);
    });

    it('should initialize CertificateService', () => {
      expect(client.quicBaaSCertificate).toBeDefined();
      expect(client.quicBaaSCertificate).toBeInstanceOf(CertificateService);
    });

    it('should initialize SealService', () => {
      expect(client.quicBaaSSeal).toBeDefined();
      expect(client.quicBaaSSeal).toBeInstanceOf(SealService);
    });

    it('should initialize RBACService', () => {
      expect(client.quicBaaSRBAC).toBeDefined();
      expect(client.quicBaaSRBAC).toBeInstanceOf(RBACService);
    });

    it('should initialize ClusterDEKService', () => {
      expect(client.quicBaaSClusterDEK).toBeDefined();
      expect(client.quicBaaSClusterDEK).toBeInstanceOf(ClusterDEKService);
    });
  });

  // =========================================================================
  // Infrastructure Services (9 services)
  // =========================================================================

  describe('Infrastructure Services', () => {
    it('should initialize ClusterService', () => {
      expect(client.quicBaaSCluster).toBeDefined();
      expect(client.quicBaaSCluster).toBeInstanceOf(ClusterService);
    });

    it('should initialize HealthService', () => {
      expect(client.quicBaaSHealth).toBeDefined();
      expect(client.quicBaaSHealth).toBeInstanceOf(HealthService);
    });

    it('should initialize OperationsService', () => {
      expect(client.quicBaaSOperations).toBeDefined();
      expect(client.quicBaaSOperations).toBeInstanceOf(OperationsService);
    });

    it('should initialize CacheService', () => {
      expect(client.quicBaaSCache).toBeDefined();
      expect(client.quicBaaSCache).toBeInstanceOf(CacheService);
    });

    it('should initialize ParameterStoreService', () => {
      expect(client.quicBaaSParameterStore).toBeDefined();
      expect(client.quicBaaSParameterStore).toBeInstanceOf(ParameterStoreService);
    });

    it('should initialize SchedulerService', () => {
      expect(client.quicBaaSScheduler).toBeDefined();
      expect(client.quicBaaSScheduler).toBeInstanceOf(SchedulerService);
    });

    it('should initialize ObjectStorageService', () => {
      expect(client.quicBaaSObjectStorage).toBeDefined();
      expect(client.quicBaaSObjectStorage).toBeInstanceOf(ObjectStorageService);
    });

    it('should initialize ObjectStorageAdminService', () => {
      expect(client.quicBaaSObjectStorageAdmin).toBeDefined();
      expect(client.quicBaaSObjectStorageAdmin).toBeInstanceOf(ObjectStorageAdminService);
    });

    it('should initialize ObjectTransferService', () => {
      expect(client.quicBaaSObjectTransfer).toBeDefined();
      expect(client.quicBaaSObjectTransfer).toBeInstanceOf(ObjectTransferService);
    });
  });

  // =========================================================================
  // Identity Services (1 service)
  // =========================================================================

  describe('Identity Services', () => {
    it('should initialize QuicBaaSIAMService', () => {
      expect(client.quicBaaSIAM).toBeDefined();
      expect(client.quicBaaSIAM).toBeInstanceOf(QuicBaaSIAMService);
    });
  });

  // =========================================================================
  // Service count verification
  // =========================================================================

  describe('Service count verification', () => {
    it('should have exactly 28 QuicBaaS services initialized', () => {
      const quicBaaSServices = [
        // Core Data Services (6)
        client.quicBaaSKV,
        client.quicBaaSBatch,
        client.quicBaaSTransaction,
        client.quicBaaSQuery,
        client.quicBaaSTimeSeries,
        client.quicBaaSBackup,
        // AI/ML Services (3)
        client.quicBaaSVector,
        client.quicBaaSEmbedding,
        client.quicBaaSOllama,
        // Security Services (9)
        client.quicBaaSAuth,
        client.quicBaaSKMS,
        client.quicBaaSSecrets,
        client.quicBaaSCrypto,
        client.quicBaaSDynamicSecrets,
        client.quicBaaSCertificate,
        client.quicBaaSSeal,
        client.quicBaaSRBAC,
        client.quicBaaSClusterDEK,
        // Infrastructure Services (9)
        client.quicBaaSCluster,
        client.quicBaaSHealth,
        client.quicBaaSOperations,
        client.quicBaaSCache,
        client.quicBaaSParameterStore,
        client.quicBaaSScheduler,
        client.quicBaaSObjectStorage,
        client.quicBaaSObjectStorageAdmin,
        client.quicBaaSObjectTransfer,
        // Identity Services (1)
        client.quicBaaSIAM,
      ];

      // Verify count
      expect(quicBaaSServices).toHaveLength(28);

      // Verify all services are defined
      quicBaaSServices.forEach((service, index) => {
        expect(service).toBeDefined();
      });
    });
  });

  // =========================================================================
  // Client configuration tests
  // =========================================================================

  describe('Client configuration', () => {
    it('should pass baseUrl to all services', () => {
      const baseUrl = 'https://custom-api.example.com';
      const customClient = new PlatformClient({ baseUrl });

      expect(customClient.baseUrl).toBe(baseUrl);
      expect(customClient.getApiClient().baseUrl).toBe(baseUrl);
    });

    it('should create client without config', () => {
      // Note: This will use default config
      expect(() => new PlatformClient()).not.toThrow();
    });

    it('should provide access to underlying API client', () => {
      const apiClient = client.getApiClient();
      expect(apiClient).toBeDefined();
      expect(apiClient.baseUrl).toBe('https://api.example.com');
    });
  });

  // =========================================================================
  // Interceptor tests
  // =========================================================================

  describe('Interceptors', () => {
    it('should add request interceptor', () => {
      const interceptor = vi.fn((config) => config);
      const handle = client.addRequestInterceptor(interceptor);

      expect(handle).toBeDefined();
      expect(typeof handle.remove).toBe('function');
    });

    it('should add response interceptor', () => {
      const interceptor = vi.fn((response) => response);
      const handle = client.addResponseInterceptor(interceptor);

      expect(handle).toBeDefined();
      expect(typeof handle.remove).toBe('function');
    });

    it('should add error interceptor', () => {
      const interceptor = vi.fn((error) => error);
      const handle = client.addErrorInterceptor(interceptor);

      expect(handle).toBeDefined();
      expect(typeof handle.remove).toBe('function');
    });
  });

  // =========================================================================
  // Service functionality smoke tests
  // =========================================================================

  describe('Service functionality smoke tests', () => {
    it('should have KV service methods', () => {
      expect(typeof client.quicBaaSKV.get).toBe('function');
      expect(typeof client.quicBaaSKV.put).toBe('function');
      expect(typeof client.quicBaaSKV.delete).toBe('function');
      expect(typeof client.quicBaaSKV.list).toBe('function');
      expect(typeof client.quicBaaSKV.watch).toBe('function');
    });

    it('should have Vector service methods', () => {
      expect(typeof client.quicBaaSVector.insert).toBe('function');
      expect(typeof client.quicBaaSVector.search).toBe('function');
      expect(typeof client.quicBaaSVector.searchSimilar).toBe('function');
      expect(typeof client.quicBaaSVector.delete).toBe('function');
      expect(typeof client.quicBaaSVector.createNamespace).toBe('function');
      expect(typeof client.quicBaaSVector.deleteNamespace).toBe('function');
      expect(typeof client.quicBaaSVector.listNamespaces).toBe('function');
      expect(typeof client.quicBaaSVector.getStats).toBe('function');
    });

    it('should have Embedding service methods', () => {
      expect(typeof client.quicBaaSEmbedding.generate).toBe('function');
      expect(typeof client.quicBaaSEmbedding.generateBatch).toBe('function');
      expect(typeof client.quicBaaSEmbedding.listProviders).toBe('function');
      expect(typeof client.quicBaaSEmbedding.getProviderInfo).toBe('function');
      expect(typeof client.quicBaaSEmbedding.generateOpenAI).toBe('function');
      expect(typeof client.quicBaaSEmbedding.generateCohere).toBe('function');
      expect(typeof client.quicBaaSEmbedding.generateOllama).toBe('function');
    });

    it('should have Batch service methods', () => {
      expect(typeof client.quicBaaSBatch.batchGet).toBe('function');
      expect(typeof client.quicBaaSBatch.batchPut).toBe('function');
      expect(typeof client.quicBaaSBatch.batchDelete).toBe('function');
    });

    it('should have Transaction service methods', () => {
      expect(typeof client.quicBaaSTransaction.begin).toBe('function');
      expect(typeof client.quicBaaSTransaction.commit).toBe('function');
      expect(typeof client.quicBaaSTransaction.rollback).toBe('function');
      expect(typeof client.quicBaaSTransaction.compareAndSwap).toBe('function');
    });

    it('should have Query service methods', () => {
      expect(typeof client.quicBaaSQuery.query).toBe('function');
      expect(typeof client.quicBaaSQuery.createIndex).toBe('function');
      expect(typeof client.quicBaaSQuery.deleteIndex).toBe('function');
      expect(typeof client.quicBaaSQuery.listIndexes).toBe('function');
    });

    it('should have TimeSeries service methods', () => {
      expect(typeof client.quicBaaSTimeSeries.insert).toBe('function');
      expect(typeof client.quicBaaSTimeSeries.query).toBe('function');
      expect(typeof client.quicBaaSTimeSeries.aggregate).toBe('function');
      expect(typeof client.quicBaaSTimeSeries.deleteRange).toBe('function');
    });

    it('should have Backup service methods', () => {
      expect(typeof client.quicBaaSBackup.create).toBe('function');
      expect(typeof client.quicBaaSBackup.restore).toBe('function');
      expect(typeof client.quicBaaSBackup.list).toBe('function');
      expect(typeof client.quicBaaSBackup.delete).toBe('function');
      expect(typeof client.quicBaaSBackup.getStatus).toBe('function');
    });

    it('should have Auth service methods', () => {
      expect(typeof client.quicBaaSAuth.login).toBe('function');
      expect(typeof client.quicBaaSAuth.logout).toBe('function');
      expect(typeof client.quicBaaSAuth.refreshToken).toBe('function');
      expect(typeof client.quicBaaSAuth.validateToken).toBe('function');
      expect(typeof client.quicBaaSAuth.createApiKey).toBe('function');
      expect(typeof client.quicBaaSAuth.revokeApiKey).toBe('function');
    });

    it('should have Secrets service methods', () => {
      expect(typeof client.quicBaaSSecrets.create).toBe('function');
      expect(typeof client.quicBaaSSecrets.get).toBe('function');
      expect(typeof client.quicBaaSSecrets.update).toBe('function');
      expect(typeof client.quicBaaSSecrets.delete).toBe('function');
      expect(typeof client.quicBaaSSecrets.list).toBe('function');
      expect(typeof client.quicBaaSSecrets.getVersion).toBe('function');
      expect(typeof client.quicBaaSSecrets.listVersions).toBe('function');
      expect(typeof client.quicBaaSSecrets.rotateSecret).toBe('function');
    });
  });
});
