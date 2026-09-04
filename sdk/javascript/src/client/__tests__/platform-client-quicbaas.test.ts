/**
 * Unit tests for PlatformClient QuicBaaS services integration
 *
 * Tests that all 28 QuicBaaS services are properly initialized and accessible.
 *
 * A note on names, because this file got them wrong once and nothing caught it
 * for as long as the suite ran in no CI stage (issue #211): the SERVICE CLASSES
 * are `QuicBaaS*`-prefixed, but the CLIENT MEMBERS that hold them mostly are
 * not. `QuicBaaSSecretsService` lives on `client.secrets`, not
 * `client.quicBaaSSecrets`. Only four members carry the prefix —
 * `quicBaaSTimeSeries`, `quicBaaSBackup`, `quicBaaSObjectStorage` and
 * `quicBaaSObjectStorageAdmin`. Assert against the member name in
 * `platform-client.ts`, which is also what the React hooks in
 * `src/react/hooks/quicbaas/` return.
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
      expect(client.kv).toBeDefined();
      expect(client.kv).toBeInstanceOf(KVService);
    });

    it('should initialize BatchService', () => {
      expect(client.batch).toBeDefined();
      expect(client.batch).toBeInstanceOf(BatchService);
    });

    it('should initialize TransactionService', () => {
      expect(client.transaction).toBeDefined();
      expect(client.transaction).toBeInstanceOf(TransactionService);
    });

    it('should initialize QueryService', () => {
      expect(client.query).toBeDefined();
      expect(client.query).toBeInstanceOf(QueryService);
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
      expect(client.vector).toBeDefined();
      expect(client.vector).toBeInstanceOf(VectorService);
    });

    it('should initialize EmbeddingService', () => {
      expect(client.embedding).toBeDefined();
      expect(client.embedding).toBeInstanceOf(EmbeddingService);
    });

    it('should initialize OllamaService', () => {
      expect(client.ollama).toBeDefined();
      expect(client.ollama).toBeInstanceOf(OllamaService);
    });
  });

  // =========================================================================
  // Security Services (9 services)
  // =========================================================================

  describe('Security Services', () => {
    it('should initialize QuicBaaSAuthService', () => {
      expect(client.auth).toBeDefined();
      expect(client.auth).toBeInstanceOf(QuicBaaSAuthService);
    });

    it('should initialize QuicBaaSKMSService', () => {
      expect(client.dataKms).toBeDefined();
      expect(client.dataKms).toBeInstanceOf(QuicBaaSKMSService);
    });

    it('should initialize QuicBaaSSecretsService', () => {
      expect(client.secrets).toBeDefined();
      expect(client.secrets).toBeInstanceOf(QuicBaaSSecretsService);
    });

    it('should initialize QuicBaaSCryptoService', () => {
      expect(client.crypto).toBeDefined();
      expect(client.crypto).toBeInstanceOf(QuicBaaSCryptoService);
    });

    it('should initialize QuicBaaSDynamicSecretsService', () => {
      expect(client.dynamicSecrets).toBeDefined();
      expect(client.dynamicSecrets).toBeInstanceOf(QuicBaaSDynamicSecretsService);
    });

    it('should initialize CertificateService', () => {
      expect(client.certificate).toBeDefined();
      expect(client.certificate).toBeInstanceOf(CertificateService);
    });

    it('should initialize SealService', () => {
      expect(client.seal).toBeDefined();
      expect(client.seal).toBeInstanceOf(SealService);
    });

    it('should initialize RBACService', () => {
      expect(client.rbac).toBeDefined();
      expect(client.rbac).toBeInstanceOf(RBACService);
    });

    it('should initialize ClusterDEKService', () => {
      expect(client.clusterDek).toBeDefined();
      expect(client.clusterDek).toBeInstanceOf(ClusterDEKService);
    });
  });

  // =========================================================================
  // Infrastructure Services (9 services)
  // =========================================================================

  describe('Infrastructure Services', () => {
    it('should initialize ClusterService', () => {
      expect(client.cluster).toBeDefined();
      expect(client.cluster).toBeInstanceOf(ClusterService);
    });

    it('should initialize HealthService', () => {
      expect(client.health).toBeDefined();
      expect(client.health).toBeInstanceOf(HealthService);
    });

    it('should initialize OperationsService', () => {
      expect(client.operations).toBeDefined();
      expect(client.operations).toBeInstanceOf(OperationsService);
    });

    it('should initialize CacheService', () => {
      expect(client.cache).toBeDefined();
      expect(client.cache).toBeInstanceOf(CacheService);
    });

    it('should initialize ParameterStoreService', () => {
      expect(client.parameterStore).toBeDefined();
      expect(client.parameterStore).toBeInstanceOf(ParameterStoreService);
    });

    it('should initialize SchedulerService', () => {
      expect(client.scheduler).toBeDefined();
      expect(client.scheduler).toBeInstanceOf(SchedulerService);
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
      expect(client.objectTransfer).toBeDefined();
      expect(client.objectTransfer).toBeInstanceOf(ObjectTransferService);
    });
  });

  // =========================================================================
  // Identity Services (1 service)
  // =========================================================================

  describe('Identity Services', () => {
    it('should initialize QuicBaaSIAMService', () => {
      expect(client.dataIam).toBeDefined();
      expect(client.dataIam).toBeInstanceOf(QuicBaaSIAMService);
    });
  });

  // =========================================================================
  // Service count verification
  // =========================================================================

  describe('Service count verification', () => {
    it('should have exactly 28 QuicBaaS services initialized', () => {
      // Twenty-four of these read as the plain capability name and four carry
      // a `quicBaaS` prefix. That inconsistency is the client's public surface
      // today, and this list is the record of it — see the note at the top of
      // the file.
      const quicBaaSServices = [
        // Core Data Services (6)
        client.kv,
        client.batch,
        client.transaction,
        client.query,
        client.quicBaaSTimeSeries,
        client.quicBaaSBackup,
        // AI/ML Services (3)
        client.vector,
        client.embedding,
        client.ollama,
        // Security Services (9)
        client.auth,
        client.dataKms,
        client.secrets,
        client.crypto,
        client.dynamicSecrets,
        client.certificate,
        client.seal,
        client.rbac,
        client.clusterDek,
        // Infrastructure Services (9)
        client.cluster,
        client.health,
        client.operations,
        client.cache,
        client.parameterStore,
        client.scheduler,
        client.quicBaaSObjectStorage,
        client.quicBaaSObjectStorageAdmin,
        client.objectTransfer,
        // Identity Services (1)
        client.dataIam,
      ];

      // Verify count
      expect(quicBaaSServices).toHaveLength(28);

      // Verify all services are defined
      quicBaaSServices.forEach((service) => {
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
      expect(typeof client.kv.get).toBe('function');
      expect(typeof client.kv.put).toBe('function');
      expect(typeof client.kv.delete).toBe('function');
      expect(typeof client.kv.list).toBe('function');
      expect(typeof client.kv.watch).toBe('function');
    });

    it('should have Vector service methods', () => {
      expect(typeof client.vector.insert).toBe('function');
      expect(typeof client.vector.search).toBe('function');
      expect(typeof client.vector.searchSimilar).toBe('function');
      expect(typeof client.vector.delete).toBe('function');
      expect(typeof client.vector.createNamespace).toBe('function');
      expect(typeof client.vector.deleteNamespace).toBe('function');
      expect(typeof client.vector.listNamespaces).toBe('function');
      expect(typeof client.vector.getStats).toBe('function');
    });

    it('should have Embedding service methods', () => {
      expect(typeof client.embedding.generate).toBe('function');
      expect(typeof client.embedding.generateBatch).toBe('function');
      expect(typeof client.embedding.listProviders).toBe('function');
      expect(typeof client.embedding.getProviderInfo).toBe('function');
      expect(typeof client.embedding.generateOpenAI).toBe('function');
      expect(typeof client.embedding.generateCohere).toBe('function');
      expect(typeof client.embedding.generateOllama).toBe('function');
    });

    it('should have Batch service methods', () => {
      expect(typeof client.batch.batchGet).toBe('function');
      expect(typeof client.batch.batchPut).toBe('function');
      expect(typeof client.batch.batchDelete).toBe('function');
    });

    it('should have Transaction service methods', () => {
      expect(typeof client.transaction.begin).toBe('function');
      expect(typeof client.transaction.commit).toBe('function');
      expect(typeof client.transaction.rollback).toBe('function');
      expect(typeof client.transaction.compareAndSwap).toBe('function');
    });

    it('should have Query service methods', () => {
      expect(typeof client.query.query).toBe('function');
      expect(typeof client.query.createIndex).toBe('function');
      expect(typeof client.query.deleteIndex).toBe('function');
      expect(typeof client.query.listIndexes).toBe('function');
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
      expect(typeof client.auth.login).toBe('function');
      expect(typeof client.auth.logout).toBe('function');
      expect(typeof client.auth.refreshToken).toBe('function');
      expect(typeof client.auth.validateToken).toBe('function');
      expect(typeof client.auth.createApiKey).toBe('function');
      expect(typeof client.auth.revokeApiKey).toBe('function');
    });

    it('should have Secrets service methods', () => {
      expect(typeof client.secrets.create).toBe('function');
      expect(typeof client.secrets.get).toBe('function');
      expect(typeof client.secrets.update).toBe('function');
      expect(typeof client.secrets.delete).toBe('function');
      expect(typeof client.secrets.list).toBe('function');
      expect(typeof client.secrets.getVersion).toBe('function');
      expect(typeof client.secrets.listVersions).toBe('function');
      expect(typeof client.secrets.rotateSecret).toBe('function');
    });
  });
});
