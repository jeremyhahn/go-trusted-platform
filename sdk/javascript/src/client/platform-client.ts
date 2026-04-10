/**
 * Platform Client
 *
 * Main entry point for the Trusted Platform SDK.
 * Provides access to all platform services through a unified client interface.
 *
 * All services are exposed as platform services. Implementation details like
 * the underlying data stores (QuicBaaS, etc.) are abstracted away.
 */

import { ApiClient } from './api-client.js';
import type { ApiClientConfig } from './config.js';

// Core Platform Services
import { AttestationService } from '../services/attestation-service.js';
import { CAService } from '../services/ca-service.js';
import { ComputeService } from '../services/compute-service.js';
import { DeviceService } from '../services/device-service.js';
import { DNSService } from '../services/dns-service.js';
import { GatewayService } from '../services/gateway-service.js';
import { IAMService } from '../services/iam-service.js';
import { IDevIDService } from '../services/idevid-service.js';
import { KMSService } from '../services/kms-service.js';
import { OverlayService } from '../services/overlay-service.js';
import { PlatformService } from '../services/platform-service.js';
import { PXEService } from '../services/pxe-service.js';
import { SDNService } from '../services/sdn-service.js';
import { TenantService } from '../services/tenant-service.js';
import { TPMService } from '../services/tpm-service.js';
import { VTPMService } from '../services/vtpm-service.js';
import { InvitationService } from '../services/invitation-service.js';
import { EABService } from '../services/eab-service.js';

// Data Platform Services (key-value, batch, query, etc.)
import {
  KVService,
  BatchService,
  TransactionService,
  QueryService,
  TimeSeriesService,
  BackupService,
} from '../services/quicbaas/index.js';

// AI/ML Platform Services (vector search, embeddings, LLM)
import {
  VectorService,
  EmbeddingService,
  OllamaService,
} from '../services/quicbaas/index.js';

// Security Platform Services (secrets, crypto, auth, seal)
import {
  QuicBaaSAuthService as AuthService,
  QuicBaaSKMSService as DataKMSService,
  QuicBaaSSecretsService as SecretsService,
  QuicBaaSCryptoService as CryptoService,
  QuicBaaSDynamicSecretsService as DynamicSecretsService,
  CertificateService,
  SealService,
  RBACService,
  ClusterDEKService,
} from '../services/quicbaas/index.js';

// Infrastructure Platform Services (cluster, health, cache, scheduler, storage)
import {
  ClusterService,
  HealthService,
  OperationsService,
  CacheService,
  ParameterStoreService,
  SchedulerService,
  ObjectStorageService,
  ObjectStorageAdminService,
  ObjectTransferService,
} from '../services/quicbaas/index.js';

// Data IAM Platform Service
import { QuicBaaSIAMService as DataIAMService } from '../services/quicbaas/index.js';

/**
 * Platform Client configuration
 */
export interface PlatformClientConfig extends ApiClientConfig {
  // Extends API client config - no additional fields needed for now
}

/**
 * Platform Client class
 *
 * The main entry point for interacting with the Trusted Platform.
 * Provides access to all platform services through a unified interface.
 *
 * @example
 * ```typescript
 * import { PlatformClient } from '@trusted-platform/sdk';
 *
 * // Create client instance
 * const client = new PlatformClient({
 *   baseUrl: 'https://platform.example.com',
 * });
 *
 * // Platform services
 * const version = await client.platform.getVersion();
 * const health = await client.platform.getHealth({ includeServices: true });
 *
 * // Data services (key-value, vector search)
 * await client.kv.put({ key: 'config/app', value: 'data' });
 * const result = await client.vector.search({ vector: embeddings, topK: 10 });
 *
 * // Security services (secrets, crypto)
 * await client.secrets.put({ path: 'db/password', secret: 'secure-value' });
 * const encrypted = await client.crypto.encrypt({ keyId: 'master', plaintext: data });
 *
 * // Create a VM with vTPM
 * const bundle = await client.vtpm.createBundle({
 *   options: { hostname: 'vm-001', ekAlgorithm: 'RSA' }
 * });
 *
 * // Issue certificate
 * const cert = await client.ca.issueCertificate({
 *   commonName: 'server.example.com',
 *   profile: 'tls-server',
 * });
 *
 * // Seal secret to TPM
 * const sealed = await client.tpm.seal({
 *   data: btoa('my-secret'),
 *   cn: 'app-secret',
 *   pcrIndices: [0, 1, 7],
 * });
 * ```
 */
export class PlatformClient {
  /** The underlying API client */
  private readonly apiClient: ApiClient;

  // =========================================================================
  // Service Instances
  // =========================================================================

  /** Attestation service for quotes and manifest management */
  public readonly attestation: AttestationService;

  /** Certificate Authority service for certificate lifecycle management */
  public readonly ca: CAService;

  /** Compute service for VM and container management */
  public readonly compute: ComputeService;

  /** Device service for device and profile management */
  public readonly device: DeviceService;

  /** DNS service for zone and record management */
  public readonly dns: DNSService;

  /** Gateway service for BGP and IPAM operations */
  public readonly gateway: GatewayService;

  /** IAM service for identity and access management */
  public readonly iam: IAMService;

  /** IDevID service for device identity management */
  public readonly idevid: IDevIDService;

  /** KMS service for cryptographic operations */
  public readonly kms: KMSService;

  /** Overlay service for VXLAN and multi-host networking */
  public readonly overlay: OverlayService;

  /** Platform service for system info and health */
  public readonly platform: PlatformService;

  /** PXE service for device provisioning */
  public readonly pxe: PXEService;

  /** SDN service for bridges, ports, and flows */
  public readonly sdn: SDNService;

  /** Tenant service for multi-tenant management */
  public readonly tenant: TenantService;

  /** TPM service for TPM operations */
  public readonly tpm: TPMService;

  /** vTPM service for virtual TPM management */
  public readonly vtpm: VTPMService;

  /** Invitation service for tenant invitation management */
  public readonly invitation: InvitationService;

  /** EAB service for ACME External Account Binding management */
  public readonly eab: EABService;

  // =========================================================================
  // Data Platform Services (key-value, batch, query, timeseries)
  // =========================================================================

  /** Key-value service for CRUD operations and Watch */
  public readonly kv: KVService;

  /** Batch service for atomic batch operations */
  public readonly batch: BatchService;

  /** Transaction service for compare-and-swap transactions */
  public readonly transaction: TransactionService;

  /** Query service for secondary index queries */
  public readonly query: QueryService;

  /** TimeSeries service for time-series data storage and analysis */
  public readonly quicBaaSTimeSeries: TimeSeriesService;

  /** Backup service for backup and restore operations */
  public readonly quicBaaSBackup: BackupService;

  // =========================================================================
  // AI/ML Platform Services (vector search, embeddings, LLM)
  // =========================================================================

  /** Vector service for similarity search and RAG applications */
  public readonly vector: VectorService;

  /** Embedding service for text/image embedding generation */
  public readonly embedding: EmbeddingService;

  /** Ollama service for local LLM and embedding operations */
  public readonly ollama: OllamaService;

  // =========================================================================
  // Security Platform Services (secrets, crypto, auth, seal)
  // =========================================================================

  /** Auth service for authentication tokens and API keys */
  public readonly auth: AuthService;

  /** Data KMS service for encryption key management */
  public readonly dataKms: DataKMSService;

  /** Secrets service for secure secret storage and retrieval */
  public readonly secrets: SecretsService;

  /** Crypto service for encryption, decryption, and signatures */
  public readonly crypto: CryptoService;

  /** DynamicSecrets service for ephemeral credential generation */
  public readonly dynamicSecrets: DynamicSecretsService;

  /** Certificate service for X.509 certificate management */
  public readonly certificate: CertificateService;

  /** Seal service for seal/unseal operations */
  public readonly seal: SealService;

  /** RBAC service for role-based access control */
  public readonly rbac: RBACService;

  /** ClusterDEK service for cluster data encryption keys */
  public readonly clusterDek: ClusterDEKService;

  // =========================================================================
  // Infrastructure Platform Services (cluster, health, cache, scheduler)
  // =========================================================================

  /** Cluster service for cluster management and membership */
  public readonly cluster: ClusterService;

  /** Health service for health checks and status */
  public readonly health: HealthService;

  /** Operations service for migrations and upgrades */
  public readonly operations: OperationsService;

  /** Cache service for distributed cache management */
  public readonly cache: CacheService;

  /** ParameterStore service for hierarchical configuration */
  public readonly parameterStore: ParameterStoreService;

  /** Scheduler service for job scheduling and cron */
  public readonly scheduler: SchedulerService;

  /** ObjectStorage service for S3-compatible object storage */
  public readonly quicBaaSObjectStorage: ObjectStorageService;

  /** ObjectStorageAdmin service for bucket management */
  public readonly quicBaaSObjectStorageAdmin: ObjectStorageAdminService;

  /** ObjectTransfer service for data transfer between nodes */
  public readonly objectTransfer: ObjectTransferService;

  // =========================================================================
  // Data Identity Platform Service
  // =========================================================================

  /** Data IAM service for data-layer identity and access management */
  public readonly dataIam: DataIAMService;

  /**
   * Creates a new Platform Client instance
   *
   * @param config - Client configuration options
   */
  constructor(config?: PlatformClientConfig) {
    this.apiClient = new ApiClient(config);

    // Initialize all services
    this.attestation = new AttestationService(this.apiClient);
    this.ca = new CAService(this.apiClient);
    this.compute = new ComputeService(this.apiClient);
    this.device = new DeviceService(this.apiClient);
    this.dns = new DNSService(this.apiClient);
    this.gateway = new GatewayService(this.apiClient);
    this.iam = new IAMService(this.apiClient);
    this.idevid = new IDevIDService(this.apiClient);
    this.kms = new KMSService(this.apiClient);
    this.overlay = new OverlayService(this.apiClient);
    this.platform = new PlatformService(this.apiClient);
    this.pxe = new PXEService(this.apiClient);
    this.sdn = new SDNService(this.apiClient);
    this.tenant = new TenantService(this.apiClient);
    this.tpm = new TPMService(this.apiClient);
    this.vtpm = new VTPMService(this.apiClient);
    this.invitation = new InvitationService(this.apiClient);
    this.eab = new EABService(this.apiClient);

    // Initialize Data Platform Services (6)
    this.kv = new KVService(this.apiClient);
    this.batch = new BatchService(this.apiClient);
    this.transaction = new TransactionService(this.apiClient);
    this.query = new QueryService(this.apiClient);
    this.quicBaaSTimeSeries = new TimeSeriesService(this.apiClient);
    this.quicBaaSBackup = new BackupService(this.apiClient);

    // Initialize AI/ML Platform Services (3)
    this.vector = new VectorService(this.apiClient);
    this.embedding = new EmbeddingService(this.apiClient);
    this.ollama = new OllamaService(this.apiClient);

    // Initialize Security Platform Services (9)
    this.auth = new AuthService(this.apiClient);
    this.dataKms = new DataKMSService(this.apiClient);
    this.secrets = new SecretsService(this.apiClient);
    this.crypto = new CryptoService(this.apiClient);
    this.dynamicSecrets = new DynamicSecretsService(this.apiClient);
    this.certificate = new CertificateService(this.apiClient);
    this.seal = new SealService(this.apiClient);
    this.rbac = new RBACService(this.apiClient);
    this.clusterDek = new ClusterDEKService(this.apiClient);

    // Initialize Infrastructure Platform Services (9)
    this.cluster = new ClusterService(this.apiClient);
    this.health = new HealthService(this.apiClient);
    this.operations = new OperationsService(this.apiClient);
    this.cache = new CacheService(this.apiClient);
    this.parameterStore = new ParameterStoreService(this.apiClient);
    this.scheduler = new SchedulerService(this.apiClient);
    this.quicBaaSObjectStorage = new ObjectStorageService(this.apiClient);
    this.quicBaaSObjectStorageAdmin = new ObjectStorageAdminService(this.apiClient);
    this.objectTransfer = new ObjectTransferService(this.apiClient);

    // Initialize Data Identity Platform Service (1)
    this.dataIam = new DataIAMService(this.apiClient);
  }

  /**
   * Gets the base URL configured for this client
   */
  get baseUrl(): string {
    return this.apiClient.baseUrl;
  }

  /**
   * Gets the underlying API client for advanced use cases
   *
   * @returns The raw API client instance
   */
  getApiClient(): ApiClient {
    return this.apiClient;
  }

  /**
   * Adds a request interceptor
   *
   * @param interceptor - The interceptor function
   * @returns Handle to remove the interceptor
   */
  addRequestInterceptor(
    interceptor: Parameters<ApiClient['addRequestInterceptor']>[0]
  ): ReturnType<ApiClient['addRequestInterceptor']> {
    return this.apiClient.addRequestInterceptor(interceptor);
  }

  /**
   * Adds a response interceptor
   *
   * @param interceptor - The interceptor function
   * @returns Handle to remove the interceptor
   */
  addResponseInterceptor(
    interceptor: Parameters<ApiClient['addResponseInterceptor']>[0]
  ): ReturnType<ApiClient['addResponseInterceptor']> {
    return this.apiClient.addResponseInterceptor(interceptor);
  }

  /**
   * Adds an error interceptor
   *
   * @param interceptor - The interceptor function
   * @returns Handle to remove the interceptor
   */
  addErrorInterceptor(
    interceptor: Parameters<ApiClient['addErrorInterceptor']>[0]
  ): ReturnType<ApiClient['addErrorInterceptor']> {
    return this.apiClient.addErrorInterceptor(interceptor);
  }
}

/**
 * Creates a new Platform Client instance
 *
 * @param config - Client configuration options
 * @returns A new PlatformClient instance
 *
 * @example
 * ```typescript
 * const client = createPlatformClient({
 *   baseUrl: 'https://platform.example.com',
 * });
 * ```
 */
export function createPlatformClient(config?: PlatformClientConfig): PlatformClient {
  return new PlatformClient(config);
}
