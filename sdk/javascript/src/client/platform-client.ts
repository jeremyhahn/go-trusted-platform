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
import type { Transport } from '../transport/transport.js';

// Core Platform Services
import { AttestationService } from '../services/attestation-service.js';
import { CAService } from '../services/ca-service.js';
import { ComputeService } from '../services/compute-service.js';
import { DeviceService } from '../services/device-service.js';
import { DNSService } from '../services/dns-service.js';
import { NTPService } from '../services/ntp-service.js';
import { BMCService } from '../services/bmc-service.js';
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
import { VPNService } from '../services/vpn-service.js';
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
 *
 * In addition to the REST/fetch options inherited from
 * `ApiClientConfig`, callers can pass a custom `transport` to
 * route every service call through an alternative wire protocol
 * (gRPC-Web, Wails IPC, an in-process mock, etc.). When omitted
 * the client constructs a default REST `ApiClient` and uses that
 * as both transport *and* `apiClient` so existing consumers see
 * no behavioral change.
 */
export interface PlatformClientConfig extends ApiClientConfig {
  /**
   * Optional custom transport. When provided, every service
   * dispatches through it instead of the default REST/fetch
   * path. Useful for desktop builds (Wails IPC), test harnesses
   * (in-memory transport), and gRPC-Web deployments.
   */
  transport?: Transport;
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
  /**
   * REST/fetch client. Always present so `getApiClient()` and
   * `baseUrl` remain useful even when the active transport is
   * something else (gRPC-Web, Wails). When the caller supplies a
   * custom `config.transport`, the apiClient is still constructed
   * for completeness but services don't talk through it.
   */
  private readonly apiClient: ApiClient;

  /**
   * Active transport — what the services actually dispatch
   * through. Defaults to `apiClient` (REST/fetch); overridden by
   * `config.transport` when the application wants gRPC-Web,
   * Wails IPC, or another wire format.
   */
  private readonly transport: Transport;

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
  /** BMC users and web certificate service (#1720) */
  public readonly bmc: BMCService;

  /** NTP status, sources and clock step */
  public readonly ntp: NTPService;

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

  /** VPN service for the remote-access VPN control plane */
  public readonly vpn: VPNService;

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
    // The transport is what every service dispatches through.
    // Apps can plug in any `Transport` implementation (gRPC-Web,
    // Wails IPC, mock); when omitted we use the REST apiClient.
    this.transport = config?.transport ?? this.apiClient;
    const t = this.transport;

    // Initialize all services
    this.attestation = new AttestationService(t);
    this.ca = new CAService(t);
    this.compute = new ComputeService(t);
    this.device = new DeviceService(t);
    this.dns = new DNSService(t);
    this.ntp = new NTPService(t);
    this.bmc = new BMCService(t);
    this.gateway = new GatewayService(t);
    this.iam = new IAMService(t);
    this.idevid = new IDevIDService(t);
    this.kms = new KMSService(t);
    this.overlay = new OverlayService(t);
    this.platform = new PlatformService(t);
    this.pxe = new PXEService(t);
    this.sdn = new SDNService(t);
    this.tenant = new TenantService(t);
    this.tpm = new TPMService(t);
    this.vtpm = new VTPMService(t);
    this.vpn = new VPNService(t);
    this.invitation = new InvitationService(t);
    this.eab = new EABService(t);

    // Initialize Data Platform Services (6)
    this.kv = new KVService(t);
    this.batch = new BatchService(t);
    this.transaction = new TransactionService(t);
    this.query = new QueryService(t);
    this.quicBaaSTimeSeries = new TimeSeriesService(t);
    this.quicBaaSBackup = new BackupService(t);

    // Initialize AI/ML Platform Services (3)
    this.vector = new VectorService(t);
    this.embedding = new EmbeddingService(t);
    this.ollama = new OllamaService(t);

    // Initialize Security Platform Services (9)
    this.auth = new AuthService(t);
    this.dataKms = new DataKMSService(t);
    this.secrets = new SecretsService(t);
    this.crypto = new CryptoService(t);
    this.dynamicSecrets = new DynamicSecretsService(t);
    this.certificate = new CertificateService(t);
    this.seal = new SealService(t);
    this.rbac = new RBACService(t);
    this.clusterDek = new ClusterDEKService(t);

    // Initialize Infrastructure Platform Services (9)
    this.cluster = new ClusterService(t);
    this.health = new HealthService(t);
    this.operations = new OperationsService(t);
    this.cache = new CacheService(t);
    this.parameterStore = new ParameterStoreService(t);
    this.scheduler = new SchedulerService(t);
    this.quicBaaSObjectStorage = new ObjectStorageService(t);
    this.quicBaaSObjectStorageAdmin = new ObjectStorageAdminService(t);
    this.objectTransfer = new ObjectTransferService(t);

    // Initialize Data Identity Platform Service (1)
    this.dataIam = new DataIAMService(t);
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
