/**
 * Platform (Daemon) Service Types
 *
 * Types for platform daemon operations including system info and health.
 * Based on pkg/api/grpc/proto/daemon.proto
 */

// =============================================================================
// Data Types
// =============================================================================

/**
 * Platform version information
 */
export interface VersionInfo {
  /** Version string */
  version: string;
  /** Git commit hash */
  gitCommit?: string;
  /** Build date */
  buildDate?: string;
  /** Go version */
  goVersion?: string;
  /** Platform */
  platform?: string;
  /** Architecture */
  arch?: string;
}

/**
 * System information
 */
export interface SystemInfo {
  /** Hostname */
  hostname: string;
  /** Operating system */
  os: string;
  /** Architecture */
  arch: string;
  /** Kernel version */
  kernelVersion?: string;
  /** CPU count */
  cpuCount: number;
  /** Total memory in bytes */
  totalMemory: number;
  /** Available memory in bytes */
  availableMemory?: number;
  /** Boot time (unix epoch) */
  bootTime?: number;
  /** Uptime in seconds */
  uptime?: number;
}

/**
 * TPM information
 */
export interface TPMInfo {
  /** TPM available */
  available: boolean;
  /** TPM version */
  version?: string;
  /** TPM manufacturer */
  manufacturer?: string;
  /** TPM model */
  model?: string;
  /** Firmware version */
  firmwareVersion?: string;
  /** Device path */
  devicePath?: string;
  /** Is simulator */
  isSimulator?: boolean;
}

/**
 * Service health status
 */
export interface ServiceHealth {
  /** Service name */
  name: string;
  /** Whether healthy */
  healthy: boolean;
  /** Status message */
  message?: string;
  /** Last check timestamp */
  lastCheck?: string;
  /** Latency in milliseconds */
  latencyMs?: number;
}

/**
 * Platform health status
 */
export interface PlatformHealth {
  /** Overall health */
  healthy: boolean;
  /** Health message */
  message?: string;
  /** Individual service health */
  services: ServiceHealth[];
  /** Check timestamp */
  timestamp: string;
}

/**
 * Platform configuration
 */
export interface PlatformConfig {
  /** Config version */
  version?: string;
  /** Data directory */
  dataDir?: string;
  /** Config file path */
  configFile?: string;
  /** Log level */
  logLevel?: string;
  /** Debug mode */
  debug?: boolean;
  /** Additional settings */
  settings?: Record<string, string>;
}

/**
 * Platform metrics
 */
export interface PlatformMetrics {
  /** CPU usage percentage */
  cpuUsagePercent: number;
  /** Memory usage percentage */
  memoryUsagePercent: number;
  /** Disk usage percentage */
  diskUsagePercent?: number;
  /** Active connections */
  activeConnections?: number;
  /** Requests per second */
  requestsPerSecond?: number;
  /** Error rate */
  errorRate?: number;
  /** Timestamp */
  timestamp: string;
}

/**
 * License information
 */
export interface LicenseInfo {
  /** License type */
  type: string;
  /** License key (partial) */
  keyPartial?: string;
  /** Organization */
  organization?: string;
  /** Expiration date */
  expiresAt?: string;
  /** Features enabled */
  features?: string[];
  /** Node limit */
  nodeLimit?: number;
  /** Is valid */
  valid: boolean;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Get version request
 */
export interface GetVersionRequest {}

/**
 * Get system info request
 */
export interface GetSystemInfoRequest {}

/**
 * Get TPM info request
 */
export interface GetTPMInfoRequest {}

/**
 * Get health request
 */
export interface GetHealthRequest {
  /** Include service details */
  includeServices?: boolean;
}

/**
 * Get config request
 */
export interface GetConfigRequest {
  /** Include sensitive values */
  includeSensitive?: boolean;
}

/**
 * Update config request
 */
export interface UpdateConfigRequest {
  /** Settings to update */
  settings: Record<string, string>;
  /** Persist changes */
  persist?: boolean;
}

/**
 * Get metrics request
 */
export interface GetMetricsRequest {
  /** Include historical data */
  includeHistory?: boolean;
}

/**
 * Get license request
 */
export interface GetLicenseRequest {}

/**
 * Reload config request
 */
export interface ReloadConfigRequest {}

/**
 * Shutdown request
 */
export interface ShutdownRequest {
  /** Graceful shutdown timeout in seconds */
  timeoutSeconds?: number;
  /** Force immediate shutdown */
  force?: boolean;
}

/**
 * Restart request
 */
export interface RestartRequest {
  /** Graceful restart timeout in seconds */
  timeoutSeconds?: number;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface PlatformStatus {
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

/**
 * Get version response
 */
export interface GetVersionResponse {
  /** Version info */
  version: VersionInfo;
}

/**
 * Get system info response
 */
export interface GetSystemInfoResponse {
  /** System info */
  system: SystemInfo;
}

/**
 * Get TPM info response
 */
export interface GetTPMInfoResponse {
  /** TPM info */
  tpm: TPMInfo;
}

/**
 * Get health response
 */
export interface GetHealthResponse {
  /** Platform health */
  health: PlatformHealth;
}

/**
 * Get config response
 */
export interface GetConfigResponse {
  /** Platform config */
  config: PlatformConfig;
}

/**
 * Update config response
 */
export interface UpdateConfigResponse {
  /** Operation status */
  status: PlatformStatus;
  /** Updated config */
  config?: PlatformConfig;
}

/**
 * Get metrics response
 */
export interface GetMetricsResponse {
  /** Current metrics */
  metrics: PlatformMetrics;
  /** Historical metrics */
  history?: PlatformMetrics[];
}

/**
 * Get license response
 */
export interface GetLicenseResponse {
  /** License info */
  license: LicenseInfo;
}

/**
 * Reload config response
 */
export interface ReloadConfigResponse {
  /** Operation status */
  status: PlatformStatus;
}

/**
 * Shutdown response
 */
export interface ShutdownResponse {
  /** Operation status */
  status: PlatformStatus;
}

/**
 * Restart response
 */
export interface RestartResponse {
  /** Operation status */
  status: PlatformStatus;
}
