/**
 * Platform (Daemon) Service
 *
 * Provides operations for platform daemon management including system info and health.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import { TPM_BASE_PATH } from './tpm-service.js';
import type { TPMInfoResponse } from '../types/tpm.js';
import type {
  GetVersionResponse,
  GetSystemInfoResponse,
  GetHealthRequest,
  GetHealthResponse,
  GetConfigRequest,
  GetConfigResponse,
  GetMetricsRequest,
  GetMetricsResponse,
  ReloadConfigResponse,
  DaemonStatusResponse,
  DaemonServiceInfo,
  ListDaemonServicesResponse,
  DaemonServiceAction,
  DaemonServiceActionResponse,
} from '../types/platform.js';

/**
 * Which listener's route layout the platform service speaks for getStatus
 * and the service-management methods. The webservice listener serves them
 * under /api/v1/platform; the daemon REST listener registers /api/v1/status
 * and /api/v1/services (pkg/api/daemon/rest_service.go).
 */
export type PlatformRouteLayout = 'webservice' | 'daemon';

/**
 * Platform service options
 */
export interface PlatformServiceOptions {
  /** Route layout; defaults to 'webservice' */
  routeLayout?: PlatformRouteLayout | undefined;
}

/**
 * Platform Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Get platform version
 * const version = await client.platform.getVersion();
 * console.log(`Platform version: ${version.data.version.version}`);
 *
 * // Check platform health
 * const health = await client.platform.getHealth({ includeServices: true });
 * if (!health.data.health.healthy) {
 *   console.error('Platform unhealthy!');
 * }
 *
 * // Get TPM info; a successful response means a TPM is available
 * const tpm = await client.platform.getTPMInfo();
 * if (tpm.success) {
 *   console.log(`TPM: ${tpm.data.version}, ${tpm.data.manufacturer?.name ?? 'unknown vendor'}`);
 * }
 * ```
 */
export class PlatformService extends BaseService {
  /**
   * Creates a new Platform service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient, options?: PlatformServiceOptions) {
    super(client, '/v1/platform');
    this.lifecycleBasePath = (options?.routeLayout ?? 'webservice') === 'daemon' ? '/v1' : '/v1/platform';
  }

  /** Base path of getStatus and the service-management routes. */
  private readonly lifecycleBasePath: string;

  // =========================================================================
  // Information Operations
  // =========================================================================

  /**
   * Get platform version
   *
   * @returns Version information
   */
  async getVersion(): Promise<ApiResponse<GetVersionResponse>> {
    return this.client.get<GetVersionResponse>(this.buildUrl('/version'));
  }

  /**
   * Get system information
   *
   * @returns System information
   */
  async getSystemInfo(): Promise<ApiResponse<GetSystemInfoResponse>> {
    return this.client.get<GetSystemInfoResponse>(this.buildUrl('/system'));
  }

  /**
   * Get TPM information
   *
   * @returns TPM information
   */
  async getTPMInfo(): Promise<ApiResponse<TPMInfoResponse>> {
    return this.client.get<TPMInfoResponse>(this.buildUrlUnder(TPM_BASE_PATH, '/info'));
  }

  // =========================================================================
  // Health Operations
  // =========================================================================

  /**
   * Get platform health status
   *
   * @param request - Health request options
   * @returns Health status
   */
  async getHealth(request?: GetHealthRequest): Promise<ApiResponse<GetHealthResponse>> {
    return this.client.get<GetHealthResponse>(this.buildUrl('/health', {
      filters: { includeServices: request?.includeServices?.toString() },
    }));
  }

  // =========================================================================
  // Configuration Operations
  // =========================================================================

  /**
   * Get platform configuration
   *
   * @param request - Config request options
   * @returns Platform configuration
   */
  async getConfig(request?: GetConfigRequest): Promise<ApiResponse<GetConfigResponse>> {
    return this.client.get<GetConfigResponse>(this.buildUrl('/config', {
      filters: { includeSensitive: request?.includeSensitive?.toString() },
    }));
  }

  /**
   * Reload platform configuration from disk
   *
   * @returns Reload result
   */
  async reloadConfig(): Promise<ApiResponse<ReloadConfigResponse>> {
    return this.client.post<ReloadConfigResponse>(this.buildUrl('/config/reload'), {});
  }

  // =========================================================================
  // Metrics Operations
  // =========================================================================

  /**
   * Get platform metrics
   *
   * @param request - Metrics request options
   * @returns Platform metrics
   */
  async getMetrics(request?: GetMetricsRequest): Promise<ApiResponse<GetMetricsResponse>> {
    return this.client.get<GetMetricsResponse>(this.buildUrl('/metrics', {
      filters: { includeHistory: request?.includeHistory?.toString() },
    }));
  }

  // =========================================================================
  // License Operations
  // =========================================================================

  // =========================================================================
  // Lifecycle Operations
  // =========================================================================

  /**
   * Get the daemon status
   *
   * @returns Daemon status
   */
  async getStatus(): Promise<ApiResponse<DaemonStatusResponse>> {
    return this.client.get<DaemonStatusResponse>(this.buildUrlUnder(this.lifecycleBasePath, '/status'));
  }

  /**
   * List the daemon services
   *
   * @returns Services and their status
   */
  async listServices(): Promise<ApiResponse<ListDaemonServicesResponse>> {
    return this.client.get<ListDaemonServicesResponse>(this.buildUrlUnder(this.lifecycleBasePath, '/services'));
  }

  /**
   * Get one daemon service's status
   *
   * @param service - Service name
   * @returns Service status
   */
  async getServiceStatus(service: string): Promise<ApiResponse<DaemonServiceInfo>> {
    return this.client.get<DaemonServiceInfo>(
      this.buildUrlUnder(this.lifecycleBasePath, `/services/${encodeURIComponent(service)}`)
    );
  }

  /**
   * Start a daemon service
   *
   * @param service - Service name
   * @returns Action result
   */
  async startService(service: string): Promise<ApiResponse<DaemonServiceActionResponse>> {
    return this.serviceAction(service, 'start');
  }

  /**
   * Stop a daemon service
   *
   * @param service - Service name
   * @returns Action result
   */
  async stopService(service: string): Promise<ApiResponse<DaemonServiceActionResponse>> {
    return this.serviceAction(service, 'stop');
  }

  /**
   * Restart a daemon service
   *
   * @param service - Service name
   * @returns Action result
   */
  async restartService(service: string): Promise<ApiResponse<DaemonServiceActionResponse>> {
    return this.serviceAction(service, 'restart');
  }

  private async serviceAction(
    service: string,
    action: DaemonServiceAction
  ): Promise<ApiResponse<DaemonServiceActionResponse>> {
    // No automatic retries: a network error can arrive after the daemon
    // acted, and the REST handler has no idempotency key, so a resend could
    // stop or restart the service a second time.
    return this.client.post<DaemonServiceActionResponse>(
      this.buildUrlUnder(this.lifecycleBasePath, `/services/${encodeURIComponent(service)}/${action}`),
      {},
      { retry: { enabled: false } }
    );
  }

}
