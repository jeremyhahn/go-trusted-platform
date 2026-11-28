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
  PlatformServicesListResponse,
  PlatformServiceInfo,
  PlatformServiceActionResponse,
} from '../types/platform-services.js';
import type {
  GetVersionResponse,
  GetSystemInfoResponse,
  GetHealthRequest,
  GetHealthResponse,
  UpdateConfigSectionRequest,
  UpdateConfigSectionResponse,
  GetConfigRequest,
  GetConfigResponse,
  ListEntityTypesResponse,
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
 * The daemon layout returns `timestamp` as an RFC 3339 string (Go time.Time).
 * Normalize it to Unix seconds so callers always see the declared number;
 * an unparseable string is dropped rather than returned as NaN.
 */
function withUnixTimestamp<T extends { timestamp?: number | undefined }>(
  response: ApiResponse<T>
): ApiResponse<T> {
  const data = response.data as (T & { timestamp?: unknown }) | undefined;
  if (data === undefined || data === null || typeof data.timestamp !== 'string') {
    return response;
  }
  const ms = Date.parse(data.timestamp);
  const normalized = { ...data } as T & { timestamp?: number | undefined };
  if (Number.isNaN(ms)) {
    delete normalized.timestamp;
  } else {
    normalized.timestamp = Math.floor(ms / 1000);
  }
  return { ...response, data: normalized };
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
   * Get the effective platform configuration (`GET /api/v1/platform/config`)
   *
   * Sends `redact=false` when `includeSensitive` is true and
   * `section=<name>` when a section is named; neither is sent otherwise.
   *
   * @param request - Config request options
   * @returns The config tree, its sources and the redaction state
   */
  async getConfig(request?: GetConfigRequest): Promise<ApiResponse<GetConfigResponse>> {
    const params = new URLSearchParams();
    if (request?.includeSensitive === true) {
      params.set('redact', 'false');
    }
    if (typeof request?.section === 'string' && request.section !== '') {
      params.set('section', request.section);
    }
    const query = params.toString();
    const url = this.buildUrl('/config');
    return this.client.get<GetConfigResponse>(query ? `${url}?${query}` : url);
  }

  /**
   * Reload platform configuration from disk
   *
   * @returns `reloaded`, the `sections` the reload applied and the
   *   `pre_reload_snapshot` id taken before it
   */
  async reloadConfig(): Promise<ApiResponse<ReloadConfigResponse>> {
    return this.client.post<ReloadConfigResponse>(this.buildUrl('/config/reload'), {});
  }

  /**
   * Apply (and optionally persist) one config section.
   * `PUT /api/v1/platform/config/sections/{section}`, served by
   * PlatformDaemon.UpdateConfig.
   */
  async updateConfigSection(
    section: string,
    request: UpdateConfigSectionRequest,
  ): Promise<ApiResponse<UpdateConfigSectionResponse>> {
    return this.client.put<UpdateConfigSectionResponse>(
      this.buildUrl(`/config/sections/${this.encodePathSegment(section)}`),
      { values: request.values, persist: request.persist ?? false },
    );
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

  /**
   * List storage entity types and their entity counts
   * (GET /api/v1/platform/entity-types, PlatformDaemon.ListEntityTypes)
   *
   * @returns Entity types, total entities and active type count
   */
  async listEntityTypes(): Promise<ApiResponse<ListEntityTypesResponse>> {
    return this.client.get<ListEntityTypesResponse>(this.buildUrl('/entity-types'));
  }

  // =========================================================================
  // License Operations
  // =========================================================================

  // =========================================================================
  // Lifecycle Operations
  // =========================================================================

  /**
   * Get the platform daemon status; an RFC 3339 timestamp is normalized to
   * Unix seconds.
   * REST: GET /v1/platform/status (webservice layout) or GET /v1/status
   * (daemon layout).
   */
  async getStatus(): Promise<ApiResponse<DaemonStatusResponse>> {
    return withUnixTimestamp(
      await this.client.get<DaemonStatusResponse>(
        this.buildUrlUnder(this.lifecycleBasePath, '/status')
      )
    );
  }

  /**
   * List the daemon services and their state.
   * REST: GET /v1/platform/services (webservice layout) or GET /v1/services
   * (daemon layout) (PlatformDaemon.ListServices).
   */
  async listServices(): Promise<ApiResponse<PlatformServicesListResponse>> {
    return withUnixTimestamp(
      await this.client.get<PlatformServicesListResponse>(
        this.buildUrlUnder(this.lifecycleBasePath, '/services')
      )
    );
  }

  /**
   * Get one daemon service's state; an unknown name answers 404.
   * REST: GET /v1/platform/services/{service} (webservice layout) or
   * GET /v1/services/{service} (daemon layout) (PlatformDaemon.GetServiceStatus).
   */
  async getServiceStatus(name: string): Promise<ApiResponse<PlatformServiceInfo>> {
    return this.client.get<PlatformServiceInfo>(
      this.buildUrlUnder(this.lifecycleBasePath, `/services/${this.encodePathSegment(name)}`)
    );
  }

  /**
   * Start a daemon service.
   * REST: POST /v1/platform/services/{service}/start (webservice layout) or
   * POST /v1/services/{service}/start (daemon layout) (PlatformDaemon.StartService).
   */
  async startService(name: string): Promise<ApiResponse<PlatformServiceActionResponse>> {
    return this.client.post<PlatformServiceActionResponse>(
      this.buildUrlUnder(this.lifecycleBasePath, `/services/${this.encodePathSegment(name)}/start`),
      {}
    );
  }

  /**
   * Stop a daemon service.
   * REST: POST /v1/platform/services/{service}/stop (webservice layout) or
   * POST /v1/services/{service}/stop (daemon layout) (PlatformDaemon.StopService).
   */
  async stopService(name: string): Promise<ApiResponse<PlatformServiceActionResponse>> {
    return this.client.post<PlatformServiceActionResponse>(
      this.buildUrlUnder(this.lifecycleBasePath, `/services/${this.encodePathSegment(name)}/stop`),
      {}
    );
  }

  /**
   * Restart a daemon service.
   * REST: POST /v1/platform/services/{service}/restart (webservice layout) or
   * POST /v1/services/{service}/restart (daemon layout) (PlatformDaemon.RestartService).
   */
  async restartService(name: string): Promise<ApiResponse<PlatformServiceActionResponse>> {
    return this.client.post<PlatformServiceActionResponse>(
      this.buildUrlUnder(this.lifecycleBasePath, `/services/${this.encodePathSegment(name)}/restart`),
      {}
    );
  }
}
