/**
 * Reverse-proxy service: route and pool CRUD, the merged config, reload,
 * status and the zone matrix (ProxyService, /api/v1/proxy).
 *
 * Field names are protojson lowerCamelCase; uint64 and int64 values arrive
 * as decimal strings.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** Auth a route demands (mirrors pkg/proxy AuthRequirements). */
export interface ProxyAuthRequirements {
  /** "public" | "mtls" | "token" | "mtls-or-token". */
  mode?: string;
  requireIdevid?: boolean;
  allowedZones?: string[];
  backendZone?: string;
  requireAttestation?: boolean;
  /** Maximum attestation age in nanoseconds (decimal string). */
  attestationMaxAgeNanos?: string | number;
  requiredScopes?: string[];
  opaPolicy?: string;
  tokenZone?: string;
}

/** One proxy route. */
export interface ProxyRoute {
  id: string;
  /** Exact hosts or "*"; empty means wildcard. */
  hosts?: string[];
  pathPrefix?: string;
  poolId?: string;
  auth?: ProxyAuthRequirements;
  stripPrefix?: boolean;
  preserveHost?: boolean;
  /** Must be false; the engine rejects TCP passthrough. */
  passthroughTcp?: boolean;
}

/** One backend of a pool. */
export interface ProxyBackend {
  url: string;
  weight?: number;
}

/** TLS to the backends of a pool. */
export interface ProxyBackendTLS {
  trustClass?: string;
  mtlsClientCert?: boolean;
}

/** One backend pool. */
export interface ProxyPool {
  id: string;
  backends?: ProxyBackend[];
  /** Balancer name; empty defaults to "round-robin". */
  balancer?: string;
  tls?: ProxyBackendTLS;
  maxIdleConnsPerHost?: number;
  /** Idle connection timeout in nanoseconds (decimal string). */
  idleConnTimeoutNanos?: string | number;
}

/** One allowed (from, to) cell of the compiled zone matrix. */
export interface ProxyZonePair {
  from: string;
  to: string;
  /** Service allowlist; empty means all services. */
  services?: string[];
}

export interface ProxyRouteResponse {
  route?: ProxyRoute;
  version?: string;
}

export interface ProxyPoolResponse {
  pool?: ProxyPool;
  version?: string;
}

export interface ProxyVersionResponse {
  version?: string;
}

export interface ListProxyRoutesResponse {
  routes?: ProxyRoute[];
  version?: string;
}

export interface ListProxyPoolsResponse {
  pools?: ProxyPool[];
  version?: string;
}

export interface GetProxyConfigResponse {
  routes?: ProxyRoute[];
  pools?: ProxyPool[];
  version?: string;
}

export interface GetProxyStatusResponse {
  version?: string;
  routeCount?: number;
  poolCount?: number;
  /** Unix seconds of the last mutation or reload (decimal string). */
  updatedAt?: string;
}

export interface GetProxyZoneMatrixResponse {
  zones?: string[];
  pairs?: ProxyZonePair[];
}

/**
 * Service for the reverse-proxy route and pool store.
 */
export class ProxyService extends BaseService {
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/proxy');
  }

  private idPath(kind: 'routes' | 'pools', id: string): string {
    return this.buildUrl(`/${kind}/${encodeURIComponent(id)}`);
  }

  /** List every route. */
  async listRoutes(): Promise<ApiResponse<ListProxyRoutesResponse>> {
    return this.client.get<ListProxyRoutesResponse>(this.buildUrl('/routes'));
  }

  /** Create a route. */
  async createRoute(route: ProxyRoute): Promise<ApiResponse<ProxyRouteResponse>> {
    return this.client.post<ProxyRouteResponse>(this.buildUrl('/routes'), route);
  }

  /** Get one route. */
  async getRoute(id: string): Promise<ApiResponse<ProxyRouteResponse>> {
    return this.client.get<ProxyRouteResponse>(this.idPath('routes', id));
  }

  /** Replace a route; the id in the path names it. */
  async updateRoute(id: string, route: Partial<ProxyRoute>): Promise<ApiResponse<ProxyRouteResponse>> {
    return this.client.put<ProxyRouteResponse>(this.idPath('routes', id), route);
  }

  /** Delete a route. */
  async deleteRoute(id: string): Promise<ApiResponse<ProxyVersionResponse>> {
    return this.client.delete<ProxyVersionResponse>(this.idPath('routes', id));
  }

  /** List every pool. */
  async listPools(): Promise<ApiResponse<ListProxyPoolsResponse>> {
    return this.client.get<ListProxyPoolsResponse>(this.buildUrl('/pools'));
  }

  /** Create a pool. */
  async createPool(pool: ProxyPool): Promise<ApiResponse<ProxyPoolResponse>> {
    return this.client.post<ProxyPoolResponse>(this.buildUrl('/pools'), pool);
  }

  /** Get one pool. */
  async getPool(id: string): Promise<ApiResponse<ProxyPoolResponse>> {
    return this.client.get<ProxyPoolResponse>(this.idPath('pools', id));
  }

  /** Replace a pool; the id in the path names it. */
  async updatePool(id: string, pool: Partial<ProxyPool>): Promise<ApiResponse<ProxyPoolResponse>> {
    return this.client.put<ProxyPoolResponse>(this.idPath('pools', id), pool);
  }

  /** Delete a pool; refused while a route uses it. */
  async deletePool(id: string): Promise<ApiResponse<ProxyVersionResponse>> {
    return this.client.delete<ProxyVersionResponse>(this.idPath('pools', id));
  }

  /** The merged route and pool configuration and its version. */
  async getProxyConfig(): Promise<ApiResponse<GetProxyConfigResponse>> {
    return this.client.get<GetProxyConfigResponse>(this.buildUrl('/config'));
  }

  /** Bump the config version so syncing gatewayd instances reload. */
  async reloadProxyConfig(): Promise<ApiResponse<ProxyVersionResponse>> {
    return this.client.post<ProxyVersionResponse>(this.buildUrl('/config/reload'));
  }

  /** Version, counts and last update time. */
  async getStatus(): Promise<ApiResponse<GetProxyStatusResponse>> {
    return this.client.get<GetProxyStatusResponse>(this.buildUrl('/status'));
  }

  /** SDN zones and the compiled allowed (from, to) pairs. */
  async getZoneMatrix(): Promise<ApiResponse<GetProxyZoneMatrixResponse>> {
    return this.client.get<GetProxyZoneMatrixResponse>(this.buildUrl('/zone-matrix'));
  }
}
