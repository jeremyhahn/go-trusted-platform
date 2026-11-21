/**
 * Proxy Service
 *
 * The reverse-proxy routes, backend pools, merged configuration, status and
 * SDN zone matrix (ProxyService, pkg/api/grpc/proto/proxy.proto), served by
 * the webservice on `/api/v1/proxy` (#2061). This slice carries the reads;
 * the writes follow.
 *
 * Types are protojson (lowerCamelCase); 64-bit integer fields are strings.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** Route authentication requirements (pkg/proxy AuthRequirements). */
export interface ProxyAuthRequirements {
  /** "public" | "mtls" | "token" | "mtls-or-token". */
  mode?: string;
  requireIdevid?: boolean;
  allowedZones?: string[];
  backendZone?: string;
  requireAttestation?: boolean;
  /** Maximum accepted attestation age in nanoseconds (int64). */
  attestationMaxAgeNanos?: string;
  requiredScopes?: string[];
  opaPolicy?: string;
  tokenZone?: string;
}

/** A proxy route (pkg/proxy RouteConfig). */
export interface ProxyRoute {
  id?: string;
  /** Exact hosts or "*"; empty means wildcard. */
  hosts?: string[];
  pathPrefix?: string;
  poolId?: string;
  auth?: ProxyAuthRequirements;
  stripPrefix?: boolean;
  preserveHost?: boolean;
  passthroughTcp?: boolean;
}

/** One backend of a pool (pkg/proxy BackendConfig). */
export interface ProxyBackend {
  url?: string;
  weight?: number;
}

/** Backend TLS settings (pkg/proxy BackendTLSConfig). */
export interface ProxyBackendTLS {
  trustClass?: string;
  mtlsClientCert?: boolean;
}

/** A backend pool (pkg/proxy BackendPoolConfig). */
export interface ProxyPool {
  id?: string;
  backends?: ProxyBackend[];
  /** Balancer name; empty defaults to "round-robin". */
  balancer?: string;
  tls?: ProxyBackendTLS;
  maxIdleConnsPerHost?: number;
  /** Idle connection timeout in nanoseconds (int64). */
  idleConnTimeoutNanos?: string;
}

/** One allowed (from, to) cell of the compiled zone matrix. */
export interface ProxyZonePair {
  from?: string;
  to?: string;
  /** Service allowlist for this path; empty means all services. */
  services?: string[];
}

/** GET /api/v1/proxy/routes. */
export interface ListProxyRoutesResponse {
  routes?: ProxyRoute[];
  /** Config version (uint64). */
  version?: string;
}

/** GET /api/v1/proxy/routes/{id}. */
export interface GetProxyRouteResponse {
  route?: ProxyRoute;
}

/** GET /api/v1/proxy/pools. */
export interface ListProxyPoolsResponse {
  pools?: ProxyPool[];
  /** Config version (uint64). */
  version?: string;
}

/** GET /api/v1/proxy/pools/{id}. */
export interface GetProxyPoolResponse {
  pool?: ProxyPool;
}

/** GET /api/v1/proxy/config. */
export interface GetProxyConfigResponse {
  routes?: ProxyRoute[];
  pools?: ProxyPool[];
  /** Config version (uint64). */
  version?: string;
}

/** GET /api/v1/proxy/status. */
export interface GetProxyStatusResponse {
  /** Config version (uint64). */
  version?: string;
  routeCount?: number;
  poolCount?: number;
  /** Unix seconds of the last mutation or reload (int64). */
  updatedAt?: string;
}

/** GET /api/v1/proxy/zone-matrix. */
export interface GetProxyZoneMatrixResponse {
  zones?: string[];
  pairs?: ProxyZonePair[];
}

/**
 * Proxy service client: the ProxyService reads on /api/v1/proxy.
 */
export class ProxyService extends BaseService {
  /**
   * Creates a new proxy service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/proxy');
  }

  /** List every proxy route with the config version. */
  async listRoutes(): Promise<ApiResponse<ListProxyRoutesResponse>> {
    return this.client.get<ListProxyRoutesResponse>(this.buildUrl('/routes'));
  }

  /** Get one proxy route by id. */
  async getRoute(id: string): Promise<ApiResponse<GetProxyRouteResponse>> {
    return this.client.get<GetProxyRouteResponse>(this.buildUrl(`/routes/${encodeURIComponent(id)}`));
  }

  /** List every backend pool with the config version. */
  async listPools(): Promise<ApiResponse<ListProxyPoolsResponse>> {
    return this.client.get<ListProxyPoolsResponse>(this.buildUrl('/pools'));
  }

  /** Get one backend pool by id. */
  async getPool(id: string): Promise<ApiResponse<GetProxyPoolResponse>> {
    return this.client.get<GetProxyPoolResponse>(this.buildUrl(`/pools/${encodeURIComponent(id)}`));
  }

  /** Get the merged route and pool configuration with its version. */
  async getConfig(): Promise<ApiResponse<GetProxyConfigResponse>> {
    return this.client.get<GetProxyConfigResponse>(this.buildUrl('/config'));
  }

  /** Get the configuration status (version, counts, last update). */
  async getStatus(): Promise<ApiResponse<GetProxyStatusResponse>> {
    return this.client.get<GetProxyStatusResponse>(this.buildUrl('/status'));
  }

  /** Get the SDN zone names and the allowed (from, to) pairs. */
  async getZoneMatrix(): Promise<ApiResponse<GetProxyZoneMatrixResponse>> {
    return this.client.get<GetProxyZoneMatrixResponse>(this.buildUrl('/zone-matrix'));
  }
}
