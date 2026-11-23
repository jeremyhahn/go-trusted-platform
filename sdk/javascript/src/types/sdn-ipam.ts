/**
 * Gateway IPAM pool types for /api/v1/sdn/gateway/ipam/pools.
 *
 * They mirror the JSON of pkg/webservice/v1/rest/gateway/ipam.go, so the
 * field names stay snake_case.
 */

/** Body of POST /sdn/gateway/ipam/pools and PUT /sdn/gateway/ipam/pools/{id}. */
export interface SDNIPAMPoolRequest {
  id?: string;
  name?: string;
  cidr?: string;
  gateway?: string;
  zone?: string;
  description?: string;
  default_lease_duration_nanos?: number;
  inactivity_timeout_nanos?: number;
  /** On update, an omitted list keeps the pool's list and [] clears it. */
  reserved?: string[];
  /** On update, an omitted bound keeps the pool's bound and '' clears it. */
  range_start?: string;
  range_end?: string;
}

/** One pool as the server answers it. */
export interface SDNIPAMPool {
  id: string;
  name: string;
  cidr: string;
  gateway?: string;
  zone?: string;
  description?: string;
  total: number;
  allocated: number;
  available: number;
  default_lease_duration_nanos?: number;
  inactivity_timeout_nanos?: number;
  reserved?: string[];
  range_start?: string;
  range_end?: string;
  created_at?: string;
  updated_at?: string;
}

/** Answer of GET /sdn/gateway/ipam/pools. */
export interface ListSDNIPAMPoolsResponse {
  pools: SDNIPAMPool[];
  count: number;
  timestamp?: string;
}

/** Filters of GET /sdn/gateway/ipam/pools. */
export interface ListSDNIPAMPoolsRequest {
  zone?: string;
}

/** Answer of DELETE /sdn/gateway/ipam/pools/{id}. */
export interface SDNIPAMActionResponse {
  resource_id: string;
  resource_type: string;
  action: string;
  success: boolean;
  message?: string;
}

/** One address allocation of GET /sdn/gateway/ipam/allocations. */
export interface SDNIPAMAllocation {
  ip: string;
  pool_id: string;
  device_id?: string;
  hostname?: string;
  status: string;
  allocated_at?: string;
  expires_at?: string;
}

/** Filters of GET /sdn/gateway/ipam/allocations. */
export interface ListSDNIPAMAllocationsRequest {
  /** Only the allocations of this pool; every pool's when omitted. */
  poolId?: string;
}

/** Answer of GET /sdn/gateway/ipam/allocations. */
export interface ListSDNIPAMAllocationsResponse {
  allocations: SDNIPAMAllocation[];
  count: number;
  timestamp?: string;
}
