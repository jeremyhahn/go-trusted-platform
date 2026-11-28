/**
 * Network zone wire types for the served `/api/v1/sdn/zones` routes.
 *
 * The handler (pkg/webservice/v1/rest/sdn/zones.go) decodes plain JSON, so
 * the field names are the handler's snake_case JSON names.
 */

/** An allowed path to another zone (zones.go NetworkZonePathSpec). */
export interface NetworkZonePathSpec {
  zone: string;
  services?: string[];
}

/** The reason and approver of a privileged zone (zones.go NetworkZonePrivilegedAccess). */
export interface NetworkZonePrivilegedAccess {
  reason: string;
  approved_by: string;
}

/** The optional fields of a zone request (zones.go NetworkZoneRequest). */
export interface NetworkZoneSpec {
  offset?: number;
  port_classes?: string[];
  internet_ingress?: boolean;
  isolate_from?: string[];
  allow_to?: NetworkZonePathSpec[];
  services?: string[];
  isolate?: boolean;
  oob?: boolean;
  lifecycle_role?: string;
  privileged_access?: NetworkZonePrivilegedAccess;
}

/** The body of POST /api/v1/sdn/zones (zones.go NetworkZoneRequest, name required). */
export type CreateNetworkZoneRequest = NetworkZoneSpec & { name: string };

/** The body of PUT /api/v1/sdn/zones/{name} (zones.go NetworkZoneRequest; the path names the zone). */
export type UpdateNetworkZoneRequest = NetworkZoneSpec;

/** The numbering derived for a zone (zones.go NetworkZoneResponse numbering). */
export interface NetworkZoneNumbering {
  vlan: number;
  subnet4: string;
  subnet6?: string;
  gateway: string;
}

/** A zone as the handler returns it (zones.go NetworkZoneResponse). */
export type NetworkZone = NetworkZoneSpec & {
  name: string;
  numbering?: NetworkZoneNumbering;
  restart_required?: boolean;
  created_at: string;
  updated_at: string;
};

/** The query of GET /api/v1/sdn/zones (zones.go ListZones `lifecycle_role`). */
export interface ListNetworkZonesRequest {
  lifecycleRole?: string;
}

/** The body of GET /api/v1/sdn/zones (zones.go NetworkZoneListResponse). */
export interface ListNetworkZonesResponse {
  zones: NetworkZone[];
  count: number;
  timestamp: string;
}

/** The body of DELETE /api/v1/sdn/zones/{name} (zones.go NetworkZoneDeleteResponse). */
export interface NetworkZoneDeleteResponse {
  deleted: boolean;
  restart_required: boolean;
}
