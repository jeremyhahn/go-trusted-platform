/**
 * Platform daemon services reply types (#2047).
 *
 * The /v1/platform/services handlers answer plain Go structs, so every
 * field below is snake_case JSON, not protojson camelCase.
 */

/**
 * The state of one daemon service, as the server reports it
 * (pkg/webservice/v1/rest/platform/services.go).
 */
export type PlatformServiceState =
  | 'stopped'
  | 'starting'
  | 'running'
  | 'stopping'
  | 'error'
  | 'unknown';

/**
 * One daemon service: the Go struct ServiceInfoResponse in
 * pkg/webservice/v1/rest/platform/types.go. Fields are snake_case JSON,
 * not protojson.
 */
export interface PlatformServiceInfo {
  name: string;
  status: PlatformServiceState;
  started_at?: string;
  uptime?: string;
  start_count: number;
  stop_count: number;
  last_error?: string;
}

/**
 * The GET /v1/platform/services reply: the Go struct ServicesListResponse in
 * pkg/webservice/v1/rest/platform/types.go. Fields are snake_case JSON,
 * not protojson; timestamp is unix seconds.
 */
export interface PlatformServicesListResponse {
  services: PlatformServiceInfo[];
  count: number;
  timestamp: number;
}

/**
 * The start, stop and restart reply: the Go struct ServiceActionResponse in
 * pkg/webservice/v1/rest/platform/types.go. Fields are snake_case JSON,
 * not protojson.
 */
export interface PlatformServiceActionResponse {
  service: string;
  action: string;
  success: boolean;
  message: string;
}
