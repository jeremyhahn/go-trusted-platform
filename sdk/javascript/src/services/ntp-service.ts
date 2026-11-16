/**
 * NTP Service
 *
 * Time synchronisation status, configured sources and a one-shot clock step.
 * Wire contract: docs/ntp/api.md (`GET /api/v1/ntp/status`,
 * `GET /api/v1/ntp/sources`, `POST /api/v1/ntp/step`, no request bodies).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** One advertised NTS-KE server name clients cannot usefully dial. */
export interface NTSServeNameFinding {
  kind: string;
  name: string;
  address: string;
  listenNetworks: string[];
  error: string;
}

/** Node clock synchronisation status (protojson, lowerCamelCase). */
export interface NTPStatus {
  synced: boolean;
  stratum: number;
  leapStatus: string;
  offsetSeconds: number;
  rootDispersion: number;
  rootDelay: number;
  /** Seconds since the epoch; 0 means never synced. */
  lastSyncUnix: number | string;
  mode: string;
  referenceId: string;
  referenceName: string;
  sourcesReachable: number;
  sourcesTotal: number;
  anomaly: boolean;
  anomalyReason: string;
  serveNameFindings?: NTSServeNameFinding[];
}

/** One configured time source. */
export interface NTPSource {
  address: string;
  mode: string;
  state: string;
  stratum: number;
  pollSeconds: number;
  reach: number;
  lastRxSeconds: number | string;
  offsetSeconds: number;
  reachable: boolean;
}

export interface GetNTPStatusResponse {
  status: NTPStatus;
}

export interface ListNTPSourcesResponse {
  sources: NTPSource[];
}

export interface StepNTPClockResponse {
  status: NTPStatus;
}

/**
 * NTP Service class
 *
 * @example
 * ```typescript
 * const status = await client.ntp.getStatus();
 * const sources = await client.ntp.listSources();
 * await client.ntp.step();
 * ```
 */
export class NTPService extends BaseService {
  /**
   * Creates a new NTP service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/ntp');
  }

  /**
   * Get the node's clock synchronisation status
   *
   * @returns NTP status
   */
  async getStatus(): Promise<ApiResponse<GetNTPStatusResponse>> {
    return this.client.get<GetNTPStatusResponse>(this.buildUrl('/status'));
  }

  /**
   * List the configured time sources
   *
   * @returns Time sources
   */
  async listSources(): Promise<ApiResponse<ListNTPSourcesResponse>> {
    return this.client.get<ListNTPSourcesResponse>(this.buildUrl('/sources'));
  }

  /**
   * Step the clock to the selected source at once
   *
   * @returns The status after the step
   */
  async step(): Promise<ApiResponse<StepNTPClockResponse>> {
    return this.client.post<StepNTPClockResponse>(this.buildUrl('/step'));
  }
}
