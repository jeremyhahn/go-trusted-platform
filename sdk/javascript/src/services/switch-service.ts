/**
 * Switch Service
 *
 * Port operations on a managed switch (docs/switch/api.md §3, §5.1).
 * Port names contain slashes (`Eth1/3`); every path segment is escaped, so a
 * port travels as `Eth1%2F3` and matches the server's encoded-path route.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** Port mode reported by the switch. */
export type SwitchPortMode = 'access' | 'trunk';

/** Status of one switch port (`switchwire.PortStatus`). */
export interface SwitchPortStatus {
  port: string;
  mode: SwitchPortMode;
  access_vlan: number;
  trunk_vlans?: number[];
  native_vlan?: number;
  enabled: boolean;
  link_up: boolean;
  description?: string;
}

/** Acknowledgement of an enable or disable request. */
export interface SwitchPortActionResponse {
  switch: string;
  port: string;
  action: 'enable' | 'disable';
  status: string;
}

/** Acknowledgement of a VLAN change. */
export interface SwitchSetPortVLANResponse {
  switch: string;
  port: string;
  vlan_id: number;
  status: string;
}

/** Highest VLAN id the server accepts. */
export const SWITCH_MAX_VLAN_ID = 4094;

/**
 * Switch Service class
 *
 * @example
 * ```typescript
 * const ports = await client.switches.listPorts('core-1');
 * await client.switches.setPortVLAN('core-1', 'Eth1/3', 200);
 * ```
 */
export class SwitchService extends BaseService {
  /**
   * Creates a new switch service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/switches');
  }

  private portPath(switchName: string, port?: string, suffix = ''): string {
    const base = `/${this.encodePathSegment(switchName)}/ports`;
    if (port === undefined) {
      return this.buildUrl(base);
    }
    return this.buildUrl(`${base}/${this.encodePathSegment(port)}${suffix}`);
  }

  /**
   * List the ports of a switch
   *
   * @param switchName - Switch name
   * @returns Status of every port
   */
  async listPorts(switchName: string): Promise<ApiResponse<SwitchPortStatus[]>> {
    return this.client.get<SwitchPortStatus[]>(this.portPath(switchName));
  }

  /**
   * Get the status of one port
   *
   * @param switchName - Switch name
   * @param port - Port name, for example `Eth1/3`
   * @returns Port status
   */
  async getPortStatus(switchName: string, port: string): Promise<ApiResponse<SwitchPortStatus>> {
    return this.client.get<SwitchPortStatus>(this.portPath(switchName, port));
  }

  /**
   * Enable a port (no body)
   *
   * @param switchName - Switch name
   * @param port - Port name
   * @returns Acknowledgement
   */
  async enablePort(switchName: string, port: string): Promise<ApiResponse<SwitchPortActionResponse>> {
    return this.client.post<SwitchPortActionResponse>(this.portPath(switchName, port, '/enable'));
  }

  /**
   * Disable a port (no body)
   *
   * @param switchName - Switch name
   * @param port - Port name
   * @returns Acknowledgement
   */
  async disablePort(switchName: string, port: string): Promise<ApiResponse<SwitchPortActionResponse>> {
    return this.client.post<SwitchPortActionResponse>(this.portPath(switchName, port, '/disable'));
  }

  /**
   * Set the access VLAN of a port
   *
   * @param switchName - Switch name
   * @param port - Port name
   * @param vlanId - VLAN id, 1 to 4094
   * @returns Acknowledgement
   */
  async setPortVLAN(
    switchName: string,
    port: string,
    vlanId: number
  ): Promise<ApiResponse<SwitchSetPortVLANResponse>> {
    if (!Number.isInteger(vlanId) || vlanId < 1 || vlanId > SWITCH_MAX_VLAN_ID) {
      throw new RangeError(`vlan_id must be an integer from 1 to ${SWITCH_MAX_VLAN_ID}`);
    }
    return this.client.post<SwitchSetPortVLANResponse>(
      this.portPath(switchName, port, '/vlan'),
      { vlan_id: vlanId }
    );
  }
}
