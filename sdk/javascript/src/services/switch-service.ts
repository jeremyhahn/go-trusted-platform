/**
 * Switch Service
 *
 * Physical switch ports: list, read one, move an access port's VLAN, enable
 * and disable. Wire contract: docs/switch/api.md
 * (`GET /api/v1/switches/{switch}/ports`,
 * `GET /api/v1/switches/{switch}/ports/{port}`,
 * `POST /api/v1/switches/{switch}/ports/{port}/vlan` with `{ vlan_id }`,
 * `POST /api/v1/switches/{switch}/ports/{port}/enable`,
 * `POST /api/v1/switches/{switch}/ports/{port}/disable`).
 *
 * Port names carry slashes (`Eth1/1`); the server router keeps the encoded
 * path, so both the switch and the port name are URL-encoded
 * (`Eth1/1` -> `Eth1%2F1`).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** A port's switching mode. */
export type SwitchPortMode = 'access' | 'trunk';

/** One switch port's state (snake_case, as sdk/go/wire/switchwire PortStatus). */
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

/** The answer to an enable or disable. */
export interface SwitchPortActionResponse {
  switch: string;
  port: string;
  action: string;
  status: string;
}

/** The answer to a VLAN move. */
export interface SetSwitchPortVLANResponse {
  switch: string;
  port: string;
  vlan_id: number;
  status: string;
}

/** Lowest and highest VLAN the server accepts (802.1Q usable range). */
const MIN_VLAN_ID = 1;
const MAX_VLAN_ID = 4094;

/**
 * Switch Service class
 *
 * @example
 * ```typescript
 * const ports = await client.switches.listPorts('core-1');
 * await client.switches.setPortVLAN('core-1', 'Eth1/1', 20);
 * await client.switches.disablePort('core-1', 'Eth1/1');
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

  private portPath(switchName: string, port: string, suffix = ''): string {
    return this.buildUrl(
      `/${encodeURIComponent(switchName)}/ports/${encodeURIComponent(port)}${suffix}`
    );
  }

  /**
   * List a switch's ports
   *
   * @param switchName - The switch name
   * @returns The ports and their state
   */
  async listPorts(switchName: string): Promise<ApiResponse<SwitchPortStatus[]>> {
    return this.client.get<SwitchPortStatus[]>(
      this.buildUrl(`/${encodeURIComponent(switchName)}/ports`)
    );
  }

  /**
   * Read one port's state
   *
   * @param switchName - The switch name
   * @param port - The port name, e.g. `Eth1/1`
   * @returns The port's state
   */
  async getPortStatus(switchName: string, port: string): Promise<ApiResponse<SwitchPortStatus>> {
    return this.client.get<SwitchPortStatus>(this.portPath(switchName, port));
  }

  /**
   * Move an access port to a VLAN
   *
   * @param switchName - The switch name
   * @param port - The port name
   * @param vlanId - The VLAN, an integer in 1..4094
   * @throws RangeError when vlanId is outside 1..4094 (no request is sent)
   */
  async setPortVLAN(
    switchName: string,
    port: string,
    vlanId: number
  ): Promise<ApiResponse<SetSwitchPortVLANResponse>> {
    if (!Number.isInteger(vlanId) || vlanId < MIN_VLAN_ID || vlanId > MAX_VLAN_ID) {
      throw new RangeError(
        `vlanId must be an integer in ${MIN_VLAN_ID}..${MAX_VLAN_ID}, got ${vlanId}`
      );
    }
    return this.client.post<SetSwitchPortVLANResponse>(this.portPath(switchName, port, '/vlan'), {
      vlan_id: vlanId,
    });
  }

  /**
   * Enable a port
   *
   * @param switchName - The switch name
   * @param port - The port name
   */
  async enablePort(switchName: string, port: string): Promise<ApiResponse<SwitchPortActionResponse>> {
    return this.client.post<SwitchPortActionResponse>(this.portPath(switchName, port, '/enable'), {});
  }

  /**
   * Disable a port
   *
   * @param switchName - The switch name
   * @param port - The port name
   */
  async disablePort(
    switchName: string,
    port: string
  ): Promise<ApiResponse<SwitchPortActionResponse>> {
    return this.client.post<SwitchPortActionResponse>(this.portPath(switchName, port, '/disable'), {});
  }
}
