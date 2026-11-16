/**
 * Container registry service: tag listing and manifest deletion over the
 * OCI distribution surface (/v2), and the registry status endpoint.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** Registry health, as the daemon's RegistryHealthStatus enum. */
export enum RegistryHealth {
  Unspecified = 0,
  Healthy = 1,
  Degraded = 2,
  Unhealthy = 3,
}

/** One component's health inside a registry status response. */
export interface RegistryComponentHealth {
  Name?: string;
  Status?: RegistryHealth;
  Message?: string;
}

/** Response of GET /v1/compute/images/status. */
export interface RegistryStatus {
  Health: RegistryHealth;
  Version?: string;
  Storage?: Record<string, unknown> | null;
  ReadOnly?: boolean;
  Components?: RegistryComponentHealth[] | null;
  StartedAt?: string;
  Timestamp?: string;
}

/** Response of GET /v2/{name}/tags/list. */
export interface RegistryTagList {
  name: string;
  tags: string[];
}

/** OCI distribution base path. */
const OCI_BASE = '/v2';

/**
 * Service for the container registry.
 */
export class RegistryService extends BaseService {
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/compute/images');
  }

  /**
   * Encode a repository name. Names may hold slashes (`team/app`): each
   * segment is encoded on its own and the slashes are kept.
   */
  private encodeRepository(name: string): string {
    return name
      .split('/')
      .map((segment) => this.encodePathSegment(segment))
      .join('/');
  }

  /**
   * List the tags of a repository.
   *
   * @param name - Repository name
   */
  async listTags(name: string): Promise<ApiResponse<RegistryTagList>> {
    return this.client.get<RegistryTagList>(
      `${OCI_BASE}/${this.encodeRepository(name)}/tags/list`,
      { rootRelative: true }
    );
  }

  /**
   * Delete a manifest by tag or digest.
   *
   * @param name - Repository name
   * @param reference - Tag or digest
   */
  async deleteManifest(name: string, reference: string): Promise<ApiResponse<undefined>> {
    return this.client.delete<undefined>(
      `${OCI_BASE}/${this.encodeRepository(name)}/manifests/${this.encodePathSegment(reference)}`,
      { rootRelative: true }
    );
  }

  /**
   * Get the registry status.
   */
  async getStatus(): Promise<ApiResponse<RegistryStatus>> {
    return this.client.get<RegistryStatus>(this.buildUrl('/status'));
  }
}
