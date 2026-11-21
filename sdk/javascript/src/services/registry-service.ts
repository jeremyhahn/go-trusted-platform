/**
 * Container registry service: tag listing and manifest deletion over the
 * OCI distribution surface (/v2), the image list and the registry status
 * endpoint.
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

/**
 * One image in the image list. The keys are the snake_case json tags of the
 * Go ImageSummary.
 */
export interface RegistryImageSummary {
  repository: string;
  tag: string;
  digest?: string;
  media_type?: string;
  size: number;
  layers: number;
  annotations?: Record<string, string>;
  created_at?: string;
  updated_at?: string;
}

/**
 * Response of GET /v1/compute/images. The keys are the snake_case json tags
 * of the Go ListImagesResponse.
 */
export interface RegistryImageList {
  images: RegistryImageSummary[];
  total: number;
}

/**
 * Query of GET /v1/compute/images. The keys are the snake_case query
 * parameters the Go handler reads before it answers with ImageSummary
 * entries in a ListImagesResponse.
 */
export interface ListImagesRequest {
  /** Only images of this repository. */
  repository?: string;
  /** Page size; the server defaults to 200. */
  limit?: number;
  /** Number of images to skip. */
  offset?: number;
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

  /**
   * List the images in the registry (RegistryService.List), through
   * `GET /api/v1/compute/images`. The server's default limit is 200.
   *
   * An empty repository and a negative or non-finite limit or offset are
   * left out of the query; a fractional limit or offset is floored.
   *
   * @param request - Optional repository filter and paging
   */
  async listImages(request?: ListImagesRequest): Promise<ApiResponse<RegistryImageList>> {
    const params = new URLSearchParams();
    if (typeof request?.repository === 'string' && request.repository !== '') {
      params.set('repository', request.repository);
    }
    for (const key of ['limit', 'offset'] as const) {
      const n = request?.[key];
      if (typeof n === 'number' && Number.isFinite(n) && n >= 0) {
        params.set(key, String(Math.floor(n)));
      }
    }
    const query = params.toString();
    const url = this.buildUrl();
    return this.client.get<RegistryImageList>(query ? `${url}?${query}` : url);
  }
}
