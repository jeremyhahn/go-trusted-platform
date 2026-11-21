/**
 * Container registry service: tag listing and manifest deletion over the
 * OCI distribution surface (/v2), image inspection by tag and the registry
 * status endpoint.
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

/*
 * Image detail types of GET /v1/compute/images/{repository}:{tag}. They are
 * the daemon's Go structs, which carry no json tags, so the keys are
 * capitalized; int64 values arrive as numbers and times as RFC 3339 strings.
 */

/** One layer of an image manifest. */
export interface RegistryImageLayer {
  Digest?: string;
  Size?: number;
  MediaType?: string;
  Annotations?: Record<string, string>;
}

/** The manifest of an image. */
export interface RegistryImageManifest {
  Digest?: string;
  MediaType?: string;
  Size?: number;
  ConfigDigest?: string;
  Layers?: RegistryImageLayer[] | null;
  Annotations?: Record<string, string>;
}

/** The artifact a tag points at. */
export interface RegistryImageArtifact {
  ID?: string;
  Repository?: string;
  Tag?: string;
  Digest?: string;
  Size?: number;
  Manifest?: RegistryImageManifest | null;
  Labels?: Record<string, string>;
  OS?: string;
  Architecture?: string;
  Author?: string;
  CreatedAt?: string;
  PushedAt?: string;
  PullCount?: number;
}

/** A signature over an image. */
export interface RegistryImageSignature {
  KeyID?: string;
  Algorithm?: string;
  Signer?: string;
  SignedAt?: string;
}

/** The vulnerability scan result of an image. */
export interface RegistryImageScan {
  Scanner?: string;
  ScannedAt?: string;
  LowCount?: number;
  MediumCount?: number;
  HighCount?: number;
  CriticalCount?: number;
}

/** Response of GET /v1/compute/images/{repository}:{tag}. */
export interface RegistryImageDetail {
  Artifact?: RegistryImageArtifact | null;
  Signatures?: RegistryImageSignature[] | null;
  ScanResult?: RegistryImageScan | null;
  Tags?: string[] | null;
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
   * Inspect an image by tag: its manifest, signatures, scan result and tags.
   * Route: GET /api/v1/compute/images/{repository}:{tag} (the server takes the
   * last colon as the tag separator). Digest references are not supported here.
   *
   * @param name - Repository name
   * @param tag - Tag
   */
  async inspect(name: string, tag: string): Promise<ApiResponse<RegistryImageDetail>> {
    return this.client.get<RegistryImageDetail>(
      this.buildUrl(`/${this.encodeRepository(name)}:${this.encodePathSegment(tag)}`)
    );
  }

  /**
   * Get the registry status.
   */
  async getStatus(): Promise<ApiResponse<RegistryStatus>> {
    return this.client.get<RegistryStatus>(this.buildUrl('/status'));
  }
}
