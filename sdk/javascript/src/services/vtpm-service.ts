/**
 * Virtual TPM (vTPM) Service
 *
 * Provides operations for vTPM bundle management including creation, cloning,
 * and templates. A bundle IS the per-guest-VM vTPM instance: the former
 * `/instances/*` surface (a separate VTPMInstanceService) was collapsed into
 * this bundle surface. Profile binding and profile-filtered listing are
 * expressed through the bundle create/list options (`deviceProfileId`), not a
 * distinct endpoint.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  CreateBundleRequest,
  ListBundlesRequest,
  CreateTemplateRequest,
  CloneTemplateRequest,
  CreateBundleResponse,
  GetBundleResponse,
  DeleteBundleResponse,
  ListBundlesResponse,
  CreateTemplateResponse,
  GetTemplateResponse,
  DeleteTemplateResponse,
  ListTemplatesResponse,
  CloneTemplateResponse,
  ValidateBundleResponse,
  GetBundlePathResponse,
  GetTPMSocketPathResponse,
  GetNVRAMPathResponse,
  CreateBundleOptions,
  CreateTemplateOptions,
} from '../types/vtpm.js';
import { BUNDLE_MODE_WIRE_NAMES, EK_ALGORITHM_WIRE_NAMES } from '../types/vtpm.js';
import { encodeOptionalEnum } from './wire-enum.js';

/** Thrown when a device profile ID is not an unsigned integer the server can read. */
export class InvalidDeviceProfileIdError extends Error {
  /** The rejected ID. */
  public readonly deviceProfileId: string;

  constructor(deviceProfileId: string) {
    super(`device profile id ${JSON.stringify(deviceProfileId)} is not an unsigned integer`);
    this.name = 'InvalidDeviceProfileIdError';
    this.deviceProfileId = deviceProfileId;
  }
}

/**
 * The bundle body pkg/webservice/v1/rest/vtpm/types.go decodes: flat,
 * snake_case, and unknown fields are refused.
 */
interface WireCreateBundleRequest {
  mode?: string;
  hostname?: string;
  ek_algorithm?: string;
  secure_boot_enabled?: boolean;
  labels?: Record<string, string>;
  template_id?: string;
  device_profile_id?: number;
}

/** The template body the REST handler decodes. */
interface WireCreateTemplateRequest {
  id: string;
  description?: string;
  ek_algorithm?: string;
  secure_boot_enabled?: boolean;
}

/** Parses a uint64 device profile ID; JSON can carry it exactly only up to 2^53 - 1. */
function toDeviceProfileId(id: string): number {
  const parsed = /^\d+$/.test(id) ? Number(id) : Number.NaN;
  if (!Number.isSafeInteger(parsed)) {
    throw new InvalidDeviceProfileIdError(id);
  }
  return parsed;
}

function toWireCreateBundle(options: CreateBundleOptions): WireCreateBundleRequest {
  const mode = encodeOptionalEnum('mode', BUNDLE_MODE_WIRE_NAMES, options.mode);
  const ekAlgorithm = encodeOptionalEnum('ekAlgorithm', EK_ALGORITHM_WIRE_NAMES, options.ekAlgorithm);
  return {
    ...(mode !== undefined && { mode }),
    ...(options.hostname !== undefined && { hostname: options.hostname }),
    ...(ekAlgorithm !== undefined && { ek_algorithm: ekAlgorithm }),
    ...(options.secureBootEnabled !== undefined && { secure_boot_enabled: options.secureBootEnabled }),
    ...(options.labels !== undefined && { labels: options.labels }),
    ...(options.templateId !== undefined && { template_id: options.templateId }),
    ...(options.deviceProfileId !== undefined && { device_profile_id: toDeviceProfileId(options.deviceProfileId) }),
  };
}

function toWireCreateTemplate(options: CreateTemplateOptions): WireCreateTemplateRequest {
  const ekAlgorithm = encodeOptionalEnum('ekAlgorithm', EK_ALGORITHM_WIRE_NAMES, options.ekAlgorithm);
  return {
    id: options.id,
    ...(options.description !== undefined && { description: options.description }),
    ...(ekAlgorithm !== undefined && { ek_algorithm: ekAlgorithm }),
    ...(options.secureBootEnabled !== undefined && { secure_boot_enabled: options.secureBootEnabled }),
  };
}

/**
 * vTPM Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a vTPM bundle bound to a device profile
 * const bundle = await client.vtpm.createBundle({
 *   options: {
 *     hostname: 'vm-001',
 *     ekAlgorithm: 'RSA',
 *     secureBootEnabled: true,
 *     deviceProfileId: '4242',
 *   }
 * });
 *
 * // Clone from template
 * const cloned = await client.vtpm.cloneTemplate({
 *   options: {
 *     templateId: 'default-template',
 *     hostname: 'vm-002',
 *   }
 * });
 * ```
 */
export class VTPMService extends BaseService {
  /**
   * Creates a new vTPM service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/vtpm');
  }

  // =========================================================================
  // Bundle Operations
  //
  // A bundle is the canonical per-guest-VM vTPM (TPM state, OVMF NVRAM,
  // optional Secure Boot keys, and — when a CA is configured — a CA-issued EK
  // certificate). Bundle create/list carry the device-profile binding used to
  // provision and discover a VM's vTPM identity.
  // =========================================================================

  /**
   * Create a new vTPM bundle
   *
   * @param request - Bundle creation request
   * @returns Created bundle
   */
  async createBundle(request: CreateBundleRequest): Promise<ApiResponse<CreateBundleResponse>> {
    return this.client.post<CreateBundleResponse>(this.buildUrl('/bundles'), toWireCreateBundle(request.options));
  }

  /**
   * Get a vTPM bundle by ID
   *
   * @param id - Bundle identifier
   * @returns Bundle information
   */
  async getBundle(id: string): Promise<ApiResponse<GetBundleResponse>> {
    return this.client.get<GetBundleResponse>(
      this.buildUrl(`/bundles/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * Delete a vTPM bundle
   *
   * @param id - Bundle identifier
   * @returns Deletion result
   */
  async deleteBundle(id: string): Promise<ApiResponse<DeleteBundleResponse>> {
    return this.client.delete<DeleteBundleResponse>(
      this.buildUrl(`/bundles/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * List vTPM bundles
   *
   * @param request - List request with filters (mode, labels, pagination, and
   *                  optional deviceProfileId to return only the bundle bound
   *                  to a given device profile)
   * @returns List of bundles
   */
  async listBundles(request?: ListBundlesRequest): Promise<ApiResponse<ListBundlesResponse>> {
    const filters: Record<string, string | number | boolean | undefined> = {};
    if (request?.options?.mode !== undefined) {
      filters.mode = request.options.mode;
    }
    if (request?.options?.labels !== undefined) {
      Object.entries(request.options.labels).forEach(([k, v]) => {
        filters[`label_${k}`] = v;
      });
    }
    if (request?.options?.deviceProfileId !== undefined) {
      filters.device_profile_id = request.options.deviceProfileId;
    }
    return this.client.get<ListBundlesResponse>(this.buildUrl('/bundles', {
      limit: request?.options?.limit,
      page: request?.options?.offset !== undefined
        ? Math.floor(request.options.offset / (request.options.limit ?? 10)) + 1
        : undefined,
      filters,
    }));
  }

  /**
   * Validate a vTPM bundle
   *
   * @param id - Bundle identifier
   * @returns Validation result
   */
  async validateBundle(id: string): Promise<ApiResponse<ValidateBundleResponse>> {
    return this.client.post<ValidateBundleResponse>(
      this.buildUrl(`/bundles/${this.encodePathSegment(id)}/validate`),
      {}
    );
  }

  /**
   * Get bundle filesystem path
   *
   * @param id - Bundle identifier
   * @returns Bundle path
   */
  async getBundlePath(id: string): Promise<ApiResponse<GetBundlePathResponse>> {
    return this.client.get<GetBundlePathResponse>(
      this.buildUrl(`/bundles/${this.encodePathSegment(id)}/path`)
    );
  }

  /**
   * Get TPM socket path for a bundle
   *
   * @param id - Bundle identifier
   * @returns TPM socket path
   */
  async getTPMSocketPath(id: string): Promise<ApiResponse<GetTPMSocketPathResponse>> {
    return this.client.get<GetTPMSocketPathResponse>(
      this.buildUrl(`/bundles/${this.encodePathSegment(id)}/tpm-socket`)
    );
  }

  /**
   * Get NVRAM path for a bundle
   *
   * @param id - Bundle identifier
   * @returns NVRAM path
   */
  async getNVRAMPath(id: string): Promise<ApiResponse<GetNVRAMPathResponse>> {
    return this.client.get<GetNVRAMPathResponse>(
      this.buildUrl(`/bundles/${this.encodePathSegment(id)}/nvram`)
    );
  }

  // =========================================================================
  // Template Operations
  // =========================================================================

  /**
   * Create a vTPM template
   *
   * @param request - Template creation request
   * @returns Created template
   */
  async createTemplate(request: CreateTemplateRequest): Promise<ApiResponse<CreateTemplateResponse>> {
    return this.client.post<CreateTemplateResponse>(this.buildUrl('/templates'), toWireCreateTemplate(request.options));
  }

  /**
   * Get a vTPM template by ID
   *
   * @param id - Template identifier
   * @returns Template information
   */
  async getTemplate(id: string): Promise<ApiResponse<GetTemplateResponse>> {
    return this.client.get<GetTemplateResponse>(
      this.buildUrl(`/templates/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * Delete a vTPM template
   *
   * @param id - Template identifier
   * @returns Deletion result
   */
  async deleteTemplate(id: string): Promise<ApiResponse<DeleteTemplateResponse>> {
    return this.client.delete<DeleteTemplateResponse>(
      this.buildUrl(`/templates/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * List vTPM templates
   *
   * @returns List of templates
   */
  async listTemplates(): Promise<ApiResponse<ListTemplatesResponse>> {
    return this.client.get<ListTemplatesResponse>(this.buildUrl('/templates'));
  }

  /**
   * Clone a template to create a new bundle
   *
   * @param request - Clone request
   * @returns Cloned bundle
   */
  async cloneTemplate(request: CloneTemplateRequest): Promise<ApiResponse<CloneTemplateResponse>> {
    return this.client.post<CloneTemplateResponse>(
      this.buildUrl(`/templates/${this.encodePathSegment(request.options.templateId)}/clone`),
      { hostname: request.options.hostname, labels: request.options.labels }
    );
  }
}
