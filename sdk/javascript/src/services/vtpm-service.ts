/**
 * Virtual TPM (vTPM) Service
 *
 * Provides operations for vTPM bundle management including creation, cloning, and templates.
 */

import type { ApiClient } from '../client/api-client.js';
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
  // Instance types
  CreateVTPMInstanceRequest,
  CreateVTPMInstanceResponse,
  GetVTPMInstanceResponse,
  GetVTPMInstanceByProfileResponse,
  ListVTPMInstancesRequest,
  ListVTPMInstancesResponse,
  DeleteVTPMInstanceResponse,
  StartVTPMInstanceResponse,
  StopVTPMInstanceResponse,
  GetVTPMInstanceStatusResponse,
  GetVTPMInstanceEKCertResponse,
  GetVTPMInstanceEKFingerprintResponse,
} from '../types/vtpm.js';

/**
 * vTPM Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a vTPM bundle
 * const bundle = await client.vtpm.createBundle({
 *   options: {
 *     hostname: 'vm-001',
 *     ekAlgorithm: 'RSA',
 *     secureBootEnabled: true,
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
  constructor(client: ApiClient) {
    super(client, '/v1/vtpm');
  }

  // =========================================================================
  // Bundle Operations
  // =========================================================================

  /**
   * Create a new vTPM bundle
   *
   * @param request - Bundle creation request
   * @returns Created bundle
   */
  async createBundle(request: CreateBundleRequest): Promise<ApiResponse<CreateBundleResponse>> {
    return this.client.post<CreateBundleResponse>(this.buildUrl('/bundles'), request);
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
   * @param request - List request with filters
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
    return this.client.post<CreateTemplateResponse>(this.buildUrl('/templates'), request);
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

  // =========================================================================
  // Instance Operations (Runtime Management)
  // =========================================================================

  /**
   * Create a new vTPM instance
   *
   * @param request - Instance creation request
   * @returns Created instance
   */
  async create(request: CreateVTPMInstanceRequest): Promise<ApiResponse<CreateVTPMInstanceResponse>> {
    return this.client.post<CreateVTPMInstanceResponse>(this.buildUrl('/instances'), request);
  }

  /**
   * Get a vTPM instance by ID
   *
   * @param id - Instance identifier
   * @returns Instance information
   */
  async get(id: string): Promise<ApiResponse<GetVTPMInstanceResponse>> {
    return this.client.get<GetVTPMInstanceResponse>(
      this.buildUrl(`/instances/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * Get a vTPM instance by profile ID
   *
   * @param profileId - Profile identifier
   * @returns Instance information
   */
  async getByProfile(profileId: number): Promise<ApiResponse<GetVTPMInstanceByProfileResponse>> {
    return this.client.get<GetVTPMInstanceByProfileResponse>(
      this.buildUrl(`/instances/profile/${profileId}`)
    );
  }

  /**
   * List vTPM instances
   *
   * @param request - List request with filters
   * @returns List of instances
   */
  async list(request?: ListVTPMInstancesRequest): Promise<ApiResponse<ListVTPMInstancesResponse>> {
    const filters: Record<string, string | number | boolean | undefined> = {};
    if (request?.profileId !== undefined) {
      filters.profileId = request.profileId;
    }
    if (request?.isRunning !== undefined) {
      filters.isRunning = request.isRunning;
    }
    if (request?.status !== undefined) {
      filters.status = request.status;
    }
    return this.client.get<ListVTPMInstancesResponse>(this.buildUrl('/instances', {
      page: request?.page,
      limit: request?.pageSize,
      filters,
    }));
  }

  /**
   * Delete a vTPM instance
   *
   * @param id - Instance identifier
   * @param force - Force delete even if running
   * @returns Deletion result
   */
  async delete(id: string, force?: boolean): Promise<ApiResponse<DeleteVTPMInstanceResponse>> {
    const filters: Record<string, string | number | boolean | undefined> = {};
    if (force !== undefined) {
      filters.force = force;
    }
    return this.client.delete<DeleteVTPMInstanceResponse>(
      this.buildUrl(`/instances/${this.encodePathSegment(id)}`, { filters })
    );
  }

  /**
   * Start a vTPM instance
   *
   * @param id - Instance identifier
   * @returns Start result with updated instance
   */
  async start(id: string): Promise<ApiResponse<StartVTPMInstanceResponse>> {
    return this.client.post<StartVTPMInstanceResponse>(
      this.buildUrl(`/instances/${this.encodePathSegment(id)}/start`),
      {}
    );
  }

  /**
   * Stop a vTPM instance
   *
   * @param id - Instance identifier
   * @param force - Force stop
   * @returns Stop result with updated instance
   */
  async stop(id: string, force?: boolean): Promise<ApiResponse<StopVTPMInstanceResponse>> {
    return this.client.post<StopVTPMInstanceResponse>(
      this.buildUrl(`/instances/${this.encodePathSegment(id)}/stop`),
      { force }
    );
  }

  /**
   * Get vTPM instance status
   *
   * @param id - Instance identifier
   * @returns Instance status details
   */
  async getStatus(id: string): Promise<ApiResponse<GetVTPMInstanceStatusResponse>> {
    return this.client.get<GetVTPMInstanceStatusResponse>(
      this.buildUrl(`/instances/${this.encodePathSegment(id)}/status`)
    );
  }

  /**
   * Get vTPM instance EK certificate
   *
   * @param id - Instance identifier
   * @param format - Certificate format (pem or der)
   * @returns EK certificate
   */
  async getEKCert(id: string, format?: 'pem' | 'der'): Promise<ApiResponse<GetVTPMInstanceEKCertResponse>> {
    const filters: Record<string, string | number | boolean | undefined> = {};
    if (format !== undefined) {
      filters.format = format;
    }
    return this.client.get<GetVTPMInstanceEKCertResponse>(
      this.buildUrl(`/instances/${this.encodePathSegment(id)}/ek-cert`, { filters })
    );
  }

  /**
   * Get vTPM instance EK fingerprint
   *
   * @param id - Instance identifier
   * @param algorithm - Hash algorithm for fingerprint
   * @returns EK fingerprint
   */
  async getEKFingerprint(id: string, algorithm?: 'sha256' | 'sha384' | 'sha512'): Promise<ApiResponse<GetVTPMInstanceEKFingerprintResponse>> {
    const filters: Record<string, string | number | boolean | undefined> = {};
    if (algorithm !== undefined) {
      filters.algorithm = algorithm;
    }
    return this.client.get<GetVTPMInstanceEKFingerprintResponse>(
      this.buildUrl(`/instances/${this.encodePathSegment(id)}/ek-fingerprint`, { filters })
    );
  }
}
