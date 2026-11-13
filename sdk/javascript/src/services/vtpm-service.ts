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
  StartBundleResponse,
  StopBundleResponse,
  QuoteBundleRequest,
  QuoteBundleResponse,
  SealBundleRequest,
  SealBundleResponse,
  UnsealBundleRequest,
  UnsealBundleResponse,
  ExtendBundlePCRRequest,
  ExtendBundlePCRResponse,
  ReadBundlePCRResponse,
  VTPMRuntimeStatus,
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
}

/** The template body the REST handler decodes. */
interface WireCreateTemplateRequest {
  id: string;
  description?: string;
  ek_algorithm?: string;
  secure_boot_enabled?: boolean;
}

/** The largest uint64, the server's device profile ID type, in decimal. */
const MAX_UINT64_DECIMAL = '18446744073709551615';

/**
 * Validates a uint64 device profile ID and returns its canonical decimal
 * digits. The bootstrap seeder assigns 64-bit IDs, past what a JS number holds
 * exactly (2^53 - 1), so the ID stays a digit string and is never a number.
 */
function toDeviceProfileIdDigits(id: string): string {
  if (!/^\d+$/.test(id)) {
    throw new InvalidDeviceProfileIdError(id);
  }
  const digits = id.replace(/^0+(?=\d)/, '');
  const fits =
    digits.length < MAX_UINT64_DECIMAL.length ||
    (digits.length === MAX_UINT64_DECIMAL.length && digits <= MAX_UINT64_DECIMAL);
  if (!fits) {
    throw new InvalidDeviceProfileIdError(id);
  }
  return digits;
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
  };
}

/**
 * Serializes the bundle body. The server reads device_profile_id as a JSON
 * number (a uint64), so its exact digits are written as a number literal
 * after JSON.stringify of the rest; a JS number would round any ID above
 * 2^53 - 1.
 */
function encodeCreateBundle(options: CreateBundleOptions): string {
  const digits =
    options.deviceProfileId !== undefined ? toDeviceProfileIdDigits(options.deviceProfileId) : undefined;
  const body = JSON.stringify(toWireCreateBundle(options));
  if (digits === undefined) {
    return body;
  }
  const separator = body === '{}' ? '' : ',';
  return `${body.slice(0, -1)}${separator}"device_profile_id":${digits}}`;
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

/** A request's outcome: the reply it returned, or the error it threw. */
type Settled<T> = { reply: ApiResponse<T> } | { thrown: unknown };

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
 * // The daemon returns the bundle itself: bundle.data?.id is its generated ID.
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
    return this.client.post<CreateBundleResponse>(this.buildUrl('/bundles'), encodeCreateBundle(request.options));
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
  // Bundle Runtime Operations
  //
  // IsVTPMRunning has no REST route: callers track the running state from
  // the start and stop results.
  // =========================================================================

  /**
   * Start the vTPM of a bundle (POST /bundles/{id}/start).
   * A lifecycle change is never replayed after a lost response: a replay
   * would answer 409 for a start that ran, or undo another caller's stop.
   */
  async startBundle(id: string): Promise<ApiResponse<StartBundleResponse>> {
    return this.withStatus(
      await this.client.post<StartBundleResponse>(
        this.buildUrl(`/bundles/${this.encodePathSegment(id)}/start`),
        {},
        { retry: { enabled: false } }
      )
    );
  }

  /**
   * Gives a daemon REST listener reply, which has no `status` block, the
   * `status` its exported type declares: `success` from the daemon's own
   * `success` flag when it has one (else true), `message` when the daemon sent
   * one. A reply that already carries `status` (the webservice shape) and a
   * failed call pass unchanged.
   */
  private withStatus<T extends { status: VTPMRuntimeStatus }>(r: ApiResponse<T>): ApiResponse<T> {
    const data = r.data as unknown;
    if (r.success !== true || typeof data !== 'object' || data === null) {
      return r;
    }
    const d = data as { status?: unknown; success?: unknown; message?: unknown };
    if (typeof d.status === 'object' && d.status !== null) {
      return r;
    }
    const status: VTPMRuntimeStatus = {
      success: typeof d.success === 'boolean' ? d.success : true,
      ...(typeof d.message === 'string' ? { message: d.message } : {}),
    };
    return { ...r, data: { ...(data as T), status } };
  }

  /**
   * Stop the vTPM of a bundle (POST /bundles/{id}/stop).
   * A lifecycle change is never replayed after a lost response. The daemon
   * REST listener answers a BundleActionResponse ({ bundle_id, action,
   * success, message }) without `stopped` or `status`; its `success` is read
   * as `stopped` (#452) and the reply is given a `status` block (withStatus).
   * A webservice reply passes unchanged.
   */
  async stopBundle(id: string): Promise<ApiResponse<StopBundleResponse>> {
    const r = await this.client.post<StopBundleResponse>(
      this.buildUrl(`/bundles/${this.encodePathSegment(id)}/stop`),
      {},
      { retry: { enabled: false } }
    );
    const data = r.data as (Partial<StopBundleResponse> & { success?: boolean }) | undefined;
    if (r.success === true && data && typeof data.stopped !== 'boolean') {
      return this.withStatus({ ...r, data: { ...data, stopped: data.success === true } as StopBundleResponse });
    }
    return this.withStatus(r);
  }

  /** Quote PCRs of a running bundle (POST /bundles/{id}/quote) */
  async quoteBundle(id: string, request: QuoteBundleRequest): Promise<ApiResponse<QuoteBundleResponse>> {
    return this.withStatus(
      await this.client.post<QuoteBundleResponse>(
        this.buildUrl(`/bundles/${this.encodePathSegment(id)}/quote`),
        request
      )
    );
  }

  /** Seal data to a running bundle (POST /bundles/{id}/seal) */
  async sealBundle(id: string, request: SealBundleRequest): Promise<ApiResponse<SealBundleResponse>> {
    return this.withStatus(
      await this.client.post<SealBundleResponse>(
        this.buildUrl(`/bundles/${this.encodePathSegment(id)}/seal`),
        request
      )
    );
  }

  /** Unseal a blob with a running bundle (POST /bundles/{id}/unseal) */
  async unsealBundle(id: string, request: UnsealBundleRequest): Promise<ApiResponse<UnsealBundleResponse>> {
    return this.withStatus(
      await this.client.post<UnsealBundleResponse>(
        this.buildUrl(`/bundles/${this.encodePathSegment(id)}/unseal`),
        request
      )
    );
  }

  /**
   * Extend a PCR of a running bundle. The webservice's
   * POST /bundles/{id}/pcrs/extend is tried first; on a 404 the daemon REST
   * listener's POST /bundles/{id}/pcr/{index}/extend (#452). A 404 means no
   * extend ran, so the fallback is never a replay. A PCR extend is
   * irreversible and never retried: a replay after a lost response would
   * extend the PCR twice.
   */
  async extendBundlePCR(
    id: string,
    request: ExtendBundlePCRRequest
  ): Promise<ApiResponse<ExtendBundlePCRResponse>> {
    const bundle = `/bundles/${this.encodePathSegment(id)}`;
    const noRetry = { retry: { enabled: false } };
    const first = await this.settle(
      this.client.post<ExtendBundlePCRResponse>(this.buildUrl(`${bundle}/pcrs/extend`), request, noRetry)
    );
    if (!this.isRouteMissing(first)) {
      return this.unsettle(first);
    }
    const second = await this.settle(
      this.client.post<{ bundle_id: string; action?: string; success?: boolean; message?: string }>(
        this.buildUrl(`${bundle}/pcr/${encodeURIComponent(String(request.pcr_index))}/extend`),
        { data: request.data },
        noRetry
      )
    );
    if (this.isRouteMissing(second)) {
      return this.unsettle(first);
    }
    const r = this.unsettle(second);
    if (r.success !== true || !r.data) {
      return r as unknown as ApiResponse<ExtendBundlePCRResponse>;
    }
    return {
      ...r,
      data: {
        status: r.data.message !== undefined ? { success: true, message: r.data.message } : { success: true },
        bundle_id: r.data.bundle_id,
        pcr_index: request.pcr_index,
        extended: r.data.success === true,
      },
    };
  }

  /**
   * Read one PCR of a running bundle. The webservice's
   * GET /bundles/{id}/pcrs?pcr_index=N is tried first; on a 404 the daemon
   * REST listener's GET /bundles/{id}/pcr/{index} (#452), whose bundle_id,
   * pcr_index and value match ReadBundlePCRResponse.
   */
  async readBundlePCR(id: string, pcrIndex: number): Promise<ApiResponse<ReadBundlePCRResponse>> {
    const bundle = `/bundles/${this.encodePathSegment(id)}`;
    const index = encodeURIComponent(String(pcrIndex));
    const first = await this.settle(
      this.client.get<ReadBundlePCRResponse>(`${this.buildUrl(`${bundle}/pcrs`)}?pcr_index=${index}`)
    );
    if (!this.isRouteMissing(first)) {
      return this.withStatus(this.unsettle(first));
    }
    const second = await this.settle(
      this.client.get<ReadBundlePCRResponse>(this.buildUrl(`${bundle}/pcr/${index}`))
    );
    if (this.isRouteMissing(second)) {
      return this.unsettle(first);
    }
    return this.withStatus(this.unsettle(second));
  }

  /** Captures a request's reply or thrown error, so a 404 of either kind can be tested. */
  private async settle<T>(p: Promise<ApiResponse<T>>): Promise<Settled<T>> {
    try {
      return { reply: await p };
    } catch (thrown) {
      return { thrown };
    }
  }

  /** Returns the settled reply, or rethrows the settled error. */
  private unsettle<T>(s: Settled<T>): ApiResponse<T> {
    if ('thrown' in s) {
      throw s.thrown;
    }
    return s.reply;
  }

  /**
   * True when the route is not registered on this listener: a returned
   * failure with status 404, or a thrown error with status 404.
   */
  private isRouteMissing<T>(s: Settled<T>): boolean {
    if ('thrown' in s) {
      const status = (s.thrown as { status?: unknown } | null)?.status;
      return status === 404;
    }
    return s.reply.success === false && s.reply.error?.status === 404;
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
