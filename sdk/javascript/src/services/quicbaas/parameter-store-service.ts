/**
 * QuicBaaS Parameter Store Service
 *
 * Provides operations for hierarchical parameter management with
 * support for encrypted secure strings, versioning, and path-based access.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService, type ListOptions } from '../base-service.js';
import type {
  GetParameterRequest,
  GetParameterResponse,
  PutParameterRequest,
  PutParameterResponse,
  DeleteParameterRequest,
  DeleteParameterResponse,
  ListParametersRequest,
  ListParametersResponse,
  GetParametersByPathRequest,
  GetParametersByPathResponse,
} from '../../types/quicbaas/infrastructure-part1.js';

/**
 * QuicBaaS Parameter Store Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Store a configuration parameter
 * await client.quicbaas.parameterStore.putParameter({
 *   name: '/myapp/prod/database/host',
 *   value: 'db.example.com',
 *   type: 'string',
 *   description: 'Production database host'
 * });
 *
 * // Store a secure parameter (encrypted)
 * await client.quicbaas.parameterStore.putParameter({
 *   name: '/myapp/prod/database/password',
 *   value: 'secret123',
 *   type: 'secureString',
 *   keyId: 'my-kms-key'
 * });
 *
 * // Get a parameter
 * const param = await client.quicbaas.parameterStore.getParameter({
 *   name: '/myapp/prod/database/host'
 * });
 * console.log(`Host: ${param.data.parameter.value}`);
 *
 * // Get all parameters under a path
 * const dbParams = await client.quicbaas.parameterStore.getParametersByPath({
 *   path: '/myapp/prod/database',
 *   recursive: true,
 *   withDecryption: true
 * });
 *
 * // List parameters with filtering
 * const allParams = await client.quicbaas.parameterStore.listParameters({
 *   pathPrefix: '/myapp/prod',
 *   type: 'secureString'
 * });
 * ```
 */
export class ParameterStoreService extends BaseService {
  /**
   * Creates a new Parameter Store service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Get a parameter by name
   *
   * Retrieves a parameter with its value. For secure strings,
   * use withDecryption: true to get the decrypted value.
   *
   * @param request - Get request with parameter name
   * @returns Parameter with value
   */
  async getParameter(request: GetParameterRequest): Promise<ApiResponse<GetParameterResponse>> {
    const url = this.buildUrl(`/parameters/${this.encodePathSegment(request.name)}`, {
      filters: {
        version: request.version?.toString(),
        withDecryption: request.withDecryption?.toString(),
      },
    });
    return this.client.get<GetParameterResponse>(url);
  }

  /**
   * Create or update a parameter
   *
   * Stores a parameter value. Use type: 'secureString' with a
   * keyId for encrypted storage.
   *
   * @param request - Put request with parameter details
   * @returns Created/updated parameter version
   */
  async putParameter(request: PutParameterRequest): Promise<ApiResponse<PutParameterResponse>> {
    return this.client.post<PutParameterResponse>(this.buildUrl('/parameters'), request);
  }

  /**
   * Delete a parameter
   *
   * Removes a parameter and all its versions.
   *
   * @param request - Delete request with parameter name
   * @returns Deletion result
   */
  async deleteParameter(request: DeleteParameterRequest): Promise<ApiResponse<DeleteParameterResponse>> {
    return this.client.delete<DeleteParameterResponse>(
      this.buildUrl(`/parameters/${this.encodePathSegment(request.name)}`)
    );
  }

  /**
   * List parameters
   *
   * Returns a paginated list of parameter metadata (without values).
   * Use getParameter to retrieve individual values.
   *
   * @param request - List request with optional filters
   * @returns List of parameter metadata
   */
  async listParameters(request?: ListParametersRequest): Promise<ApiResponse<ListParametersResponse>> {
    const options: ListOptions = {
      page: request?.page,
      limit: request?.limit,
      filters: {},
    };

    if (request?.pathPrefix !== undefined) {
      options.filters!.pathPrefix = request.pathPrefix;
    }
    if (request?.type !== undefined) {
      options.filters!.type = request.type;
    }
    if (request?.tags !== undefined) {
      for (const [key, value] of Object.entries(request.tags)) {
        options.filters![`tag.${key}`] = value;
      }
    }

    return this.client.get<ListParametersResponse>(this.buildUrl('/parameters', options));
  }

  /**
   * Get parameters by path
   *
   * Retrieves all parameters under a specific path. Supports
   * recursive lookup and decryption of secure strings.
   *
   * @param request - Request with path and options
   * @returns Parameters at the specified path
   */
  async getParametersByPath(request: GetParametersByPathRequest): Promise<ApiResponse<GetParametersByPathResponse>> {
    const options: ListOptions = {
      page: request.page,
      limit: request.limit,
      filters: {
        recursive: request.recursive?.toString(),
        withDecryption: request.withDecryption?.toString(),
        maxDepth: request.maxDepth?.toString(),
      },
    };

    return this.client.get<GetParametersByPathResponse>(
      this.buildUrl(`/parameters/path/${this.encodePathSegment(request.path)}`, options)
    );
  }
}
