/**
 * QuicBaaS Secrets Service
 *
 * Provides secret storage operations with versioning support including
 * create, read, update, delete, and version management.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  CreateSecretRequest,
  CreateSecretResponse,
  GetSecretRequest,
  GetSecretResponse,
  UpdateSecretRequest,
  UpdateSecretResponse,
  DeleteSecretRequest,
  DeleteSecretResponse,
  ListSecretsRequest,
  ListSecretsResponse,
  GetSecretVersionRequest,
  GetSecretVersionResponse,
  ListSecretVersionsRequest,
  ListSecretVersionsResponse,
  RotateSecretRequest,
  RotateSecretResponse,
} from '../../types/quicbaas/security-part1.js';

/**
 * QuicBaaS Secrets Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a new secret
 * const createResult = await client.quicbaas.secrets.create({
 *   path: 'app/config/database',
 *   data: {
 *     username: 'dbuser',
 *     password: 'securepassword123',
 *     host: 'db.example.com',
 *     port: '5432',
 *   },
 *   type: 'database',
 *   tags: { environment: 'production' },
 * });
 *
 * // Get the secret
 * const getResult = await client.quicbaas.secrets.get({
 *   path: 'app/config/database',
 * });
 *
 * if (getResult.success && getResult.data?.data) {
 *   console.log('Database Host:', getResult.data.data.host);
 * }
 *
 * // Update the secret (creates new version)
 * const updateResult = await client.quicbaas.secrets.update({
 *   path: 'app/config/database',
 *   data: {
 *     username: 'dbuser',
 *     password: 'newpassword456',
 *     host: 'db.example.com',
 *     port: '5432',
 *   },
 * });
 *
 * // List all versions
 * const versionsResult = await client.quicbaas.secrets.listVersions({
 *   path: 'app/config/database',
 * });
 *
 * // Rotate the secret
 * const rotateResult = await client.quicbaas.secrets.rotateSecret({
 *   path: 'app/config/database',
 * });
 *
 * // Delete the secret
 * await client.quicbaas.secrets.delete({
 *   path: 'app/config/database',
 *   permanent: false, // soft delete
 * });
 * ```
 */
export class QuicBaaSSecretsService extends BaseService {
  /**
   * Creates a new QuicBaaS Secrets service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas/secrets');
  }

  // =========================================================================
  // Secret CRUD Operations
  // =========================================================================

  /**
   * Create a new secret
   *
   * Stores a new secret at the specified path. The secret data is
   * stored as key-value pairs. Supports optional type classification,
   * expiration, and tagging.
   *
   * @param request - Secret creation request with path and data
   * @returns Created secret metadata and version
   */
  async create(request: CreateSecretRequest): Promise<ApiResponse<CreateSecretResponse>> {
    return this.client.post<CreateSecretResponse>(this.buildUrl('/data'), request);
  }

  /**
   * Get a secret by path
   *
   * Retrieves the secret data and metadata at the specified path.
   * Optionally retrieves a specific version.
   *
   * @param request - Get request with path and optional version
   * @returns Secret data and metadata
   */
  async get(request: GetSecretRequest): Promise<ApiResponse<GetSecretResponse>> {
    const url = request.version !== undefined
      ? this.buildUrl(`/data/${this.encodePathSegment(request.path)}?version=${request.version}`)
      : this.buildUrl(`/data/${this.encodePathSegment(request.path)}`);
    return this.client.get<GetSecretResponse>(url);
  }

  /**
   * Update a secret
   *
   * Updates the secret data at the specified path. Creates a new
   * version of the secret. Supports optimistic locking via CAS
   * (check-and-set) parameter.
   *
   * @param request - Update request with path and new data
   * @returns Updated secret metadata and new version
   */
  async update(request: UpdateSecretRequest): Promise<ApiResponse<UpdateSecretResponse>> {
    return this.client.put<UpdateSecretResponse>(
      this.buildUrl(`/data/${this.encodePathSegment(request.path)}`),
      { data: request.data, cas: request.cas }
    );
  }

  /**
   * Delete a secret
   *
   * Deletes the secret at the specified path. Can delete specific
   * versions or all versions. Supports soft delete (recoverable)
   * or permanent deletion.
   *
   * @param request - Delete request with path and options
   * @returns Deletion result with deleted versions
   */
  async delete(request: DeleteSecretRequest): Promise<ApiResponse<DeleteSecretResponse>> {
    const url = this.buildUrl(`/data/${this.encodePathSegment(request.path)}`, {
      filters: {
        permanent: request.permanent?.toString(),
        versions: request.versions?.join(','),
      },
    });
    return this.client.delete<DeleteSecretResponse>(url);
  }

  /**
   * List secrets with optional filtering
   *
   * Returns a paginated list of secrets with optional filtering by
   * path prefix, type, or tags.
   *
   * @param options - List options with filtering and pagination
   * @returns List of secret metadata
   */
  async list(options?: ListSecretsRequest): Promise<ApiResponse<ListSecretsResponse>> {
    return this.client.get<ListSecretsResponse>(this.buildUrl('/metadata', {
      page: options?.page,
      limit: options?.pageSize,
      filters: {
        pathPrefix: options?.pathPrefix,
        type: options?.type,
        includeDeleted: options?.includeDeleted?.toString(),
        ...options?.tags,
      },
    }));
  }

  // =========================================================================
  // Version Management
  // =========================================================================

  /**
   * Get a specific version of a secret
   *
   * Retrieves the data and metadata for a specific version of
   * the secret.
   *
   * @param request - Request with path and version number
   * @returns Secret data and version information
   */
  async getVersion(request: GetSecretVersionRequest): Promise<ApiResponse<GetSecretVersionResponse>> {
    return this.client.get<GetSecretVersionResponse>(
      this.buildUrl(`/data/${this.encodePathSegment(request.path)}/versions/${request.version}`)
    );
  }

  /**
   * List all versions of a secret
   *
   * Returns a paginated list of all versions for the secret
   * at the specified path.
   *
   * @param request - Request with path and pagination options
   * @returns List of version information
   */
  async listVersions(request: ListSecretVersionsRequest): Promise<ApiResponse<ListSecretVersionsResponse>> {
    return this.client.get<ListSecretVersionsResponse>(
      this.buildUrl(`/data/${this.encodePathSegment(request.path)}/versions`, {
        page: request.page,
        limit: request.pageSize,
      })
    );
  }

  /**
   * Rotate a secret
   *
   * Creates a new version of the secret with optionally provided
   * new data. If no new data is provided, generates new values
   * automatically (if supported by secret type).
   *
   * @param request - Rotation request with path and optional new data
   * @returns Rotation result with old and new versions
   */
  async rotateSecret(request: RotateSecretRequest): Promise<ApiResponse<RotateSecretResponse>> {
    return this.client.post<RotateSecretResponse>(
      this.buildUrl(`/data/${this.encodePathSegment(request.path)}/rotate`),
      { newData: request.newData }
    );
  }
}
