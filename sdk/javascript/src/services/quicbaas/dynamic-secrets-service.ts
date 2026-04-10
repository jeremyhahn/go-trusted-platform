/**
 * QuicBaaS Dynamic Secrets Service
 *
 * Provides dynamic credential generation for various backends including
 * databases, cloud providers, and other services.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  GenerateDynamicSecretRequest,
  GenerateDynamicSecretResponse,
  RevokeDynamicSecretRequest,
  RevokeDynamicSecretResponse,
  ConfigureDynamicSecretRequest,
  ConfigureDynamicSecretResponse,
  ListDynamicSecretConfigsRequest,
  ListDynamicSecretConfigsResponse,
  DeleteDynamicSecretConfigRequest,
  DeleteDynamicSecretConfigResponse,
} from '../../types/quicbaas/security-part1.js';

/**
 * QuicBaaS Dynamic Secrets Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Configure a PostgreSQL database backend
 * const configResult = await client.quicbaas.dynamicSecrets.configure({
 *   name: 'prod-postgres',
 *   backend: 'database',
 *   databaseType: 'postgresql',
 *   connection: 'postgresql://admin:adminpass@db.example.com:5432/mydb',
 *   defaultTtl: 3600, // 1 hour
 *   maxTtl: 86400, // 24 hours
 *   creationStatements: [
 *     "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
 *     "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
 *   ],
 *   revocationStatements: [
 *     "DROP ROLE IF EXISTS \"{{name}}\";",
 *   ],
 *   enabled: true,
 * });
 *
 * // Generate a dynamic credential
 * const credResult = await client.quicbaas.dynamicSecrets.generate({
 *   configId: 'prod-postgres',
 *   ttl: 1800, // 30 minutes
 *   role: 'readonly',
 * });
 *
 * if (credResult.success && credResult.data?.credential) {
 *   console.log('Username:', credResult.data.credential.username);
 *   console.log('Password:', credResult.data.credential.password);
 *   console.log('Expires At:', credResult.data.credential.expiresAt);
 * }
 *
 * // List all configurations
 * const configsResult = await client.quicbaas.dynamicSecrets.listConfigurations({
 *   backend: 'database',
 *   enabled: true,
 * });
 *
 * // Revoke a credential
 * await client.quicbaas.dynamicSecrets.revoke({
 *   credentialId: credResult.data.credential.credentialId,
 * });
 *
 * // Delete a configuration
 * await client.quicbaas.dynamicSecrets.deleteConfiguration({
 *   configId: 'prod-postgres',
 *   force: true, // revokes all active credentials
 * });
 * ```
 */
export class QuicBaaSDynamicSecretsService extends BaseService {
  /**
   * Creates a new QuicBaaS Dynamic Secrets service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas/dynamic-secrets');
  }

  // =========================================================================
  // Credential Operations
  // =========================================================================

  /**
   * Generate a dynamic credential
   *
   * Creates a new short-lived credential from the specified configuration.
   * The credential type depends on the backend (e.g., database username/password,
   * cloud access keys, SSH certificates).
   *
   * @param request - Generation request with configuration ID and options
   * @returns Generated credential with expiration
   */
  async generate(request: GenerateDynamicSecretRequest): Promise<ApiResponse<GenerateDynamicSecretResponse>> {
    return this.client.post<GenerateDynamicSecretResponse>(
      this.buildUrl(`/configs/${this.encodePathSegment(request.configId)}/generate`),
      { ttl: request.ttl, role: request.role, parameters: request.parameters }
    );
  }

  /**
   * Revoke a dynamic credential
   *
   * Immediately revokes an active credential, removing access from
   * the backend system. The credential can no longer be used after
   * revocation.
   *
   * @param request - Revocation request with credential ID
   * @returns Revocation result
   */
  async revoke(request: RevokeDynamicSecretRequest): Promise<ApiResponse<RevokeDynamicSecretResponse>> {
    return this.client.delete<RevokeDynamicSecretResponse>(
      this.buildUrl(`/credentials/${this.encodePathSegment(request.credentialId)}`)
    );
  }

  // =========================================================================
  // Configuration Operations
  // =========================================================================

  /**
   * Configure a dynamic secret backend
   *
   * Creates or updates a configuration for generating dynamic credentials.
   * Supports various backends including databases, cloud providers,
   * Kubernetes, PKI, and more.
   *
   * @param request - Configuration request with backend settings
   * @returns Created or updated configuration
   */
  async configure(request: ConfigureDynamicSecretRequest): Promise<ApiResponse<ConfigureDynamicSecretResponse>> {
    return this.client.post<ConfigureDynamicSecretResponse>(this.buildUrl('/configs'), request);
  }

  /**
   * List dynamic secret configurations
   *
   * Returns a paginated list of configurations with optional filtering
   * by backend type or enabled status.
   *
   * @param options - List options with filtering and pagination
   * @returns List of configurations
   */
  async listConfigurations(options?: ListDynamicSecretConfigsRequest): Promise<ApiResponse<ListDynamicSecretConfigsResponse>> {
    return this.client.get<ListDynamicSecretConfigsResponse>(this.buildUrl('/configs', {
      page: options?.page,
      limit: options?.pageSize,
      filters: {
        backend: options?.backend,
        enabled: options?.enabled?.toString(),
      },
    }));
  }

  /**
   * Delete a dynamic secret configuration
   *
   * Removes a configuration. Optionally revokes all active credentials
   * generated from this configuration if force is specified.
   *
   * @param request - Delete request with configuration ID
   * @returns Deletion result with count of revoked credentials
   */
  async deleteConfiguration(request: DeleteDynamicSecretConfigRequest): Promise<ApiResponse<DeleteDynamicSecretConfigResponse>> {
    const url = this.buildUrl(`/configs/${this.encodePathSegment(request.configId)}`, {
      filters: {
        force: request.force?.toString(),
      },
    });
    return this.client.delete<DeleteDynamicSecretConfigResponse>(url);
  }
}
