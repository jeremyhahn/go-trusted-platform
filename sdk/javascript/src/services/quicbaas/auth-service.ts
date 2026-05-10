/**
 * QuicBaaS Authentication Service
 *
 * Provides authentication operations including login, logout, token management,
 * and API key management for QuicBaaS security.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { Transport } from '../../transport/transport.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  LoginRequest,
  LoginResponse,
  LogoutRequest,
  LogoutResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  ValidateTokenRequest,
  ValidateTokenResponse,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  RevokeApiKeyRequest,
  RevokeApiKeyResponse,
} from '../../types/quicbaas/security-part1.js';

/**
 * QuicBaaS Authentication Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Login with username and password
 * const loginResult = await client.quicbaas.auth.login({
 *   method: 'password',
 *   username: 'user@example.com',
 *   password: 'securePassword123',
 * });
 *
 * if (loginResult.success && loginResult.data) {
 *   console.log('Access Token:', loginResult.data.accessToken);
 *   console.log('Expires At:', loginResult.data.expiresAt);
 * }
 *
 * // Validate a token
 * const validateResult = await client.quicbaas.auth.validateToken({
 *   token: loginResult.data.accessToken,
 * });
 *
 * // Refresh the access token
 * const refreshResult = await client.quicbaas.auth.refreshToken({
 *   refreshToken: loginResult.data.refreshToken,
 * });
 *
 * // Create an API key
 * const apiKeyResult = await client.quicbaas.auth.createApiKey({
 *   name: 'ci-pipeline-key',
 *   scopes: ['read:secrets', 'write:secrets'],
 *   expiresAt: Date.now() / 1000 + 86400 * 30, // 30 days
 * });
 *
 * // Logout
 * await client.quicbaas.auth.logout({ invalidateAll: true });
 * ```
 */
export class QuicBaaSAuthService extends BaseService {
  /**
   * Creates a new QuicBaaS Authentication service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/quicbaas/auth');
  }

  // =========================================================================
  // Authentication Operations
  // =========================================================================

  /**
   * Authenticate a user and obtain access tokens
   *
   * Supports multiple authentication methods including password, token,
   * certificate, LDAP, OIDC, and API key authentication.
   *
   * @param request - Login request with authentication credentials
   * @returns Login response with access and refresh tokens
   */
  async login(request: LoginRequest): Promise<ApiResponse<LoginResponse>> {
    return this.client.post<LoginResponse>(this.buildUrl('/login'), request);
  }

  /**
   * Logout and invalidate tokens
   *
   * Can invalidate a specific token or all tokens for the user.
   *
   * @param request - Logout request with optional token to invalidate
   * @returns Logout response with number of tokens invalidated
   */
  async logout(request?: LogoutRequest): Promise<ApiResponse<LogoutResponse>> {
    return this.client.post<LogoutResponse>(this.buildUrl('/logout'), request ?? {});
  }

  /**
   * Refresh an access token using a refresh token
   *
   * Obtains a new access token without requiring re-authentication.
   * The refresh token may also be rotated for security.
   *
   * @param request - Refresh token request
   * @returns New access token (and optionally new refresh token)
   */
  async refreshToken(request: RefreshTokenRequest): Promise<ApiResponse<RefreshTokenResponse>> {
    return this.client.post<RefreshTokenResponse>(this.buildUrl('/refresh'), request);
  }

  /**
   * Validate a token and retrieve its metadata
   *
   * Checks if a token is valid and returns information about it
   * including the user ID, expiration, and scopes.
   *
   * @param request - Token validation request
   * @returns Validation result with token metadata
   */
  async validateToken(request: ValidateTokenRequest): Promise<ApiResponse<ValidateTokenResponse>> {
    return this.client.post<ValidateTokenResponse>(this.buildUrl('/validate'), request);
  }

  // =========================================================================
  // API Key Management
  // =========================================================================

  /**
   * Create a new API key
   *
   * Generates a new API key with the specified name, scopes, and optional
   * expiration. The API key value is only returned once on creation.
   *
   * @param request - API key creation request
   * @returns Created API key with ID and value
   */
  async createApiKey(request: CreateApiKeyRequest): Promise<ApiResponse<CreateApiKeyResponse>> {
    return this.client.post<CreateApiKeyResponse>(this.buildUrl('/apikeys'), request);
  }

  /**
   * Revoke an API key
   *
   * Permanently invalidates an API key, preventing any further use.
   *
   * @param request - API key revocation request with key ID
   * @returns Revocation result
   */
  async revokeApiKey(request: RevokeApiKeyRequest): Promise<ApiResponse<RevokeApiKeyResponse>> {
    return this.client.delete<RevokeApiKeyResponse>(
      this.buildUrl(`/apikeys/${this.encodePathSegment(request.keyId)}`)
    );
  }
}
