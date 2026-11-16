/**
 * Unit tests for QuicBaaSAuthService
 *
 * Tests authentication operations including login, logout, token management,
 * and API key management for QuicBaaS security.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QuicBaaSAuthService } from '../auth-service.js';
import type { ApiClient } from '../../../client/api-client.js';
import type { ApiResponse } from '../../../types/api.js';

// Mock ApiClient
function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
    interceptors: {
      request: { add: vi.fn(), getAll: vi.fn(() => []) },
      response: { add: vi.fn(), getAll: vi.fn(() => []) },
      error: { add: vi.fn(), getAll: vi.fn(() => []) },
    },
    addRequestInterceptor: vi.fn(),
    addResponseInterceptor: vi.fn(),
    addErrorInterceptor: vi.fn(),
  } as unknown as ApiClient;
}

describe('QuicBaaSAuthService', () => {
  let service: QuicBaaSAuthService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new QuicBaaSAuthService(mockClient);
  });

  // =========================================================================
  // login() tests
  // =========================================================================

  describe('login', () => {
    it('should login with username and password', async () => {
      const mockResponse: ApiResponse<{
        accessToken: string;
        refreshToken: string;
        expiresAt: number;
        tokenType: string;
      }> = {
        success: true,
        data: {
          accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
          refreshToken: 'refresh-token-123',
          expiresAt: Date.now() + 3600000,
          tokenType: 'Bearer',
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.login({
        method: 'password',
        username: 'user@example.com',
        password: 'securePassword123',
      });

      expect(result.success).toBe(true);
      expect(result.data?.accessToken).toBeDefined();
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/login', {
        method: 'password',
        username: 'user@example.com',
        password: 'securePassword123',
      });
    });

    it('should login with API key', async () => {
      const mockResponse: ApiResponse<{
        accessToken: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          accessToken: 'api-key-token',
          expiresAt: Date.now() + 86400000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.login({
        method: 'apikey',
        apiKey: 'api-key-value',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/login', {
        method: 'apikey',
        apiKey: 'api-key-value',
      });
    });

    it('should login with token', async () => {
      const mockResponse: ApiResponse<{
        accessToken: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          accessToken: 'new-token',
          expiresAt: Date.now() + 3600000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.login({
        method: 'token',
        token: 'existing-token',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/login', {
        method: 'token',
        token: 'existing-token',
      });
    });

    it('should login with certificate', async () => {
      const mockResponse: ApiResponse<{
        accessToken: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          accessToken: 'cert-token',
          expiresAt: Date.now() + 3600000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.login({
        method: 'certificate',
        certificate: 'base64-encoded-cert',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/login', {
        method: 'certificate',
        certificate: 'base64-encoded-cert',
      });
    });

    it('should login with LDAP', async () => {
      const mockResponse: ApiResponse<{
        accessToken: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          accessToken: 'ldap-token',
          expiresAt: Date.now() + 3600000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.login({
        method: 'ldap',
        username: 'ldap-user',
        password: 'ldap-password',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/login', {
        method: 'ldap',
        username: 'ldap-user',
        password: 'ldap-password',
      });
    });

    it('should handle invalid credentials error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid username or password' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.login({
        method: 'password',
        username: 'user@example.com',
        password: 'wrong-password',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_CREDENTIALS');
    });

    it('should handle account locked error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'ACCOUNT_LOCKED', message: 'Account is locked due to too many failed attempts' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.login({
        method: 'password',
        username: 'locked-user@example.com',
        password: 'password',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ACCOUNT_LOCKED');
    });
  });

  // =========================================================================
  // logout() tests
  // =========================================================================

  describe('logout', () => {
    it('should logout without parameters', async () => {
      const mockResponse: ApiResponse<{ tokensInvalidated: number }> = {
        success: true,
        data: { tokensInvalidated: 1 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.logout();

      expect(result.success).toBe(true);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/logout', {});
    });

    it('should logout and invalidate all tokens', async () => {
      const mockResponse: ApiResponse<{ tokensInvalidated: number }> = {
        success: true,
        data: { tokensInvalidated: 5 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.logout({ invalidateAll: true });

      expect(result.success).toBe(true);
      expect(result.data?.tokensInvalidated).toBe(5);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/logout', {
        invalidateAll: true,
      });
    });

    it('should logout specific token', async () => {
      const mockResponse: ApiResponse<{ tokensInvalidated: number }> = {
        success: true,
        data: { tokensInvalidated: 1 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.logout({ token: 'specific-token' });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/logout', {
        token: 'specific-token',
      });
    });

    it('should handle logout error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Not authenticated' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.logout();

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('UNAUTHORIZED');
    });
  });

  // =========================================================================
  // refreshToken() tests
  // =========================================================================

  describe('refreshToken', () => {
    it('should refresh access token', async () => {
      const mockResponse: ApiResponse<{
        accessToken: string;
        refreshToken?: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          accessToken: 'new-access-token',
          refreshToken: 'new-refresh-token',
          expiresAt: Date.now() + 3600000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.refreshToken({
        refreshToken: 'old-refresh-token',
      });

      expect(result.success).toBe(true);
      expect(result.data?.accessToken).toBe('new-access-token');
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/refresh', {
        refreshToken: 'old-refresh-token',
      });
    });

    it('should handle expired refresh token error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'TOKEN_EXPIRED', message: 'Refresh token has expired' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.refreshToken({
        refreshToken: 'expired-token',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('TOKEN_EXPIRED');
    });

    it('should handle invalid refresh token error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_TOKEN', message: 'Invalid refresh token' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.refreshToken({
        refreshToken: 'invalid-token',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_TOKEN');
    });
  });

  // =========================================================================
  // validateToken() tests
  // =========================================================================

  describe('validateToken', () => {
    it('should validate a valid token', async () => {
      const mockResponse: ApiResponse<{
        valid: boolean;
        userId: string;
        expiresAt: number;
        scopes: string[];
      }> = {
        success: true,
        data: {
          valid: true,
          userId: 'user-123',
          expiresAt: Date.now() + 3600000,
          scopes: ['read:secrets', 'write:secrets'],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.validateToken({
        token: 'valid-token',
      });

      expect(result.success).toBe(true);
      expect(result.data?.valid).toBe(true);
      expect(result.data?.userId).toBe('user-123');
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/validate', {
        token: 'valid-token',
      });
    });

    it('should validate an invalid token', async () => {
      const mockResponse: ApiResponse<{
        valid: boolean;
        reason?: string;
      }> = {
        success: true,
        data: {
          valid: false,
          reason: 'Token has been revoked',
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.validateToken({
        token: 'revoked-token',
      });

      expect(result.success).toBe(true);
      expect(result.data?.valid).toBe(false);
    });

    it('should handle validation error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'MALFORMED_TOKEN', message: 'Token is malformed' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.validateToken({
        token: 'malformed-token',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('MALFORMED_TOKEN');
    });
  });

  // =========================================================================
  // createApiKey() tests
  // =========================================================================

  describe('createApiKey', () => {
    it('should create an API key', async () => {
      const mockResponse: ApiResponse<{
        keyId: string;
        apiKey: string;
        name: string;
        createdAt: number;
      }> = {
        success: true,
        data: {
          keyId: 'key-123',
          apiKey: 'secret-api-key-value',
          name: 'ci-pipeline-key',
          createdAt: Date.now(),
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.createApiKey({
        name: 'ci-pipeline-key',
      });

      expect(result.success).toBe(true);
      expect(result.data?.apiKey).toBeDefined();
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/apikeys', {
        name: 'ci-pipeline-key',
      });
    });

    it('should create an API key with scopes', async () => {
      const mockResponse: ApiResponse<{
        keyId: string;
        apiKey: string;
        name: string;
        scopes: string[];
      }> = {
        success: true,
        data: {
          keyId: 'key-456',
          apiKey: 'scoped-api-key',
          name: 'scoped-key',
          scopes: ['read:secrets', 'write:secrets'],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.createApiKey({
        name: 'scoped-key',
        scopes: ['read:secrets', 'write:secrets'],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/apikeys', {
        name: 'scoped-key',
        scopes: ['read:secrets', 'write:secrets'],
      });
    });

    it('should create an API key with expiration', async () => {
      const expiresAt = Date.now() / 1000 + 86400 * 30;
      const mockResponse: ApiResponse<{
        keyId: string;
        apiKey: string;
        name: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          keyId: 'key-789',
          apiKey: 'expiring-api-key',
          name: 'temp-key',
          expiresAt,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.createApiKey({
        name: 'temp-key',
        expiresAt,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/auth/apikeys', {
        name: 'temp-key',
        expiresAt,
      });
    });

    it('should handle API key creation error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NAME_EXISTS', message: 'An API key with this name already exists' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.createApiKey({
        name: 'duplicate-key',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NAME_EXISTS');
    });
  });

  // =========================================================================
  // revokeApiKey() tests
  // =========================================================================

  describe('revokeApiKey', () => {
    it('should revoke an API key', async () => {
      const mockResponse: ApiResponse<{ revoked: boolean; keyId: string }> = {
        success: true,
        data: { revoked: true, keyId: 'key-123' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.revokeApiKey({
        keyId: 'key-123',
      });

      expect(result.success).toBe(true);
      expect(result.data?.keyId).toBe('key-123');
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/quicbaas/auth/apikeys/key-123');
    });

    it('should encode key ID in URL', async () => {
      const mockResponse: ApiResponse<{ revoked: boolean; keyId: string }> = {
        success: true,
        data: { revoked: true, keyId: 'key/with/slashes' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      await service.revokeApiKey({
        keyId: 'key/with/slashes',
      });

      expect(mockClient.delete).toHaveBeenCalledWith('/v1/quicbaas/auth/apikeys/key%2Fwith%2Fslashes');
    });

    it('should handle API key not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'API key not found' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.revokeApiKey({
        keyId: 'nonexistent-key',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });

    it('should handle permission denied error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'PERMISSION_DENIED', message: 'Cannot revoke this API key' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.revokeApiKey({
        keyId: 'protected-key',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('PERMISSION_DENIED');
    });
  });
});
