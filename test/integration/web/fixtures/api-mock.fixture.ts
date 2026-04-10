import { test as base, Page, Route } from '@playwright/test';

/**
 * API Mock Fixtures
 *
 * Provides utilities for mocking API responses in integration tests.
 * Use these when you need to test UI behavior with specific API responses
 * without depending on backend state.
 */

// Mock data types
export interface MockUser {
  id: string;
  name: string;
  email: string;
  status: 'active' | 'pending' | 'disabled';
  roles: string[];
  createdAt: string;
  lastLogin?: string;
}

export interface MockRole {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  userCount: number;
}

export interface MockTenant {
  id: string;
  name: string;
  domain: string;
  status: 'active' | 'suspended';
  memberCount: number;
  createdAt: string;
}

export interface MockDevice {
  id: string;
  name: string;
  type: 'physical' | 'virtual';
  status: 'online' | 'offline' | 'disabled';
  tpmVersion?: string;
  lastSeen?: string;
}

export interface MockCertificate {
  id: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  status: 'valid' | 'revoked' | 'expired';
  notBefore: string;
  notAfter: string;
}

export interface MockKey {
  id: string;
  name: string;
  algorithm: string;
  keyType: 'symmetric' | 'asymmetric';
  usage: string[];
  status: 'active' | 'disabled' | 'pending_deletion';
  createdAt: string;
}

// Sample mock data
export const mockUsers: MockUser[] = [
  {
    id: 'user-1',
    name: 'Alice Admin',
    email: 'alice@platform.local',
    status: 'active',
    roles: ['admin'],
    createdAt: '2024-01-01T00:00:00Z',
    lastLogin: '2024-01-15T10:30:00Z',
  },
  {
    id: 'user-2',
    name: 'Bob User',
    email: 'bob@platform.local',
    status: 'active',
    roles: ['user'],
    createdAt: '2024-01-02T00:00:00Z',
    lastLogin: '2024-01-14T09:00:00Z',
  },
  {
    id: 'user-3',
    name: 'Charlie Pending',
    email: 'charlie@platform.local',
    status: 'pending',
    roles: ['user'],
    createdAt: '2024-01-10T00:00:00Z',
  },
];

export const mockRoles: MockRole[] = [
  {
    id: 'role-1',
    name: 'admin',
    description: 'Full administrative access',
    permissions: ['*:*'],
    userCount: 1,
  },
  {
    id: 'role-2',
    name: 'user',
    description: 'Standard user access',
    permissions: ['read:*', 'write:own'],
    userCount: 2,
  },
  {
    id: 'role-3',
    name: 'viewer',
    description: 'Read-only access',
    permissions: ['read:*'],
    userCount: 0,
  },
];

export const mockTenant: MockTenant = {
  id: 'tenant-1',
  name: 'Test Organization',
  domain: 'platform.local',
  status: 'active',
  memberCount: 3,
  createdAt: '2024-01-01T00:00:00Z',
};

export const mockDevices: MockDevice[] = [
  {
    id: 'device-1',
    name: 'Server-001',
    type: 'physical',
    status: 'online',
    tpmVersion: '2.0',
    lastSeen: '2024-01-15T12:00:00Z',
  },
  {
    id: 'device-2',
    name: 'VM-Staging',
    type: 'virtual',
    status: 'online',
    lastSeen: '2024-01-15T11:30:00Z',
  },
  {
    id: 'device-3',
    name: 'Server-002',
    type: 'physical',
    status: 'offline',
    tpmVersion: '2.0',
    lastSeen: '2024-01-10T08:00:00Z',
  },
];

export const mockCertificates: MockCertificate[] = [
  {
    id: 'cert-1',
    subject: 'CN=server-001.platform.local',
    issuer: 'CN=Platform Root CA',
    serialNumber: '01:23:45:67:89:AB',
    status: 'valid',
    notBefore: '2024-01-01T00:00:00Z',
    notAfter: '2025-01-01T00:00:00Z',
  },
  {
    id: 'cert-2',
    subject: 'CN=client-001.platform.local',
    issuer: 'CN=Platform Root CA',
    serialNumber: '01:23:45:67:89:AC',
    status: 'valid',
    notBefore: '2024-01-05T00:00:00Z',
    notAfter: '2025-01-05T00:00:00Z',
  },
];

export const mockKeys: MockKey[] = [
  {
    id: 'key-1',
    name: 'master-encryption-key',
    algorithm: 'AES-256-GCM',
    keyType: 'symmetric',
    usage: ['encrypt', 'decrypt'],
    status: 'active',
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: 'key-2',
    name: 'signing-key',
    algorithm: 'ECDSA-P256',
    keyType: 'asymmetric',
    usage: ['sign', 'verify'],
    status: 'active',
    createdAt: '2024-01-02T00:00:00Z',
  },
];

export interface ApiMockFixtures {
  /** Mock all API endpoints with sample data */
  mockAllApis: (page: Page) => Promise<void>;
  /** Mock specific API endpoint */
  mockApiEndpoint: (
    page: Page,
    pattern: string | RegExp,
    response: unknown,
    options?: { status?: number; contentType?: string }
  ) => Promise<void>;
  /** Mock API to return error */
  mockApiError: (
    page: Page,
    pattern: string | RegExp,
    errorCode: string,
    errorMessage: string,
    status?: number
  ) => Promise<void>;
}

/**
 * Extended test with API mock fixtures
 */
export const test = base.extend<ApiMockFixtures>({
  /**
   * Mock all API endpoints with sample data
   */
  mockAllApis: async ({ }, use) => {
    const mockAll = async (page: Page) => {
      // IAM - Users
      await page.route('**/api/v1/iam/users', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockUsers),
        });
      });

      // IAM - Roles
      await page.route('**/api/v1/iam/roles', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockRoles),
        });
      });

      // IAM - Permissions
      await page.route('**/api/v1/iam/permissions', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'perm-1', name: 'read:users', description: 'Read user data' },
            { id: 'perm-2', name: 'write:users', description: 'Modify user data' },
          ]),
        });
      });

      // Tenant
      await page.route('**/api/v1/tenant', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockTenant),
        });
      });

      await page.route('**/api/v1/tenant/members', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockUsers),
        });
      });

      await page.route('**/api/v1/tenant/invitations', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        });
      });

      // Devices
      await page.route('**/v1/devices', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDevices),
        });
      });

      // CA - Certificates
      await page.route('**/api/ca/certificates', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockCertificates),
        });
      });

      // KMS - Keys
      await page.route('**/api/kms/keys', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockKeys),
        });
      });
    };

    await use(mockAll);
  },

  /**
   * Mock specific API endpoint
   */
  mockApiEndpoint: async ({ }, use) => {
    const mock = async (
      page: Page,
      pattern: string | RegExp,
      response: unknown,
      options?: { status?: number; contentType?: string }
    ) => {
      await page.route(pattern, (route) => {
        route.fulfill({
          status: options?.status || 200,
          contentType: options?.contentType || 'application/json',
          body: JSON.stringify(response),
        });
      });
    };

    await use(mock);
  },

  /**
   * Mock API to return error
   */
  mockApiError: async ({ }, use) => {
    const mockError = async (
      page: Page,
      pattern: string | RegExp,
      errorCode: string,
      errorMessage: string,
      status = 500
    ) => {
      await page.route(pattern, (route) => {
        route.fulfill({
          status,
          contentType: 'application/json',
          body: JSON.stringify({
            code: errorCode,
            message: errorMessage,
          }),
        });
      });
    };

    await use(mockError);
  },
});

export { expect } from '@playwright/test';
