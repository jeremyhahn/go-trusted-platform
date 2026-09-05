/**
 * Device and profile API mocks shared by the device E2E specs.
 *
 * Lifted out of devices.spec.ts so other specs (attestation-reports.spec.ts)
 * can drive the same mocked device registry: Playwright forbids importing one
 * test file from another. The shapes are the SDK's wire shapes; the mocks
 * answer the platform's envelopes.
 */

import type { Page, Route, Request } from '@playwright/test';
import type { ApiError } from './api-mock';
import type { DeviceRole } from 'trusted-platform-sdk';

// ============================================================================
// Device Types and Mock Data
// ============================================================================

/**
 * SDK Device type - matches the SDK's Device interface
 * The page transforms this to a local Device type with name, type, status, tpm
 */
export interface Device {
  id: number;
  model?: string;
  serial: string;
  attestPub?: string;
  ekCert?: string;
  hashAlgoId: number;
  createdAt: string;
  updatedAt: string;
}

/**
 * Extended device type for detail views (matches what the page expects)
 * The detail page uses DeviceDetail from @/types/device which has these fields
 */
export interface DeviceDetail extends Device {
  // Display fields expected by detail page
  name?: string;
  type?: 'physical' | 'virtual';
  status?: 'online' | 'offline' | 'disabled';
  registeredAt?: string;
  lastSeen?: string;
  tpm?: TPMInfo;
  // Extended fields
  description?: string;
  tags?: string[];
  certificates: DeviceCertificate[];
  attestationHistory: AttestationRecord[];
}

export interface TPMInfo {
  manufacturer: string;
  version: string;
  firmwareVersion: string;
  hasEK: boolean;
  hasSRK: boolean;
}

export interface DeviceCertificate {
  id: string;
  type: 'EK' | 'AIK' | 'IDevID' | 'LDevID';
  subject: string;
  serialNumber: string;
  issuedAt: string;
  expiresAt: string;
  status: 'active' | 'revoked' | 'expired';
}

export interface AttestationRecord {
  id: string;
  timestamp: string;
  status: 'passed' | 'failed' | 'pending';
  nonce: string;
  pcrValues: Record<number, string>;
  signature: string;
  quote: string;
}

export interface DeviceListResponse {
  devices: Device[];
  pagination: {
    page: number;
    pageSize: number;
    totalPages: number;
    totalItems: number;
  };
}

// ============================================================================
// Device Profile Types and Mock Data
// ============================================================================

/**
 * Device Profile type matching the SDK's DeviceProfile interface
 */
export interface DeviceProfile {
  id: number;
  name: string;
  model?: string;
  role: DeviceRole;
  // The operator surface sends an open-keyed phase map plus three selector
  // strings naming the active key — never fixed per-phase fields (#378).
  networks?: Record<string, NetworkConfig>;
  enrollment_network?: string;
  post_enrollment_network?: string;
  failure_network?: string;
  createdAt: string;
  updatedAt: string;
}

export interface NetworkConfig {
  vlan?: number;
  subnet?: string;
  gateway?: string;
}

export interface ProfileListResponse {
  profiles: DeviceProfile[];
}

// Mock data generators
let deviceIdCounter = 1;

/**
 * Creates a mock device matching the SDK Device interface.
 * The page transforms this to a local Device type:
 * - name: derived from model or serial
 * - type: hardcoded to 'physical' (SDK doesn't have this field)
 * - status: hardcoded to 'online' (SDK doesn't have this field)
 * - tpm: derived from attestPub (if present, shows 'Unknown' manufacturer)
 */
export function createMockDevice(overrides: Partial<Device> = {}): Device {
  const id = overrides.id || deviceIdCounter++;
  const now = new Date();

  return {
    id,
    model: `Device-${id}`,
    serial: `SN-${String(id).padStart(8, '0')}`,
    attestPub: 'mock-attest-pub-key',
    ekCert: 'mock-ek-certificate',
    hashAlgoId: 11, // SHA256
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    ...overrides,
  };
}

/**
 * Creates a mock device detail for detail page tests.
 * Includes all fields expected by the detail page including display fields.
 */
export function createMockDeviceDetail(overrides: Partial<DeviceDetail> = {}): DeviceDetail {
  const baseDevice = createMockDevice(overrides);
  const now = new Date();
  const futureDate = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  // Determine if device has TPM based on attestPub
  const hasTPM = !!(overrides.attestPub ?? baseDevice.attestPub);

  return {
    ...baseDevice,
    // Display fields expected by detail page
    name: overrides.model || baseDevice.model || 'Unknown Device',
    type: 'physical' as const,
    status: 'online' as const,
    registeredAt: baseDevice.createdAt,
    lastSeen: baseDevice.updatedAt,
    tpm: hasTPM ? {
      manufacturer: 'Unknown',
      version: '2.0',
      firmwareVersion: '1.0',
      hasEK: !!baseDevice.ekCert,
      hasSRK: false,
    } : undefined,
    // Extended fields
    description: 'Test device for E2E testing',
    tags: ['test', 'e2e'],
    certificates: overrides.certificates ?? [
      {
        id: `cert-${baseDevice.id}-1`,
        type: 'EK',
        subject: `CN=Device ${baseDevice.id} EK`,
        serialNumber: `EK-${String(baseDevice.id).padStart(8, '0')}`,
        issuedAt: now.toISOString(),
        expiresAt: futureDate.toISOString(),
        status: 'active',
      },
    ],
    attestationHistory: overrides.attestationHistory ?? [
      {
        id: `attest-${baseDevice.id}-1`,
        timestamp: now.toISOString(),
        status: 'passed',
        nonce: 'mock-nonce-value',
        pcrValues: { 0: 'abc123', 1: 'def456', 7: 'ghi789' },
        signature: 'mock-signature',
        quote: 'mock-quote',
      },
    ],
    ...overrides,
  };
}

// Profile mock data generators
let profileIdCounter = 1;

/**
 * Creates a mock device profile matching the SDK DeviceProfile interface.
 */
export function createMockProfile(overrides: Partial<DeviceProfile> = {}): DeviceProfile {
  const id = overrides.id || profileIdCounter++;
  const now = new Date();

  return {
    id,
    name: `Profile-${id}`,
    model: `Model-${id}`,
    role: 'SERVER' as DeviceRole,
    networks: {
      provisioning: {
        vlan: 100,
        subnet: '10.0.0.0/24',
        gateway: '10.0.0.1',
      },
      trusted: {
        vlan: 200,
        subnet: '10.1.0.0/24',
        gateway: '10.1.0.1',
      },
    },
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    ...overrides,
  };
}

// ============================================================================
// API Mock Configuration
// ============================================================================

export interface DeviceApiMockConfig {
  initialDevices?: Device[];
  deviceDetail?: DeviceDetail | null;
  fetchError?: ApiError | null;
  fetchDetailError?: ApiError | null;
  createError?: ApiError | null;
  updateError?: ApiError | null;
  deleteError?: ApiError | null;
}

interface DeviceApiState {
  devices: Device[];
  config: DeviceApiMockConfig;
}

/**
 * Mock the devices API endpoints.
 *
 * Handles:
 * - GET /api/v1/devices - List devices
 * - GET /api/v1/devices/:id - Get device details
 * - POST /api/v1/devices - Create device
 * - PUT /api/v1/devices/:id - Update device
 * - DELETE /api/v1/devices/:id - Delete device
 */
export async function mockDeviceApi(
  page: Page,
  config: DeviceApiMockConfig = {}
): Promise<{
  getDevices: () => Device[];
  addDevice: (device: Device) => void;
  removeDevice: (id: number) => void;
  clearDevices: () => void;
  setError: (endpoint: 'fetch' | 'fetchDetail' | 'create' | 'update' | 'delete', error: ApiError | null) => void;
}> {
  const state: DeviceApiState = {
    devices: config.initialDevices || [],
    config: {
      fetchError: null,
      fetchDetailError: null,
      createError: null,
      updateError: null,
      deleteError: null,
      ...config,
    },
  };

  // Route handler for devices list (matches /api/v1/devices with or without query params)
  await page.route('**/api/v1/devices*', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.fetchError) {
        await route.fulfill({
          status: state.config.fetchError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.fetchError.error,
            code: state.config.fetchError.errorCode || 'HTTP_' + state.config.fetchError.status,
          }),
        });
        return;
      }

      const response: DeviceListResponse = {
        devices: state.devices,
        pagination: {
          page: 1,
          pageSize: 100,
          totalPages: Math.ceil(state.devices.length / 100) || 1,
          totalItems: state.devices.length,
        },
      };

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.createError) {
        await route.fulfill({
          status: state.config.createError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.createError.error,
            code: state.config.createError.errorCode || 'HTTP_' + state.config.createError.status,
          }),
        });
        return;
      }

      try {
        const body = request.postDataJSON();
        const newDevice = createMockDevice({
          model: body.device?.name || body.device?.model,
          serial: body.device?.serial,
        });

        state.devices.unshift(newDevice);

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ device: newDevice }),
        });
      } catch {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Invalid request body', code: 'HTTP_400' }),
        });
      }
      return;
    }

    await route.continue();
  });

  // Route handler for individual device operations
  await page.route('**/api/v1/devices/*', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();

    // Extract device ID from URL
    const match = url.match(/\/devices\/(\d+)/);
    const deviceId = match ? parseInt(match[1], 10) : null;

    if (method === 'GET') {
      if (state.config.fetchDetailError) {
        await route.fulfill({
          status: state.config.fetchDetailError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.fetchDetailError.error,
            code: state.config.fetchDetailError.errorCode || 'HTTP_' + state.config.fetchDetailError.status,
          }),
        });
        return;
      }

      // Return provided detail or find from list
      // Note: The page uses response.data directly, so we return the device detail directly
      // (This is a workaround for the page bug that should use response.data.device)
      if (config.deviceDetail) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(config.deviceDetail),
        });
        return;
      }

      const device = state.devices.find((d) => d.id === deviceId);
      if (device) {
        const detail = createMockDeviceDetail({ ...device });
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(detail),
        });
      } else {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Device not found', code: 'HTTP_404' }),
        });
      }
      return;
    }

    if (method === 'PUT') {
      if (state.config.updateError) {
        await route.fulfill({
          status: state.config.updateError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.updateError.error,
            code: state.config.updateError.errorCode || 'HTTP_' + state.config.updateError.status,
          }),
        });
        return;
      }

      const index = state.devices.findIndex((d) => d.id === deviceId);
      if (index !== -1) {
        try {
          const body = request.postDataJSON();
          state.devices[index] = {
            ...state.devices[index],
            ...body.device,
            updatedAt: new Date().toISOString(),
          };

          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ device: state.devices[index] }),
          });
        } catch {
          await route.fulfill({
            status: 400,
            contentType: 'application/json',
            body: JSON.stringify({ message: 'Invalid request body', code: 'HTTP_400' }),
          });
        }
      } else {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Device not found', code: 'HTTP_404' }),
        });
      }
      return;
    }

    if (method === 'DELETE') {
      if (state.config.deleteError) {
        await route.fulfill({
          status: state.config.deleteError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.deleteError.error,
            code: state.config.deleteError.errorCode || 'HTTP_' + state.config.deleteError.status,
          }),
        });
        return;
      }

      const index = state.devices.findIndex((d) => d.id === deviceId);
      if (index !== -1) {
        state.devices.splice(index, 1);
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    await route.continue();
  });

  return {
    getDevices: () => [...state.devices],
    addDevice: (device: Device) => {
      state.devices.unshift(device);
    },
    removeDevice: (id: number) => {
      const index = state.devices.findIndex((d) => d.id === id);
      if (index !== -1) {
        state.devices.splice(index, 1);
      }
    },
    clearDevices: () => {
      state.devices = [];
    },
    setError: (endpoint: 'fetch' | 'fetchDetail' | 'create' | 'update' | 'delete', error: ApiError | null) => {
      if (endpoint === 'fetch') {
        state.config.fetchError = error;
      } else if (endpoint === 'fetchDetail') {
        state.config.fetchDetailError = error;
      } else if (endpoint === 'create') {
        state.config.createError = error;
      } else if (endpoint === 'update') {
        state.config.updateError = error;
      } else if (endpoint === 'delete') {
        state.config.deleteError = error;
      }
    },
  };
}

// ============================================================================
// Device Profile API Mock Configuration
// ============================================================================

export interface ProfileApiMockConfig {
  initialProfiles?: DeviceProfile[];
  fetchError?: ApiError | null;
  createError?: ApiError | null;
  deleteError?: ApiError | null;
}

interface ProfileApiState {
  profiles: DeviceProfile[];
  config: ProfileApiMockConfig;
}

/**
 * Mock the device profiles API endpoints.
 *
 * Handles:
 * - GET /api/v1/devices/profiles - List profiles
 * - POST /api/v1/devices/profiles - Create profile
 * - DELETE /api/v1/devices/profiles/:id - Delete profile
 */
export async function mockProfileApi(
  page: Page,
  config: ProfileApiMockConfig = {}
): Promise<{
  getProfiles: () => DeviceProfile[];
  addProfile: (profile: DeviceProfile) => void;
  removeProfile: (id: number) => void;
  clearProfiles: () => void;
  setError: (endpoint: 'fetch' | 'create' | 'delete', error: ApiError | null) => void;
}> {
  const state: ProfileApiState = {
    profiles: config.initialProfiles || [],
    config: {
      fetchError: null,
      createError: null,
      deleteError: null,
      ...config,
    },
  };

  // Route handler for profiles list (matches /api/v1/devices/profiles with or without query params)
  await page.route('**/api/v1/devices/profiles', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.fetchError) {
        await route.fulfill({
          status: state.config.fetchError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.fetchError.error,
            code: state.config.fetchError.errorCode || 'HTTP_' + state.config.fetchError.status,
          }),
        });
        return;
      }

      const response: ProfileListResponse = {
        profiles: state.profiles,
      };

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.createError) {
        await route.fulfill({
          status: state.config.createError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.createError.error,
            code: state.config.createError.errorCode || 'HTTP_' + state.config.createError.status,
          }),
        });
        return;
      }

      try {
        const body = request.postDataJSON();
        const profileData = body.profile || body;
        const newProfile = createMockProfile({
          name: profileData.name,
          model: profileData.model,
          role: profileData.role || 'SERVER',
        });

        state.profiles.unshift(newProfile);

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ profile: newProfile }),
        });
      } catch {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Invalid request body', code: 'HTTP_400' }),
        });
      }
      return;
    }

    await route.continue();
  });

  // Route handler for individual profile operations
  await page.route('**/api/v1/devices/profiles/*', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();

    // Extract profile ID from URL
    const match = url.match(/\/profiles\/(\d+)/);
    const profileId = match ? parseInt(match[1], 10) : null;

    if (method === 'DELETE') {
      if (state.config.deleteError) {
        await route.fulfill({
          status: state.config.deleteError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.deleteError.error,
            code: state.config.deleteError.errorCode || 'HTTP_' + state.config.deleteError.status,
          }),
        });
        return;
      }

      const index = state.profiles.findIndex((p) => p.id === profileId);
      if (index !== -1) {
        state.profiles.splice(index, 1);
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    await route.continue();
  });

  return {
    getProfiles: () => [...state.profiles],
    addProfile: (profile: DeviceProfile) => {
      state.profiles.unshift(profile);
    },
    removeProfile: (id: number) => {
      const index = state.profiles.findIndex((p) => p.id === id);
      if (index !== -1) {
        state.profiles.splice(index, 1);
      }
    },
    clearProfiles: () => {
      state.profiles = [];
    },
    setError: (endpoint: 'fetch' | 'create' | 'delete', error: ApiError | null) => {
      if (endpoint === 'fetch') {
        state.config.fetchError = error;
      } else if (endpoint === 'create') {
        state.config.createError = error;
      } else if (endpoint === 'delete') {
        state.config.deleteError = error;
      }
    },
  };
}

