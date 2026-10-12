import { Page, Route, Request } from '@playwright/test';
import type { TPMInfoResponse } from 'trusted-platform-sdk';

/**
 * Dashboard API Mock Fixtures for E2E Tests
 *
 * Provides comprehensive mocking utilities for all dashboard API endpoints
 * using Playwright's page.route() functionality. Enables testing UI interactions
 * without requiring a real backend.
 */

// ============================================================================
// Common Types
// ============================================================================

export interface ApiError {
  error: string;
  errorCode?: string;
  status: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

// ============================================================================
// Device Types
// ============================================================================

export interface Device {
  id: string;
  name: string;
  description?: string;
  status: 'online' | 'offline' | 'pending' | 'error';
  platform: string;
  os_version: string;
  tpm_enabled: boolean;
  last_seen: string;
  created_at: string;
  updated_at: string;
  attestation_status: 'attested' | 'pending' | 'failed' | 'none';
  tags?: string[];
}

export interface DeviceListResponse extends PaginatedResponse<Device> {
  devices: Device[];
}

// ============================================================================
// CA Types
// ============================================================================

export interface Certificate {
  id: string;
  serial_number: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  status: 'valid' | 'revoked' | 'expired';
  key_type: 'RSA' | 'EC' | 'ED25519';
  key_size: number;
  signature_algorithm: string;
  fingerprint_sha256: string;
  created_at: string;
  revoked_at?: string;
  revocation_reason?: string;
}

export interface CertificateListResponse extends PaginatedResponse<Certificate> {
  certificates: Certificate[];
}

export interface CertificateIssueRequest {
  subject: string;
  key_type: 'RSA' | 'EC' | 'ED25519';
  key_size?: number;
  validity_days: number;
  san?: string[];
}

// ============================================================================
// KMS Types
// ============================================================================

export interface KMSKey {
  id: string;
  name: string;
  description?: string;
  algorithm: 'AES-256' | 'RSA-2048' | 'RSA-4096' | 'EC-P256' | 'EC-P384' | 'ED25519';
  status: 'active' | 'disabled' | 'pending_deletion' | 'deleted';
  usage: 'encrypt' | 'sign' | 'wrap' | 'all';
  created_at: string;
  updated_at: string;
  rotation_period_days?: number;
  last_rotated_at?: string;
  tags?: string[];
}

export interface KMSKeyListResponse extends PaginatedResponse<KMSKey> {
  keys: KMSKey[];
}

export interface EncryptRequest {
  key_id: string;
  plaintext: string;
  aad?: string;
}

export interface EncryptResponse {
  ciphertext: string;
  key_id: string;
  algorithm: string;
}

export interface DecryptRequest {
  key_id: string;
  ciphertext: string;
  aad?: string;
}

export interface DecryptResponse {
  plaintext: string;
  key_id: string;
}

// ============================================================================
// IAM Types
// ============================================================================

export interface User {
  id: string;
  email: string;
  username: string;
  display_name?: string;
  status: 'active' | 'disabled' | 'pending' | 'locked';
  roles: string[];
  groups: string[];
  mfa_enabled: boolean;
  last_login?: string;
  created_at: string;
  updated_at: string;
}

export interface UserListResponse extends PaginatedResponse<User> {
  users: User[];
}

export interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: string[];
  created_at: string;
  updated_at: string;
}

export interface RoleListResponse extends PaginatedResponse<Role> {
  roles: Role[];
}

export interface Group {
  id: string;
  name: string;
  description?: string;
  member_count: number;
  roles: string[];
  created_at: string;
  updated_at: string;
}

export interface GroupListResponse extends PaginatedResponse<Group> {
  groups: Group[];
}

// ============================================================================
// Platform Types
// ============================================================================

export interface PlatformHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  timestamp: string;
  uptime_seconds: number;
  services: Record<string, ServiceHealth>;
}

export interface ServiceHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  latency_ms?: number;
  message?: string;
  last_check: string;
}

export interface PlatformConfig {
  version: string;
  environment: string;
  features: Record<string, boolean>;
  limits: Record<string, number>;
}

// ============================================================================
// Storage Types (QuicBaaS)
// ============================================================================

export interface KVEntry {
  key: string;
  value: string;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at: string;
  ttl?: number;
}

export interface KVListResponse {
  entries: KVEntry[];
  total: number;
  cursor?: string;
}

export interface Bucket {
  name: string;
  region: string;
  created_at: string;
  object_count: number;
  total_size_bytes: number;
}

export interface BucketListResponse {
  buckets: Bucket[];
  total: number;
}

export interface StorageObject {
  key: string;
  size: number;
  content_type: string;
  etag: string;
  last_modified: string;
  metadata?: Record<string, string>;
}

export interface ObjectListResponse {
  objects: StorageObject[];
  total: number;
  prefix?: string;
  delimiter?: string;
  is_truncated: boolean;
  continuation_token?: string;
}

export interface Backup {
  id: string;
  name: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  type: 'full' | 'incremental';
  size_bytes: number;
  created_at: string;
  completed_at?: string;
  error_message?: string;
}

export interface BackupListResponse {
  backups: Backup[];
  total: number;
}

// ============================================================================
// TPM Types
// ============================================================================

/** The `GET /api/v1/tpm/info` payload, exactly as the SDK types it. */
export type TPMInfo = TPMInfoResponse;

export interface TPMKey {
  handle: string;
  name: string;
  type: 'RSA' | 'ECC';
  usage: 'signing' | 'encryption' | 'attestation';
  persistent: boolean;
  created_at: string;
}

export interface TPMKeyListResponse {
  keys: TPMKey[];
  total: number;
}

export interface PCRValue {
  index: number;
  algorithm: string;
  value: string;
  description?: string;
}

export interface PCRResponse {
  pcrs: PCRValue[];
  bank: string;
}

// ============================================================================
// Attestation Types
// ============================================================================

export interface AttestationManifest {
  id: string;
  device_id: string;
  status: 'valid' | 'invalid' | 'pending' | 'expired';
  pcr_values: PCRValue[];
  quote: string;
  signature: string;
  created_at: string;
  expires_at: string;
  verified_at?: string;
}

export interface ManifestListResponse {
  manifests: AttestationManifest[];
  total: number;
}

export interface AttestationVerifyRequest {
  manifest_id?: string;
  device_id?: string;
  quote: string;
  signature: string;
  pcr_selection?: number[];
}

export interface AttestationVerifyResponse {
  verified: boolean;
  device_id: string;
  manifest_id: string;
  pcr_match: boolean;
  signature_valid: boolean;
  errors?: string[];
}

// ============================================================================
// ID Counters for Mock Data Generation
// ============================================================================

let deviceIdCounter = 1;
let certificateIdCounter = 1;
let keyIdCounter = 1;
let userIdCounter = 1;
let roleIdCounter = 1;
let groupIdCounter = 1;
let backupIdCounter = 1;
let manifestIdCounter = 1;

/**
 * Reset all ID counters. Useful between test runs.
 */
export function resetIdCounters(): void {
  deviceIdCounter = 1;
  certificateIdCounter = 1;
  keyIdCounter = 1;
  userIdCounter = 1;
  roleIdCounter = 1;
  groupIdCounter = 1;
  backupIdCounter = 1;
  manifestIdCounter = 1;
}

// ============================================================================
// Mock Data Generators
// ============================================================================

/**
 * Generate a mock device object.
 */
export function createMockDevice(overrides: Partial<Device> = {}): Device {
  const id = overrides.id || `device-${deviceIdCounter++}`;
  const now = new Date();

  return {
    id,
    name: `Device ${id}`,
    description: 'Test device for E2E testing',
    status: 'online',
    platform: 'linux',
    os_version: 'Ubuntu 22.04',
    tpm_enabled: true,
    last_seen: now.toISOString(),
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    attestation_status: 'attested',
    tags: ['test', 'e2e'],
    ...overrides,
  };
}

/**
 * Generate a mock certificate object.
 */
export function createMockCertificate(overrides: Partial<Certificate> = {}): Certificate {
  const id = overrides.id || `cert-${certificateIdCounter++}`;
  const now = new Date();
  const notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  return {
    id,
    serial_number: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    subject: `CN=test-${id}.example.com`,
    issuer: 'CN=Test CA',
    not_before: now.toISOString(),
    not_after: notAfter.toISOString(),
    status: 'valid',
    key_type: 'EC',
    key_size: 256,
    signature_algorithm: 'ECDSA-SHA256',
    fingerprint_sha256: `sha256:${Array(64).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join('')}`,
    created_at: now.toISOString(),
    ...overrides,
  };
}

/**
 * Generate a mock KMS key object.
 */
export function createMockKMSKey(overrides: Partial<KMSKey> = {}): KMSKey {
  const id = overrides.id || `key-${keyIdCounter++}`;
  const now = new Date();

  return {
    id,
    name: `Key ${id}`,
    description: 'Test key for E2E testing',
    algorithm: 'AES-256',
    status: 'active',
    usage: 'encrypt',
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    rotation_period_days: 90,
    tags: ['test'],
    ...overrides,
  };
}

/**
 * Generate a mock user object.
 */
export function createMockUser(overrides: Partial<User> = {}): User {
  const id = overrides.id || `user-${userIdCounter++}`;
  const now = new Date();

  return {
    id,
    email: `user${userIdCounter}@example.com`,
    username: `user${userIdCounter}`,
    display_name: `Test User ${userIdCounter}`,
    status: 'active',
    roles: ['member'],
    groups: [],
    mfa_enabled: false,
    last_login: now.toISOString(),
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    ...overrides,
  };
}

/**
 * Generate a mock role object.
 */
export function createMockRole(overrides: Partial<Role> = {}): Role {
  const id = overrides.id || `role-${roleIdCounter++}`;
  const now = new Date();

  return {
    id,
    name: `Role ${id}`,
    description: 'Test role for E2E testing',
    permissions: ['read', 'write'],
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    ...overrides,
  };
}

/**
 * Generate a mock group object.
 */
export function createMockGroup(overrides: Partial<Group> = {}): Group {
  const id = overrides.id || `group-${groupIdCounter++}`;
  const now = new Date();

  return {
    id,
    name: `Group ${id}`,
    description: 'Test group for E2E testing',
    member_count: 5,
    roles: ['member'],
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    ...overrides,
  };
}

/**
 * Generate a mock KV entry object.
 */
export function createMockKVEntry(key: string, value: string, overrides: Partial<KVEntry> = {}): KVEntry {
  const now = new Date();

  return {
    key,
    value,
    metadata: {},
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    ...overrides,
  };
}

/**
 * Generate a mock bucket object.
 */
export function createMockBucket(name: string, overrides: Partial<Bucket> = {}): Bucket {
  const now = new Date();

  return {
    name,
    region: 'us-east-1',
    created_at: now.toISOString(),
    object_count: 100,
    total_size_bytes: 1024 * 1024 * 100,
    ...overrides,
  };
}

/**
 * Generate a mock storage object.
 */
export function createMockStorageObject(key: string, overrides: Partial<StorageObject> = {}): StorageObject {
  const now = new Date();

  return {
    key,
    size: 1024,
    content_type: 'application/octet-stream',
    etag: `"${Math.random().toString(36).substr(2, 32)}"`,
    last_modified: now.toISOString(),
    metadata: {},
    ...overrides,
  };
}

/**
 * Generate a mock backup object.
 */
export function createMockBackup(overrides: Partial<Backup> = {}): Backup {
  const id = overrides.id || `backup-${backupIdCounter++}`;
  const now = new Date();

  return {
    id,
    name: `Backup ${id}`,
    status: 'completed',
    type: 'full',
    size_bytes: 1024 * 1024 * 500,
    created_at: now.toISOString(),
    completed_at: now.toISOString(),
    ...overrides,
  };
}

/**
 * Generate a mock TPM info object.
 */
export function createMockTPMInfo(overrides: Partial<TPMInfo> = {}): TPMInfo {
  return {
    version: 'TPM_VERSION_2_0',
    manufacturer: {
      name: 'Intel',
      id: 0x494e5443,
      model: 'PTT',
      firmwareVersion: '7.85.4555.0',
    },
    capabilities: [],
    pcrBanks: ['PCR_BANK_SHA256'],
    maxNvramSize: 16384,
    isSimulator: false,
    fipsMode: false,
    properties: {},
    nvIndexes: [],
    ...overrides,
  };
}

/**
 * Generate a mock TPM key object.
 */
export function createMockTPMKey(overrides: Partial<TPMKey> = {}): TPMKey {
  const now = new Date();

  return {
    handle: `0x8100000${Math.floor(Math.random() * 10)}`,
    name: 'Attestation Key',
    type: 'ECC',
    usage: 'attestation',
    persistent: true,
    created_at: now.toISOString(),
    ...overrides,
  };
}

/**
 * Generate a mock PCR value object.
 */
export function createMockPCRValue(index: number, overrides: Partial<PCRValue> = {}): PCRValue {
  return {
    index,
    algorithm: 'SHA256',
    value: Array(64).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join(''),
    description: `PCR ${index}`,
    ...overrides,
  };
}

/**
 * Generate a mock attestation manifest object.
 */
export function createMockManifest(overrides: Partial<AttestationManifest> = {}): AttestationManifest {
  const id = overrides.id || `manifest-${manifestIdCounter++}`;
  const now = new Date();
  const expires = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

  return {
    id,
    device_id: `device-${Math.floor(Math.random() * 100)}`,
    status: 'valid',
    pcr_values: [0, 1, 2, 3, 4, 5, 6, 7].map((i) => createMockPCRValue(i)),
    quote: Buffer.from('mock-quote-data').toString('base64'),
    signature: Buffer.from('mock-signature').toString('base64'),
    created_at: now.toISOString(),
    expires_at: expires.toISOString(),
    verified_at: now.toISOString(),
    ...overrides,
  };
}

// ============================================================================
// API Mock Configurations
// ============================================================================

export interface DeviceApiMockConfig {
  initialDevices?: Device[];
  listError?: ApiError | null;
  getError?: ApiError | null;
  createError?: ApiError | null;
  updateError?: ApiError | null;
  deleteError?: ApiError | null;
}

export interface CertificateApiMockConfig {
  initialCertificates?: Certificate[];
  listError?: ApiError | null;
  getError?: ApiError | null;
  issueError?: ApiError | null;
  revokeError?: ApiError | null;
}

export interface KMSApiMockConfig {
  initialKeys?: KMSKey[];
  listError?: ApiError | null;
  getError?: ApiError | null;
  createError?: ApiError | null;
  deleteError?: ApiError | null;
  encryptError?: ApiError | null;
  decryptError?: ApiError | null;
}

export interface IAMApiMockConfig {
  initialUsers?: User[];
  initialRoles?: Role[];
  initialGroups?: Group[];
  userListError?: ApiError | null;
  userGetError?: ApiError | null;
  userCreateError?: ApiError | null;
  userUpdateError?: ApiError | null;
  userDeleteError?: ApiError | null;
  roleListError?: ApiError | null;
  groupListError?: ApiError | null;
}

export interface PlatformApiMockConfig {
  healthStatus?: 'healthy' | 'degraded' | 'unhealthy';
  healthError?: ApiError | null;
  configError?: ApiError | null;
  config?: Partial<PlatformConfig>;
}

export interface StorageApiMockConfig {
  initialKVEntries?: KVEntry[];
  initialBuckets?: Bucket[];
  initialObjects?: Record<string, StorageObject[]>;
  initialBackups?: Backup[];
  kvListError?: ApiError | null;
  kvSetError?: ApiError | null;
  kvDeleteError?: ApiError | null;
  bucketListError?: ApiError | null;
  objectListError?: ApiError | null;
  backupListError?: ApiError | null;
  backupCreateError?: ApiError | null;
}

export interface TPMApiMockConfig {
  tpmInfo?: TPMInfo;
  initialKeys?: TPMKey[];
  pcrValues?: PCRValue[];
  infoError?: ApiError | null;
  keysError?: ApiError | null;
  pcrsError?: ApiError | null;
}

export interface AttestationApiMockConfig {
  initialManifests?: AttestationManifest[];
  listError?: ApiError | null;
  buildError?: ApiError | null;
  verifyError?: ApiError | null;
  verifyResult?: Partial<AttestationVerifyResponse>;
}

// ============================================================================
// API State Interfaces
// ============================================================================

interface DeviceApiState {
  devices: Device[];
  config: DeviceApiMockConfig;
}

interface CertificateApiState {
  certificates: Certificate[];
  config: CertificateApiMockConfig;
}

interface KMSApiState {
  keys: KMSKey[];
  config: KMSApiMockConfig;
}

interface IAMApiState {
  users: User[];
  roles: Role[];
  groups: Group[];
  config: IAMApiMockConfig;
}

interface StorageApiState {
  kvEntries: KVEntry[];
  buckets: Bucket[];
  objects: Record<string, StorageObject[]>;
  backups: Backup[];
  config: StorageApiMockConfig;
}

interface TPMApiState {
  tpmInfo: TPMInfo;
  keys: TPMKey[];
  pcrValues: PCRValue[];
  config: TPMApiMockConfig;
}

interface AttestationApiState {
  manifests: AttestationManifest[];
  config: AttestationApiMockConfig;
}

// ============================================================================
// Helper Functions
// ============================================================================

function fulfillError(route: Route, error: ApiError): Promise<void> {
  return route.fulfill({
    status: error.status,
    contentType: 'application/json',
    body: JSON.stringify({
      error: error.error,
      errorCode: error.errorCode,
    }),
  });
}

function fulfillJSON(route: Route, status: number, data: unknown): Promise<void> {
  return route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(data),
  });
}

function extractIdFromUrl(url: string, pattern: RegExp): string | null {
  const match = url.match(pattern);
  return match ? match[1] : null;
}

// ============================================================================
// Device API Mock
// ============================================================================

/**
 * Mock the devices API endpoints.
 *
 * Handles:
 * - GET /api/v1/devices - List devices
 * - GET /api/v1/devices/:id - Get device
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
  updateDevice: (id: string, updates: Partial<Device>) => void;
  removeDevice: (id: string) => void;
  clearDevices: () => void;
  setError: (endpoint: 'list' | 'get' | 'create' | 'update' | 'delete', error: ApiError | null) => void;
}> {
  const state: DeviceApiState = {
    devices: config.initialDevices || [],
    config: {
      listError: null,
      getError: null,
      createError: null,
      updateError: null,
      deleteError: null,
      ...config,
    },
  };

  // List and Create devices
  await page.route('**/api/v1/devices', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.listError) {
        await fulfillError(route, state.config.listError);
        return;
      }

      await fulfillJSON(route, 200, {
        devices: state.devices,
        items: state.devices,
        total: state.devices.length,
        page: 1,
        page_size: 50,
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.createError) {
        await fulfillError(route, state.config.createError);
        return;
      }

      try {
        const body = request.postDataJSON();
        const newDevice = createMockDevice({
          name: body.name,
          description: body.description,
          platform: body.platform,
          tags: body.tags,
        });

        state.devices.unshift(newDevice);

        await fulfillJSON(route, 201, { device: newDevice });
      } catch {
        await fulfillJSON(route, 400, { error: 'Invalid request body' });
      }
      return;
    }

    await route.continue();
  });

  // Get, Update, Delete single device
  await page.route('**/api/v1/devices/*', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();
    const deviceId = extractIdFromUrl(url, /\/devices\/([^/?]+)/);

    if (method === 'GET') {
      if (state.config.getError) {
        await fulfillError(route, state.config.getError);
        return;
      }

      const device = state.devices.find((d) => d.id === deviceId);
      if (!device) {
        await fulfillJSON(route, 404, { error: 'Device not found' });
        return;
      }

      await fulfillJSON(route, 200, { device });
      return;
    }

    if (method === 'PUT') {
      if (state.config.updateError) {
        await fulfillError(route, state.config.updateError);
        return;
      }

      const index = state.devices.findIndex((d) => d.id === deviceId);
      if (index === -1) {
        await fulfillJSON(route, 404, { error: 'Device not found' });
        return;
      }

      try {
        const body = request.postDataJSON();
        state.devices[index] = {
          ...state.devices[index],
          ...body,
          updated_at: new Date().toISOString(),
        };

        await fulfillJSON(route, 200, { device: state.devices[index] });
      } catch {
        await fulfillJSON(route, 400, { error: 'Invalid request body' });
      }
      return;
    }

    if (method === 'DELETE') {
      if (state.config.deleteError) {
        await fulfillError(route, state.config.deleteError);
        return;
      }

      const index = state.devices.findIndex((d) => d.id === deviceId);
      if (index !== -1) {
        state.devices.splice(index, 1);
      }

      await fulfillJSON(route, 200, { success: true });
      return;
    }

    await route.continue();
  });

  return {
    getDevices: () => [...state.devices],
    addDevice: (device: Device) => {
      state.devices.unshift(device);
    },
    updateDevice: (id: string, updates: Partial<Device>) => {
      const index = state.devices.findIndex((d) => d.id === id);
      if (index !== -1) {
        state.devices[index] = { ...state.devices[index], ...updates };
      }
    },
    removeDevice: (id: string) => {
      const index = state.devices.findIndex((d) => d.id === id);
      if (index !== -1) {
        state.devices.splice(index, 1);
      }
    },
    clearDevices: () => {
      state.devices = [];
    },
    setError: (endpoint, error) => {
      switch (endpoint) {
        case 'list':
          state.config.listError = error;
          break;
        case 'get':
          state.config.getError = error;
          break;
        case 'create':
          state.config.createError = error;
          break;
        case 'update':
          state.config.updateError = error;
          break;
        case 'delete':
          state.config.deleteError = error;
          break;
      }
    },
  };
}

// ============================================================================
// CA API Mock
// ============================================================================

/**
 * Mock the CA/certificates API endpoints.
 *
 * Handles:
 * - GET /api/v1/ca/certificates - List certificates
 * - GET /api/v1/ca/certificates/:id - Get certificate
 * - POST /api/v1/ca/certificates - Issue certificate
 * - DELETE /api/v1/ca/certificates/:id - Revoke certificate
 */
export async function mockCertificateApi(
  page: Page,
  config: CertificateApiMockConfig = {}
): Promise<{
  getCertificates: () => Certificate[];
  addCertificate: (cert: Certificate) => void;
  revokeCertificate: (id: string, reason?: string) => void;
  clearCertificates: () => void;
  setError: (endpoint: 'list' | 'get' | 'issue' | 'revoke', error: ApiError | null) => void;
}> {
  const state: CertificateApiState = {
    certificates: config.initialCertificates || [],
    config: {
      listError: null,
      getError: null,
      issueError: null,
      revokeError: null,
      ...config,
    },
  };

  // List and Issue certificates
  await page.route('**/api/v1/ca/certificates', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.listError) {
        await fulfillError(route, state.config.listError);
        return;
      }

      await fulfillJSON(route, 200, {
        certificates: state.certificates,
        items: state.certificates,
        total: state.certificates.length,
        page: 1,
        page_size: 50,
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.issueError) {
        await fulfillError(route, state.config.issueError);
        return;
      }

      try {
        const body = request.postDataJSON() as CertificateIssueRequest;
        const notAfter = new Date();
        notAfter.setDate(notAfter.getDate() + (body.validity_days || 365));

        const newCert = createMockCertificate({
          subject: body.subject,
          key_type: body.key_type,
          key_size: body.key_size || (body.key_type === 'RSA' ? 2048 : 256),
          not_after: notAfter.toISOString(),
        });

        state.certificates.unshift(newCert);

        await fulfillJSON(route, 201, { certificate: newCert });
      } catch {
        await fulfillJSON(route, 400, { error: 'Invalid request body' });
      }
      return;
    }

    await route.continue();
  });

  // Get, Revoke single certificate
  await page.route('**/api/v1/ca/certificates/*', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();
    const certId = extractIdFromUrl(url, /\/certificates\/([^/?]+)/);

    if (method === 'GET') {
      if (state.config.getError) {
        await fulfillError(route, state.config.getError);
        return;
      }

      const cert = state.certificates.find((c) => c.id === certId);
      if (!cert) {
        await fulfillJSON(route, 404, { error: 'Certificate not found' });
        return;
      }

      await fulfillJSON(route, 200, { certificate: cert });
      return;
    }

    if (method === 'DELETE') {
      if (state.config.revokeError) {
        await fulfillError(route, state.config.revokeError);
        return;
      }

      const index = state.certificates.findIndex((c) => c.id === certId);
      if (index !== -1) {
        state.certificates[index] = {
          ...state.certificates[index],
          status: 'revoked',
          revoked_at: new Date().toISOString(),
          revocation_reason: 'User requested revocation',
        };
      }

      await fulfillJSON(route, 200, { success: true });
      return;
    }

    await route.continue();
  });

  return {
    getCertificates: () => [...state.certificates],
    addCertificate: (cert: Certificate) => {
      state.certificates.unshift(cert);
    },
    revokeCertificate: (id: string, reason?: string) => {
      const index = state.certificates.findIndex((c) => c.id === id);
      if (index !== -1) {
        state.certificates[index] = {
          ...state.certificates[index],
          status: 'revoked',
          revoked_at: new Date().toISOString(),
          revocation_reason: reason || 'Revoked',
        };
      }
    },
    clearCertificates: () => {
      state.certificates = [];
    },
    setError: (endpoint, error) => {
      switch (endpoint) {
        case 'list':
          state.config.listError = error;
          break;
        case 'get':
          state.config.getError = error;
          break;
        case 'issue':
          state.config.issueError = error;
          break;
        case 'revoke':
          state.config.revokeError = error;
          break;
      }
    },
  };
}

// ============================================================================
// KMS API Mock
// ============================================================================

/**
 * Mock the KMS API endpoints.
 *
 * Handles:
 * - GET /api/v1/kms/keys - List keys
 * - GET /api/v1/kms/keys/:id - Get key
 * - POST /api/v1/kms/keys - Create key
 * - DELETE /api/v1/kms/keys/:id - Delete key
 * - POST /api/v1/kms/encrypt - Encrypt data
 * - POST /api/v1/kms/decrypt - Decrypt data
 */
export async function mockKMSApi(
  page: Page,
  config: KMSApiMockConfig = {}
): Promise<{
  getKeys: () => KMSKey[];
  addKey: (key: KMSKey) => void;
  removeKey: (id: string) => void;
  clearKeys: () => void;
  setError: (endpoint: 'list' | 'get' | 'create' | 'delete' | 'encrypt' | 'decrypt', error: ApiError | null) => void;
}> {
  const state: KMSApiState = {
    keys: config.initialKeys || [],
    config: {
      listError: null,
      getError: null,
      createError: null,
      deleteError: null,
      encryptError: null,
      decryptError: null,
      ...config,
    },
  };

  // List and Create keys
  await page.route('**/api/v1/kms/keys', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.listError) {
        await fulfillError(route, state.config.listError);
        return;
      }

      await fulfillJSON(route, 200, {
        keys: state.keys,
        items: state.keys,
        total: state.keys.length,
        page: 1,
        page_size: 50,
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.createError) {
        await fulfillError(route, state.config.createError);
        return;
      }

      try {
        const body = request.postDataJSON();
        const newKey = createMockKMSKey({
          name: body.name,
          description: body.description,
          algorithm: body.algorithm,
          usage: body.usage,
          tags: body.tags,
        });

        state.keys.unshift(newKey);

        await fulfillJSON(route, 201, { key: newKey });
      } catch {
        await fulfillJSON(route, 400, { error: 'Invalid request body' });
      }
      return;
    }

    await route.continue();
  });

  // Get, Delete single key
  await page.route('**/api/v1/kms/keys/*', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();
    const keyId = extractIdFromUrl(url, /\/keys\/([^/?]+)/);

    if (method === 'GET') {
      if (state.config.getError) {
        await fulfillError(route, state.config.getError);
        return;
      }

      const key = state.keys.find((k) => k.id === keyId);
      if (!key) {
        await fulfillJSON(route, 404, { error: 'Key not found' });
        return;
      }

      await fulfillJSON(route, 200, { key });
      return;
    }

    if (method === 'DELETE') {
      if (state.config.deleteError) {
        await fulfillError(route, state.config.deleteError);
        return;
      }

      const index = state.keys.findIndex((k) => k.id === keyId);
      if (index !== -1) {
        state.keys[index] = {
          ...state.keys[index],
          status: 'pending_deletion',
        };
      }

      await fulfillJSON(route, 200, { success: true });
      return;
    }

    await route.continue();
  });

  // Encrypt endpoint
  await page.route('**/api/v1/kms/encrypt', async (route: Route, request: Request) => {
    if (request.method() !== 'POST') {
      await route.continue();
      return;
    }

    if (state.config.encryptError) {
      await fulfillError(route, state.config.encryptError);
      return;
    }

    try {
      const body = request.postDataJSON() as EncryptRequest;
      const key = state.keys.find((k) => k.id === body.key_id);

      if (!key) {
        await fulfillJSON(route, 404, { error: 'Key not found' });
        return;
      }

      if (key.status !== 'active') {
        await fulfillJSON(route, 400, { error: 'Key is not active' });
        return;
      }

      const response: EncryptResponse = {
        ciphertext: Buffer.from(`encrypted:${body.plaintext}`).toString('base64'),
        key_id: body.key_id,
        algorithm: key.algorithm,
      };

      await fulfillJSON(route, 200, response);
    } catch {
      await fulfillJSON(route, 400, { error: 'Invalid request body' });
    }
  });

  // Decrypt endpoint
  await page.route('**/api/v1/kms/decrypt', async (route: Route, request: Request) => {
    if (request.method() !== 'POST') {
      await route.continue();
      return;
    }

    if (state.config.decryptError) {
      await fulfillError(route, state.config.decryptError);
      return;
    }

    try {
      const body = request.postDataJSON() as DecryptRequest;
      const key = state.keys.find((k) => k.id === body.key_id);

      if (!key) {
        await fulfillJSON(route, 404, { error: 'Key not found' });
        return;
      }

      if (key.status !== 'active') {
        await fulfillJSON(route, 400, { error: 'Key is not active' });
        return;
      }

      const decoded = Buffer.from(body.ciphertext, 'base64').toString();
      const plaintext = decoded.replace('encrypted:', '');

      const response: DecryptResponse = {
        plaintext,
        key_id: body.key_id,
      };

      await fulfillJSON(route, 200, response);
    } catch {
      await fulfillJSON(route, 400, { error: 'Invalid request body' });
    }
  });

  return {
    getKeys: () => [...state.keys],
    addKey: (key: KMSKey) => {
      state.keys.unshift(key);
    },
    removeKey: (id: string) => {
      const index = state.keys.findIndex((k) => k.id === id);
      if (index !== -1) {
        state.keys.splice(index, 1);
      }
    },
    clearKeys: () => {
      state.keys = [];
    },
    setError: (endpoint, error) => {
      switch (endpoint) {
        case 'list':
          state.config.listError = error;
          break;
        case 'get':
          state.config.getError = error;
          break;
        case 'create':
          state.config.createError = error;
          break;
        case 'delete':
          state.config.deleteError = error;
          break;
        case 'encrypt':
          state.config.encryptError = error;
          break;
        case 'decrypt':
          state.config.decryptError = error;
          break;
      }
    },
  };
}

// ============================================================================
// IAM API Mock
// ============================================================================

/**
 * Mock the IAM API endpoints.
 *
 * Handles:
 * - GET /api/v1/iam/users - List users
 * - GET /api/v1/iam/users/:id - Get user
 * - POST /api/v1/iam/users - Create user
 * - PUT /api/v1/iam/users/:id - Update user
 * - DELETE /api/v1/iam/users/:id - Delete user
 * - GET /api/v1/iam/roles - List roles
 * - GET /api/v1/iam/groups - List groups
 */
export async function mockIAMApi(
  page: Page,
  config: IAMApiMockConfig = {}
): Promise<{
  getUsers: () => User[];
  getRoles: () => Role[];
  getGroups: () => Group[];
  addUser: (user: User) => void;
  updateUser: (id: string, updates: Partial<User>) => void;
  removeUser: (id: string) => void;
  addRole: (role: Role) => void;
  addGroup: (group: Group) => void;
  clearAll: () => void;
  setError: (
    endpoint: 'userList' | 'userGet' | 'userCreate' | 'userUpdate' | 'userDelete' | 'roleList' | 'groupList',
    error: ApiError | null
  ) => void;
}> {
  const state: IAMApiState = {
    users: config.initialUsers || [],
    roles: config.initialRoles || [],
    groups: config.initialGroups || [],
    config: {
      userListError: null,
      userGetError: null,
      userCreateError: null,
      userUpdateError: null,
      userDeleteError: null,
      roleListError: null,
      groupListError: null,
      ...config,
    },
  };

  // List and Create users
  await page.route('**/api/v1/iam/users', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.userListError) {
        await fulfillError(route, state.config.userListError);
        return;
      }

      await fulfillJSON(route, 200, {
        users: state.users,
        items: state.users,
        total: state.users.length,
        page: 1,
        page_size: 50,
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.userCreateError) {
        await fulfillError(route, state.config.userCreateError);
        return;
      }

      try {
        const body = request.postDataJSON();
        const newUser = createMockUser({
          email: body.email,
          username: body.username,
          display_name: body.display_name,
          roles: body.roles,
          groups: body.groups,
        });

        state.users.unshift(newUser);

        await fulfillJSON(route, 201, { user: newUser });
      } catch {
        await fulfillJSON(route, 400, { error: 'Invalid request body' });
      }
      return;
    }

    await route.continue();
  });

  // Get, Update, Delete single user
  await page.route('**/api/v1/iam/users/*', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();
    const userId = extractIdFromUrl(url, /\/users\/([^/?]+)/);

    if (method === 'GET') {
      if (state.config.userGetError) {
        await fulfillError(route, state.config.userGetError);
        return;
      }

      const user = state.users.find((u) => u.id === userId);
      if (!user) {
        await fulfillJSON(route, 404, { error: 'User not found' });
        return;
      }

      await fulfillJSON(route, 200, { user });
      return;
    }

    if (method === 'PUT') {
      if (state.config.userUpdateError) {
        await fulfillError(route, state.config.userUpdateError);
        return;
      }

      const index = state.users.findIndex((u) => u.id === userId);
      if (index === -1) {
        await fulfillJSON(route, 404, { error: 'User not found' });
        return;
      }

      try {
        const body = request.postDataJSON();
        state.users[index] = {
          ...state.users[index],
          ...body,
          updated_at: new Date().toISOString(),
        };

        await fulfillJSON(route, 200, { user: state.users[index] });
      } catch {
        await fulfillJSON(route, 400, { error: 'Invalid request body' });
      }
      return;
    }

    if (method === 'DELETE') {
      if (state.config.userDeleteError) {
        await fulfillError(route, state.config.userDeleteError);
        return;
      }

      const index = state.users.findIndex((u) => u.id === userId);
      if (index !== -1) {
        state.users.splice(index, 1);
      }

      await fulfillJSON(route, 200, { success: true });
      return;
    }

    await route.continue();
  });

  // List roles
  await page.route('**/api/v1/iam/roles', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (state.config.roleListError) {
      await fulfillError(route, state.config.roleListError);
      return;
    }

    await fulfillJSON(route, 200, {
      roles: state.roles,
      items: state.roles,
      total: state.roles.length,
      page: 1,
      page_size: 50,
    });
  });

  // List groups
  await page.route('**/api/v1/iam/groups', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (state.config.groupListError) {
      await fulfillError(route, state.config.groupListError);
      return;
    }

    await fulfillJSON(route, 200, {
      groups: state.groups,
      items: state.groups,
      total: state.groups.length,
      page: 1,
      page_size: 50,
    });
  });

  return {
    getUsers: () => [...state.users],
    getRoles: () => [...state.roles],
    getGroups: () => [...state.groups],
    addUser: (user: User) => {
      state.users.unshift(user);
    },
    updateUser: (id: string, updates: Partial<User>) => {
      const index = state.users.findIndex((u) => u.id === id);
      if (index !== -1) {
        state.users[index] = { ...state.users[index], ...updates };
      }
    },
    removeUser: (id: string) => {
      const index = state.users.findIndex((u) => u.id === id);
      if (index !== -1) {
        state.users.splice(index, 1);
      }
    },
    addRole: (role: Role) => {
      state.roles.unshift(role);
    },
    addGroup: (group: Group) => {
      state.groups.unshift(group);
    },
    clearAll: () => {
      state.users = [];
      state.roles = [];
      state.groups = [];
    },
    setError: (endpoint, error) => {
      switch (endpoint) {
        case 'userList':
          state.config.userListError = error;
          break;
        case 'userGet':
          state.config.userGetError = error;
          break;
        case 'userCreate':
          state.config.userCreateError = error;
          break;
        case 'userUpdate':
          state.config.userUpdateError = error;
          break;
        case 'userDelete':
          state.config.userDeleteError = error;
          break;
        case 'roleList':
          state.config.roleListError = error;
          break;
        case 'groupList':
          state.config.groupListError = error;
          break;
      }
    },
  };
}

// ============================================================================
// Platform API Mock
// ============================================================================

/**
 * Mock the Platform API endpoints.
 *
 * Handles:
 * - GET /api/v1/platform/health - Get health status
 * - GET /api/v1/platform/config - Get config
 */
export async function mockPlatformApi(
  page: Page,
  config: PlatformApiMockConfig = {}
): Promise<{
  setHealthStatus: (status: 'healthy' | 'degraded' | 'unhealthy') => void;
  setConfig: (updates: Partial<PlatformConfig>) => void;
  setError: (endpoint: 'health' | 'config', error: ApiError | null) => void;
}> {
  let healthStatus = config.healthStatus || 'healthy';
  let healthError = config.healthError || null;
  let configError = config.configError || null;
  let platformConfig: PlatformConfig = {
    version: '1.0.0',
    environment: 'development',
    features: {
      tpm_enabled: true,
      attestation_enabled: true,
      kms_enabled: true,
    },
    limits: {
      max_devices: 100,
      max_certificates: 1000,
      max_keys: 500,
    },
    ...config.config,
  };

  // Health endpoint
  await page.route('**/api/v1/platform/health', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (healthError) {
      await fulfillError(route, healthError);
      return;
    }

    const response: PlatformHealth = {
      status: healthStatus,
      version: platformConfig.version,
      timestamp: new Date().toISOString(),
      uptime_seconds: 86400,
      services: {
        database: { status: 'healthy', latency_ms: 5, last_check: new Date().toISOString() },
        cache: { status: 'healthy', latency_ms: 1, last_check: new Date().toISOString() },
        tpm: { status: 'healthy', latency_ms: 10, last_check: new Date().toISOString() },
        kms: { status: 'healthy', latency_ms: 8, last_check: new Date().toISOString() },
        ca: { status: 'healthy', latency_ms: 12, last_check: new Date().toISOString() },
      },
    };

    if (healthStatus === 'degraded') {
      response.services.cache = { status: 'degraded', latency_ms: 100, message: 'High latency', last_check: new Date().toISOString() };
    } else if (healthStatus === 'unhealthy') {
      response.services.database = { status: 'unhealthy', message: 'Connection failed', last_check: new Date().toISOString() };
    }

    await fulfillJSON(route, 200, response);
  });

  // Config endpoint
  await page.route('**/api/v1/platform/config', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (configError) {
      await fulfillError(route, configError);
      return;
    }

    await fulfillJSON(route, 200, platformConfig);
  });

  return {
    setHealthStatus: (status) => {
      healthStatus = status;
    },
    setConfig: (updates) => {
      platformConfig = { ...platformConfig, ...updates };
    },
    setError: (endpoint, error) => {
      if (endpoint === 'health') {
        healthError = error;
      } else {
        configError = error;
      }
    },
  };
}

// ============================================================================
// Storage API Mock (QuicBaaS)
// ============================================================================

/**
 * Mock the Storage/QuicBaaS API endpoints.
 *
 * Handles:
 * - GET /api/v1/quicbaas/kv - List KV entries
 * - PUT /api/v1/quicbaas/kv - Set KV entry
 * - DELETE /api/v1/quicbaas/kv/:key - Delete KV entry
 * - GET /api/v1/quicbaas/storage/buckets - List buckets
 * - GET /api/v1/quicbaas/storage/buckets/:bucket/objects - List objects
 * - GET /api/v1/quicbaas/backups - List backups
 * - POST /api/v1/quicbaas/backups - Create backup
 */
export async function mockStorageApi(
  page: Page,
  config: StorageApiMockConfig = {}
): Promise<{
  getKVEntries: () => KVEntry[];
  getBuckets: () => Bucket[];
  getObjects: (bucket: string) => StorageObject[];
  getBackups: () => Backup[];
  setKV: (key: string, value: string, metadata?: Record<string, string>) => void;
  deleteKV: (key: string) => void;
  addBucket: (bucket: Bucket) => void;
  addObject: (bucket: string, object: StorageObject) => void;
  addBackup: (backup: Backup) => void;
  clearAll: () => void;
  setError: (
    endpoint: 'kvList' | 'kvSet' | 'kvDelete' | 'bucketList' | 'objectList' | 'backupList' | 'backupCreate',
    error: ApiError | null
  ) => void;
}> {
  const state: StorageApiState = {
    kvEntries: config.initialKVEntries || [],
    buckets: config.initialBuckets || [],
    objects: config.initialObjects || {},
    backups: config.initialBackups || [],
    config: {
      kvListError: null,
      kvSetError: null,
      kvDeleteError: null,
      bucketListError: null,
      objectListError: null,
      backupListError: null,
      backupCreateError: null,
      ...config,
    },
  };

  // KV operations
  await page.route('**/api/v1/quicbaas/kv', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.kvListError) {
        await fulfillError(route, state.config.kvListError);
        return;
      }

      await fulfillJSON(route, 200, {
        entries: state.kvEntries,
        total: state.kvEntries.length,
      });
      return;
    }

    if (method === 'PUT') {
      if (state.config.kvSetError) {
        await fulfillError(route, state.config.kvSetError);
        return;
      }

      try {
        const body = request.postDataJSON();
        const existingIndex = state.kvEntries.findIndex((e) => e.key === body.key);

        const entry = createMockKVEntry(body.key, body.value, {
          metadata: body.metadata,
          ttl: body.ttl,
        });

        if (existingIndex !== -1) {
          state.kvEntries[existingIndex] = entry;
        } else {
          state.kvEntries.push(entry);
        }

        await fulfillJSON(route, 200, { entry });
      } catch {
        await fulfillJSON(route, 400, { error: 'Invalid request body' });
      }
      return;
    }

    await route.continue();
  });

  // KV delete
  await page.route('**/api/v1/quicbaas/kv/*', async (route: Route, request: Request) => {
    if (request.method() !== 'DELETE') {
      await route.continue();
      return;
    }

    if (state.config.kvDeleteError) {
      await fulfillError(route, state.config.kvDeleteError);
      return;
    }

    const url = request.url();
    const key = extractIdFromUrl(url, /\/kv\/([^/?]+)/);

    if (key) {
      const decodedKey = decodeURIComponent(key);
      const index = state.kvEntries.findIndex((e) => e.key === decodedKey);
      if (index !== -1) {
        state.kvEntries.splice(index, 1);
      }
    }

    await fulfillJSON(route, 200, { success: true });
  });

  // Buckets list
  await page.route('**/api/v1/quicbaas/storage/buckets', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (state.config.bucketListError) {
      await fulfillError(route, state.config.bucketListError);
      return;
    }

    await fulfillJSON(route, 200, {
      buckets: state.buckets,
      total: state.buckets.length,
    });
  });

  // Objects list
  await page.route('**/api/v1/quicbaas/storage/buckets/*/objects', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (state.config.objectListError) {
      await fulfillError(route, state.config.objectListError);
      return;
    }

    const url = request.url();
    const bucketName = extractIdFromUrl(url, /\/buckets\/([^/]+)\/objects/);

    const objects = bucketName ? (state.objects[bucketName] || []) : [];

    await fulfillJSON(route, 200, {
      objects,
      total: objects.length,
      is_truncated: false,
    });
  });

  // Backups list and create
  await page.route('**/api/v1/quicbaas/backups', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.backupListError) {
        await fulfillError(route, state.config.backupListError);
        return;
      }

      await fulfillJSON(route, 200, {
        backups: state.backups,
        total: state.backups.length,
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.backupCreateError) {
        await fulfillError(route, state.config.backupCreateError);
        return;
      }

      try {
        const body = request.postDataJSON();
        const newBackup = createMockBackup({
          name: body.name,
          type: body.type || 'full',
          status: 'pending',
        });

        state.backups.unshift(newBackup);

        await fulfillJSON(route, 201, { backup: newBackup });
      } catch {
        await fulfillJSON(route, 400, { error: 'Invalid request body' });
      }
      return;
    }

    await route.continue();
  });

  return {
    getKVEntries: () => [...state.kvEntries],
    getBuckets: () => [...state.buckets],
    getObjects: (bucket: string) => [...(state.objects[bucket] || [])],
    getBackups: () => [...state.backups],
    setKV: (key: string, value: string, metadata?: Record<string, string>) => {
      const entry = createMockKVEntry(key, value, { metadata });
      const existingIndex = state.kvEntries.findIndex((e) => e.key === key);
      if (existingIndex !== -1) {
        state.kvEntries[existingIndex] = entry;
      } else {
        state.kvEntries.push(entry);
      }
    },
    deleteKV: (key: string) => {
      const index = state.kvEntries.findIndex((e) => e.key === key);
      if (index !== -1) {
        state.kvEntries.splice(index, 1);
      }
    },
    addBucket: (bucket: Bucket) => {
      state.buckets.push(bucket);
    },
    addObject: (bucket: string, object: StorageObject) => {
      if (!state.objects[bucket]) {
        state.objects[bucket] = [];
      }
      state.objects[bucket].push(object);
    },
    addBackup: (backup: Backup) => {
      state.backups.unshift(backup);
    },
    clearAll: () => {
      state.kvEntries = [];
      state.buckets = [];
      state.objects = {};
      state.backups = [];
    },
    setError: (endpoint, error) => {
      switch (endpoint) {
        case 'kvList':
          state.config.kvListError = error;
          break;
        case 'kvSet':
          state.config.kvSetError = error;
          break;
        case 'kvDelete':
          state.config.kvDeleteError = error;
          break;
        case 'bucketList':
          state.config.bucketListError = error;
          break;
        case 'objectList':
          state.config.objectListError = error;
          break;
        case 'backupList':
          state.config.backupListError = error;
          break;
        case 'backupCreate':
          state.config.backupCreateError = error;
          break;
      }
    },
  };
}

// ============================================================================
// TPM API Mock
// ============================================================================

/**
 * Mock the TPM API endpoints.
 *
 * Handles:
 * - GET /api/v1/tpm/info - Get TPM info
 * - GET /api/v1/tpm/keys - List TPM keys
 * - GET /api/v1/tpm/pcrs - Get PCR values
 */
export async function mockTPMApi(
  page: Page,
  config: TPMApiMockConfig = {}
): Promise<{
  getTPMInfo: () => TPMInfo;
  getKeys: () => TPMKey[];
  getPCRs: () => PCRValue[];
  setTPMInfo: (updates: Partial<TPMInfo>) => void;
  addKey: (key: TPMKey) => void;
  setPCRValue: (index: number, value: string) => void;
  setError: (endpoint: 'info' | 'keys' | 'pcrs', error: ApiError | null) => void;
}> {
  const state: TPMApiState = {
    tpmInfo: config.tpmInfo || createMockTPMInfo(),
    keys: config.initialKeys || [],
    pcrValues: config.pcrValues || [0, 1, 2, 3, 4, 5, 6, 7].map((i) => createMockPCRValue(i)),
    config: {
      infoError: null,
      keysError: null,
      pcrsError: null,
      ...config,
    },
  };

  // TPM info
  await page.route('**/api/v1/tpm/info', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (state.config.infoError) {
      await fulfillError(route, state.config.infoError);
      return;
    }

    await fulfillJSON(route, 200, state.tpmInfo);
  });

  // TPM keys
  await page.route('**/api/v1/tpm/keys', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (state.config.keysError) {
      await fulfillError(route, state.config.keysError);
      return;
    }

    await fulfillJSON(route, 200, {
      keys: state.keys,
      total: state.keys.length,
    });
  });

  // TPM PCRs
  await page.route('**/api/v1/tpm/pcrs', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (state.config.pcrsError) {
      await fulfillError(route, state.config.pcrsError);
      return;
    }

    await fulfillJSON(route, 200, {
      pcrs: state.pcrValues,
      bank: 'SHA256',
    });
  });

  return {
    getTPMInfo: () => ({ ...state.tpmInfo }),
    getKeys: () => [...state.keys],
    getPCRs: () => [...state.pcrValues],
    setTPMInfo: (updates: Partial<TPMInfo>) => {
      state.tpmInfo = { ...state.tpmInfo, ...updates };
    },
    addKey: (key: TPMKey) => {
      state.keys.push(key);
    },
    setPCRValue: (index: number, value: string) => {
      const existingIndex = state.pcrValues.findIndex((p) => p.index === index);
      if (existingIndex !== -1) {
        state.pcrValues[existingIndex] = { ...state.pcrValues[existingIndex], value };
      } else {
        state.pcrValues.push(createMockPCRValue(index, { value }));
      }
    },
    setError: (endpoint, error) => {
      switch (endpoint) {
        case 'info':
          state.config.infoError = error;
          break;
        case 'keys':
          state.config.keysError = error;
          break;
        case 'pcrs':
          state.config.pcrsError = error;
          break;
      }
    },
  };
}

// ============================================================================
// Attestation API Mock
// ============================================================================

/**
 * Mock the Attestation API endpoints.
 *
 * Handles:
 * - GET /api/v1/attestation/manifests - List manifests
 * - POST /api/v1/attestation/manifests - Build manifest
 * - POST /api/v1/attestation/verify - Verify attestation
 */
export async function mockAttestationApi(
  page: Page,
  config: AttestationApiMockConfig = {}
): Promise<{
  getManifests: () => AttestationManifest[];
  addManifest: (manifest: AttestationManifest) => void;
  clearManifests: () => void;
  setVerifyResult: (result: Partial<AttestationVerifyResponse>) => void;
  setError: (endpoint: 'list' | 'build' | 'verify', error: ApiError | null) => void;
}> {
  const state: AttestationApiState = {
    manifests: config.initialManifests || [],
    config: {
      listError: null,
      buildError: null,
      verifyError: null,
      verifyResult: {
        verified: true,
        pcr_match: true,
        signature_valid: true,
      },
      ...config,
    },
  };

  // List and Build manifests
  await page.route('**/api/v1/attestation/manifests', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.listError) {
        await fulfillError(route, state.config.listError);
        return;
      }

      await fulfillJSON(route, 200, {
        manifests: state.manifests,
        total: state.manifests.length,
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.buildError) {
        await fulfillError(route, state.config.buildError);
        return;
      }

      try {
        const body = request.postDataJSON();
        const newManifest = createMockManifest({
          device_id: body.device_id,
          status: 'pending',
        });

        state.manifests.unshift(newManifest);

        await fulfillJSON(route, 201, { manifest: newManifest });
      } catch {
        await fulfillJSON(route, 400, { error: 'Invalid request body' });
      }
      return;
    }

    await route.continue();
  });

  // Verify attestation
  await page.route('**/api/v1/attestation/verify', async (route: Route, request: Request) => {
    if (request.method() !== 'POST') {
      await route.continue();
      return;
    }

    if (state.config.verifyError) {
      await fulfillError(route, state.config.verifyError);
      return;
    }

    try {
      const body = request.postDataJSON() as AttestationVerifyRequest;

      const response: AttestationVerifyResponse = {
        verified: true,
        device_id: body.device_id || 'device-1',
        manifest_id: body.manifest_id || `manifest-${Date.now()}`,
        pcr_match: true,
        signature_valid: true,
        ...state.config.verifyResult,
      };

      await fulfillJSON(route, 200, response);
    } catch {
      await fulfillJSON(route, 400, { error: 'Invalid request body' });
    }
  });

  return {
    getManifests: () => [...state.manifests],
    addManifest: (manifest: AttestationManifest) => {
      state.manifests.unshift(manifest);
    },
    clearManifests: () => {
      state.manifests = [];
    },
    setVerifyResult: (result: Partial<AttestationVerifyResponse>) => {
      state.config.verifyResult = { ...state.config.verifyResult, ...result };
    },
    setError: (endpoint, error) => {
      switch (endpoint) {
        case 'list':
          state.config.listError = error;
          break;
        case 'build':
          state.config.buildError = error;
          break;
        case 'verify':
          state.config.verifyError = error;
          break;
      }
    },
  };
}

// ============================================================================
// Combined Dashboard API Mock
// ============================================================================

export interface DashboardApiMockConfig {
  device?: DeviceApiMockConfig;
  certificate?: CertificateApiMockConfig;
  kms?: KMSApiMockConfig;
  iam?: IAMApiMockConfig;
  platform?: PlatformApiMockConfig;
  storage?: StorageApiMockConfig;
  tpm?: TPMApiMockConfig;
  attestation?: AttestationApiMockConfig;
}

export interface DashboardApiMocks {
  device: Awaited<ReturnType<typeof mockDeviceApi>>;
  certificate: Awaited<ReturnType<typeof mockCertificateApi>>;
  kms: Awaited<ReturnType<typeof mockKMSApi>>;
  iam: Awaited<ReturnType<typeof mockIAMApi>>;
  platform: Awaited<ReturnType<typeof mockPlatformApi>>;
  storage: Awaited<ReturnType<typeof mockStorageApi>>;
  tpm: Awaited<ReturnType<typeof mockTPMApi>>;
  attestation: Awaited<ReturnType<typeof mockAttestationApi>>;
}

/**
 * Mock all dashboard API endpoints with default configurations.
 *
 * @param page - Playwright page object
 * @param config - Configuration for each API mock
 * @returns Object containing all mock API handlers
 */
export async function mockAllDashboardApis(
  page: Page,
  config: DashboardApiMockConfig = {}
): Promise<DashboardApiMocks> {
  const [device, certificate, kms, iam, platform, storage, tpm, attestation] = await Promise.all([
    mockDeviceApi(page, config.device),
    mockCertificateApi(page, config.certificate),
    mockKMSApi(page, config.kms),
    mockIAMApi(page, config.iam),
    mockPlatformApi(page, config.platform),
    mockStorageApi(page, config.storage),
    mockTPMApi(page, config.tpm),
    mockAttestationApi(page, config.attestation),
  ]);

  return {
    device,
    certificate,
    kms,
    iam,
    platform,
    storage,
    tpm,
    attestation,
  };
}

/**
 * Create a pre-populated dashboard with realistic test data.
 *
 * @param page - Playwright page object
 * @returns Object containing all mock API handlers with pre-populated data
 */
export async function mockDashboardWithTestData(page: Page): Promise<DashboardApiMocks> {
  // Create realistic test data
  const devices = [
    createMockDevice({ id: 'device-1', name: 'Production Server 1', status: 'online', attestation_status: 'attested' }),
    createMockDevice({ id: 'device-2', name: 'Production Server 2', status: 'online', attestation_status: 'attested' }),
    createMockDevice({ id: 'device-3', name: 'Dev Server 1', status: 'offline', attestation_status: 'pending' }),
    createMockDevice({ id: 'device-4', name: 'Test Server', status: 'error', attestation_status: 'failed' }),
  ];

  const certificates = [
    createMockCertificate({ id: 'cert-1', subject: 'CN=api.example.com', status: 'valid' }),
    createMockCertificate({ id: 'cert-2', subject: 'CN=web.example.com', status: 'valid' }),
    createMockCertificate({ id: 'cert-3', subject: 'CN=old.example.com', status: 'revoked' }),
  ];

  const keys = [
    createMockKMSKey({ id: 'key-1', name: 'Master Encryption Key', algorithm: 'AES-256', usage: 'encrypt' }),
    createMockKMSKey({ id: 'key-2', name: 'Signing Key', algorithm: 'EC-P256', usage: 'sign' }),
    createMockKMSKey({ id: 'key-3', name: 'Backup Key', algorithm: 'RSA-4096', usage: 'wrap' }),
  ];

  const users = [
    createMockUser({ id: 'user-1', email: 'admin@example.com', username: 'admin', roles: ['admin', 'owner'] }),
    createMockUser({ id: 'user-2', email: 'developer@example.com', username: 'developer', roles: ['developer'] }),
    createMockUser({ id: 'user-3', email: 'viewer@example.com', username: 'viewer', roles: ['viewer'] }),
  ];

  const roles = [
    createMockRole({ id: 'role-admin', name: 'Admin', permissions: ['*'] }),
    createMockRole({ id: 'role-developer', name: 'Developer', permissions: ['read', 'write', 'deploy'] }),
    createMockRole({ id: 'role-viewer', name: 'Viewer', permissions: ['read'] }),
  ];

  const groups = [
    createMockGroup({ id: 'group-1', name: 'Engineering', member_count: 10, roles: ['developer'] }),
    createMockGroup({ id: 'group-2', name: 'Operations', member_count: 5, roles: ['admin'] }),
  ];

  const kvEntries = [
    createMockKVEntry('config/app', '{"debug": false}'),
    createMockKVEntry('secrets/api-key', 'sk-***'),
    createMockKVEntry('cache/session', '{"user": "admin"}'),
  ];

  const buckets = [
    createMockBucket('backups', { object_count: 50, total_size_bytes: 1024 * 1024 * 1024 }),
    createMockBucket('logs', { object_count: 1000, total_size_bytes: 1024 * 1024 * 100 }),
  ];

  const backups = [
    createMockBackup({ id: 'backup-1', name: 'Daily Backup', status: 'completed', type: 'full' }),
    createMockBackup({ id: 'backup-2', name: 'Incremental', status: 'completed', type: 'incremental' }),
  ];

  const tpmKeys = [
    createMockTPMKey({ handle: '0x81000001', name: 'Primary Key', type: 'ECC', usage: 'signing' }),
    createMockTPMKey({ handle: '0x81000002', name: 'Attestation Key', type: 'ECC', usage: 'attestation' }),
  ];

  const manifests = [
    createMockManifest({ id: 'manifest-1', device_id: 'device-1', status: 'valid' }),
    createMockManifest({ id: 'manifest-2', device_id: 'device-2', status: 'valid' }),
  ];

  return mockAllDashboardApis(page, {
    device: { initialDevices: devices },
    certificate: { initialCertificates: certificates },
    kms: { initialKeys: keys },
    iam: { initialUsers: users, initialRoles: roles, initialGroups: groups },
    storage: { initialKVEntries: kvEntries, initialBuckets: buckets, initialBackups: backups },
    tpm: { initialKeys: tpmKeys },
    attestation: { initialManifests: manifests },
  });
}
