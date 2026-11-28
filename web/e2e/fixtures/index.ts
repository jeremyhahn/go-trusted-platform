/**
 * E2E Test Fixtures Index
 *
 * Re-exports all fixtures for convenient importing in test files.
 */

// Auth setup fixtures
export {
  createMockJWT,
  setJWTCookie,
  clearAuthCookies,
  createTenantOwnerSession,
  createTenantMemberSession,
  createNoTenantSession,
  createCustomSession,
  isAuthenticated,
  getCurrentSession,
  setupTenantOwnerPage,
  setupTenantMemberPage,
} from './auth-setup';

export type {
  JWTClaims,
  UserSession,
} from './auth-setup';

// API mock fixtures
export {
  createMockInvitation,
  createMockTenantInfo,
  mockInvitationApi,
  mockTenantApi,
  mockHealthApi,
  mockAllApis,
  mockWebAuthnRegistration,
  mockWebAuthnLogin,
  mockInvitationValidation,
  errorEnvelope,
} from './api-mock';

export type {
  Invitation,
  InvitationListResponse,
  TenantInfo,
  HealthResponse,
  ApiError,
  InvitationApiMockConfig,
  TenantApiMockConfig,
  HealthApiMockConfig,
} from './api-mock';

// WebAuthn mock fixtures
export {
  mockWebAuthn,
  resetWebAuthnMock,
} from './webauthn-mock';

export type {
  WebAuthnMockOptions,
} from './webauthn-mock';

// Dashboard API mock fixtures
export {
  // ID counter management
  resetIdCounters,
  // Mock data generators
  createMockDevice,
  createMockCertificate,
  createMockKMSKey,
  createMockUser,
  createMockRole,
  createMockGroup,
  createMockKVEntry,
  createMockBucket,
  createMockStorageObject,
  createMockBackup,
  createMockTPMInfo,
  createMockTPMKey,
  createMockPCRValue,
  createMockManifest,
  // Individual API mocks
  mockDeviceApi,
  mockCertificateApi,
  mockKMSApi,
  mockIAMApi,
  mockPlatformApi,
  mockStorageApi,
  mockTPMApi,
  mockAttestationApi,
  // Combined API mocks
  mockAllDashboardApis,
  mockDashboardWithTestData,
} from './dashboard-api-mocks';

export type {
  // Common types
  ApiError as DashboardApiError,
  PaginatedResponse,
  // Device types
  Device,
  DeviceListResponse,
  DeviceApiMockConfig,
  // CA types
  Certificate,
  CertificateListResponse,
  CertificateIssueRequest,
  CertificateApiMockConfig,
  // KMS types
  KMSKey,
  KMSKeyListResponse,
  EncryptRequest,
  EncryptResponse,
  DecryptRequest,
  DecryptResponse,
  KMSApiMockConfig,
  // IAM types
  User,
  UserListResponse,
  Role,
  RoleListResponse,
  Group,
  GroupListResponse,
  IAMApiMockConfig,
  // Platform types
  PlatformHealth,
  ServiceHealth,
  PlatformConfig,
  PlatformApiMockConfig,
  // Storage types
  KVEntry,
  KVListResponse,
  Bucket,
  BucketListResponse,
  StorageObject,
  ObjectListResponse,
  Backup,
  BackupListResponse,
  StorageApiMockConfig,
  // TPM types
  TPMInfo,
  TPMKey,
  TPMKeyListResponse,
  PCRValue,
  PCRResponse,
  TPMApiMockConfig,
  // Attestation types
  AttestationManifest,
  ManifestListResponse,
  AttestationVerifyRequest,
  AttestationVerifyResponse,
  AttestationApiMockConfig,
  // Combined types
  DashboardApiMockConfig,
  DashboardApiMocks,
} from './dashboard-api-mocks';
