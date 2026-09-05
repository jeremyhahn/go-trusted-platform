/**
 * Type exports for the Trusted Platform SDK
 */

// Core API types
export {
  type ApiResponse,
  type HttpMethod,
  type RequestBody,
  type QueryParams,
  type HeadersInit,
  successResponse,
  errorResponse,
  isSuccessResponse,
  isErrorResponse,
  unwrapResponse,
  toSearchParams,
  appendQueryParams,
} from './api.js';

// Common utility types
export {
  type PaginationParams,
  type PaginationMeta,
  type PaginatedResponse,
  type SortDirection,
  type SortParams,
  type FilterOperator,
  type FilterCondition,
  type Timestamps,
  type BaseEntity,
  type Branded,
  type UUID,
  type ISODateString,
  type Result,
  type EmptyObject,
  type DeepPartial,
  type RequireKeys,
  type OptionalKeys,
  asUUID,
  asISODateString,
  ok,
  err,
  isOk,
  isErr,
  unwrapResult,
} from './common.js';

// Certificate Authority types
export * from './ca.js';

// Key Management Service types
export * from './kms.js';

// Attestation types
export * from './attestation.js';

// TPM types
export * from './tpm.js';

// vTPM types
export * from './vtpm.js';

// Compute types
export * from './compute.js';

// Device types
export * from './device.js';

// IAM types
export * from './iam.js';

// IDevID types
export * from './idevid.js';

// Tenant types
export * from './tenant.js';

// SDN types
export * from './sdn.js';

// DNS types
export * from './dns.js';

// PXE types
export * from './pxe.js';

// Gateway types
export * from './gateway.js';

// Device self-service (mTLS device-facing profile) types
export * from './device-self-service.js';

// Overlay types
export * from './overlay.js';

// Platform types
export * from './platform.js';

// Invitation types
export * from './invitation.js';

// EAB types
export * from './eab.js';

// QuicBaaS types (28 services)
export * from './quicbaas/index.js';
