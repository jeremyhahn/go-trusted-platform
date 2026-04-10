/**
 * QuicBaaS Security Types - Part 2
 *
 * Types for Certificate Management, Seal/Unseal Operations, RBAC, and Cluster DEK services.
 * Based on QuicBaaS security API specifications.
 *
 * Note: Types are prefixed with "QuicBaaS" to avoid conflicts with platform-level types
 * (e.g., CA types, TPM seal types).
 */

// Import shared types from security-part1
import type { QuicBaaSSecurityStatus } from './security-part1.js';

// Re-export for consumers
export type { QuicBaaSSecurityStatus };

// =============================================================================
// Common Types
// =============================================================================


// =============================================================================
// Certificate Service Types
// =============================================================================

/**
 * QuicBaaS certificate type
 */
export type QuicBaaSCertificateType =
  | 'UNSPECIFIED'
  | 'ROOT_CA'
  | 'INTERMEDIATE_CA'
  | 'END_ENTITY'
  | 'CODE_SIGNING'
  | 'TLS_SERVER'
  | 'TLS_CLIENT'
  | 'MTLS';

/**
 * QuicBaaS certificate status
 */
export type QuicBaaSCertificateStatus =
  | 'UNSPECIFIED'
  | 'ACTIVE'
  | 'REVOKED'
  | 'EXPIRED'
  | 'PENDING'
  | 'SUSPENDED';

/**
 * QuicBaaS certificate revocation reason
 */
export type QuicBaaSRevocationReason =
  | 'UNSPECIFIED'
  | 'KEY_COMPROMISE'
  | 'CA_COMPROMISE'
  | 'AFFILIATION_CHANGED'
  | 'SUPERSEDED'
  | 'CESSATION_OF_OPERATION'
  | 'CERTIFICATE_HOLD'
  | 'REMOVE_FROM_CRL'
  | 'PRIVILEGE_WITHDRAWN'
  | 'AA_COMPROMISE';

/**
 * Key algorithm for certificate keys
 */
export type QuicBaaSCertKeyAlgorithm =
  | 'RSA_2048'
  | 'RSA_3072'
  | 'RSA_4096'
  | 'ECDSA_P256'
  | 'ECDSA_P384'
  | 'ECDSA_P521'
  | 'ED25519';

/**
 * QuicBaaS certificate subject information
 */
export interface QuicBaaSCertificateSubject {
  /** Common Name */
  commonName: string;
  /** Organization */
  organization?: string;
  /** Organizational Unit */
  organizationalUnit?: string;
  /** Country */
  country?: string;
  /** State or Province */
  stateOrProvince?: string;
  /** Locality */
  locality?: string;
  /** Email address */
  emailAddress?: string;
}

/**
 * X.509 certificate key usage flags
 */
export interface QuicBaaSKeyUsageFlags {
  /** Digital signature */
  digitalSignature?: boolean;
  /** Non-repudiation */
  nonRepudiation?: boolean;
  /** Key encipherment */
  keyEncipherment?: boolean;
  /** Data encipherment */
  dataEncipherment?: boolean;
  /** Key agreement */
  keyAgreement?: boolean;
  /** Certificate signing */
  keyCertSign?: boolean;
  /** CRL signing */
  crlSign?: boolean;
  /** Encipher only */
  encipherOnly?: boolean;
  /** Decipher only */
  decipherOnly?: boolean;
}

/**
 * Extended key usage
 */
export type QuicBaaSExtendedKeyUsage =
  | 'SERVER_AUTH'
  | 'CLIENT_AUTH'
  | 'CODE_SIGNING'
  | 'EMAIL_PROTECTION'
  | 'TIME_STAMPING'
  | 'OCSP_SIGNING';

/**
 * QuicBaaS certificate metadata
 */
export interface QuicBaaSCertificateMetadata {
  /** Certificate ID */
  certificateId: string;
  /** Serial number */
  serialNumber: string;
  /** Certificate type */
  type: QuicBaaSCertificateType;
  /** Certificate status */
  status: QuicBaaSCertificateStatus;
  /** Subject information */
  subject: QuicBaaSCertificateSubject;
  /** Issuer information */
  issuer: QuicBaaSCertificateSubject;
  /** Not valid before (unix epoch) */
  notBefore: number;
  /** Not valid after (unix epoch) */
  notAfter: number;
  /** Key algorithm */
  keyAlgorithm: QuicBaaSCertKeyAlgorithm;
  /** Key usage flags */
  keyUsage?: QuicBaaSKeyUsageFlags;
  /** Extended key usage */
  extendedKeyUsage?: QuicBaaSExtendedKeyUsage[];
  /** Subject alternative names */
  subjectAltNames?: string[];
  /** Issuer certificate ID */
  issuerCertificateId?: string;
  /** Fingerprint (SHA-256) */
  fingerprint: string;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Revocation timestamp (unix epoch) */
  revokedAt?: number;
  /** Revocation reason */
  revocationReason?: QuicBaaSRevocationReason;
}

/**
 * Certificate chain entry
 */
export interface QuicBaaSCertificateChainEntry {
  /** Certificate ID */
  certificateId: string;
  /** Certificate PEM */
  certificatePem: string;
  /** Certificate metadata */
  metadata: QuicBaaSCertificateMetadata;
  /** Position in chain (0 = leaf) */
  position: number;
}

// Certificate Request Types

/**
 * QuicBaaS issue certificate request
 */
export interface QuicBaaSIssueCertificateRequest {
  /** Subject information */
  subject: QuicBaaSCertificateSubject;
  /** Certificate type */
  type: QuicBaaSCertificateType;
  /** Key algorithm */
  keyAlgorithm: QuicBaaSCertKeyAlgorithm;
  /** Validity period in days */
  validityDays: number;
  /** Issuer certificate ID (for non-root certificates) */
  issuerCertificateId?: string;
  /** Key usage flags */
  keyUsage?: QuicBaaSKeyUsageFlags;
  /** Extended key usage */
  extendedKeyUsage?: QuicBaaSExtendedKeyUsage[];
  /** Subject alternative names */
  subjectAltNames?: string[];
  /** Certificate signing request (PEM format) */
  csr?: string;
  /** Custom extensions */
  extensions?: Record<string, string>;
}

/**
 * QuicBaaS revoke certificate request
 */
export interface QuicBaaSRevokeCertificateRequest {
  /** Certificate ID */
  certificateId: string;
  /** Revocation reason */
  reason: QuicBaaSRevocationReason;
  /** Optional revocation comment */
  comment?: string;
}

/**
 * QuicBaaS get certificate request
 */
export interface QuicBaaSGetCertificateRequest {
  /** Certificate ID */
  certificateId: string;
  /** Whether to include the certificate PEM */
  includePem?: boolean;
}

/**
 * QuicBaaS list certificates request
 */
export interface QuicBaaSListCertificatesRequest {
  /** Filter by certificate type */
  type?: QuicBaaSCertificateType;
  /** Filter by status */
  status?: QuicBaaSCertificateStatus;
  /** Filter by issuer certificate ID */
  issuerCertificateId?: string;
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
}

/**
 * QuicBaaS renew certificate request
 */
export interface QuicBaaSRenewCertificateRequest {
  /** Certificate ID to renew */
  certificateId: string;
  /** New validity period in days */
  validityDays: number;
  /** Whether to reuse the existing key */
  reuseKey?: boolean;
}

/**
 * QuicBaaS get certificate chain request
 */
export interface QuicBaaSGetCertificateChainRequest {
  /** Certificate ID */
  certificateId: string;
  /** Whether to include intermediate certificates */
  includeIntermediates?: boolean;
  /** Whether to include the root certificate */
  includeRoot?: boolean;
}

/**
 * QuicBaaS verify certificate request
 */
export interface QuicBaaSVerifyCertificateRequest {
  /** Certificate ID to verify */
  certificateId?: string;
  /** Certificate PEM to verify */
  certificatePem?: string;
  /** Trust anchor certificate IDs */
  trustAnchors?: string[];
  /** Check revocation status */
  checkRevocation?: boolean;
  /** Verification time (unix epoch, defaults to now) */
  verificationTime?: number;
}

// Certificate Response Types

/**
 * QuicBaaS issue certificate response
 */
export interface QuicBaaSIssueCertificateResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Certificate metadata */
  certificate?: QuicBaaSCertificateMetadata;
  /** Certificate PEM */
  certificatePem?: string;
  /** Private key PEM (if generated) */
  privateKeyPem?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS revoke certificate response
 */
export interface QuicBaaSRevokeCertificateResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Certificate ID */
  certificateId: string;
  /** New certificate status */
  certificateStatus: QuicBaaSCertificateStatus;
  /** Revocation timestamp (unix epoch) */
  revokedAt: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS get certificate response
 */
export interface QuicBaaSGetCertificateResponse {
  /** Certificate metadata */
  certificate: QuicBaaSCertificateMetadata;
  /** Certificate PEM */
  certificatePem?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS list certificates response
 */
export interface QuicBaaSListCertificatesResponse {
  /** Certificates */
  certificates: QuicBaaSCertificateMetadata[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Total count */
  totalCount: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS renew certificate response
 */
export interface QuicBaaSRenewCertificateResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Old certificate ID */
  oldCertificateId: string;
  /** New certificate metadata */
  certificate?: QuicBaaSCertificateMetadata;
  /** New certificate PEM */
  certificatePem?: string;
  /** New private key PEM (if regenerated) */
  privateKeyPem?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS get certificate chain response
 */
export interface QuicBaaSGetCertificateChainResponse {
  /** Certificate chain */
  chain: QuicBaaSCertificateChainEntry[];
  /** Chain length */
  chainLength: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS verify certificate response
 */
export interface QuicBaaSVerifyCertificateResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Whether the certificate is valid */
  valid: boolean;
  /** Validation errors (if any) */
  validationErrors?: string[];
  /** Chain verification result */
  chainValid?: boolean;
  /** Revocation check result */
  revocationStatus?: QuicBaaSCertificateStatus;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

// =============================================================================
// Seal Service Types
// =============================================================================

/**
 * QuicBaaS seal state
 */
export type QuicBaaSSealState =
  | 'SEALED'
  | 'UNSEALED'
  | 'UNINITIALIZED'
  | 'INITIALIZING'
  | 'SEALING'
  | 'UNSEALING'
  | 'ERROR';

/**
 * QuicBaaS seal algorithm
 */
export type QuicBaaSSealAlgorithm =
  | 'SHAMIR'
  | 'TRANSIT'
  | 'TPM'
  | 'HSM'
  | 'CLOUD_KMS';

/**
 * QuicBaaS seal key share
 */
export interface QuicBaaSSealKeyShare {
  /** Share index */
  index: number;
  /** Share value (base64 encoded) */
  share: string;
  /** Share holder ID (optional) */
  holderId?: string;
}

/**
 * QuicBaaS seal status information
 */
export interface QuicBaaSSealStatus {
  /** Current seal state */
  state: QuicBaaSSealState;
  /** Seal algorithm */
  algorithm: QuicBaaSSealAlgorithm;
  /** Total number of key shares */
  totalShares: number;
  /** Threshold required to unseal */
  threshold: number;
  /** Number of shares currently provided */
  sharesProvided: number;
  /** Whether initialization is complete */
  initialized: boolean;
  /** Seal version */
  version: number;
  /** Cluster ID */
  clusterId?: string;
  /** Node ID */
  nodeId?: string;
  /** Last sealed timestamp (unix epoch) */
  lastSealedAt?: number;
  /** Last unsealed timestamp (unix epoch) */
  lastUnsealedAt?: number;
}

// Seal Request Types

/**
 * QuicBaaS seal request
 */
export interface QuicBaaSSealRequest {
  /** Force seal even if cluster is active */
  force?: boolean;
  /** Comment for audit log */
  comment?: string;
}

/**
 * QuicBaaS unseal request
 */
export interface QuicBaaSUnsealRequest {
  /** Key share to provide */
  share: string;
  /** Share holder ID (optional) */
  holderId?: string;
  /** Reset unseal progress */
  reset?: boolean;
}

/**
 * QuicBaaS get seal status request
 */
export interface QuicBaaSGetSealStatusRequest {
  /** Include detailed information */
  includeDetails?: boolean;
}

/**
 * QuicBaaS initialize seal request
 */
export interface QuicBaaSInitializeSealRequest {
  /** Seal algorithm */
  algorithm: QuicBaaSSealAlgorithm;
  /** Total number of key shares */
  totalShares: number;
  /** Threshold required to unseal */
  threshold: number;
  /** PGP keys for encrypting key shares */
  pgpKeys?: string[];
  /** Root token PGP key */
  rootTokenPgpKey?: string;
  /** Recovery keys (for TPM/HSM/Cloud KMS) */
  recoveryKeys?: number;
  /** Recovery threshold */
  recoveryThreshold?: number;
}

/**
 * QuicBaaS rekey seal request
 */
export interface QuicBaaSRekeySealRequest {
  /** New total number of key shares */
  newTotalShares?: number;
  /** New threshold */
  newThreshold?: number;
  /** PGP keys for encrypting new key shares */
  pgpKeys?: string[];
  /** Backup existing shares */
  backup?: boolean;
  /** Share for verification */
  share?: string;
  /** Nonce for multi-step rekey */
  nonce?: string;
}

// Seal Response Types

/**
 * QuicBaaS seal response
 */
export interface QuicBaaSSealResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** New seal state */
  sealState: QuicBaaSSealState;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS unseal response
 */
export interface QuicBaaSUnsealResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Current seal state */
  sealState: QuicBaaSSealState;
  /** Number of shares provided */
  sharesProvided: number;
  /** Threshold required */
  threshold: number;
  /** Progress percentage */
  progress: number;
  /** Cluster ID (after unseal) */
  clusterId?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS get seal status response
 */
export interface QuicBaaSGetSealStatusResponse {
  /** Seal status */
  sealStatus: QuicBaaSSealStatus;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS initialize seal response
 */
export interface QuicBaaSInitializeSealResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Key shares */
  keyShares?: QuicBaaSSealKeyShare[];
  /** Key shares (PGP encrypted) */
  keySharesPgp?: string[];
  /** Root token */
  rootToken?: string;
  /** Root token (PGP encrypted) */
  rootTokenPgp?: string;
  /** Recovery keys */
  recoveryKeys?: QuicBaaSSealKeyShare[];
  /** Recovery keys (PGP encrypted) */
  recoveryKeysPgp?: string[];
  /** Seal status after initialization */
  sealStatus: QuicBaaSSealStatus;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS rekey seal response
 */
export interface QuicBaaSRekeySealResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Whether rekey is complete */
  complete: boolean;
  /** Nonce for continuing rekey */
  nonce?: string;
  /** New key shares (if complete) */
  keyShares?: QuicBaaSSealKeyShare[];
  /** New key shares (PGP encrypted) */
  keySharesPgp?: string[];
  /** Verification required */
  verificationRequired: boolean;
  /** Shares verified */
  sharesVerified: number;
  /** Shares needed for verification */
  sharesNeeded: number;
  /** New seal status (if complete) */
  sealStatus?: QuicBaaSSealStatus;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

// =============================================================================
// RBAC Service Types
// =============================================================================

/**
 * QuicBaaS permission action
 */
export type QuicBaaSPermissionAction =
  | 'CREATE'
  | 'READ'
  | 'UPDATE'
  | 'DELETE'
  | 'LIST'
  | 'EXECUTE'
  | 'ADMIN'
  | 'GRANT'
  | 'REVOKE';

/**
 * QuicBaaS resource type
 */
export type QuicBaaSResourceType =
  | 'DATABASE'
  | 'TABLE'
  | 'KEY'
  | 'SECRET'
  | 'CERTIFICATE'
  | 'POLICY'
  | 'ROLE'
  | 'USER'
  | 'TOKEN'
  | 'CLUSTER'
  | 'NODE'
  | 'BACKUP'
  | 'AUDIT_LOG';

/**
 * QuicBaaS permission definition
 */
export interface QuicBaaSPermission {
  /** Permission ID */
  permissionId: string;
  /** Resource type */
  resourceType: QuicBaaSResourceType;
  /** Resource pattern (supports wildcards) */
  resourcePattern: string;
  /** Allowed actions */
  actions: QuicBaaSPermissionAction[];
  /** Conditions (optional) */
  conditions?: Record<string, string>;
}

/**
 * QuicBaaS role definition
 */
export interface QuicBaaSRole {
  /** Role ID */
  roleId: string;
  /** Role name */
  name: string;
  /** Role description */
  description?: string;
  /** Permissions assigned to this role */
  permissions: QuicBaaSPermission[];
  /** Parent roles (for inheritance) */
  parentRoles?: string[];
  /** Whether this is a system role */
  isSystem: boolean;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Last update timestamp (unix epoch) */
  updatedAt: number;
  /** Created by user ID */
  createdBy?: string;
}

/**
 * QuicBaaS role assignment
 */
export interface QuicBaaSRoleAssignment {
  /** Assignment ID */
  assignmentId: string;
  /** Role ID */
  roleId: string;
  /** Principal ID (user or service account) */
  principalId: string;
  /** Principal type */
  principalType: 'USER' | 'SERVICE_ACCOUNT' | 'GROUP';
  /** Scope (optional, for scoped assignments) */
  scope?: string;
  /** Assignment timestamp (unix epoch) */
  assignedAt: number;
  /** Expires at timestamp (unix epoch) */
  expiresAt?: number;
  /** Assigned by user ID */
  assignedBy?: string;
}

// RBAC Request Types

/**
 * QuicBaaS create role request
 */
export interface QuicBaaSCreateRoleRequest {
  /** Role name */
  name: string;
  /** Role description */
  description?: string;
  /** Permissions to assign */
  permissions: Omit<QuicBaaSPermission, 'permissionId'>[];
  /** Parent role IDs (for inheritance) */
  parentRoles?: string[];
}

/**
 * QuicBaaS get role request
 */
export interface QuicBaaSGetRoleRequest {
  /** Role ID */
  roleId: string;
  /** Expand parent roles */
  expandParents?: boolean;
  /** Include effective permissions */
  includeEffectivePermissions?: boolean;
}

/**
 * QuicBaaS update role request
 */
export interface QuicBaaSUpdateRoleRequest {
  /** Role ID */
  roleId: string;
  /** New role name */
  name?: string;
  /** New description */
  description?: string;
  /** Permissions to set (replaces existing) */
  permissions?: Omit<QuicBaaSPermission, 'permissionId'>[];
  /** Add permissions */
  addPermissions?: Omit<QuicBaaSPermission, 'permissionId'>[];
  /** Remove permission IDs */
  removePermissionIds?: string[];
  /** Parent role IDs */
  parentRoles?: string[];
}

/**
 * QuicBaaS delete role request
 */
export interface QuicBaaSDeleteRoleRequest {
  /** Role ID */
  roleId: string;
  /** Force deletion even if assigned */
  force?: boolean;
}

/**
 * QuicBaaS list roles request
 */
export interface QuicBaaSListRolesRequest {
  /** Filter by name pattern */
  namePattern?: string;
  /** Include system roles */
  includeSystem?: boolean;
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
}

/**
 * QuicBaaS assign role request
 */
export interface QuicBaaSAssignRoleRequest {
  /** Role ID */
  roleId: string;
  /** Principal ID */
  principalId: string;
  /** Principal type */
  principalType: 'USER' | 'SERVICE_ACCOUNT' | 'GROUP';
  /** Scope (optional) */
  scope?: string;
  /** Expiration timestamp (unix epoch) */
  expiresAt?: number;
}

/**
 * QuicBaaS revoke role request
 */
export interface QuicBaaSRevokeRoleRequest {
  /** Role ID */
  roleId: string;
  /** Principal ID */
  principalId: string;
  /** Principal type */
  principalType: 'USER' | 'SERVICE_ACCOUNT' | 'GROUP';
  /** Scope (optional) */
  scope?: string;
}

/**
 * QuicBaaS check permission request
 */
export interface QuicBaaSCheckPermissionRequest {
  /** Principal ID */
  principalId: string;
  /** Principal type */
  principalType: 'USER' | 'SERVICE_ACCOUNT' | 'GROUP';
  /** Resource type */
  resourceType: QuicBaaSResourceType;
  /** Resource identifier */
  resourceId: string;
  /** Action to check */
  action: QuicBaaSPermissionAction;
  /** Context for condition evaluation */
  context?: Record<string, string>;
}

// RBAC Response Types

/**
 * QuicBaaS create role response
 */
export interface QuicBaaSCreateRoleResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Created role */
  role?: QuicBaaSRole;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS get role response
 */
export interface QuicBaaSGetRoleResponse {
  /** Role */
  role: QuicBaaSRole;
  /** Effective permissions (if requested) */
  effectivePermissions?: QuicBaaSPermission[];
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS update role response
 */
export interface QuicBaaSUpdateRoleResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Updated role */
  role?: QuicBaaSRole;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS delete role response
 */
export interface QuicBaaSDeleteRoleResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Deleted role ID */
  roleId: string;
  /** Number of assignments removed */
  assignmentsRemoved: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS list roles response
 */
export interface QuicBaaSListRolesResponse {
  /** Roles */
  roles: QuicBaaSRole[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Total count */
  totalCount: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS assign role response
 */
export interface QuicBaaSAssignRoleResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Role assignment */
  assignment?: QuicBaaSRoleAssignment;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS revoke role response
 */
export interface QuicBaaSRevokeRoleResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Revoked assignment ID */
  assignmentId: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * QuicBaaS check permission response
 */
export interface QuicBaaSCheckPermissionResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Whether permission is allowed */
  allowed: boolean;
  /** Matching role IDs (if allowed) */
  matchingRoles?: string[];
  /** Matching permission IDs (if allowed) */
  matchingPermissions?: string[];
  /** Denial reason (if denied) */
  denialReason?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

// =============================================================================
// Cluster DEK Service Types
// =============================================================================

/**
 * DEK status
 */
export type QuicBaaSDEKStatus =
  | 'ACTIVE'
  | 'INACTIVE'
  | 'ROTATING'
  | 'DESTROYED'
  | 'PENDING_ROTATION';

/**
 * DEK algorithm
 */
export type QuicBaaSDEKAlgorithm =
  | 'AES_128_GCM'
  | 'AES_256_GCM'
  | 'CHACHA20_POLY1305';

/**
 * DEK scope
 */
export type QuicBaaSDEKScope =
  | 'CLUSTER'
  | 'DATABASE'
  | 'TABLE'
  | 'COLUMN'
  | 'NODE';

/**
 * Data Encryption Key metadata
 */
export interface QuicBaaSDEKMetadata {
  /** DEK ID */
  dekId: string;
  /** DEK version */
  version: number;
  /** DEK algorithm */
  algorithm: QuicBaaSDEKAlgorithm;
  /** DEK status */
  status: QuicBaaSDEKStatus;
  /** DEK scope */
  scope: QuicBaaSDEKScope;
  /** Scope identifier (e.g., database name) */
  scopeId?: string;
  /** Key Encryption Key ID (wrapping key) */
  kekId: string;
  /** KEK version used */
  kekVersion: number;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Last rotation timestamp (unix epoch) */
  lastRotatedAt?: number;
  /** Next rotation timestamp (unix epoch) */
  nextRotationAt?: number;
  /** Auto-rotation enabled */
  autoRotate: boolean;
  /** Rotation period in days */
  rotationPeriodDays?: number;
  /** Cluster ID */
  clusterId: string;
  /** Node ID (if node-scoped) */
  nodeId?: string;
  /** Key material hash (for verification) */
  keyHash: string;
}

/**
 * Cluster DEK status
 */
export interface QuicBaaSClusterDEKStatus {
  /** Cluster ID */
  clusterId: string;
  /** Total DEKs */
  totalDeks: number;
  /** Active DEKs */
  activeDeks: number;
  /** DEKs pending rotation */
  pendingRotation: number;
  /** Last rotation timestamp (unix epoch) */
  lastRotationAt?: number;
  /** Next rotation timestamp (unix epoch) */
  nextRotationAt?: number;
  /** Overall status */
  overallStatus: 'HEALTHY' | 'DEGRADED' | 'ROTATING' | 'ERROR';
  /** Status message */
  statusMessage?: string;
  /** Node statuses */
  nodeStatuses?: Record<string, QuicBaaSDEKStatus>;
}

// Cluster DEK Request Types

/**
 * Generate DEK request
 */
export interface QuicBaaSGenerateDEKRequest {
  /** DEK algorithm */
  algorithm: QuicBaaSDEKAlgorithm;
  /** DEK scope */
  scope: QuicBaaSDEKScope;
  /** Scope identifier */
  scopeId?: string;
  /** KEK ID to use for wrapping */
  kekId: string;
  /** Enable auto-rotation */
  autoRotate?: boolean;
  /** Rotation period in days */
  rotationPeriodDays?: number;
  /** Node ID (for node-scoped DEKs) */
  nodeId?: string;
}

/**
 * Rotate DEK request
 */
export interface QuicBaaSRotateDEKRequest {
  /** DEK ID to rotate */
  dekId: string;
  /** New algorithm (optional) */
  newAlgorithm?: QuicBaaSDEKAlgorithm;
  /** New KEK ID (optional) */
  newKekId?: string;
  /** Force rotation even if not due */
  force?: boolean;
}

/**
 * Get DEK request
 */
export interface QuicBaaSGetDEKRequest {
  /** DEK ID */
  dekId: string;
  /** Specific version (optional) */
  version?: number;
  /** Include wrapped key material */
  includeKeyMaterial?: boolean;
}

/**
 * List DEKs request
 */
export interface QuicBaaSListDEKsRequest {
  /** Filter by scope */
  scope?: QuicBaaSDEKScope;
  /** Filter by scope ID */
  scopeId?: string;
  /** Filter by status */
  status?: QuicBaaSDEKStatus;
  /** Filter by KEK ID */
  kekId?: string;
  /** Include only active */
  activeOnly?: boolean;
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
}

/**
 * Get cluster DEK status request
 */
export interface QuicBaaSGetClusterDEKStatusRequest {
  /** Include node-level details */
  includeNodeDetails?: boolean;
  /** Include pending rotations */
  includePendingRotations?: boolean;
}

// Cluster DEK Response Types

/**
 * Generate DEK response
 */
export interface QuicBaaSGenerateDEKResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** DEK metadata */
  dek?: QuicBaaSDEKMetadata;
  /** Wrapped DEK (base64) */
  wrappedKey?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Rotate DEK response
 */
export interface QuicBaaSRotateDEKResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** DEK ID */
  dekId: string;
  /** Old version */
  oldVersion: number;
  /** New version */
  newVersion: number;
  /** New DEK metadata */
  dek?: QuicBaaSDEKMetadata;
  /** Wrapped DEK (base64) */
  wrappedKey?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Get DEK response
 */
export interface QuicBaaSGetDEKResponse {
  /** DEK metadata */
  dek: QuicBaaSDEKMetadata;
  /** Wrapped key material (base64, if requested) */
  wrappedKey?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * List DEKs response
 */
export interface QuicBaaSListDEKsResponse {
  /** DEKs */
  deks: QuicBaaSDEKMetadata[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Total count */
  totalCount: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Get cluster DEK status response
 */
export interface QuicBaaSGetClusterDEKStatusResponse {
  /** Cluster DEK status */
  clusterStatus: QuicBaaSClusterDEKStatus;
  /** Pending rotations (if requested) */
  pendingRotations?: QuicBaaSDEKMetadata[];
  /** Timestamp (unix epoch) */
  timestamp: number;
}
