/**
 * Identity and Access Management (IAM) Types
 *
 * Types for IAM operations including users, roles, groups, tenants, policies, and applications.
 * Based on pkg/api/grpc/proto/iam.proto
 */

// =============================================================================
// User Types
// =============================================================================

/**
 * IAM user
 */
export interface IAMUser {
  /** User ID */
  id: string;
  /** Tenant ID */
  tenantId: string;
  /** Email address */
  email: string;
  /** Display name */
  name: string;
  /** Assigned role IDs */
  roles: string[];
  /** Group memberships */
  groups: string[];
  /** User attributes */
  attributes?: Record<string, string>;
  /** MFA verified */
  mfaVerified: boolean;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
  /** Last authentication timestamp */
  lastAuth?: string;
}

/**
 * Create user request
 */
export interface CreateIAMUserRequest {
  /** Tenant ID */
  tenantId: string;
  /** Email address */
  email: string;
  /** Display name */
  name: string;
  /** Initial role IDs */
  roles?: string[];
  /** Initial group memberships */
  groups?: string[];
  /** User attributes */
  attributes?: Record<string, string>;
}

/**
 * Get user request
 */
export interface GetIAMUserRequest {
  /** Tenant ID */
  tenantId: string;
  /** User ID */
  userId: string;
}

/**
 * List users request
 */
export interface ListIAMUsersRequest {
  /** Tenant ID */
  tenantId: string;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
  /** Email filter */
  emailFilter?: string;
  /** Role filter */
  roleFilter?: string;
  /** Group filter */
  groupFilter?: string;
}

/**
 * Update user request
 */
export interface UpdateIAMUserRequest {
  /** Tenant ID */
  tenantId: string;
  /** User ID */
  userId: string;
  /** Updated email */
  email?: string;
  /** Updated name */
  name?: string;
  /** Updated roles */
  roles?: string[];
  /** Updated groups */
  groups?: string[];
  /** Updated attributes */
  attributes?: Record<string, string>;
}

/**
 * Delete user request
 */
export interface DeleteIAMUserRequest {
  /** Tenant ID */
  tenantId: string;
  /** User ID */
  userId: string;
}

// =============================================================================
// Role Types
// =============================================================================

/**
 * IAM role
 */
export interface IAMRole {
  /** Role ID */
  id: string;
  /** Tenant ID */
  tenantId: string;
  /** Role name */
  name: string;
  /** Description */
  description?: string;
  /** Permissions */
  permissions: string[];
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
}

/**
 * Create role request
 */
export interface CreateIAMRoleRequest {
  /** Tenant ID */
  tenantId: string;
  /** Role ID */
  id?: string;
  /** Role name */
  name: string;
  /** Description */
  description?: string;
  /** Permissions */
  permissions: string[];
}

/**
 * Get role request
 */
export interface GetIAMRoleRequest {
  /** Tenant ID */
  tenantId: string;
  /** Role ID */
  roleId: string;
}

/**
 * List roles request
 */
export interface ListIAMRolesRequest {
  /** Tenant ID */
  tenantId: string;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Update role request
 */
export interface UpdateIAMRoleRequest {
  /** Tenant ID */
  tenantId: string;
  /** Role ID */
  roleId: string;
  /** Updated name */
  name?: string;
  /** Updated description */
  description?: string;
  /** Updated permissions */
  permissions?: string[];
}

/**
 * Delete role request
 */
export interface DeleteIAMRoleRequest {
  /** Tenant ID */
  tenantId: string;
  /** Role ID */
  roleId: string;
}

/**
 * Assign role request
 */
export interface AssignIAMRoleRequest {
  /** Tenant ID */
  tenantId: string;
  /** User ID */
  userId: string;
  /** Role ID */
  roleId: string;
}

/**
 * Revoke role request
 */
export interface RevokeIAMRoleRequest {
  /** Tenant ID */
  tenantId: string;
  /** User ID */
  userId: string;
  /** Role ID */
  roleId: string;
}

// =============================================================================
// Group Types
// =============================================================================

/**
 * IAM group
 */
export interface IAMGroup {
  /** Group ID */
  id: string;
  /** Tenant ID */
  tenantId: string;
  /** Group name */
  name: string;
  /** Description */
  description?: string;
  /** Member user IDs */
  members: string[];
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
}

/**
 * Create group request
 */
export interface CreateIAMGroupRequest {
  /** Tenant ID */
  tenantId: string;
  /** Group ID */
  id?: string;
  /** Group name */
  name: string;
  /** Description */
  description?: string;
}

/**
 * Get group request
 */
export interface GetIAMGroupRequest {
  /** Tenant ID */
  tenantId: string;
  /** Group ID */
  groupId: string;
}

/**
 * List groups request
 */
export interface ListIAMGroupsRequest {
  /** Tenant ID */
  tenantId: string;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Update group request
 */
export interface UpdateIAMGroupRequest {
  /** Tenant ID */
  tenantId: string;
  /** Group ID */
  groupId: string;
  /** Updated name */
  name?: string;
  /** Updated description */
  description?: string;
}

/**
 * Delete group request
 */
export interface DeleteIAMGroupRequest {
  /** Tenant ID */
  tenantId: string;
  /** Group ID */
  groupId: string;
}

/**
 * Add group member request
 */
export interface AddGroupMemberRequest {
  /** Tenant ID */
  tenantId: string;
  /** Group ID */
  groupId: string;
  /** User ID */
  userId: string;
}

/**
 * Remove group member request
 */
export interface RemoveGroupMemberRequest {
  /** Tenant ID */
  tenantId: string;
  /** Group ID */
  groupId: string;
  /** User ID */
  userId: string;
}

// =============================================================================
// Authentication Types
// =============================================================================

/**
 * Authenticate request
 */
export interface AuthenticateIAMRequest {
  /** Tenant ID */
  tenantId: string;
  /** Username */
  username: string;
  /** Password */
  password: string;
  /** MFA code */
  mfaCode?: string;
}

/**
 * Authenticate response
 */
export interface AuthenticateIAMResponse {
  /** User ID */
  userId: string;
  /** Tenant ID */
  tenantId: string;
  /** Access token */
  accessToken: string;
  /** Refresh token */
  refreshToken: string;
  /** Expires in seconds */
  expiresIn: number;
  /** Token type */
  tokenType: string;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Check permission request
 */
export interface CheckIAMPermissionRequest {
  /** Tenant ID */
  tenantId: string;
  /** Subject ID (user) */
  subjectId: string;
  /** Roles */
  roles?: string[];
  /** Groups */
  groups?: string[];
  /** Action to check */
  action: string;
  /** Resource to check */
  resource: string;
  /** Context attributes */
  context?: Record<string, string>;
  /** Additional attributes */
  attributes?: Record<string, string>;
}

/**
 * Check permission response
 */
export interface CheckIAMPermissionResponse {
  /** Whether allowed */
  allowed: boolean;
  /** Matched policy name */
  matchedPolicy?: string;
  /** Matched rule name */
  matchedRule?: string;
  /** Reason */
  reason?: string;
  /** Evaluation time in nanoseconds */
  evaluationTimeNs?: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Create token request
 */
export interface CreateIAMTokenRequest {
  /** Tenant ID */
  tenantId: string;
  /** User ID */
  userId: string;
  /** Token scopes */
  scopes?: string[];
  /** Expires in seconds */
  expiresIn?: number;
}

/**
 * Create token response
 */
export interface CreateIAMTokenResponse {
  /** Token ID */
  tokenId: string;
  /** Access token */
  accessToken: string;
  /** Refresh token */
  refreshToken: string;
  /** Expires in seconds */
  expiresIn: number;
  /** Token type */
  tokenType: string;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Revoke token request
 */
export interface RevokeIAMTokenRequest {
  /** Token ID */
  tokenId?: string;
  /** Token value */
  token?: string;
}

/**
 * Verify token request
 */
export interface VerifyIAMTokenRequest {
  /** Token to verify */
  token: string;
}

/**
 * Verify token response
 */
export interface VerifyIAMTokenResponse {
  /** Whether valid */
  valid: boolean;
  /** User ID */
  userId?: string;
  /** Tenant ID */
  tenantId?: string;
  /** Token scopes */
  scopes?: string[];
  /** Expires at timestamp */
  expiresAt?: number;
  /** Response timestamp */
  timestamp: string;
}

// =============================================================================
// Tenant Types
// =============================================================================

/**
 * Tenant settings
 */
export interface IAMTenantSettings {
  /** Maximum users */
  maxUsers?: number;
  /** MFA required */
  mfaRequired?: boolean;
}

/**
 * IAM tenant
 */
export interface IAMTenant {
  /** Tenant ID */
  id: string;
  /** Tenant name */
  name: string;
  /** Settings */
  settings?: IAMTenantSettings;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
}

/**
 * Create tenant request
 */
export interface CreateIAMTenantRequest {
  /** Tenant ID */
  id?: string;
  /** Tenant name */
  name: string;
  /** Settings */
  settings?: IAMTenantSettings;
}

/**
 * Get tenant request
 */
export interface GetIAMTenantRequest {
  /** Tenant ID */
  tenantId: string;
}

/**
 * List tenants request
 */
export interface ListIAMTenantsRequest {
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Update tenant request
 */
export interface UpdateIAMTenantRequest {
  /** Tenant ID */
  tenantId: string;
  /** Updated name */
  name?: string;
  /** Updated settings */
  settings?: IAMTenantSettings;
}

/**
 * Delete tenant request
 */
export interface DeleteIAMTenantRequest {
  /** Tenant ID */
  tenantId: string;
}

// =============================================================================
// Policy Types
// =============================================================================

/**
 * IAM policy
 */
export interface IAMPolicy {
  /** Policy name */
  name: string;
  /** Tenant ID */
  tenantId: string;
  /** Description */
  description?: string;
  /** Priority */
  priority: number;
  /** Policy spec YAML (base64) */
  specYaml: string;
  /** Labels */
  labels?: Record<string, string>;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
}

/**
 * Create policy request
 */
export interface CreateIAMPolicyRequest {
  /** Tenant ID */
  tenantId: string;
  /** Policy name */
  name: string;
  /** Description */
  description?: string;
  /** Priority */
  priority?: number;
  /** Policy spec YAML (base64) */
  specYaml: string;
  /** Labels */
  labels?: Record<string, string>;
}

/**
 * Get policy request
 */
export interface GetIAMPolicyRequest {
  /** Tenant ID */
  tenantId: string;
  /** Policy name */
  policyName: string;
}

/**
 * List policies request
 */
export interface ListIAMPoliciesRequest {
  /** Tenant ID */
  tenantId: string;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Update policy request
 */
export interface UpdateIAMPolicyRequest {
  /** Tenant ID */
  tenantId: string;
  /** Policy name */
  policyName: string;
  /** Updated description */
  description?: string;
  /** Updated priority */
  priority?: number;
  /** Updated policy spec YAML (base64) */
  specYaml?: string;
  /** Updated labels */
  labels?: Record<string, string>;
}

/**
 * Delete policy request
 */
export interface DeleteIAMPolicyRequest {
  /** Tenant ID */
  tenantId: string;
  /** Policy name */
  policyName: string;
}

/**
 * Validate policy request
 */
export interface ValidateIAMPolicyRequest {
  /** Tenant ID */
  tenantId: string;
  /** Policy spec YAML (base64) */
  specYaml: string;
}

/**
 * Validate policy response
 */
export interface ValidateIAMPolicyResponse {
  /** Whether valid */
  valid: boolean;
  /** Validation errors */
  errors?: string[];
  /** Response timestamp */
  timestamp: string;
}

/**
 * Test policy request
 */
export interface TestIAMPolicyRequest {
  /** Tenant ID */
  tenantId: string;
  /** Subject ID */
  subjectId: string;
  /** Roles */
  roles?: string[];
  /** Groups */
  groups?: string[];
  /** Action */
  action: string;
  /** Resource */
  resource: string;
  /** Context */
  context?: Record<string, string>;
  /** Attributes */
  attributes?: Record<string, string>;
}

/**
 * Test policy response
 */
export interface TestIAMPolicyResponse {
  /** Whether allowed */
  allowed: boolean;
  /** Matched policy */
  matchedPolicy?: string;
  /** Matched rule */
  matchedRule?: string;
  /** Evaluation time in nanoseconds */
  evaluationTimeNs?: number;
  /** Response timestamp */
  timestamp: string;
}

// =============================================================================
// Application Types
// =============================================================================

/**
 * IAM application
 */
export interface IAMApp {
  /** Client ID */
  clientId: string;
  /** Client secret (only returned on creation) */
  clientSecret?: string;
  /** Tenant ID */
  tenantId: string;
  /** Application name */
  name: string;
  /** Redirect URIs */
  redirectUris: string[];
  /** Allowed grant types */
  grantTypes: string[];
  /** Allowed response types */
  responseTypes: string[];
  /** Resource prefix */
  resourcePrefix?: string;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
}

/**
 * Register app request
 */
export interface RegisterIAMAppRequest {
  /** Tenant ID */
  tenantId: string;
  /** Application name */
  name: string;
  /** Redirect URIs */
  redirectUris?: string[];
  /** Allowed grant types */
  grantTypes?: string[];
  /** Allowed response types */
  responseTypes?: string[];
  /** Resource prefix */
  resourcePrefix?: string;
}

/**
 * Get app request
 */
export interface GetIAMAppRequest {
  /** Tenant ID */
  tenantId: string;
  /** Client ID */
  clientId: string;
}

/**
 * List apps request
 */
export interface ListIAMAppsRequest {
  /** Tenant ID */
  tenantId: string;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Update app request
 */
export interface UpdateIAMAppRequest {
  /** Tenant ID */
  tenantId: string;
  /** Client ID */
  clientId: string;
  /** Updated name */
  name?: string;
  /** Updated redirect URIs */
  redirectUris?: string[];
  /** Updated grant types */
  grantTypes?: string[];
  /** Updated response types */
  responseTypes?: string[];
  /** Updated resource prefix */
  resourcePrefix?: string;
}

/**
 * Delete app request
 */
export interface DeleteIAMAppRequest {
  /** Tenant ID */
  tenantId: string;
  /** Client ID */
  clientId: string;
}

/**
 * Rotate app secret request
 */
export interface RotateIAMAppSecretRequest {
  /** Tenant ID */
  tenantId: string;
  /** Client ID */
  clientId: string;
}

/**
 * Rotate app secret response
 */
export interface RotateIAMAppSecretResponse {
  /** Client ID */
  clientId: string;
  /** Application name */
  name: string;
  /** New client secret */
  clientSecret: string;
  /** Response timestamp */
  timestamp: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface IAMStatus {
  /** Whether succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details */
  error?: {
    code: string;
    message: string;
    metadata?: Record<string, string>;
  };
}

/**
 * Pagination response
 */
export interface IAMPaginationResponse {
  /** Current page */
  page: number;
  /** Page size */
  pageSize: number;
  /** Total pages */
  totalPages: number;
  /** Total items */
  totalItems: number;
}

/**
 * User response
 */
export interface IAMUserResponse {
  /** User */
  user: IAMUser;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List users response
 */
export interface ListIAMUsersResponse {
  /** Users */
  users: IAMUser[];
  /** Pagination info */
  pagination?: IAMPaginationResponse;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete user response
 */
export interface DeleteIAMUserResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Role response
 */
export interface IAMRoleResponse {
  /** Role */
  role: IAMRole;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List roles response
 */
export interface ListIAMRolesResponse {
  /** Roles */
  roles: IAMRole[];
  /** Pagination info */
  pagination?: IAMPaginationResponse;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete role response
 */
export interface DeleteIAMRoleResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Assign role response
 */
export interface AssignIAMRoleResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Revoke role response
 */
export interface RevokeIAMRoleResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Group response
 */
export interface IAMGroupResponse {
  /** Group */
  group: IAMGroup;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List groups response
 */
export interface ListIAMGroupsResponse {
  /** Groups */
  groups: IAMGroup[];
  /** Pagination info */
  pagination?: IAMPaginationResponse;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete group response
 */
export interface DeleteIAMGroupResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Add group member response
 */
export interface AddGroupMemberResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Remove group member response
 */
export interface RemoveGroupMemberResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Revoke token response
 */
export interface RevokeIAMTokenResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Tenant response
 */
export interface IAMTenantResponse {
  /** Tenant */
  tenant: IAMTenant;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List tenants response
 */
export interface ListIAMTenantsResponse {
  /** Tenants */
  tenants: IAMTenant[];
  /** Pagination info */
  pagination?: IAMPaginationResponse;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete tenant response
 */
export interface DeleteIAMTenantResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Policy response
 */
export interface IAMPolicyResponse {
  /** Policy */
  policy: IAMPolicy;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List policies response
 */
export interface ListIAMPoliciesResponse {
  /** Policies */
  policies: IAMPolicy[];
  /** Pagination info */
  pagination?: IAMPaginationResponse;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete policy response
 */
export interface DeleteIAMPolicyResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}

/**
 * App response
 */
export interface IAMAppResponse {
  /** Application */
  app: IAMApp;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List apps response
 */
export interface ListIAMAppsResponse {
  /** Applications */
  apps: IAMApp[];
  /** Pagination info */
  pagination?: IAMPaginationResponse;
  /** Total count */
  total: number;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Delete app response
 */
export interface DeleteIAMAppResponse {
  /** Operation status */
  status: IAMStatus;
  /** Response timestamp */
  timestamp: string;
}
