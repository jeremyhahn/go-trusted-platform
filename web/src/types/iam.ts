/**
 * IAM (Identity & Access Management) Type Definitions
 *
 * These types match the backend API responses from:
 * /api/v1/iam/tenants/{tenant}/users
 * /api/v1/iam/tenants/{tenant}/roles
 * /api/v1/iam/tenants/{tenant}/groups
 * /api/v1/iam/tenants/{tenant}/policies
 */

// User types
export interface User {
  id: string;
  tenant_id: string;
  email: string;
  name?: string;
  roles?: string[];
  groups?: string[];
  attributes?: Record<string, string>;
  mfa_verified: boolean;
  created_at?: string;
  updated_at?: string;
  last_auth?: string;
}

export interface ListUsersResponse {
  total: number;
  limit: number;
  offset: number;
  users: User[];
}

export interface CreateUserRequest {
  email: string;
  name?: string;
  roles?: string[];
  groups?: string[];
  attributes?: Record<string, string>;
}

export interface UpdateUserRequest {
  email?: string;
  name?: string;
  roles?: string[];
  groups?: string[];
  attributes?: Record<string, string>;
}

// Role types
export interface Role {
  id: string;
  tenant_id: string;
  name?: string;
  description?: string;
  permissions?: string[];
  created_at?: string;
  updated_at?: string;
}

export interface ListRolesResponse {
  total: number;
  limit: number;
  offset: number;
  roles: Role[];
}

export interface CreateRoleRequest {
  id: string;
  name?: string;
  description?: string;
  permissions?: string[];
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  permissions?: string[];
}

// Group types
export interface Group {
  id: string;
  tenant_id: string;
  name?: string;
  description?: string;
  members?: string[];
  created_at?: string;
  updated_at?: string;
}

export interface ListGroupsResponse {
  total: number;
  limit: number;
  offset: number;
  groups: Group[];
}

export interface CreateGroupRequest {
  id: string;
  name?: string;
  description?: string;
}

export interface UpdateGroupRequest {
  name?: string;
  description?: string;
}

// Policy types
export interface Policy {
  name: string;
  tenant_id: string;
  description?: string;
  priority: number;
  spec_yaml?: string;
  labels?: Record<string, string>;
  created_at?: string;
  updated_at?: string;
}

export interface ListPoliciesResponse {
  total: number;
  limit: number;
  offset: number;
  policies: Policy[];
}

export interface CreatePolicyRequest {
  name: string;
  description?: string;
  priority?: number;
  spec_yaml: string;
  labels?: Record<string, string>;
}

export interface UpdatePolicyRequest {
  description?: string;
  priority?: number;
  spec_yaml?: string;
  labels?: Record<string, string>;
}

export interface ValidatePolicyRequest {
  spec_yaml: string;
}

export interface ValidatePolicyResponse {
  valid: boolean;
  errors?: string[];
}

export interface TestPolicyRequest {
  subject_id: string;
  roles?: string[];
  groups?: string[];
  action: string;
  resource: string;
  context?: Record<string, string>;
  attributes?: Record<string, string>;
}

export interface TestPolicyResponse {
  allowed: boolean;
  matched_policy?: string;
  matched_rule?: string;
  evaluation_time_ns: number;
}

// Application (OAuth client) types
export interface Application {
  client_id: string;
  client_secret?: string;
  tenant_id: string;
  name: string;
  redirect_uris?: string[];
  grant_types?: string[];
  response_types?: string[];
  resource_prefix?: string;
  created_at?: string;
  updated_at?: string;
}

export interface ListAppsResponse {
  total: number;
  limit: number;
  offset: number;
  apps: Application[];
}

export interface RegisterAppRequest {
  name: string;
  redirect_uris?: string[];
  grant_types?: string[];
  response_types?: string[];
  resource_prefix?: string;
}

export interface UpdateAppRequest {
  name?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  response_types?: string[];
  resource_prefix?: string;
}

export interface RotateSecretResponse {
  client_id: string;
  name: string;
  client_secret: string;
}

// Tenant types
export interface TenantSettings {
  max_users?: number;
  mfa_required: boolean;
}

export interface Tenant {
  id: string;
  name?: string;
  settings?: TenantSettings;
  created_at?: string;
  updated_at?: string;
}

export interface ListTenantsResponse {
  total: number;
  limit: number;
  offset: number;
  tenants: Tenant[];
}

export interface CreateTenantRequest {
  id: string;
  name?: string;
  settings?: TenantSettings;
}

export interface UpdateTenantRequest {
  name?: string;
  settings?: TenantSettings;
}

// Generic success response
export interface SuccessResponse {
  success: boolean;
  message?: string;
}

// Pagination parameters
export interface PaginationParams {
  limit?: number;
  offset?: number;
}

// Legacy types for backward compatibility with existing UI components
export type UserStatus = 'active' | 'disabled' | 'pending';

export interface LegacyUser {
  id: string;
  email: string;
  name: string;
  avatarUrl?: string;
  roles: LegacyRole[];
  permissions: Permission[];
  status: UserStatus;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
}

export interface LegacyRole {
  id: string;
  name: string;
  description: string;
  permissions: Permission[];
  userCount: number;
  createdAt?: string;
  updatedAt?: string;
}

export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  description: string;
}

export interface Token {
  id: string;
  name: string;
  scopes: string[];
  createdAt: string;
  expiresAt: string;
  lastUsedAt?: string;
  userId?: string;
}

export interface TokenWithSecret extends Token {
  secret: string;
}

// Legacy input types for backward compatibility
export interface CreateUserInput {
  email: string;
  name: string;
  password: string;
  roleIds?: string[];
  status?: UserStatus;
}

export interface UpdateUserInput {
  email?: string;
  name?: string;
  password?: string;
  roleIds?: string[];
  status?: UserStatus;
  avatarUrl?: string;
}

export interface CreateRoleInput {
  name: string;
  description: string;
  permissionIds: string[];
}

export interface UpdateRoleInput {
  name?: string;
  description?: string;
  permissionIds?: string[];
}

export interface CreateTokenInput {
  name: string;
  scopes: string[];
  expiresAt?: string;
}

// Grouped permissions for tree view
export interface PermissionGroup {
  resource: string;
  permissions: Permission[];
}

// Activity log entry
export interface ActivityLogEntry {
  id: string;
  userId: string;
  action: string;
  resource: string;
  timestamp: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
}
