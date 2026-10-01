/**
 * Tenant Management Types
 *
 * Type definitions matching the backend API responses from go-trusted-platform
 */

// Tenant state from backend
export type TenantState = 'created' | 'active' | 'suspended' | 'deleted';

// Tenant role for members
export type TenantRole = 'owner' | 'admin' | 'member' | 'viewer';

// Invitation status from backend
export type InvitationStatus = 'pending' | 'accepted' | 'expired' | 'revoked';

// Compute quota settings
export interface ComputeQuota {
  max_vms: number;
  max_containers: number;
  max_vcpus: number;
  max_memory_mb: number;
  max_disk_gb: number;
}

// Network quota settings
export interface NetworkQuota {
  max_bridges: number;
  max_ports: number;
  max_bandwidth_mbps: number;
}

// Storage quota settings
export interface StorageQuota {
  max_volumes_gb: number;
  max_snapshots: number;
}

// Tenant entity from backend REST API
export interface Tenant {
  id: string;
  name: string;
  display_name: string;
  state: TenantState;
  compute_quota?: ComputeQuota;
  network_quota?: NetworkQuota;
  storage_quota?: StorageQuota;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

// Tenant list response from backend
export interface TenantListResponse {
  tenants: Tenant[];
  total: number;
  limit: number;
  offset: number;
  timestamp: string;
}

// Tenant quotas response from backend
export interface TenantQuotasResponse {
  tenant_id: string;
  compute: ComputeQuota;
  network: NetworkQuota;
  storage: StorageQuota;
  timestamp: string;
}

// Tenant usage response from backend
export interface TenantUsageResponse {
  tenant_id: string;
  vms: number;
  containers: number;
  vcpus: number;
  memory_mb: number;
  disk_gb: number;
  bridges: number;
  ports: number;
  bandwidth_mbps: number;
  volumes: number;
  snapshots: number;
  timestamp: string;
}

// IAM User from backend
export interface IAMUser {
  id: string;
  name: string;
  email: string;
  created_at: string;
  updated_at: string;
  roles?: string[];
}

// Member representation for the UI
export interface Member {
  id: string;
  userId: string;
  user: {
    id: string;
    email: string;
    name: string;
    avatarUrl?: string;
  };
  role: TenantRole;
  joinedAt: string;
}

// Invitation from backend API
export interface Invitation {
  id: number;
  email: string;
  role: string;
  status: InvitationStatus;
  token?: string;
  expires_at: string;
  created_at: string;
}

// Invitation list response from backend
export interface InvitationListResponse {
  invitations: Invitation[];
  total: number;
}

// Request types for API calls
export interface CreateTenantInput {
  name: string;
  display_name?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

export interface UpdateTenantInput {
  display_name?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

export interface SendInvitationInput {
  email: string;
  role: TenantRole;
}

export interface UpdateMemberRoleInput {
  role: TenantRole;
}

// Tenant settings for UI compatibility (derived from quotas)
export interface TenantSettings {
  allowedDomains?: string[];
  maxMembers: number;
  features: string[];
}

// Helper function to convert backend Tenant to UI-friendly format
export function toUITenant(tenant: Tenant): Tenant & { plan: 'free' | 'pro' | 'enterprise'; settings: TenantSettings } {
  // Determine plan based on quotas or labels
  let plan: 'free' | 'pro' | 'enterprise' = 'free';
  if (tenant.labels?.plan) {
    plan = tenant.labels.plan as 'free' | 'pro' | 'enterprise';
  } else if (tenant.compute_quota && tenant.compute_quota.max_vms > 10) {
    plan = 'enterprise';
  } else if (tenant.compute_quota && tenant.compute_quota.max_vms > 5) {
    plan = 'pro';
  }

  // Build settings from quotas and labels
  const settings: TenantSettings = {
    allowedDomains: tenant.labels?.allowed_domains?.split(',').filter(Boolean) || [],
    maxMembers: tenant.compute_quota?.max_vcpus || 10,
    features: tenant.annotations?.features?.split(',').filter(Boolean) || [],
  };

  return {
    ...tenant,
    plan,
    settings,
  };
}
