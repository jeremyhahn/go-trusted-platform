//go:build integration

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package tenant provides integration test adapters for Tenant services.
// This file defines the interface and types for tenant operations across all protocols.
package tenant

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// TenantCommands defines the interface for tenant operations across all protocols
type TenantCommands interface {
	// Setup prepares the adapter for testing
	Setup(ctx context.Context) error

	// Teardown cleans up after testing
	Teardown(ctx context.Context) error

	// Name returns the adapter name
	Name() string

	// Tenant CRUD Operations

	// CreateTenant creates a new tenant
	CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error)

	// GetTenant retrieves a tenant by ID
	GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error)

	// GetTenantByName retrieves a tenant by name
	GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error)

	// UpdateTenant updates an existing tenant
	UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error)

	// DeleteTenant removes a tenant
	DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error)

	// ListTenants lists all tenants with optional pagination
	ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error)

	// Tenant Lifecycle Operations

	// SuspendTenant suspends a tenant
	SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error)

	// ResumeTenant resumes a suspended tenant
	ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error)

	// Quota Operations

	// GetQuotas retrieves tenant quotas
	GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error)

	// UpdateQuotas updates tenant quotas
	UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error)

	// GetUsage retrieves tenant resource usage
	GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error)

	// CheckQuota checks if a resource request can be fulfilled
	CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error)

	// Network Operations

	// ValidateVLAN validates a VLAN ID for a tenant
	ValidateVLAN(ctx context.Context, opts ValidateVLANOptions) (*ValidateVLANResult, error)

	// GetBridgeName retrieves the OVS bridge name for a tenant
	GetBridgeName(ctx context.Context, opts GetBridgeNameOptions) (*GetBridgeNameResult, error)

	// Sync Operations

	// SyncTenants synchronizes tenant manager state
	SyncTenants(ctx context.Context) (*SyncTenantsResult, error)

	// Per-Tenant Barrier Operations (added 2026-04-28)
	//
	// These operations exercise the per-tenant cryptographic barrier shipped
	// across the platform's REST/gRPC/QUIC/MCP/Unix transports. Each tenant
	// has an independent barrier auto-initialized on CreateTenant and
	// auto-sealed on DeleteTenant; explicit lifecycle control is exposed via
	// these methods.

	// InitTenantBarrier explicitly initializes a per-tenant barrier with
	// optional Shamir threshold/shares configuration.
	InitTenantBarrier(ctx context.Context, opts InitTenantBarrierOptions) (*InitTenantBarrierResult, error)

	// UnsealTenantBarrier unseals a per-tenant barrier using the provided
	// key bytes. An empty key falls back to the deterministic init credential.
	UnsealTenantBarrier(ctx context.Context, opts UnsealTenantBarrierOptions) (*UnsealTenantBarrierResult, error)

	// SealTenantBarrier seals a per-tenant barrier, returning it to the
	// sealed state.
	SealTenantBarrier(ctx context.Context, opts SealTenantBarrierOptions) (*SealTenantBarrierResult, error)

	// TenantBarrierStatus reports the current sealed/initialized state and
	// active strategy metadata of a per-tenant barrier.
	TenantBarrierStatus(ctx context.Context, opts TenantBarrierStatusOptions) (*TenantBarrierStatusResult, error)
}

// ============================================================================
// Tenant CRUD Options and Results
// ============================================================================

// CreateTenantOptions contains options for creating a tenant
type CreateTenantOptions struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	VLANRange   *VLANRangeOption  `json:"vlan_range,omitempty"`
}

// VLANRangeOption represents a VLAN range in options
type VLANRangeOption struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

// CreateTenantResult contains the result of tenant creation
type CreateTenantResult struct {
	Tenant *TenantData `json:"tenant"`
}

// TenantData represents tenant data in results
type TenantData struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	DisplayName  string            `json:"display_name"`
	State        tenant.State      `json:"state"`
	OVSBridge    string            `json:"ovs_bridge,omitempty"`
	VLANRange    *VLANRangeData    `json:"vlan_range,omitempty"`
	ComputeQuota *ComputeQuotaData `json:"compute_quota,omitempty"`
	NetworkQuota *NetworkQuotaData `json:"network_quota,omitempty"`
	StorageQuota *StorageQuotaData `json:"storage_quota,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// VLANRangeData represents VLAN range in results
type VLANRangeData struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

// ComputeQuotaData represents compute quota in results
type ComputeQuotaData struct {
	MaxVMs        int64 `json:"max_vms"`
	MaxContainers int64 `json:"max_containers"`
	MaxVCPUs      int64 `json:"max_vcpus"`
	MaxMemoryMB   int64 `json:"max_memory_mb"`
	MaxDiskGB     int64 `json:"max_disk_gb"`
}

// NetworkQuotaData represents network quota in results
type NetworkQuotaData struct {
	MaxBridges       int64 `json:"max_bridges"`
	MaxPorts         int64 `json:"max_ports"`
	MaxBandwidthMbps int64 `json:"max_bandwidth_mbps"`
}

// StorageQuotaData represents storage quota in results
type StorageQuotaData struct {
	MaxVolumesGB int64 `json:"max_volumes_gb"`
	MaxSnapshots int64 `json:"max_snapshots"`
}

// GetTenantOptions contains options for getting a tenant
type GetTenantOptions struct {
	TenantID string `json:"tenant_id"`
}

// GetTenantResult contains the result of getting a tenant
type GetTenantResult struct {
	Tenant *TenantData `json:"tenant"`
}

// GetTenantByNameOptions contains options for getting a tenant by name
type GetTenantByNameOptions struct {
	Name string `json:"name"`
}

// GetTenantByNameResult contains the result of getting a tenant by name
type GetTenantByNameResult struct {
	Tenant *TenantData `json:"tenant"`
}

// UpdateTenantOptions contains options for updating a tenant
type UpdateTenantOptions struct {
	TenantID    string            `json:"tenant_id"`
	DisplayName *string           `json:"display_name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// UpdateTenantResult contains the result of updating a tenant
type UpdateTenantResult struct {
	Tenant *TenantData `json:"tenant"`
}

// DeleteTenantOptions contains options for deleting a tenant
type DeleteTenantOptions struct {
	TenantID string `json:"tenant_id"`
}

// DeleteTenantResult contains the result of deleting a tenant
type DeleteTenantResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ListTenantsOptions contains options for listing tenants
type ListTenantsOptions struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// ListTenantsResult contains the result of listing tenants
type ListTenantsResult struct {
	Tenants []*TenantData `json:"tenants"`
	Total   int           `json:"total"`
}

// ============================================================================
// Tenant Lifecycle Options and Results
// ============================================================================

// SuspendTenantOptions contains options for suspending a tenant
type SuspendTenantOptions struct {
	TenantID string `json:"tenant_id"`
}

// SuspendTenantResult contains the result of suspending a tenant
type SuspendTenantResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ResumeTenantOptions contains options for resuming a tenant
type ResumeTenantOptions struct {
	TenantID string `json:"tenant_id"`
}

// ResumeTenantResult contains the result of resuming a tenant
type ResumeTenantResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ============================================================================
// Quota Options and Results
// ============================================================================

// GetQuotasOptions contains options for getting quotas
type GetQuotasOptions struct {
	TenantID string `json:"tenant_id"`
}

// GetQuotasResult contains the result of getting quotas
type GetQuotasResult struct {
	TenantID string            `json:"tenant_id"`
	Compute  *ComputeQuotaData `json:"compute"`
	Network  *NetworkQuotaData `json:"network"`
	Storage  *StorageQuotaData `json:"storage"`
}

// UpdateQuotasOptions contains options for updating quotas
type UpdateQuotasOptions struct {
	TenantID string              `json:"tenant_id"`
	Compute  *ComputeQuotaUpdate `json:"compute,omitempty"`
	Network  *NetworkQuotaUpdate `json:"network,omitempty"`
	Storage  *StorageQuotaUpdate `json:"storage,omitempty"`
}

// ComputeQuotaUpdate represents compute quota update options
type ComputeQuotaUpdate struct {
	MaxVMs        int64 `json:"max_vms,omitempty"`
	MaxContainers int64 `json:"max_containers,omitempty"`
	MaxVCPUs      int64 `json:"max_vcpus,omitempty"`
	MaxMemoryMB   int64 `json:"max_memory_mb,omitempty"`
	MaxDiskGB     int64 `json:"max_disk_gb,omitempty"`
}

// NetworkQuotaUpdate represents network quota update options
type NetworkQuotaUpdate struct {
	MaxBridges       int64 `json:"max_bridges,omitempty"`
	MaxPorts         int64 `json:"max_ports,omitempty"`
	MaxBandwidthMbps int64 `json:"max_bandwidth_mbps,omitempty"`
}

// StorageQuotaUpdate represents storage quota update options
type StorageQuotaUpdate struct {
	MaxVolumesGB int64 `json:"max_volumes_gb,omitempty"`
	MaxSnapshots int64 `json:"max_snapshots,omitempty"`
}

// UpdateQuotasResult contains the result of updating quotas
type UpdateQuotasResult struct {
	TenantID string            `json:"tenant_id"`
	Compute  *ComputeQuotaData `json:"compute"`
	Network  *NetworkQuotaData `json:"network"`
	Storage  *StorageQuotaData `json:"storage"`
}

// GetUsageOptions contains options for getting usage
type GetUsageOptions struct {
	TenantID string `json:"tenant_id"`
}

// GetUsageResult contains the result of getting usage
type GetUsageResult struct {
	TenantID      string `json:"tenant_id"`
	VMs           int64  `json:"vms"`
	Containers    int64  `json:"containers"`
	VCPUs         int64  `json:"vcpus"`
	MemoryMB      int64  `json:"memory_mb"`
	DiskGB        int64  `json:"disk_gb"`
	Bridges       int64  `json:"bridges"`
	Ports         int64  `json:"ports"`
	BandwidthMbps int64  `json:"bandwidth_mbps"`
	Volumes       int64  `json:"volumes"`
	Snapshots     int64  `json:"snapshots"`
}

// CheckQuotaOptions contains options for checking quota
type CheckQuotaOptions struct {
	TenantID string `json:"tenant_id"`
	Resource string `json:"resource"`
	Amount   int64  `json:"amount"`
}

// CheckQuotaResult contains the result of checking quota
type CheckQuotaResult struct {
	TenantID string `json:"tenant_id"`
	Resource string `json:"resource"`
	Amount   int64  `json:"amount"`
	Allowed  bool   `json:"allowed"`
	Message  string `json:"message,omitempty"`
}

// ============================================================================
// Network Options and Results
// ============================================================================

// ValidateVLANOptions contains options for validating a VLAN
type ValidateVLANOptions struct {
	TenantID string `json:"tenant_id"`
	VLANID   uint16 `json:"vlan_id"`
}

// ValidateVLANResult contains the result of validating a VLAN
type ValidateVLANResult struct {
	TenantID string `json:"tenant_id"`
	VLANID   uint16 `json:"vlan_id"`
	Valid    bool   `json:"valid"`
	Message  string `json:"message,omitempty"`
}

// GetBridgeNameOptions contains options for getting bridge name
type GetBridgeNameOptions struct {
	TenantID string `json:"tenant_id"`
}

// GetBridgeNameResult contains the result of getting bridge name
type GetBridgeNameResult struct {
	TenantID   string `json:"tenant_id"`
	BridgeName string `json:"bridge_name"`
}

// ============================================================================
// Sync Options and Results
// ============================================================================

// SyncTenantsResult contains the result of syncing tenants
type SyncTenantsResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ============================================================================
// Per-Tenant Barrier Options and Results (added 2026-04-28)
// ============================================================================

// InitTenantBarrierOptions configures explicit barrier initialization.
type InitTenantBarrierOptions struct {
	TenantID  string `json:"tenant_id"`
	Threshold int32  `json:"threshold,omitempty"`
	Shares    int32  `json:"shares,omitempty"`
}

// InitTenantBarrierResult is the result of an explicit barrier init.
type InitTenantBarrierResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// UnsealTenantBarrierOptions configures barrier unseal. An empty Key falls
// back to the deterministic init credential.
type UnsealTenantBarrierOptions struct {
	TenantID string `json:"tenant_id"`
	Key      []byte `json:"key,omitempty"`
}

// UnsealTenantBarrierResult is the result of barrier unseal.
type UnsealTenantBarrierResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// SealTenantBarrierOptions configures barrier seal.
type SealTenantBarrierOptions struct {
	TenantID string `json:"tenant_id"`
}

// SealTenantBarrierResult is the result of barrier seal.
type SealTenantBarrierResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// TenantBarrierStatusOptions configures the barrier status query.
type TenantBarrierStatusOptions struct {
	TenantID string `json:"tenant_id"`
}

// TenantBarrierStatusResult mirrors the platform proto TenantBarrierStatus
// for adapter parity. Uninitialized barriers report Sealed=true,
// Initialized=false rather than erroring.
type TenantBarrierStatusResult struct {
	TenantID       string `json:"tenant_id"`
	Sealed         bool   `json:"sealed"`
	Initialized    bool   `json:"initialized"`
	Strategy       string `json:"strategy"`
	HardwareBacked bool   `json:"hardware_backed"`
}
