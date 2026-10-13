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

package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"google.golang.org/grpc/status"
)

// TenantError represents a tenant operation error.
type TenantError struct {
	Code    string
	Message string
}

func (e *TenantError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *TenantError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// Tenant-specific error types.
var (
	ErrTenantServiceUnavailable = &TenantError{
		Code:    "TENANT_SERVICE_UNAVAILABLE",
		Message: "tenant management service is not available",
	}

	ErrTenantIDRequired = &TenantError{
		Code:    "TENANT_ID_REQUIRED",
		Message: "tenant ID is required",
	}

	ErrTenantNameRequired = &TenantError{
		Code:    "TENANT_NAME_REQUIRED",
		Message: "tenant name is required",
	}

	ErrTenantResourceTypeRequired = &TenantError{
		Code:    "TENANT_RESOURCE_TYPE_REQUIRED",
		Message: "resource type is required",
	}

	ErrTenantAmountRequired = &TenantError{
		Code:    "TENANT_AMOUNT_REQUIRED",
		Message: "amount is required",
	}

	ErrTenantInvalidResourceType = &TenantError{
		Code:    "TENANT_INVALID_RESOURCE_TYPE",
		Message: "invalid resource type",
	}

	ErrTenantBarrierUnsealKeyDecode = &TenantError{
		Code:    "TENANT_BARRIER_UNSEAL_KEY_DECODE",
		Message: "failed to base64-decode barrier unseal key",
	}
)

// TenantServiceProvider is an interface for accessing the tenant management service.
type TenantServiceProvider interface {
	TenantManager() *tenant.Manager
}

// getTenantManager returns the tenant manager from the service provider.
func (r *ToolRegistry) getTenantManager() *tenant.Manager {
	if provider, ok := r.service.(TenantServiceProvider); ok {
		return provider.TenantManager()
	}
	return nil
}

// registerTenantTools registers all tenant management MCP tools.
func (r *ToolRegistry) registerTenantTools() {
	// tenant_list - List all tenants with pagination
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_list",
		Description: "List all tenants with pagination support",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of tenants to return (default: 100)",
					"default":     100,
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Number of tenants to skip for pagination (default: 0)",
					"default":     0,
				},
			},
		},
	})

	// tenant_get - Get tenant by ID
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_get",
		Description: "Get detailed information about a tenant by its ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Unique tenant identifier (UUID)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// tenant_get_by_name - Get tenant by name
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_get_by_name",
		Description: "Get detailed information about a tenant by its name",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Unique tenant name",
				},
			},
			"required": []string{"name"},
		},
	})

	// tenant_create - Create new tenant
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_create",
		Description: "Create a new tenant with optional quotas. Provisions the tenant's DEK and per-tenant barrier.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Unique tenant name (required)",
				},
				"display_name": map[string]interface{}{
					"type":        "string",
					"description": "Human-readable display name",
				},
				"labels": map[string]interface{}{
					"type":        "object",
					"description": "Key-value labels for tenant metadata",
				},
				"annotations": map[string]interface{}{
					"type":        "object",
					"description": "Key-value annotations for tenant metadata",
				},
				"max_vms": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of VMs (compute quota)",
				},
				"max_containers": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of containers (compute quota)",
				},
				"max_vcpus": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of vCPUs (compute quota)",
				},
				"max_memory_mb": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum memory in MB (compute quota)",
				},
				"max_disk_gb": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum disk space in GB (compute quota)",
				},
				"max_bridges": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of network bridges (network quota)",
				},
				"max_ports": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of network ports (network quota)",
				},
				"max_bandwidth_mbps": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum network bandwidth in Mbps (network quota)",
				},
				"max_volumes_gb": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum total volume storage in GB (storage quota)",
				},
				"max_snapshots": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of snapshots (storage quota)",
				},
			},
			"required": []string{"name"},
		},
	})

	// tenant_update - Update tenant metadata
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_update",
		Description: "Update tenant metadata including display name, labels, and annotations",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
				"display_name": map[string]interface{}{
					"type":        "string",
					"description": "New human-readable display name",
				},
				"labels": map[string]interface{}{
					"type":        "object",
					"description": "Key-value labels to set (replaces existing labels)",
				},
				"annotations": map[string]interface{}{
					"type":        "object",
					"description": "Key-value annotations to set (replaces existing annotations)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// tenant_delete - Delete tenant
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_delete",
		Description: "Delete a tenant and all its associated resources including its DEK and per-tenant barrier",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID to delete (required)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// tenant_suspend - Suspend tenant
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_suspend",
		Description: "Suspend a tenant, blocking all network traffic on its bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID to suspend (required)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// tenant_resume - Resume tenant
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_resume",
		Description: "Resume a suspended tenant, restoring network traffic on its bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID to resume (required)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// tenant_get_quotas - Get tenant quotas
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_get_quotas",
		Description: "Get compute, network, and storage quotas for a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// tenant_update_quotas - Update tenant quotas
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_update_quotas",
		Description: "Update compute, network, and storage quotas for a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
				"max_vms": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of VMs",
				},
				"max_containers": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of containers",
				},
				"max_vcpus": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of vCPUs",
				},
				"max_memory_mb": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum memory in MB",
				},
				"max_disk_gb": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum disk space in GB",
				},
				"max_bridges": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of network bridges",
				},
				"max_ports": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of network ports",
				},
				"max_bandwidth_mbps": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum network bandwidth in Mbps",
				},
				"max_volumes_gb": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum total volume storage in GB",
				},
				"max_snapshots": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of snapshots",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// tenant_get_usage - Get tenant usage stats
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_get_usage",
		Description: "Get current resource usage statistics for a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// tenant_check_quota - Check quota availability
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_check_quota",
		Description: "Check if a tenant has sufficient quota for a resource request",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
				"resource_type": map[string]interface{}{
					"type":        "string",
					"description": "Resource type to check (vms, containers, vcpus, memory, disk, bridges, ports, bandwidth, volumes, snapshots)",
				},
				"amount": map[string]interface{}{
					"type":        "integer",
					"description": "Amount of resource to request",
				},
			},
			"required": []string{"tenant_id", "resource_type", "amount"},
		},
	})

	// tenant_sync - Synchronize tenant state
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_sync",
		Description: "Synchronize tenant manager state with external systems (usage tracker, quota reservations)",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// tenant_rotate_dek - Rotate the Data Encryption Key for a tenant
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_rotate_dek",
		Description: "Rotate the Data Encryption Key for a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
				"background": map[string]interface{}{
					"type":        "boolean",
					"description": "Run re-encryption in background (optional, default: false)",
					"default":     false,
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// tenant_get_dek_status - Get DEK status including usage and rotation progress
	r.addTool(mcpwire.ToolDefinition{
		Name:        "tenant_get_dek_status",
		Description: "Get DEK status including usage and rotation progress",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// platform_tenant_barrier_init - Explicitly initialize a per-tenant barrier
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tenant_barrier_init",
		Description: "Explicitly initialize the per-tenant cryptographic barrier for a tenant. Useful when automatic initialization during tenant creation was skipped or failed.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
				"threshold": map[string]interface{}{
					"type":        "integer",
					"description": "Optional Shamir share threshold required to unseal the barrier",
				},
				"shares": map[string]interface{}{
					"type":        "integer",
					"description": "Optional total number of Shamir shares to generate",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// platform_tenant_barrier_unseal - Unseal a per-tenant barrier
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tenant_barrier_unseal",
		Description: "Unseal a per-tenant cryptographic barrier using the supplied key material. The key argument is base64-encoded; an empty key falls back to the deterministic init credential.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
				"key": map[string]interface{}{
					"type":        "string",
					"description": "Optional base64-encoded unseal key bytes",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// platform_tenant_barrier_seal - Seal a per-tenant barrier
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tenant_barrier_seal",
		Description: "Seal a per-tenant cryptographic barrier, returning it to the sealed state. Subsequent reads/writes against the tenant namespace will fail until the barrier is unsealed.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// platform_tenant_barrier_status - Report per-tenant barrier status
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tenant_barrier_status",
		Description: "Return the current sealed/initialized state and active strategy metadata of a per-tenant barrier.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
			},
			"required": []string{"tenant_id"},
		},
	})
}

// executeTenantList handles the tenant_list tool execution.
func (r *ToolRegistry) executeTenantList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	limit := getInt(args, "limit")
	if limit <= 0 {
		limit = 100
	}
	offset := getInt(args, "offset")

	tenants, total, err := mgr.ListTenants(ctx, limit, offset)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"tenants": formatTenantList(tenants),
		"count":   len(tenants),
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	}, nil
}

// executeTenantGet handles the tenant_get tool execution.
func (r *ToolRegistry) executeTenantGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	entity, err := mgr.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return formatTenantEntity(entity), nil
}

// executeTenantGetByName handles the tenant_get_by_name tool execution.
func (r *ToolRegistry) executeTenantGetByName(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	name := getString(args, "name")
	if name == "" {
		return nil, ErrTenantNameRequired
	}

	entity, err := mgr.GetTenantByName(ctx, name)
	if err != nil {
		return nil, err
	}

	return formatTenantEntity(entity), nil
}

// executeTenantCreate handles the tenant_create tool execution.
func (r *ToolRegistry) executeTenantCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	name := getString(args, "name")
	if name == "" {
		return nil, ErrTenantNameRequired
	}

	req := &tenant.CreateTenantRequest{
		Name:        name,
		DisplayName: getString(args, "display_name"),
		Labels:      getStringMap(args, "labels"),
		Annotations: getStringMap(args, "annotations"),
	}

	// Handle compute quota overrides
	if hasComputeQuotaArgs(args) {
		req.ComputeQuota = &tenant.ComputeQuota{
			MaxVMs:        getInt64(args, "max_vms"),
			MaxContainers: getInt64(args, "max_containers"),
			MaxVCPUs:      getInt64(args, "max_vcpus"),
			MaxMemoryMB:   getInt64(args, "max_memory_mb"),
			MaxDiskGB:     getInt64(args, "max_disk_gb"),
		}
	}

	// Handle network quota overrides
	if hasNetworkQuotaArgs(args) {
		req.NetworkQuota = &tenant.NetworkQuota{
			MaxBridges:       getInt64(args, "max_bridges"),
			MaxPorts:         getInt64(args, "max_ports"),
			MaxBandwidthMbps: getInt64(args, "max_bandwidth_mbps"),
		}
	}

	// Handle storage quota overrides
	if hasStorageQuotaArgs(args) {
		req.StorageQuota = &tenant.StorageQuota{
			MaxVolumesGB: getInt64(args, "max_volumes_gb"),
			MaxSnapshots: getInt64(args, "max_snapshots"),
		}
	}

	entity, err := mgr.CreateTenant(ctx, req)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"tenant":  formatTenantEntity(entity),
		"message": fmt.Sprintf("tenant '%s' created successfully", name),
	}, nil
}

// executeTenantUpdate handles the tenant_update tool execution.
func (r *ToolRegistry) executeTenantUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	req := &tenant.UpdateTenantRequest{}

	if displayName := getString(args, "display_name"); displayName != "" {
		req.DisplayName = &displayName
	}

	if labels := getStringMap(args, "labels"); labels != nil {
		req.Labels = labels
	}

	if annotations := getStringMap(args, "annotations"); annotations != nil {
		req.Annotations = annotations
	}

	entity, err := mgr.UpdateTenant(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"tenant":  formatTenantEntity(entity),
		"message": "tenant updated successfully",
	}, nil
}

// executeTenantDelete handles the tenant_delete tool execution.
func (r *ToolRegistry) executeTenantDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	err := mgr.DeleteTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":   true,
		"tenant_id": tenantID,
		"message":   "tenant deleted successfully",
	}, nil
}

// executeTenantSuspend handles the tenant_suspend tool execution.
func (r *ToolRegistry) executeTenantSuspend(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	err := mgr.SuspendTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Get updated tenant info
	entity, err := mgr.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"tenant":  formatTenantEntity(entity),
		"message": "tenant suspended successfully",
	}, nil
}

// executeTenantResume handles the tenant_resume tool execution.
func (r *ToolRegistry) executeTenantResume(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	err := mgr.ResumeTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Get updated tenant info
	entity, err := mgr.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"tenant":  formatTenantEntity(entity),
		"message": "tenant resumed successfully",
	}, nil
}

// executeTenantGetQuotas handles the tenant_get_quotas tool execution.
func (r *ToolRegistry) executeTenantGetQuotas(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	quotas, err := mgr.GetQuotas(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"tenant_id": tenantID,
		"compute": map[string]interface{}{
			"max_vms":        quotas.Compute.MaxVMs,
			"max_containers": quotas.Compute.MaxContainers,
			"max_vcpus":      quotas.Compute.MaxVCPUs,
			"max_memory_mb":  quotas.Compute.MaxMemoryMB,
			"max_disk_gb":    quotas.Compute.MaxDiskGB,
		},
		"network": map[string]interface{}{
			"max_bridges":        quotas.Network.MaxBridges,
			"max_ports":          quotas.Network.MaxPorts,
			"max_bandwidth_mbps": quotas.Network.MaxBandwidthMbps,
		},
		"storage": map[string]interface{}{
			"max_volumes_gb": quotas.Storage.MaxVolumesGB,
			"max_snapshots":  quotas.Storage.MaxSnapshots,
		},
	}, nil
}

// executeTenantUpdateQuotas handles the tenant_update_quotas tool execution.
func (r *ToolRegistry) executeTenantUpdateQuotas(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	// Get current quotas first
	currentQuotas, err := mgr.GetQuotas(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Update with any provided values
	quotas := &tenant.TenantQuotas{
		Compute: currentQuotas.Compute,
		Network: currentQuotas.Network,
		Storage: currentQuotas.Storage,
	}

	// Apply compute quota updates
	if v := getInt64(args, "max_vms"); v > 0 {
		quotas.Compute.MaxVMs = v
	}
	if v := getInt64(args, "max_containers"); v > 0 {
		quotas.Compute.MaxContainers = v
	}
	if v := getInt64(args, "max_vcpus"); v > 0 {
		quotas.Compute.MaxVCPUs = v
	}
	if v := getInt64(args, "max_memory_mb"); v > 0 {
		quotas.Compute.MaxMemoryMB = v
	}
	if v := getInt64(args, "max_disk_gb"); v > 0 {
		quotas.Compute.MaxDiskGB = v
	}

	// Apply network quota updates
	if v := getInt64(args, "max_bridges"); v > 0 {
		quotas.Network.MaxBridges = v
	}
	if v := getInt64(args, "max_ports"); v > 0 {
		quotas.Network.MaxPorts = v
	}
	if v := getInt64(args, "max_bandwidth_mbps"); v > 0 {
		quotas.Network.MaxBandwidthMbps = v
	}

	// Apply storage quota updates
	if v := getInt64(args, "max_volumes_gb"); v > 0 {
		quotas.Storage.MaxVolumesGB = v
	}
	if v := getInt64(args, "max_snapshots"); v > 0 {
		quotas.Storage.MaxSnapshots = v
	}

	err = mgr.UpdateQuotas(ctx, tenantID, quotas)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":   true,
		"tenant_id": tenantID,
		"compute": map[string]interface{}{
			"max_vms":        quotas.Compute.MaxVMs,
			"max_containers": quotas.Compute.MaxContainers,
			"max_vcpus":      quotas.Compute.MaxVCPUs,
			"max_memory_mb":  quotas.Compute.MaxMemoryMB,
			"max_disk_gb":    quotas.Compute.MaxDiskGB,
		},
		"network": map[string]interface{}{
			"max_bridges":        quotas.Network.MaxBridges,
			"max_ports":          quotas.Network.MaxPorts,
			"max_bandwidth_mbps": quotas.Network.MaxBandwidthMbps,
		},
		"storage": map[string]interface{}{
			"max_volumes_gb": quotas.Storage.MaxVolumesGB,
			"max_snapshots":  quotas.Storage.MaxSnapshots,
		},
		"message": "quotas updated successfully",
	}, nil
}

// executeTenantGetUsage handles the tenant_get_usage tool execution.
func (r *ToolRegistry) executeTenantGetUsage(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	usage, err := mgr.GetUsage(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"tenant_id": tenantID,
		"usage": map[string]interface{}{
			"vms":            usage.VMs,
			"containers":     usage.Containers,
			"vcpus":          usage.VCPUs,
			"memory_mb":      usage.MemoryMB,
			"disk_gb":        usage.DiskGB,
			"bridges":        usage.Bridges,
			"ports":          usage.Ports,
			"bandwidth_mbps": usage.BandwidthMbps,
			"volumes":        usage.Volumes,
			"snapshots":      usage.Snapshots,
		},
		"timestamp": usage.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}

// executeTenantCheckQuota handles the tenant_check_quota tool execution.
func (r *ToolRegistry) executeTenantCheckQuota(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	resourceType := getString(args, "resource_type")
	if resourceType == "" {
		return nil, ErrTenantResourceTypeRequired
	}

	amount := getInt64(args, "amount")
	if amount <= 0 {
		return nil, ErrTenantAmountRequired
	}

	// Convert string to ResourceType
	rt := quota.ResourceType(resourceType)
	if !rt.IsValid() {
		return nil, ErrTenantInvalidResourceType
	}

	err := mgr.CheckQuota(ctx, tenantID, rt, amount)
	available := err == nil

	result := map[string]interface{}{
		"tenant_id":     tenantID,
		"resource_type": resourceType,
		"amount":        amount,
		"available":     available,
	}

	if err != nil {
		result["error"] = err.Error()
	}

	return result, nil
}

// executeTenantSync handles the tenant_sync tool execution.
func (r *ToolRegistry) executeTenantSync(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	err := mgr.Sync(ctx)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": "tenant manager state synchronized successfully",
	}, nil
}

// executeTenantRotateDEK handles the tenant_rotate_dek tool execution.
func (r *ToolRegistry) executeTenantRotateDEK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	// The rotation itself reports both versions, so read them from its
	// result rather than bracketing the rotate with two status reads —
	// a concurrent rotation between those reads would report versions
	// that never belonged to this call.
	result, err := mgr.RotateTenantDEKWithOptions(ctx, tenantID, false)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":     true,
		"tenant_id":   tenantID,
		"old_version": result.OldVersion,
		"new_version": result.NewVersion,
		"timestamp":   time.Now().Format("2006-01-02T15:04:05Z07:00"),
		"message":     "DEK rotated successfully",
	}, nil
}

// executeTenantGetDEKStatus handles the tenant_get_dek_status tool execution.
func (r *ToolRegistry) executeTenantGetDEKStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	status, err := mgr.GetTenantDEKStatus(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"tenant_id":       tenantID,
		"path":            status.Path,
		"version":         status.Version,
		"algorithm":       status.Algorithm,
		"status":          status.Status,
		"is_default":      status.IsDefault,
		"created_at":      status.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		"rotated_at":      status.RotatedAt.Format("2006-01-02T15:04:05Z07:00"),
		"usage_count":     status.UsageCount,
		"bytes_used":      status.BytesUsed,
		"max_usage_count": status.MaxUsageCount,
		"max_bytes_used":  status.MaxBytesUsed,
		"warning_percent": status.WarningPercent,
		"usage_percent":   status.UsagePercent,
		"needs_rotation":  status.NeedsRotation,
	}

	// Include re-encryption progress if available
	if status.ReencryptProgress != nil {
		result["reencrypt_progress"] = map[string]interface{}{
			"in_progress":          status.ReencryptProgress.InProgress,
			"total_keys":           status.ReencryptProgress.TotalKeys,
			"processed_keys":       status.ReencryptProgress.ProcessedKeys,
			"failed_keys":          status.ReencryptProgress.FailedKeys,
			"started_at":           status.ReencryptProgress.StartedAt.Format("2006-01-02T15:04:05Z07:00"),
			"estimated_completion": status.ReencryptProgress.EstimatedCompletion.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	return result, nil
}

// executeTenantBarrierInit handles the platform_tenant_barrier_init tool
// execution. The threshold and shares arguments are accepted for API parity
// with REST/gRPC/QUIC but are currently informational; the underlying
// Manager.InitTenantBarrier uses the platform default Shamir parameters.
func (r *ToolRegistry) executeTenantBarrierInit(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	if err := mgr.InitTenantBarrier(ctx, tenantID); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":   true,
		"tenant_id": tenantID,
		"threshold": getInt(args, "threshold"),
		"shares":    getInt(args, "shares"),
		"message":   "tenant barrier initialized successfully",
	}, nil
}

// executeTenantBarrierUnseal handles the platform_tenant_barrier_unseal tool
// execution. The "key" argument is base64-encoded; an empty key is rejected by
// the underlying Manager.UnsealTenantBarrier.
func (r *ToolRegistry) executeTenantBarrierUnseal(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	var key []byte
	if encoded := getString(args, "key"); encoded != "" {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, ErrTenantBarrierUnsealKeyDecode
		}
		key = decoded
	}

	if err := mgr.UnsealTenantBarrier(ctx, tenantID, key); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":   true,
		"tenant_id": tenantID,
		"message":   "tenant barrier unsealed successfully",
	}, nil
}

// executeTenantBarrierSeal handles the platform_tenant_barrier_seal tool
// execution.
func (r *ToolRegistry) executeTenantBarrierSeal(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	if err := mgr.SealTenantBarrier(ctx, tenantID); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":   true,
		"tenant_id": tenantID,
		"message":   "tenant barrier sealed successfully",
	}, nil
}

// executeTenantBarrierStatus handles the platform_tenant_barrier_status tool
// execution.
func (r *ToolRegistry) executeTenantBarrierStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr := r.getTenantManager()
	if mgr == nil {
		return nil, ErrTenantServiceUnavailable
	}

	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}

	state, err := mgr.TenantBarrierStatus(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"tenant_id":       state.TenantID,
		"sealed":          state.Sealed,
		"initialized":     state.Initialized,
		"strategy":        state.Strategy,
		"hardware_backed": state.HardwareBacked,
	}, nil
}

// formatTenantEntity formats a TenantEntity for MCP response.
func formatTenantEntity(entity *tenant.TenantEntity) map[string]interface{} {
	if entity == nil {
		return nil
	}

	result := map[string]interface{}{
		"id":           entity.ID,
		"name":         entity.Name,
		"display_name": entity.DisplayName,
		"state":        string(entity.State),
		"created_at":   entity.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		"updated_at":   entity.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	// Include DEK handle if set
	if entity.DEKHandle() != 0 {
		result["dek_handle"] = entity.DEKHandle()
	}

	// Include quotas
	result["compute_quota"] = map[string]interface{}{
		"max_vms":        entity.ComputeQuota.MaxVMs,
		"max_containers": entity.ComputeQuota.MaxContainers,
		"max_vcpus":      entity.ComputeQuota.MaxVCPUs,
		"max_memory_mb":  entity.ComputeQuota.MaxMemoryMB,
		"max_disk_gb":    entity.ComputeQuota.MaxDiskGB,
	}

	result["network_quota"] = map[string]interface{}{
		"max_bridges":        entity.NetworkQuota.MaxBridges,
		"max_ports":          entity.NetworkQuota.MaxPorts,
		"max_bandwidth_mbps": entity.NetworkQuota.MaxBandwidthMbps,
	}

	result["storage_quota"] = map[string]interface{}{
		"max_volumes_gb": entity.StorageQuota.MaxVolumesGB,
		"max_snapshots":  entity.StorageQuota.MaxSnapshots,
	}

	// Include labels if present
	if len(entity.Labels) > 0 {
		result["labels"] = entity.Labels
	}

	// Include annotations if present
	if len(entity.Annotations) > 0 {
		result["annotations"] = entity.Annotations
	}

	// Include deleted timestamp if set
	if entity.DeletedAt != nil {
		result["deleted_at"] = entity.DeletedAt.Format("2006-01-02T15:04:05Z07:00")
	}

	return result
}

// formatTenantList formats a slice of TenantEntity for MCP response.
func formatTenantList(tenants []*tenant.TenantEntity) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(tenants))
	for _, t := range tenants {
		result = append(result, formatTenantEntity(t))
	}
	return result
}

// hasComputeQuotaArgs checks if any compute quota arguments were provided.
func hasComputeQuotaArgs(args map[string]interface{}) bool {
	keys := []string{"max_vms", "max_containers", "max_vcpus", "max_memory_mb", "max_disk_gb"}
	for _, key := range keys {
		if _, ok := args[key]; ok {
			return true
		}
	}
	return false
}

// hasNetworkQuotaArgs checks if any network quota arguments were provided.
func hasNetworkQuotaArgs(args map[string]interface{}) bool {
	keys := []string{"max_bridges", "max_ports", "max_bandwidth_mbps"}
	for _, key := range keys {
		if _, ok := args[key]; ok {
			return true
		}
	}
	return false
}

// hasStorageQuotaArgs checks if any storage quota arguments were provided.
func hasStorageQuotaArgs(args map[string]interface{}) bool {
	keys := []string{"max_volumes_gb", "max_snapshots"}
	for _, key := range keys {
		if _, ok := args[key]; ok {
			return true
		}
	}
	return false
}
