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
	"maps"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The tenant tools are the TenantService over MCP. Every tool calls the
// TenantService server the gRPC, QUIC, REST and Unix transports serve, so a
// tool answers what its RPC answers: the same validation, the same error
// class and the same tenant isolation (docs/tenant/api.md §7). Nothing here
// validates or decides; the tools translate arguments to a request and a
// response to a result.

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

	ErrTenantBarrierUnsealKeyDecode = &TenantError{
		Code:    "TENANT_BARRIER_UNSEAL_KEY_DECODE",
		Message: "failed to base64-decode barrier unseal key",
	}
)

// ErrTenantCallerUnbound refuses a tenant tool to a caller whose identity
// carries no tenant. The TenantService admits a caller with no tenant
// binding, because on the Unix socket that caller is the local operator. An
// MCP caller is never that operator: one with no binding authenticated on a
// path that projects no tenant claim (the legacy token adapter), and the
// service could not keep it to its own tenant.
type ErrTenantCallerUnbound struct{}

func (ErrTenantCallerUnbound) Error() string {
	return "mcp: the tenant tools need a tenant-bound platform token; this caller's identity carries no tenant"
}

// GRPCStatus classes the error PermissionDenied.
func (e ErrTenantCallerUnbound) GRPCStatus() *status.Status {
	return status.New(codes.PermissionDenied, e.Error())
}

// TenantServiceProvider is implemented by a ServiceProvider that serves the
// TenantService. A provider without it answers every tenant tool
// ErrTenantServiceUnavailable.
type TenantServiceProvider interface {
	TenantService() platformv1.TenantServiceServer
}

// tenantServer returns the TenantService the tenant tools call. It refuses
// an unbound caller before anything else, so such a caller learns nothing,
// not even whether the service is configured.
func (r *ToolRegistry) tenantServer(ctx context.Context) (platformv1.TenantServiceServer, error) {
	if authCtx, ok := AuthorizedContextFromContext(ctx); !ok || authCtx == nil {
		return nil, ErrTenantCallerUnbound{}
	}
	provider, ok := r.service.(TenantServiceProvider)
	if !ok {
		return nil, ErrTenantServiceUnavailable
	}
	server := provider.TenantService()
	if server == nil {
		return nil, ErrTenantServiceUnavailable
	}
	return server, nil
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
		Description: "Update compute, network, and storage quotas for a tenant. A limit not given keeps its current value.",
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
					"description": "Shamir share threshold; must be 0: the per-tenant barrier initializes deterministically and a Shamir request is refused",
				},
				"shares": map[string]interface{}{
					"type":        "integer",
					"description": "Shamir share count; must be 0: the per-tenant barrier initializes deterministically and a Shamir request is refused",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	// platform_tenant_barrier_unseal - Unseal a per-tenant barrier
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_tenant_barrier_unseal",
		Description: "Unseal a per-tenant cryptographic barrier using the supplied base64-encoded key material.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID (required)",
				},
				"key": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded unseal key bytes (required)",
				},
			},
			"required": []string{"tenant_id", "key"},
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

// executeTenantList handles the tenant_list tool (ListTenants).
func (r *ToolRegistry) executeTenantList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.ListTenants(ctx, &platformv1.ListTenantsRequest{
		Limit:  int32(getInt(args, "limit")),
		Offset: int32(getInt(args, "offset")),
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"tenants": formatTenants(resp.GetTenants()),
		"count":   len(resp.GetTenants()),
		"total":   resp.GetTotal(),
	}, nil
}

// executeTenantGet handles the tenant_get tool (GetTenant).
func (r *ToolRegistry) executeTenantGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: getString(args, "tenant_id"),
	})
	if err != nil {
		return nil, err
	}

	return formatTenant(resp.GetTenant()), nil
}

// executeTenantGetByName handles the tenant_get_by_name tool (GetTenantByName).
func (r *ToolRegistry) executeTenantGetByName(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{
		Name: getString(args, "name"),
	})
	if err != nil {
		return nil, err
	}

	return formatTenant(resp.GetTenant()), nil
}

// executeTenantCreate handles the tenant_create tool (CreateTenant).
func (r *ToolRegistry) executeTenantCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name:         getString(args, "name"),
		DisplayName:  getString(args, "display_name"),
		Labels:       getStringMap(args, "labels"),
		Annotations:  getStringMap(args, "annotations"),
		ComputeQuota: computeQuotaFromArgs(args),
		NetworkQuota: networkQuotaFromArgs(args),
		StorageQuota: storageQuotaFromArgs(args),
	})
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), map[string]interface{}{
		"tenant": formatTenant(resp.GetTenant()),
	}), nil
}

// executeTenantUpdate handles the tenant_update tool (UpdateTenant).
func (r *ToolRegistry) executeTenantUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.UpdateTenant(ctx, &platformv1.UpdateTenantRequest{
		TenantId:    getString(args, "tenant_id"),
		DisplayName: getString(args, "display_name"),
		Labels:      getStringMap(args, "labels"),
		Annotations: getStringMap(args, "annotations"),
	})
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), map[string]interface{}{
		"tenant": formatTenant(resp.GetTenant()),
	}), nil
}

// executeTenantDelete handles the tenant_delete tool (DeleteTenant).
func (r *ToolRegistry) executeTenantDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	tenantID := getString(args, "tenant_id")
	resp, err := server.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{TenantId: tenantID})
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), map[string]interface{}{"tenant_id": tenantID}), nil
}

// executeTenantSuspend handles the tenant_suspend tool (SuspendTenant).
func (r *ToolRegistry) executeTenantSuspend(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	tenantID := getString(args, "tenant_id")
	resp, err := server.SuspendTenant(ctx, &platformv1.SuspendTenantRequest{TenantId: tenantID})
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), map[string]interface{}{"tenant_id": tenantID}), nil
}

// executeTenantResume handles the tenant_resume tool (ResumeTenant).
func (r *ToolRegistry) executeTenantResume(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	tenantID := getString(args, "tenant_id")
	resp, err := server.ResumeTenant(ctx, &platformv1.ResumeTenantRequest{TenantId: tenantID})
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), map[string]interface{}{"tenant_id": tenantID}), nil
}

// executeTenantGetQuotas handles the tenant_get_quotas tool (GetQuotas).
func (r *ToolRegistry) executeTenantGetQuotas(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.GetQuotas(ctx, &platformv1.GetQuotasRequest{
		TenantId: getString(args, "tenant_id"),
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"tenant_id": resp.GetTenantId(),
		"compute":   formatComputeQuota(resp.GetCompute()),
		"network":   formatNetworkQuota(resp.GetNetwork()),
		"storage":   formatStorageQuota(resp.GetStorage()),
	}, nil
}

// executeTenantUpdateQuotas handles the tenant_update_quotas tool. UpdateQuotas
// replaces every limit, so the tool reads the current quotas (GetQuotas) and
// sends them back with the limits the caller gave.
func (r *ToolRegistry) executeTenantUpdateQuotas(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	tenantID := getString(args, "tenant_id")
	current, err := server.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: tenantID})
	if err != nil {
		return nil, err
	}

	req := &platformv1.UpdateQuotasRequest{
		TenantId: tenantID,
		Compute: &platformv1.ComputeQuota{
			MaxVms:        quotaArg(args, "max_vms", current.GetCompute().GetMaxVms()),
			MaxContainers: quotaArg(args, "max_containers", current.GetCompute().GetMaxContainers()),
			MaxVcpus:      quotaArg(args, "max_vcpus", current.GetCompute().GetMaxVcpus()),
			MaxMemoryMb:   quotaArg(args, "max_memory_mb", current.GetCompute().GetMaxMemoryMb()),
		},
		Network: &platformv1.NetworkQuota{
			MaxBridges:       quotaArg(args, "max_bridges", current.GetNetwork().GetMaxBridges()),
			MaxPorts:         quotaArg(args, "max_ports", current.GetNetwork().GetMaxPorts()),
			MaxBandwidthMbps: quotaArg(args, "max_bandwidth_mbps", current.GetNetwork().GetMaxBandwidthMbps()),
		},
		Storage: &platformv1.StorageQuota{
			MaxVolumesGb: quotaArg(args, "max_volumes_gb", current.GetStorage().GetMaxVolumesGb()),
			MaxSnapshots: quotaArg(args, "max_snapshots", current.GetStorage().GetMaxSnapshots()),
		},
	}
	resp, err := server.UpdateQuotas(ctx, req)
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), map[string]interface{}{
		"tenant_id": tenantID,
		"compute":   formatComputeQuota(req.GetCompute()),
		"network":   formatNetworkQuota(req.GetNetwork()),
		"storage":   formatStorageQuota(req.GetStorage()),
	}), nil
}

// executeTenantGetUsage handles the tenant_get_usage tool (GetUsage).
func (r *ToolRegistry) executeTenantGetUsage(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.GetUsage(ctx, &platformv1.GetUsageRequest{
		TenantId: getString(args, "tenant_id"),
	})
	if err != nil {
		return nil, err
	}

	usage := resp.GetUsage()
	return map[string]interface{}{
		"tenant_id": usage.GetTenantId(),
		"usage": map[string]interface{}{
			"vms":            usage.GetVms(),
			"containers":     usage.GetContainers(),
			"vcpus":          usage.GetVcpus(),
			"memory_mb":      usage.GetMemoryMb(),
			"disk_gb":        usage.GetDiskGb(),
			"bridges":        usage.GetBridges(),
			"ports":          usage.GetPorts(),
			"bandwidth_mbps": usage.GetBandwidthMbps(),
			"volumes":        usage.GetVolumes(),
			"snapshots":      usage.GetSnapshots(),
		},
		"timestamp": formatTimestamp(usage.GetTimestamp()),
	}, nil
}

// executeTenantCheckQuota handles the tenant_check_quota tool (CheckQuota).
// A request over quota is an answer (available false), not an error.
func (r *ToolRegistry) executeTenantCheckQuota(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: getString(args, "tenant_id"),
		Resource: getString(args, "resource_type"),
		Amount:   getInt64(args, "amount"),
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"tenant_id":     resp.GetTenantId(),
		"resource_type": resp.GetResource(),
		"amount":        resp.GetAmount(),
		"available":     resp.GetAvailable(),
		"message":       resp.GetMessage(),
	}, nil
}

// executeTenantSync handles the tenant_sync tool (Sync). A sync that ran
// with errors is an answer (success false), as it is over gRPC.
func (r *ToolRegistry) executeTenantSync(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.Sync(ctx, &platformv1.SyncTenantsRequest{})
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), nil), nil
}

// executeTenantRotateDEK handles the tenant_rotate_dek tool (RotateTenantDEK).
func (r *ToolRegistry) executeTenantRotateDEK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{
		TenantId:   getString(args, "tenant_id"),
		Background: getBool(args, "background"),
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":     true,
		"tenant_id":   resp.GetTenantId(),
		"old_version": resp.GetOldVersion(),
		"new_version": resp.GetNewVersion(),
		"timestamp":   formatTimestamp(resp.GetTimestamp()),
		"message":     "DEK rotated successfully",
	}, nil
}

// executeTenantGetDEKStatus handles the tenant_get_dek_status tool
// (GetTenantDEKStatus).
func (r *ToolRegistry) executeTenantGetDEKStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{
		TenantId: getString(args, "tenant_id"),
	})
	if err != nil {
		return nil, err
	}

	dek := resp.GetDekStatus()
	result := map[string]interface{}{
		"tenant_id":       dek.GetTenantId(),
		"path":            dek.GetPath(),
		"version":         dek.GetVersion(),
		"algorithm":       dek.GetAlgorithm(),
		"status":          dek.GetStatus(),
		"is_default":      dek.GetIsDefault(),
		"created_at":      formatTimestamp(dek.GetCreatedAt()),
		"rotated_at":      formatTimestamp(dek.GetRotatedAt()),
		"usage_count":     dek.GetUsageCount(),
		"bytes_used":      dek.GetBytesUsed(),
		"max_usage_count": dek.GetMaxUsageCount(),
		"max_bytes_used":  dek.GetMaxBytesUsed(),
		"warning_percent": dek.GetWarningPercent(),
		"usage_percent":   dek.GetUsagePercent(),
		"needs_rotation":  dek.GetNeedsRotation(),
	}

	if progress := dek.GetReencryptProgress(); progress != nil {
		result["reencrypt_progress"] = map[string]interface{}{
			"in_progress":          progress.GetInProgress(),
			"total_keys":           progress.GetTotalKeys(),
			"processed_keys":       progress.GetProcessedKeys(),
			"failed_keys":          progress.GetFailedKeys(),
			"started_at":           formatTimestamp(progress.GetStartedAt()),
			"estimated_completion": formatTimestamp(progress.GetEstimatedCompletion()),
		}
	}

	return result, nil
}

// executeTenantBarrierInit handles the platform_tenant_barrier_init tool
// (InitTenantBarrier).
func (r *ToolRegistry) executeTenantBarrierInit(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	tenantID := getString(args, "tenant_id")
	resp, err := server.InitTenantBarrier(ctx, &platformv1.InitTenantBarrierRequest{
		TenantId:  tenantID,
		Threshold: int32(getInt(args, "threshold")),
		Shares:    int32(getInt(args, "shares")),
	})
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), map[string]interface{}{"tenant_id": tenantID}), nil
}

// executeTenantBarrierUnseal handles the platform_tenant_barrier_unseal tool
// (UnsealTenantBarrier). The "key" argument is base64-encoded.
func (r *ToolRegistry) executeTenantBarrierUnseal(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(getString(args, "key"))
	if err != nil {
		return nil, ErrTenantBarrierUnsealKeyDecode
	}

	tenantID := getString(args, "tenant_id")
	resp, err := server.UnsealTenantBarrier(ctx, &platformv1.UnsealTenantBarrierRequest{
		TenantId: tenantID,
		Key:      key,
	})
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), map[string]interface{}{"tenant_id": tenantID}), nil
}

// executeTenantBarrierSeal handles the platform_tenant_barrier_seal tool
// (SealTenantBarrier).
func (r *ToolRegistry) executeTenantBarrierSeal(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	tenantID := getString(args, "tenant_id")
	resp, err := server.SealTenantBarrier(ctx, &platformv1.SealTenantBarrierRequest{TenantId: tenantID})
	if err != nil {
		return nil, err
	}

	return statusResult(resp.GetStatus(), map[string]interface{}{"tenant_id": tenantID}), nil
}

// executeTenantBarrierStatus handles the platform_tenant_barrier_status tool
// (GetTenantBarrierStatus).
func (r *ToolRegistry) executeTenantBarrierStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	server, err := r.tenantServer(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := server.GetTenantBarrierStatus(ctx, &platformv1.GetTenantBarrierStatusRequest{
		TenantId: getString(args, "tenant_id"),
	})
	if err != nil {
		return nil, err
	}

	barrier := resp.GetBarrierStatus()
	return map[string]interface{}{
		"tenant_id":       barrier.GetTenantId(),
		"sealed":          barrier.GetSealed(),
		"initialized":     barrier.GetInitialized(),
		"strategy":        barrier.GetStrategy(),
		"hardware_backed": barrier.GetHardwareBacked(),
	}, nil
}

// statusResult is a tool result carrying an RPC Status as success and
// message, together with the fields the tool adds.
func statusResult(st *platformv1.Status, fields map[string]interface{}) map[string]interface{} {
	result := map[string]interface{}{
		"success": st.GetSuccess(),
		"message": st.GetMessage(),
	}
	maps.Copy(result, fields)
	return result
}

// tenantStateNames are the tenant states under the names the tenant package
// gives them, which the tools have always answered with.
var tenantStateNames = map[platformv1.TenantState]string{
	platformv1.TenantState_TENANT_STATE_PENDING:   string(tenant.StateCreated),
	platformv1.TenantState_TENANT_STATE_ACTIVE:    string(tenant.StateActive),
	platformv1.TenantState_TENANT_STATE_SUSPENDED: string(tenant.StateSuspended),
	platformv1.TenantState_TENANT_STATE_DELETING:  string(tenant.StateDeleting),
	platformv1.TenantState_TENANT_STATE_DELETED:   string(tenant.StateDeleted),
}

// tenantStateName names a tenant state, falling back to the enum name for a
// state the tenant package does not define.
func tenantStateName(state platformv1.TenantState) string {
	if name, ok := tenantStateNames[state]; ok {
		return name
	}
	return state.String()
}

// formatTenant renders a Tenant as a tool result.
func formatTenant(t *platformv1.Tenant) map[string]interface{} {
	if t == nil {
		return nil
	}

	result := map[string]interface{}{
		"id":            t.GetId(),
		"name":          t.GetName(),
		"display_name":  t.GetDisplayName(),
		"state":         tenantStateName(t.GetState()),
		"created_at":    formatTimestamp(t.GetCreatedAt()),
		"updated_at":    formatTimestamp(t.GetUpdatedAt()),
		"compute_quota": formatComputeQuota(t.GetComputeQuota()),
		"network_quota": formatNetworkQuota(t.GetNetworkQuota()),
		"storage_quota": formatStorageQuota(t.GetStorageQuota()),
	}

	if path := t.GetDekPath(); path != "" {
		result["dek_path"] = path
	}
	if labels := t.GetLabels(); len(labels) > 0 {
		result["labels"] = labels
	}
	if annotations := t.GetAnnotations(); len(annotations) > 0 {
		result["annotations"] = annotations
	}

	return result
}

// formatTenants renders a list of Tenants as a tool result.
func formatTenants(tenants []*platformv1.Tenant) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(tenants))
	for _, t := range tenants {
		result = append(result, formatTenant(t))
	}
	return result
}

func formatComputeQuota(q *platformv1.ComputeQuota) map[string]interface{} {
	return map[string]interface{}{
		"max_vms":        q.GetMaxVms(),
		"max_containers": q.GetMaxContainers(),
		"max_vcpus":      q.GetMaxVcpus(),
		"max_memory_mb":  q.GetMaxMemoryMb(),
	}
}

func formatNetworkQuota(q *platformv1.NetworkQuota) map[string]interface{} {
	return map[string]interface{}{
		"max_bridges":        q.GetMaxBridges(),
		"max_ports":          q.GetMaxPorts(),
		"max_bandwidth_mbps": q.GetMaxBandwidthMbps(),
	}
}

func formatStorageQuota(q *platformv1.StorageQuota) map[string]interface{} {
	return map[string]interface{}{
		"max_volumes_gb": q.GetMaxVolumesGb(),
		"max_snapshots":  q.GetMaxSnapshots(),
	}
}

// formatTimestamp renders a timestamp as RFC 3339, and an absent one as "".
func formatTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().Format(time.RFC3339)
}

// quotaArg is the limit the caller gave under key, or current when the
// caller gave none. A limit is positive, so 0 keeps the current value.
func quotaArg(args map[string]interface{}, key string, current int64) int64 {
	if v := getInt64(args, key); v > 0 {
		return v
	}
	return current
}

// computeQuotaFromArgs is the compute quota the caller gave, or nil (the
// tenant default) when the caller gave no compute limit.
func computeQuotaFromArgs(args map[string]interface{}) *platformv1.ComputeQuota {
	if !hasComputeQuotaArgs(args) {
		return nil
	}
	return &platformv1.ComputeQuota{
		MaxVms:        getInt64(args, "max_vms"),
		MaxContainers: getInt64(args, "max_containers"),
		MaxVcpus:      getInt64(args, "max_vcpus"),
		MaxMemoryMb:   getInt64(args, "max_memory_mb"),
	}
}

// networkQuotaFromArgs is the network quota the caller gave, or nil.
func networkQuotaFromArgs(args map[string]interface{}) *platformv1.NetworkQuota {
	if !hasNetworkQuotaArgs(args) {
		return nil
	}
	return &platformv1.NetworkQuota{
		MaxBridges:       getInt64(args, "max_bridges"),
		MaxPorts:         getInt64(args, "max_ports"),
		MaxBandwidthMbps: getInt64(args, "max_bandwidth_mbps"),
	}
}

// storageQuotaFromArgs is the storage quota the caller gave, or nil.
func storageQuotaFromArgs(args map[string]interface{}) *platformv1.StorageQuota {
	if !hasStorageQuotaArgs(args) {
		return nil
	}
	return &platformv1.StorageQuota{
		MaxVolumesGb: getInt64(args, "max_volumes_gb"),
		MaxSnapshots: getInt64(args, "max_snapshots"),
	}
}

// hasComputeQuotaArgs checks if any compute quota arguments were provided.
func hasComputeQuotaArgs(args map[string]interface{}) bool {
	return hasAnyArg(args, "max_vms", "max_containers", "max_vcpus", "max_memory_mb")
}

// hasNetworkQuotaArgs checks if any network quota arguments were provided.
func hasNetworkQuotaArgs(args map[string]interface{}) bool {
	return hasAnyArg(args, "max_bridges", "max_ports", "max_bandwidth_mbps")
}

// hasStorageQuotaArgs checks if any storage quota arguments were provided.
func hasStorageQuotaArgs(args map[string]interface{}) bool {
	return hasAnyArg(args, "max_volumes_gb", "max_snapshots")
}

// hasAnyArg reports whether args holds any of keys.
func hasAnyArg(args map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if _, ok := args[key]; ok {
			return true
		}
	}
	return false
}
