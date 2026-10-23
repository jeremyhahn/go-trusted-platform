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

// Tenant argument and response mapping for the MCP transport.
//
// The tenant_* and platform_tenant_barrier_* tools (pkg/api/mcp/tenant_tools.go)
// take flat snake_case arguments and return display shapes rather than the
// pb responses:
//
//   - a tenant renders its state as the tenant package's name ("created",
//     "active", ...) and its timestamps as RFC 3339 strings, or "" when unset;
//   - tenant_get and tenant_get_by_name return the bare tenant, and the
//     status-only tools return {"success", "message", ...} with no "status"
//     object;
//   - quota limits travel as flat max_* arguments, and the quota check names
//     its resource "resource_type".
//
// Methods whose shapes the generic pb JSON round-trip cannot express have an
// argument builder or reply decoder below. GetQuotas needs neither: its result
// carries the pb field names.

import (
	"encoding/json"
	"maps"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	// Tool routing — mirrors pkg/api/mcp/tenant_tools.go registrations.
	for method, tool := range map[string]string{
		platformv1.TenantService_CreateTenant_FullMethodName:           "tenant_create",
		platformv1.TenantService_DeleteTenant_FullMethodName:           "tenant_delete",
		platformv1.TenantService_GetTenant_FullMethodName:              "tenant_get",
		platformv1.TenantService_GetTenantByName_FullMethodName:        "tenant_get_by_name",
		platformv1.TenantService_ListTenants_FullMethodName:            "tenant_list",
		platformv1.TenantService_UpdateTenant_FullMethodName:           "tenant_update",
		platformv1.TenantService_SuspendTenant_FullMethodName:          "tenant_suspend",
		platformv1.TenantService_ResumeTenant_FullMethodName:           "tenant_resume",
		platformv1.TenantService_GetQuotas_FullMethodName:              "tenant_get_quotas",
		platformv1.TenantService_UpdateQuotas_FullMethodName:           "tenant_update_quotas",
		platformv1.TenantService_GetUsage_FullMethodName:               "tenant_get_usage",
		platformv1.TenantService_CheckQuota_FullMethodName:             "tenant_check_quota",
		platformv1.TenantService_Sync_FullMethodName:                   "tenant_sync",
		platformv1.TenantService_RotateTenantDEK_FullMethodName:        "tenant_rotate_dek",
		platformv1.TenantService_GetTenantDEKStatus_FullMethodName:     "tenant_get_dek_status",
		platformv1.TenantService_InitTenantBarrier_FullMethodName:      "platform_tenant_barrier_init",
		platformv1.TenantService_UnsealTenantBarrier_FullMethodName:    "platform_tenant_barrier_unseal",
		platformv1.TenantService_SealTenantBarrier_FullMethodName:      "platform_tenant_barrier_seal",
		platformv1.TenantService_GetTenantBarrierStatus_FullMethodName: "platform_tenant_barrier_status",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	// Argument builders — quota limits flatten to the tools' max_* arguments.
	for method, build := range map[string]mcpArgBuilder{
		platformv1.TenantService_CreateTenant_FullMethodName: argBuilder(
			platformv1.TenantService_CreateTenant_FullMethodName, buildTenantCreateArgs),
		platformv1.TenantService_UpdateQuotas_FullMethodName: argBuilder(
			platformv1.TenantService_UpdateQuotas_FullMethodName, buildTenantUpdateQuotasArgs),
		platformv1.TenantService_CheckQuota_FullMethodName: argBuilder(
			platformv1.TenantService_CheckQuota_FullMethodName, buildTenantCheckQuotaArgs),
	} {
		mcpArgBuilders[method] = build
	}

	// Reply decoders — display shapes onto the pb replies. Every status-only
	// method shares decodeTenantStatusResult.
	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.TenantService_CreateTenant_FullMethodName: wireDecoder(
			platformv1.TenantService_CreateTenant_FullMethodName, decodeTenantCreateJSON),
		platformv1.TenantService_GetTenant_FullMethodName: wireDecoder(
			platformv1.TenantService_GetTenant_FullMethodName, decodeTenantGetJSON),
		platformv1.TenantService_GetTenantByName_FullMethodName: wireDecoder(
			platformv1.TenantService_GetTenantByName_FullMethodName, decodeTenantGetByNameJSON),
		platformv1.TenantService_ListTenants_FullMethodName: wireDecoder(
			platformv1.TenantService_ListTenants_FullMethodName, decodeTenantListJSON),
		platformv1.TenantService_UpdateTenant_FullMethodName: wireDecoder(
			platformv1.TenantService_UpdateTenant_FullMethodName, decodeTenantUpdateJSON),
		platformv1.TenantService_GetUsage_FullMethodName: wireDecoder(
			platformv1.TenantService_GetUsage_FullMethodName, decodeTenantUsageJSON),
		platformv1.TenantService_CheckQuota_FullMethodName: wireDecoder(
			platformv1.TenantService_CheckQuota_FullMethodName, decodeTenantCheckQuotaJSON),
		platformv1.TenantService_RotateTenantDEK_FullMethodName: wireDecoder(
			platformv1.TenantService_RotateTenantDEK_FullMethodName, decodeTenantRotateDEKJSON),
		platformv1.TenantService_GetTenantDEKStatus_FullMethodName: wireDecoder(
			platformv1.TenantService_GetTenantDEKStatus_FullMethodName, decodeTenantDEKStatusJSON),
		platformv1.TenantService_GetTenantBarrierStatus_FullMethodName: wireDecoder(
			platformv1.TenantService_GetTenantBarrierStatus_FullMethodName, decodeTenantBarrierStatusJSON),

		platformv1.TenantService_DeleteTenant_FullMethodName:        decodeTenantStatusResult,
		platformv1.TenantService_SuspendTenant_FullMethodName:       decodeTenantStatusResult,
		platformv1.TenantService_ResumeTenant_FullMethodName:        decodeTenantStatusResult,
		platformv1.TenantService_UpdateQuotas_FullMethodName:        decodeTenantStatusResult,
		platformv1.TenantService_Sync_FullMethodName:                decodeTenantStatusResult,
		platformv1.TenantService_InitTenantBarrier_FullMethodName:   decodeTenantStatusResult,
		platformv1.TenantService_UnsealTenantBarrier_FullMethodName: decodeTenantStatusResult,
		platformv1.TenantService_SealTenantBarrier_FullMethodName:   decodeTenantStatusResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

// tenantStatesByName maps the state names the tenant tools render
// (pkg/api/mcp tenantStateNames) back onto the pb enum.
var tenantStatesByName = map[string]platformv1.TenantState{
	"created":   platformv1.TenantState_TENANT_STATE_PENDING,
	"active":    platformv1.TenantState_TENANT_STATE_ACTIVE,
	"suspended": platformv1.TenantState_TENANT_STATE_SUSPENDED,
	"deleting":  platformv1.TenantState_TENANT_STATE_DELETING,
	"deleted":   platformv1.TenantState_TENANT_STATE_DELETED,
}

// tenantStateFromName reads a rendered tenant state. The tools fall back to
// the enum name for a state the tenant package does not define, so that is
// accepted too.
func tenantStateFromName(name string) (platformv1.TenantState, error) {
	if state, ok := tenantStatesByName[name]; ok {
		return state, nil
	}
	if value, ok := platformv1.TenantState_value[name]; ok {
		return platformv1.TenantState(value), nil
	}
	return platformv1.TenantState_TENANT_STATE_UNSPECIFIED, ErrUnknownTenantState{State: name}
}

// buildTenantCreateArgs builds the tenant_create arguments: the quotas the
// caller set travel as flat max_* arguments.
func buildTenantCreateArgs(req *platformv1.CreateTenantRequest) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"name":         req.GetName(),
		"display_name": req.GetDisplayName(),
		"labels":       req.GetLabels(),
		"annotations":  req.GetAnnotations(),
	}
	addQuotaArgs(out, req.GetComputeQuota(), req.GetNetworkQuota(), req.GetStorageQuota())
	return out, nil
}

// buildTenantUpdateQuotasArgs builds the tenant_update_quotas arguments. The
// tool keeps the current limit for any max_* argument that is absent or zero.
func buildTenantUpdateQuotasArgs(req *platformv1.UpdateQuotasRequest) (map[string]interface{}, error) {
	out := map[string]interface{}{"tenant_id": req.GetTenantId()}
	addQuotaArgs(out, req.GetCompute(), req.GetNetwork(), req.GetStorage())
	return out, nil
}

// buildTenantCheckQuotaArgs builds the tenant_check_quota arguments, which
// name the resource "resource_type".
func buildTenantCheckQuotaArgs(req *platformv1.CheckQuotaRequest) (map[string]interface{}, error) {
	return map[string]interface{}{
		"tenant_id":     req.GetTenantId(),
		"resource_type": req.GetResource(),
		"amount":        req.GetAmount(),
	}, nil
}

// addQuotaArgs adds the max_* arguments of every quota that is set.
func addQuotaArgs(out map[string]interface{},
	compute *platformv1.ComputeQuota, network *platformv1.NetworkQuota, storage *platformv1.StorageQuota) {

	if compute != nil {
		maps.Copy(out, map[string]interface{}{
			"max_vms":        compute.GetMaxVms(),
			"max_containers": compute.GetMaxContainers(),
			"max_vcpus":      compute.GetMaxVcpus(),
			"max_memory_mb":  compute.GetMaxMemoryMb(),
		})
	}
	if network != nil {
		maps.Copy(out, map[string]interface{}{
			"max_bridges":        network.GetMaxBridges(),
			"max_ports":          network.GetMaxPorts(),
			"max_bandwidth_mbps": network.GetMaxBandwidthMbps(),
		})
	}
	if storage != nil {
		maps.Copy(out, map[string]interface{}{
			"max_volumes_gb": storage.GetMaxVolumesGb(),
			"max_snapshots":  storage.GetMaxSnapshots(),
		})
	}
}

// unmarshalTenantResult decodes a tenant tool result into its wire shape.
func unmarshalTenantResult(data []byte, wire interface{}) error {
	if err := json.Unmarshal(data, wire); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	return nil
}

// tenantWire is a tenant as the tools render it.
type tenantWire struct {
	ID           string                   `json:"id"`
	Name         string                   `json:"name"`
	DisplayName  string                   `json:"display_name"`
	State        string                   `json:"state"`
	DekPath      string                   `json:"dek_path"`
	ComputeQuota *platformv1.ComputeQuota `json:"compute_quota"`
	NetworkQuota *platformv1.NetworkQuota `json:"network_quota"`
	StorageQuota *platformv1.StorageQuota `json:"storage_quota"`
	Labels       map[string]string        `json:"labels"`
	Annotations  map[string]string        `json:"annotations"`
	CreatedAt    optionalTime             `json:"created_at"`
	UpdatedAt    optionalTime             `json:"updated_at"`
}

// toPb maps a rendered tenant onto the pb message; nil stays nil.
func (w *tenantWire) toPb() (*platformv1.Tenant, error) {
	if w == nil {
		return nil, nil
	}
	state, err := tenantStateFromName(w.State)
	if err != nil {
		return nil, err
	}
	return &platformv1.Tenant{
		Id:           w.ID,
		Name:         w.Name,
		DisplayName:  w.DisplayName,
		State:        state,
		DekPath:      w.DekPath,
		ComputeQuota: w.ComputeQuota,
		NetworkQuota: w.NetworkQuota,
		StorageQuota: w.StorageQuota,
		Labels:       w.Labels,
		Annotations:  w.Annotations,
		CreatedAt:    timestampOrNil(w.CreatedAt.Time),
		UpdatedAt:    timestampOrNil(w.UpdatedAt.Time),
	}, nil
}

// tenantStatusWire is the {"success", "message"} pair the status-only tools
// return, which tenant_create and tenant_update carry beside the tenant.
type tenantStatusWire struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Tenant  *tenantWire `json:"tenant"`
}

func (w tenantStatusWire) status() *platformv1.Status {
	return &platformv1.Status{Success: w.Success, Message: w.Message}
}

// decodeTenantStatusResult decodes a status-only tool result. Each such reply
// carries just the pb Status, under "status".
func decodeTenantStatusResult(result interface{}, reply interface{}) error {
	var wire tenantStatusWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	return mapToStruct(map[string]interface{}{"status": wire.status()}, reply)
}

// decodeTenantJSON decodes a bare rendered tenant.
func decodeTenantJSON(data []byte) (*platformv1.Tenant, error) {
	var wire tenantWire
	if err := unmarshalTenantResult(data, &wire); err != nil {
		return nil, err
	}
	return wire.toPb()
}

func decodeTenantGetJSON(data []byte) (*platformv1.GetTenantResponse, error) {
	t, err := decodeTenantJSON(data)
	if err != nil {
		return nil, err
	}
	return &platformv1.GetTenantResponse{Tenant: t}, nil
}

func decodeTenantGetByNameJSON(data []byte) (*platformv1.GetTenantByNameResponse, error) {
	t, err := decodeTenantJSON(data)
	if err != nil {
		return nil, err
	}
	return &platformv1.GetTenantByNameResponse{Tenant: t}, nil
}

// decodeTenantWithStatusJSON decodes the tenant_create and tenant_update
// result.
func decodeTenantWithStatusJSON(data []byte) (*platformv1.Status, *platformv1.Tenant, error) {
	var wire tenantStatusWire
	if err := unmarshalTenantResult(data, &wire); err != nil {
		return nil, nil, err
	}
	t, err := wire.Tenant.toPb()
	if err != nil {
		return nil, nil, err
	}
	return wire.status(), t, nil
}

func decodeTenantCreateJSON(data []byte) (*platformv1.CreateTenantResponse, error) {
	st, t, err := decodeTenantWithStatusJSON(data)
	if err != nil {
		return nil, err
	}
	return &platformv1.CreateTenantResponse{Status: st, Tenant: t}, nil
}

func decodeTenantUpdateJSON(data []byte) (*platformv1.UpdateTenantResponse, error) {
	st, t, err := decodeTenantWithStatusJSON(data)
	if err != nil {
		return nil, err
	}
	return &platformv1.UpdateTenantResponse{Status: st, Tenant: t}, nil
}

// decodeTenantListJSON decodes the tenant_list result
// ({"tenants": [...], "count", "total"}).
func decodeTenantListJSON(data []byte) (*platformv1.ListTenantsResponse, error) {
	var wire struct {
		Tenants []*tenantWire `json:"tenants"`
		Total   int32         `json:"total"`
	}
	if err := unmarshalTenantResult(data, &wire); err != nil {
		return nil, err
	}
	tenants := make([]*platformv1.Tenant, 0, len(wire.Tenants))
	for _, w := range wire.Tenants {
		t, err := w.toPb()
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, t)
	}
	return &platformv1.ListTenantsResponse{Tenants: tenants, Total: wire.Total}, nil
}

// decodeTenantUsageJSON decodes the tenant_get_usage result, which carries
// the tenant and the moment beside the counters rather than inside them.
func decodeTenantUsageJSON(data []byte) (*platformv1.GetUsageResponse, error) {
	var wire struct {
		TenantID  string                  `json:"tenant_id"`
		Usage     *platformv1.TenantUsage `json:"usage"`
		Timestamp optionalTime            `json:"timestamp"`
	}
	if err := unmarshalTenantResult(data, &wire); err != nil {
		return nil, err
	}
	usage := wire.Usage
	if usage == nil {
		usage = &platformv1.TenantUsage{}
	}
	usage.TenantId = wire.TenantID
	usage.Timestamp = timestampOrNil(wire.Timestamp.Time)
	return &platformv1.GetUsageResponse{Usage: usage}, nil
}

// decodeTenantCheckQuotaJSON decodes the tenant_check_quota result, which
// names the resource "resource_type".
func decodeTenantCheckQuotaJSON(data []byte) (*platformv1.CheckQuotaResponse, error) {
	var wire struct {
		TenantID     string `json:"tenant_id"`
		ResourceType string `json:"resource_type"`
		Amount       int64  `json:"amount"`
		Available    bool   `json:"available"`
		Message      string `json:"message"`
	}
	if err := unmarshalTenantResult(data, &wire); err != nil {
		return nil, err
	}
	return &platformv1.CheckQuotaResponse{
		TenantId:  wire.TenantID,
		Resource:  wire.ResourceType,
		Amount:    wire.Amount,
		Available: wire.Available,
		Message:   wire.Message,
	}, nil
}

func decodeTenantRotateDEKJSON(data []byte) (*platformv1.RotateTenantDEKResponse, error) {
	var wire struct {
		TenantID   string       `json:"tenant_id"`
		OldVersion uint32       `json:"old_version"`
		NewVersion uint32       `json:"new_version"`
		Timestamp  optionalTime `json:"timestamp"`
	}
	if err := unmarshalTenantResult(data, &wire); err != nil {
		return nil, err
	}
	return &platformv1.RotateTenantDEKResponse{
		TenantId:   wire.TenantID,
		OldVersion: wire.OldVersion,
		NewVersion: wire.NewVersion,
		Timestamp:  timestampOrNil(wire.Timestamp.Time),
	}, nil
}

// tenantDEKStatusWire is the flat tenant_get_dek_status result.
type tenantDEKStatusWire struct {
	TenantID          string                  `json:"tenant_id"`
	Path              string                  `json:"path"`
	Version           uint64                  `json:"version"`
	Algorithm         string                  `json:"algorithm"`
	Status            string                  `json:"status"`
	IsDefault         bool                    `json:"is_default"`
	CreatedAt         optionalTime            `json:"created_at"`
	RotatedAt         optionalTime            `json:"rotated_at"`
	UsageCount        uint64                  `json:"usage_count"`
	BytesUsed         uint64                  `json:"bytes_used"`
	MaxUsageCount     uint64                  `json:"max_usage_count"`
	MaxBytesUsed      uint64                  `json:"max_bytes_used"`
	WarningPercent    int32                   `json:"warning_percent"`
	UsagePercent      float64                 `json:"usage_percent"`
	NeedsRotation     bool                    `json:"needs_rotation"`
	ReencryptProgress *tenantReencryptionWire `json:"reencrypt_progress"`
}

// tenantReencryptionWire is the re-encryption progress inside a DEK status.
type tenantReencryptionWire struct {
	InProgress          bool         `json:"in_progress"`
	TotalKeys           int32        `json:"total_keys"`
	ProcessedKeys       int32        `json:"processed_keys"`
	FailedKeys          int32        `json:"failed_keys"`
	StartedAt           optionalTime `json:"started_at"`
	EstimatedCompletion optionalTime `json:"estimated_completion"`
}

// toPb maps the re-encryption progress onto the pb message; nil stays nil.
func (w *tenantReencryptionWire) toPb() *platformv1.DEKReencryptionProgress {
	if w == nil {
		return nil
	}
	return &platformv1.DEKReencryptionProgress{
		InProgress:          w.InProgress,
		TotalKeys:           w.TotalKeys,
		ProcessedKeys:       w.ProcessedKeys,
		FailedKeys:          w.FailedKeys,
		StartedAt:           timestampOrNil(w.StartedAt.Time),
		EstimatedCompletion: timestampOrNil(w.EstimatedCompletion.Time),
	}
}

func decodeTenantDEKStatusJSON(data []byte) (*platformv1.GetTenantDEKStatusResponse, error) {
	var wire tenantDEKStatusWire
	if err := unmarshalTenantResult(data, &wire); err != nil {
		return nil, err
	}
	return &platformv1.GetTenantDEKStatusResponse{DekStatus: &platformv1.TenantDEKStatus{
		TenantId:          wire.TenantID,
		Path:              wire.Path,
		Version:           wire.Version,
		Algorithm:         wire.Algorithm,
		Status:            wire.Status,
		IsDefault:         wire.IsDefault,
		CreatedAt:         timestampOrNil(wire.CreatedAt.Time),
		RotatedAt:         timestampOrNil(wire.RotatedAt.Time),
		UsageCount:        wire.UsageCount,
		BytesUsed:         wire.BytesUsed,
		MaxUsageCount:     wire.MaxUsageCount,
		MaxBytesUsed:      wire.MaxBytesUsed,
		WarningPercent:    wire.WarningPercent,
		UsagePercent:      wire.UsagePercent,
		NeedsRotation:     wire.NeedsRotation,
		ReencryptProgress: wire.ReencryptProgress.toPb(),
	}}, nil
}

// decodeTenantBarrierStatusJSON decodes the flat
// platform_tenant_barrier_status result, whose fields carry the pb names.
func decodeTenantBarrierStatusJSON(data []byte) (*platformv1.GetTenantBarrierStatusResponse, error) {
	barrier := &platformv1.TenantBarrierStatus{}
	if err := unmarshalTenantResult(data, barrier); err != nil {
		return nil, err
	}
	return &platformv1.GetTenantBarrierStatusResponse{BarrierStatus: barrier}, nil
}
