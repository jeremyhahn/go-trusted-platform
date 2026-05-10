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
// This file implements the TenantCommands interface using gRPC protocol.
package tenant

import (
	"context"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrGRPCConnectionFailed indicates a gRPC connection failure
type ErrGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCCallFailed indicates a gRPC method call failure
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements TenantCommands using native gRPC API
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   platformv1.TenantServiceClient
}

// NewGRPCAdapter creates a new gRPC adapter
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{
		endpoint: GetGRPCEndpoint(),
	}
}

// Setup prepares the adapter for testing
func (a *GRPCAdapter) Setup(ctx context.Context) error {
	tlsConfig := helpers.TLSConfigOrInsecure()

	// Create a short timeout context for the dial attempt (5 seconds)
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Use WithBlock to fail fast if server is not reachable
	conn, err := grpc.DialContext(dialCtx, a.endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{
			Endpoint: a.endpoint,
			Err:      err,
		}
	}

	a.conn = conn
	a.client = platformv1.NewTenantServiceClient(conn)

	return nil
}

// Teardown cleans up after testing
func (a *GRPCAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name
func (a *GRPCAdapter) Name() string {
	return "gRPC"
}

// =============================================================================
// Tenant CRUD Operations
// =============================================================================

// CreateTenant creates a new tenant
func (a *GRPCAdapter) CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error) {
	req := &platformv1.CreateTenantRequest{
		Name:        opts.Name,
		DisplayName: opts.DisplayName,
		Labels:      opts.Labels,
		Annotations: opts.Annotations,
	}

	if opts.VLANRange != nil {
		req.VlanRangeStart = uint32(opts.VLANRange.Start)
		req.VlanRangeEnd = uint32(opts.VLANRange.End)
	}

	resp, err := a.client.CreateTenant(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateTenant", Err: err}
	}

	return &CreateTenantResult{
		Tenant: a.pbToTenantData(resp.GetTenant()),
	}, nil
}

// GetTenant retrieves a tenant by ID
func (a *GRPCAdapter) GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error) {
	req := &platformv1.GetTenantRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.GetTenant(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetTenant", Err: err}
	}

	return &GetTenantResult{
		Tenant: a.pbToTenantData(resp.GetTenant()),
	}, nil
}

// GetTenantByName retrieves a tenant by name
func (a *GRPCAdapter) GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error) {
	req := &platformv1.GetTenantByNameRequest{
		Name: opts.Name,
	}

	resp, err := a.client.GetTenantByName(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetTenantByName", Err: err}
	}

	return &GetTenantByNameResult{
		Tenant: a.pbToTenantData(resp.GetTenant()),
	}, nil
}

// UpdateTenant updates an existing tenant
func (a *GRPCAdapter) UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error) {
	req := &platformv1.UpdateTenantRequest{
		TenantId:    opts.TenantID,
		Labels:      opts.Labels,
		Annotations: opts.Annotations,
	}

	if opts.DisplayName != nil {
		req.DisplayName = *opts.DisplayName
	}

	resp, err := a.client.UpdateTenant(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateTenant", Err: err}
	}

	return &UpdateTenantResult{
		Tenant: a.pbToTenantData(resp.GetTenant()),
	}, nil
}

// DeleteTenant removes a tenant
func (a *GRPCAdapter) DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error) {
	req := &platformv1.DeleteTenantRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.DeleteTenant(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteTenant", Err: err}
	}

	return &DeleteTenantResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// ListTenants lists all tenants with optional pagination
func (a *GRPCAdapter) ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error) {
	req := &platformv1.ListTenantsRequest{
		Limit:  int32(opts.Limit),
		Offset: int32(opts.Offset),
	}

	resp, err := a.client.ListTenants(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListTenants", Err: err}
	}

	tenants := make([]*TenantData, 0, len(resp.GetTenants()))
	for _, t := range resp.GetTenants() {
		tenants = append(tenants, a.pbToTenantData(t))
	}

	return &ListTenantsResult{
		Tenants: tenants,
		Total:   int(resp.GetTotal()),
	}, nil
}

// =============================================================================
// Tenant Lifecycle Operations
// =============================================================================

// SuspendTenant suspends a tenant
func (a *GRPCAdapter) SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error) {
	req := &platformv1.SuspendTenantRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.SuspendTenant(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "SuspendTenant", Err: err}
	}

	return &SuspendTenantResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// ResumeTenant resumes a suspended tenant
func (a *GRPCAdapter) ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error) {
	req := &platformv1.ResumeTenantRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.ResumeTenant(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ResumeTenant", Err: err}
	}

	return &ResumeTenantResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// =============================================================================
// Quota Operations
// =============================================================================

// GetQuotas retrieves tenant quotas
func (a *GRPCAdapter) GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error) {
	req := &platformv1.GetQuotasRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.GetQuotas(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetQuotas", Err: err}
	}

	return &GetQuotasResult{
		TenantID: resp.GetTenantId(),
		Compute:  a.pbToComputeQuotaData(resp.GetCompute()),
		Network:  a.pbToNetworkQuotaData(resp.GetNetwork()),
		Storage:  a.pbToStorageQuotaData(resp.GetStorage()),
	}, nil
}

// UpdateQuotas updates tenant quotas
func (a *GRPCAdapter) UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error) {
	req := &platformv1.UpdateQuotasRequest{
		TenantId: opts.TenantID,
	}

	if opts.Compute != nil {
		req.Compute = &platformv1.ComputeQuota{
			MaxVms:        opts.Compute.MaxVMs,
			MaxContainers: opts.Compute.MaxContainers,
			MaxVcpus:      opts.Compute.MaxVCPUs,
			MaxMemoryMb:   opts.Compute.MaxMemoryMB,
		}
	}

	if opts.Network != nil {
		req.Network = &platformv1.NetworkQuota{
			MaxBridges:       opts.Network.MaxBridges,
			MaxPorts:         opts.Network.MaxPorts,
			MaxBandwidthMbps: opts.Network.MaxBandwidthMbps,
		}
	}

	if opts.Storage != nil {
		req.Storage = &platformv1.StorageQuota{
			MaxVolumesGb: opts.Storage.MaxVolumesGB,
			MaxSnapshots: opts.Storage.MaxSnapshots,
		}
	}

	_, err := a.client.UpdateQuotas(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateQuotas", Err: err}
	}

	// Fetch updated quotas
	quotasResp, err := a.client.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetQuotas after UpdateQuotas", Err: err}
	}

	return &UpdateQuotasResult{
		TenantID: quotasResp.GetTenantId(),
		Compute:  a.pbToComputeQuotaData(quotasResp.GetCompute()),
		Network:  a.pbToNetworkQuotaData(quotasResp.GetNetwork()),
		Storage:  a.pbToStorageQuotaData(quotasResp.GetStorage()),
	}, nil
}

// GetUsage retrieves tenant resource usage
func (a *GRPCAdapter) GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error) {
	req := &platformv1.GetUsageRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.GetUsage(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetUsage", Err: err}
	}

	usage := resp.GetUsage()
	return &GetUsageResult{
		TenantID:      usage.GetTenantId(),
		VMs:           usage.GetVms(),
		Containers:    usage.GetContainers(),
		VCPUs:         usage.GetVcpus(),
		MemoryMB:      usage.GetMemoryMb(),
		DiskGB:        usage.GetDiskGb(),
		Bridges:       usage.GetBridges(),
		Ports:         usage.GetPorts(),
		BandwidthMbps: usage.GetBandwidthMbps(),
		Volumes:       usage.GetVolumes(),
		Snapshots:     usage.GetSnapshots(),
	}, nil
}

// CheckQuota checks if a resource request can be fulfilled
func (a *GRPCAdapter) CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error) {
	req := &platformv1.CheckQuotaRequest{
		TenantId: opts.TenantID,
		Resource: opts.Resource,
		Amount:   opts.Amount,
	}

	resp, err := a.client.CheckQuota(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CheckQuota", Err: err}
	}

	return &CheckQuotaResult{
		TenantID: resp.GetTenantId(),
		Resource: resp.GetResource(),
		Amount:   resp.GetAmount(),
		Allowed:  resp.GetAvailable(),
		Message:  resp.GetMessage(),
	}, nil
}

// =============================================================================
// Network Operations
// =============================================================================

// ValidateVLAN validates a VLAN ID for a tenant
func (a *GRPCAdapter) ValidateVLAN(ctx context.Context, opts ValidateVLANOptions) (*ValidateVLANResult, error) {
	req := &platformv1.ValidateVLANRequest{
		TenantId: opts.TenantID,
		VlanId:   uint32(opts.VLANID),
	}

	resp, err := a.client.ValidateVLAN(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ValidateVLAN", Err: err}
	}

	return &ValidateVLANResult{
		TenantID: resp.GetTenantId(),
		VLANID:   uint16(resp.GetVlanId()),
		Valid:    resp.GetValid(),
		Message:  resp.GetMessage(),
	}, nil
}

// GetBridgeName retrieves the OVS bridge name for a tenant
func (a *GRPCAdapter) GetBridgeName(ctx context.Context, opts GetBridgeNameOptions) (*GetBridgeNameResult, error) {
	req := &platformv1.GetBridgeNameRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.GetBridgeName(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetBridgeName", Err: err}
	}

	return &GetBridgeNameResult{
		TenantID:   resp.GetTenantId(),
		BridgeName: resp.GetBridgeName(),
	}, nil
}

// =============================================================================
// Sync Operations
// =============================================================================

// SyncTenants synchronizes tenant manager state
func (a *GRPCAdapter) SyncTenants(ctx context.Context) (*SyncTenantsResult, error) {
	req := &platformv1.SyncTenantsRequest{}

	resp, err := a.client.Sync(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "Sync", Err: err}
	}

	return &SyncTenantsResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// =============================================================================
// Helper Methods - Protobuf to Data Conversion
// =============================================================================

// pbToTenantData converts protobuf Tenant to TenantData
func (a *GRPCAdapter) pbToTenantData(pb *platformv1.Tenant) *TenantData {
	if pb == nil {
		return nil
	}

	data := &TenantData{
		ID:          pb.GetId(),
		Name:        pb.GetName(),
		DisplayName: pb.GetDisplayName(),
		State:       a.pbToTenantState(pb.GetState()),
		OVSBridge:   pb.GetOvsBridge(),
		Labels:      pb.GetLabels(),
		Annotations: pb.GetAnnotations(),
	}

	if pb.GetVlanStart() > 0 || pb.GetVlanEnd() > 0 {
		data.VLANRange = &VLANRangeData{
			Start: uint16(pb.GetVlanStart()),
			End:   uint16(pb.GetVlanEnd()),
		}
	}

	if pb.GetComputeQuota() != nil {
		data.ComputeQuota = a.pbToComputeQuotaData(pb.GetComputeQuota())
	}

	if pb.GetNetworkQuota() != nil {
		data.NetworkQuota = a.pbToNetworkQuotaData(pb.GetNetworkQuota())
	}

	if pb.GetStorageQuota() != nil {
		data.StorageQuota = a.pbToStorageQuotaData(pb.GetStorageQuota())
	}

	if pb.GetCreatedAt() != nil {
		data.CreatedAt = pb.GetCreatedAt().AsTime()
	}

	if pb.GetUpdatedAt() != nil {
		data.UpdatedAt = pb.GetUpdatedAt().AsTime()
	}

	return data
}

// pbToTenantState converts protobuf TenantState to tenant.State
func (a *GRPCAdapter) pbToTenantState(state platformv1.TenantState) tenant.State {
	switch state {
	case platformv1.TenantState_TENANT_STATE_PENDING:
		return tenant.StateCreated
	case platformv1.TenantState_TENANT_STATE_ACTIVE:
		return tenant.StateActive
	case platformv1.TenantState_TENANT_STATE_SUSPENDED:
		return tenant.StateSuspended
	case platformv1.TenantState_TENANT_STATE_DELETING:
		return tenant.StateDeleting
	case platformv1.TenantState_TENANT_STATE_DELETED:
		return tenant.StateDeleted
	default:
		return tenant.StateCreated
	}
}

// pbToComputeQuotaData converts protobuf ComputeQuota to ComputeQuotaData
func (a *GRPCAdapter) pbToComputeQuotaData(pb *platformv1.ComputeQuota) *ComputeQuotaData {
	if pb == nil {
		return nil
	}
	return &ComputeQuotaData{
		MaxVMs:        pb.GetMaxVms(),
		MaxContainers: pb.GetMaxContainers(),
		MaxVCPUs:      pb.GetMaxVcpus(),
		MaxMemoryMB:   pb.GetMaxMemoryMb(),
	}
}

// pbToNetworkQuotaData converts protobuf NetworkQuota to NetworkQuotaData
func (a *GRPCAdapter) pbToNetworkQuotaData(pb *platformv1.NetworkQuota) *NetworkQuotaData {
	if pb == nil {
		return nil
	}
	return &NetworkQuotaData{
		MaxBridges:       pb.GetMaxBridges(),
		MaxPorts:         pb.GetMaxPorts(),
		MaxBandwidthMbps: pb.GetMaxBandwidthMbps(),
	}
}

// pbToStorageQuotaData converts protobuf StorageQuota to StorageQuotaData
func (a *GRPCAdapter) pbToStorageQuotaData(pb *platformv1.StorageQuota) *StorageQuotaData {
	if pb == nil {
		return nil
	}
	return &StorageQuotaData{
		MaxVolumesGB: pb.GetMaxVolumesGb(),
		MaxSnapshots: pb.GetMaxSnapshots(),
	}
}

// =============================================================================
// Per-Tenant Barrier Operations (added 2026-04-28)
// =============================================================================

// InitTenantBarrier explicitly initializes a per-tenant barrier.
func (a *GRPCAdapter) InitTenantBarrier(ctx context.Context, opts InitTenantBarrierOptions) (*InitTenantBarrierResult, error) {
	resp, err := a.client.InitTenantBarrier(ctx, &platformv1.InitTenantBarrierRequest{
		TenantId:  opts.TenantID,
		Threshold: opts.Threshold,
		Shares:    opts.Shares,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "InitTenantBarrier", Err: err}
	}
	return &InitTenantBarrierResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// UnsealTenantBarrier unseals a per-tenant barrier.
func (a *GRPCAdapter) UnsealTenantBarrier(ctx context.Context, opts UnsealTenantBarrierOptions) (*UnsealTenantBarrierResult, error) {
	resp, err := a.client.UnsealTenantBarrier(ctx, &platformv1.UnsealTenantBarrierRequest{
		TenantId: opts.TenantID,
		Key:      opts.Key,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UnsealTenantBarrier", Err: err}
	}
	return &UnsealTenantBarrierResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// SealTenantBarrier seals a per-tenant barrier.
func (a *GRPCAdapter) SealTenantBarrier(ctx context.Context, opts SealTenantBarrierOptions) (*SealTenantBarrierResult, error) {
	resp, err := a.client.SealTenantBarrier(ctx, &platformv1.SealTenantBarrierRequest{
		TenantId: opts.TenantID,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "SealTenantBarrier", Err: err}
	}
	return &SealTenantBarrierResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// TenantBarrierStatus reports per-tenant barrier state.
func (a *GRPCAdapter) TenantBarrierStatus(ctx context.Context, opts TenantBarrierStatusOptions) (*TenantBarrierStatusResult, error) {
	resp, err := a.client.GetTenantBarrierStatus(ctx, &platformv1.GetTenantBarrierStatusRequest{
		TenantId: opts.TenantID,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetTenantBarrierStatus", Err: err}
	}
	st := resp.GetBarrierStatus()
	return &TenantBarrierStatusResult{
		TenantID:       st.GetTenantId(),
		Sealed:         st.GetSealed(),
		Initialized:    st.GetInitialized(),
		Strategy:       st.GetStrategy(),
		HardwareBacked: st.GetHardwareBacked(),
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify GRPCAdapter implements TenantCommands
var _ TenantCommands = (*GRPCAdapter)(nil)
