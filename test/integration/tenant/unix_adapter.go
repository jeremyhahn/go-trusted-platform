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
// This file implements the TenantCommands interface using gRPC over Unix domain socket.
package tenant

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// unixDialTimeout is the timeout for establishing Unix socket connection.
	unixDialTimeout = 10 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixConnectionFailed indicates a Unix socket connection failure.
type ErrUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixConnectionFailed) Error() string {
	return fmt.Sprintf("unix connection failed to %s: %v", e.Path, e.Err)
}

func (e ErrUnixConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixRPCFailed indicates a gRPC call over Unix socket failed.
type ErrUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixRPCFailed) Error() string {
	return fmt.Sprintf("unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error {
	return e.Err
}

// ErrUnixBackendUnavailable indicates the backend is not reachable over Unix socket.
type ErrUnixBackendUnavailable struct {
	Err error
}

func (e ErrUnixBackendUnavailable) Error() string {
	return fmt.Sprintf("unix backend unavailable: %v", e.Err)
}

func (e ErrUnixBackendUnavailable) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Protocol Adapter
// =============================================================================

// UnixAdapter implements TenantCommands using gRPC over Unix domain socket.
// Unix domain sockets use insecure transport credentials because TLS is not
// needed for local IPC -- the kernel enforces access control via file permissions.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     platformv1.TenantServiceClient
}

// NewUnixAdapter creates a new Unix socket adapter.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{
		socketPath: GetSocketPath(),
	}
}

// Setup initializes the gRPC connection over Unix socket.
func (a *UnixAdapter) Setup(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, unixDialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, "unix://"+a.socketPath,
		helpers.GRPCUnixCredentials(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			socketAddr := strings.TrimPrefix(addr, "unix://")
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketAddr)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		return ErrUnixConnectionFailed{
			Path: a.socketPath,
			Err:  err,
		}
	}

	a.conn = conn
	a.client = platformv1.NewTenantServiceClient(conn)

	return nil
}

// Teardown closes the gRPC connection.
func (a *UnixAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name.
func (a *UnixAdapter) Name() string {
	return "Unix"
}

// =============================================================================
// Tenant CRUD Operations
// =============================================================================

// CreateTenant creates a new tenant via gRPC over Unix socket.
func (a *UnixAdapter) CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error) {
	req := &platformv1.CreateTenantRequest{
		Name:        opts.Name,
		DisplayName: opts.DisplayName,
		Labels:      opts.Labels,
		Annotations: opts.Annotations,
	}

	resp, err := a.client.CreateTenant(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateTenant", Err: err}
	}

	return &CreateTenantResult{
		Tenant: a.pbToTenantData(resp.GetTenant()),
	}, nil
}

// GetTenant retrieves a tenant by ID via gRPC over Unix socket.
func (a *UnixAdapter) GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error) {
	req := &platformv1.GetTenantRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.GetTenant(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetTenant", Err: err}
	}

	return &GetTenantResult{
		Tenant: a.pbToTenantData(resp.GetTenant()),
	}, nil
}

// GetTenantByName retrieves a tenant by name via gRPC over Unix socket.
func (a *UnixAdapter) GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error) {
	req := &platformv1.GetTenantByNameRequest{
		Name: opts.Name,
	}

	resp, err := a.client.GetTenantByName(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetTenantByName", Err: err}
	}

	return &GetTenantByNameResult{
		Tenant: a.pbToTenantData(resp.GetTenant()),
	}, nil
}

// UpdateTenant updates an existing tenant via gRPC over Unix socket.
func (a *UnixAdapter) UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error) {
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
		return nil, ErrUnixRPCFailed{Method: "UpdateTenant", Err: err}
	}

	return &UpdateTenantResult{
		Tenant: a.pbToTenantData(resp.GetTenant()),
	}, nil
}

// DeleteTenant removes a tenant via gRPC over Unix socket.
func (a *UnixAdapter) DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error) {
	req := &platformv1.DeleteTenantRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.DeleteTenant(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteTenant", Err: err}
	}

	return &DeleteTenantResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// ListTenants lists all tenants with optional pagination via gRPC over Unix socket.
func (a *UnixAdapter) ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error) {
	req := &platformv1.ListTenantsRequest{
		Limit:  int32(opts.Limit),
		Offset: int32(opts.Offset),
	}

	resp, err := a.client.ListTenants(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListTenants", Err: err}
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

// SuspendTenant suspends a tenant via gRPC over Unix socket.
func (a *UnixAdapter) SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error) {
	req := &platformv1.SuspendTenantRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.SuspendTenant(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "SuspendTenant", Err: err}
	}

	return &SuspendTenantResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// ResumeTenant resumes a suspended tenant via gRPC over Unix socket.
func (a *UnixAdapter) ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error) {
	req := &platformv1.ResumeTenantRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.ResumeTenant(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ResumeTenant", Err: err}
	}

	return &ResumeTenantResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// =============================================================================
// Quota Operations
// =============================================================================

// GetQuotas retrieves tenant quotas via gRPC over Unix socket.
func (a *UnixAdapter) GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error) {
	req := &platformv1.GetQuotasRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.GetQuotas(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetQuotas", Err: err}
	}

	return &GetQuotasResult{
		TenantID: resp.GetTenantId(),
		Compute:  a.pbToComputeQuotaData(resp.GetCompute()),
		Network:  a.pbToNetworkQuotaData(resp.GetNetwork()),
		Storage:  a.pbToStorageQuotaData(resp.GetStorage()),
	}, nil
}

// UpdateQuotas updates tenant quotas via gRPC over Unix socket.
func (a *UnixAdapter) UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error) {
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
		return nil, ErrUnixRPCFailed{Method: "UpdateQuotas", Err: err}
	}

	// Fetch updated quotas
	quotasResp, err := a.client.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: opts.TenantID})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetQuotas after UpdateQuotas", Err: err}
	}

	return &UpdateQuotasResult{
		TenantID: quotasResp.GetTenantId(),
		Compute:  a.pbToComputeQuotaData(quotasResp.GetCompute()),
		Network:  a.pbToNetworkQuotaData(quotasResp.GetNetwork()),
		Storage:  a.pbToStorageQuotaData(quotasResp.GetStorage()),
	}, nil
}

// GetUsage retrieves tenant resource usage via gRPC over Unix socket.
func (a *UnixAdapter) GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error) {
	req := &platformv1.GetUsageRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.GetUsage(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetUsage", Err: err}
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

// CheckQuota checks if a resource request can be fulfilled via gRPC over Unix socket.
func (a *UnixAdapter) CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error) {
	req := &platformv1.CheckQuotaRequest{
		TenantId: opts.TenantID,
		Resource: opts.Resource,
		Amount:   opts.Amount,
	}

	resp, err := a.client.CheckQuota(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CheckQuota", Err: err}
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

// SyncTenants synchronizes tenant manager state via gRPC over Unix socket.
func (a *UnixAdapter) SyncTenants(ctx context.Context) (*SyncTenantsResult, error) {
	req := &platformv1.SyncTenantsRequest{}

	resp, err := a.client.Sync(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "Sync", Err: err}
	}

	return &SyncTenantsResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// =============================================================================
// Helper Methods - Protobuf to Data Conversion
// =============================================================================

// pbToTenantData converts protobuf Tenant to TenantData.
func (a *UnixAdapter) pbToTenantData(pb *platformv1.Tenant) *TenantData {
	if pb == nil {
		return nil
	}

	data := &TenantData{
		ID:          pb.GetId(),
		Name:        pb.GetName(),
		DisplayName: pb.GetDisplayName(),
		State:       a.pbToTenantState(pb.GetState()),
		Labels:      pb.GetLabels(),
		Annotations: pb.GetAnnotations(),
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

// pbToTenantState converts protobuf TenantState to tenant.State.
func (a *UnixAdapter) pbToTenantState(state platformv1.TenantState) tenant.State {
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

// pbToComputeQuotaData converts protobuf ComputeQuota to ComputeQuotaData.
func (a *UnixAdapter) pbToComputeQuotaData(pb *platformv1.ComputeQuota) *ComputeQuotaData {
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

// pbToNetworkQuotaData converts protobuf NetworkQuota to NetworkQuotaData.
func (a *UnixAdapter) pbToNetworkQuotaData(pb *platformv1.NetworkQuota) *NetworkQuotaData {
	if pb == nil {
		return nil
	}
	return &NetworkQuotaData{
		MaxBridges:       pb.GetMaxBridges(),
		MaxPorts:         pb.GetMaxPorts(),
		MaxBandwidthMbps: pb.GetMaxBandwidthMbps(),
	}
}

// pbToStorageQuotaData converts protobuf StorageQuota to StorageQuotaData.
func (a *UnixAdapter) pbToStorageQuotaData(pb *platformv1.StorageQuota) *StorageQuotaData {
	if pb == nil {
		return nil
	}
	return &StorageQuotaData{
		MaxVolumesGB: pb.GetMaxVolumesGb(),
		MaxSnapshots: pb.GetMaxSnapshots(),
	}
}

// =============================================================================
// Per-Tenant Barrier Operations
// =============================================================================

// InitTenantBarrier explicitly initializes a per-tenant barrier via gRPC over Unix socket.
func (a *UnixAdapter) InitTenantBarrier(ctx context.Context, opts InitTenantBarrierOptions) (*InitTenantBarrierResult, error) {
	req := &platformv1.InitTenantBarrierRequest{
		TenantId:  opts.TenantID,
		Threshold: opts.Threshold,
		Shares:    opts.Shares,
	}

	resp, err := a.client.InitTenantBarrier(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "InitTenantBarrier", Err: err}
	}

	return &InitTenantBarrierResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// UnsealTenantBarrier unseals a per-tenant barrier via gRPC over Unix socket.
func (a *UnixAdapter) UnsealTenantBarrier(ctx context.Context, opts UnsealTenantBarrierOptions) (*UnsealTenantBarrierResult, error) {
	req := &platformv1.UnsealTenantBarrierRequest{
		TenantId: opts.TenantID,
		Key:      opts.Key,
	}

	resp, err := a.client.UnsealTenantBarrier(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UnsealTenantBarrier", Err: err}
	}

	return &UnsealTenantBarrierResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// SealTenantBarrier seals a per-tenant barrier via gRPC over Unix socket.
func (a *UnixAdapter) SealTenantBarrier(ctx context.Context, opts SealTenantBarrierOptions) (*SealTenantBarrierResult, error) {
	req := &platformv1.SealTenantBarrierRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.SealTenantBarrier(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "SealTenantBarrier", Err: err}
	}

	return &SealTenantBarrierResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// TenantBarrierStatus reports the current sealed/initialized state of a per-tenant
// barrier via gRPC over Unix socket.
func (a *UnixAdapter) TenantBarrierStatus(ctx context.Context, opts TenantBarrierStatusOptions) (*TenantBarrierStatusResult, error) {
	req := &platformv1.GetTenantBarrierStatusRequest{
		TenantId: opts.TenantID,
	}

	resp, err := a.client.GetTenantBarrierStatus(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetTenantBarrierStatus", Err: err}
	}

	status := resp.GetBarrierStatus()
	return &TenantBarrierStatusResult{
		TenantID:       status.GetTenantId(),
		Sealed:         status.GetSealed(),
		Initialized:    status.GetInitialized(),
		Strategy:       status.GetStrategy(),
		HardwareBacked: status.GetHardwareBacked(),
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify UnixAdapter implements TenantCommands.
var _ TenantCommands = (*UnixAdapter)(nil)
