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
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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
	endpoint  string
	tlsConfig *tls.Config
	conn      *grpc.ClientConn
	client    platformv1.TenantServiceClient
}

// NewGRPCAdapter creates a new gRPC adapter that dials with the harness
// admin credential (system tenant).
func NewGRPCAdapter() *GRPCAdapter {
	return NewGRPCAdapterWithTLS(helpers.TLSConfigOrInsecure())
}

// NewGRPCAdapterWithTLS creates a gRPC adapter that dials with tlsConfig,
// so a test can call as the tenant another client credential is bound to.
func NewGRPCAdapterWithTLS(tlsConfig *tls.Config) *GRPCAdapter {
	return &GRPCAdapter{
		endpoint:  GetGRPCEndpoint(),
		tlsConfig: tlsConfig,
	}
}

// Setup prepares the adapter for testing
func (a *GRPCAdapter) Setup(ctx context.Context) error {
	tlsConfig := a.tlsConfig

	conn, err := grpc.NewClient(a.endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{
			Endpoint: a.endpoint,
			Err:      err,
		}
	}

	// Wait for the connection with a short timeout (5 seconds) to fail fast
	// if the server is not reachable
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := helpers.WaitGRPCReady(dialCtx, conn); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
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

	resp, err := a.client.CreateTenant(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateTenant", Err: err}
	}

	return &CreateTenantResult{
		Tenant: pbToTenantData(resp.GetTenant()),
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
		Tenant: pbToTenantData(resp.GetTenant()),
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
		Tenant: pbToTenantData(resp.GetTenant()),
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
		Tenant: pbToTenantData(resp.GetTenant()),
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
		tenants = append(tenants, pbToTenantData(t))
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
		Compute:  pbToComputeQuotaData(resp.GetCompute()),
		Network:  pbToNetworkQuotaData(resp.GetNetwork()),
		Storage:  pbToStorageQuotaData(resp.GetStorage()),
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
		Compute:  pbToComputeQuotaData(quotasResp.GetCompute()),
		Network:  pbToNetworkQuotaData(quotasResp.GetNetwork()),
		Storage:  pbToStorageQuotaData(quotasResp.GetStorage()),
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
