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

// Package tenant provides a client for tenant service operations.
package tenant

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to tenant service operations.
type Client struct {
	grpc platformv1.TenantServiceClient
}

// NewClient creates a new tenant service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewTenantServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new tenant service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.TenantServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// Tenant CRUD Operations

// List retrieves tenants with optional filtering.
func (c *Client) List(ctx context.Context, limit, offset int32, selector *platformv1.LabelSelector) ([]*platformv1.Tenant, int32, error) {
	resp, err := c.grpc.ListTenants(ctx, &platformv1.ListTenantsRequest{
		Limit:    limit,
		Offset:   offset,
		Selector: selector,
	})
	if err != nil {
		return nil, 0, &ErrListTenantsFailed{Cause: err}
	}
	return resp.Tenants, resp.Total, nil
}

// Get retrieves a tenant by ID.
func (c *Client) Get(ctx context.Context, tenantID string) (*platformv1.Tenant, error) {
	resp, err := c.grpc.GetTenant(ctx, &platformv1.GetTenantRequest{TenantId: tenantID})
	if err != nil {
		return nil, &ErrGetTenantFailed{ID: tenantID, Cause: err}
	}
	return resp.Tenant, nil
}

// GetByName retrieves a tenant by name.
func (c *Client) GetByName(ctx context.Context, name string) (*platformv1.Tenant, error) {
	resp, err := c.grpc.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{Name: name})
	if err != nil {
		return nil, &ErrGetTenantByNameFailed{Name: name, Cause: err}
	}
	return resp.Tenant, nil
}

// Create creates a new tenant.
func (c *Client) Create(ctx context.Context, req *platformv1.CreateTenantRequest) (*platformv1.Tenant, error) {
	resp, err := c.grpc.CreateTenant(ctx, req)
	if err != nil {
		return nil, &ErrCreateTenantFailed{Cause: err}
	}
	return resp.Tenant, nil
}

// Update updates an existing tenant.
func (c *Client) Update(ctx context.Context, req *platformv1.UpdateTenantRequest) (*platformv1.Tenant, error) {
	resp, err := c.grpc.UpdateTenant(ctx, req)
	if err != nil {
		return nil, &ErrUpdateTenantFailed{ID: req.TenantId, Cause: err}
	}
	return resp.Tenant, nil
}

// Delete deletes a tenant.
func (c *Client) Delete(ctx context.Context, tenantID string) error {
	_, err := c.grpc.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{TenantId: tenantID})
	if err != nil {
		return &ErrDeleteTenantFailed{ID: tenantID, Cause: err}
	}
	return nil
}

// Tenant Lifecycle Operations

// Suspend suspends a tenant.
func (c *Client) Suspend(ctx context.Context, tenantID string) error {
	_, err := c.grpc.SuspendTenant(ctx, &platformv1.SuspendTenantRequest{TenantId: tenantID})
	if err != nil {
		return &ErrSuspendTenantFailed{ID: tenantID, Cause: err}
	}
	return nil
}

// Resume resumes a suspended tenant.
func (c *Client) Resume(ctx context.Context, tenantID string) error {
	_, err := c.grpc.ResumeTenant(ctx, &platformv1.ResumeTenantRequest{TenantId: tenantID})
	if err != nil {
		return &ErrResumeTenantFailed{ID: tenantID, Cause: err}
	}
	return nil
}

// Quota Management

// GetQuotas retrieves quotas for a tenant.
func (c *Client) GetQuotas(ctx context.Context, tenantID string) (*platformv1.GetQuotasResponse, error) {
	resp, err := c.grpc.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: tenantID})
	if err != nil {
		return nil, &ErrGetQuotasFailed{ID: tenantID, Cause: err}
	}
	return resp, nil
}

// UpdateQuotas updates quotas for a tenant.
func (c *Client) UpdateQuotas(ctx context.Context, req *platformv1.UpdateQuotasRequest) error {
	_, err := c.grpc.UpdateQuotas(ctx, req)
	if err != nil {
		return &ErrUpdateQuotasFailed{ID: req.TenantId, Cause: err}
	}
	return nil
}

// GetUsage retrieves resource usage for a tenant.
func (c *Client) GetUsage(ctx context.Context, tenantID string) (*platformv1.TenantUsage, error) {
	resp, err := c.grpc.GetUsage(ctx, &platformv1.GetUsageRequest{TenantId: tenantID})
	if err != nil {
		return nil, &ErrGetUsageFailed{ID: tenantID, Cause: err}
	}
	return resp.Usage, nil
}

// CheckQuota checks if a resource request fits within tenant quota.
func (c *Client) CheckQuota(ctx context.Context, tenantID, resource string, amount int64) (*platformv1.CheckQuotaResponse, error) {
	resp, err := c.grpc.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: tenantID,
		Resource: resource,
		Amount:   amount,
	})
	if err != nil {
		return nil, &ErrCheckQuotaFailed{ID: tenantID, Cause: err}
	}
	return resp, nil
}

// Network Isolation

// ValidateVLAN validates a VLAN ID for a tenant.
func (c *Client) ValidateVLAN(ctx context.Context, tenantID string, vlanID uint32) (*platformv1.ValidateVLANResponse, error) {
	resp, err := c.grpc.ValidateVLAN(ctx, &platformv1.ValidateVLANRequest{
		TenantId: tenantID,
		VlanId:   vlanID,
	})
	if err != nil {
		return nil, &ErrValidateVLANFailed{ID: tenantID, Cause: err}
	}
	return resp, nil
}

// GetBridgeName returns the OVS bridge name for a tenant.
func (c *Client) GetBridgeName(ctx context.Context, tenantID string) (string, error) {
	resp, err := c.grpc.GetBridgeName(ctx, &platformv1.GetBridgeNameRequest{TenantId: tenantID})
	if err != nil {
		return "", &ErrGetBridgeNameFailed{ID: tenantID, Cause: err}
	}
	return resp.BridgeName, nil
}

// State Synchronization

// Sync synchronizes tenant state.
func (c *Client) Sync(ctx context.Context) error {
	_, err := c.grpc.Sync(ctx, &platformv1.SyncTenantsRequest{})
	if err != nil {
		return &ErrSyncTenantsFailed{Cause: err}
	}
	return nil
}

// DEK Management

// RotateDEK rotates the Data Encryption Key for a tenant.
func (c *Client) RotateDEK(ctx context.Context, tenantID string, background bool) (*platformv1.RotateTenantDEKResponse, error) {
	resp, err := c.grpc.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{
		TenantId:   tenantID,
		Background: background,
	})
	if err != nil {
		return nil, &ErrRotateDEKFailed{ID: tenantID, Cause: err}
	}
	return resp, nil
}

// GetDEKStatus retrieves the DEK status for a tenant.
func (c *Client) GetDEKStatus(ctx context.Context, tenantID string) (*platformv1.TenantDEKStatus, error) {
	resp, err := c.grpc.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{TenantId: tenantID})
	if err != nil {
		return nil, &ErrGetDEKStatusFailed{ID: tenantID, Cause: err}
	}
	return resp.DekStatus, nil
}

// Per-Tenant Barrier Lifecycle (added 2026-04-28)
//
// These methods expose the platform's per-tenant barrier ops over the
// platform's own gRPC TenantService. Each tenant has an independent
// cryptographic barrier auto-initialized on Create and auto-sealed on Delete;
// these methods give explicit lifecycle control.

// InitTenantBarrier explicitly initializes a per-tenant barrier with optional
// Shamir threshold/shares configuration. Both zero means deterministic
// non-Shamir init.
func (c *Client) InitTenantBarrier(ctx context.Context, tenantID string, threshold, shares int32) error {
	if _, err := c.grpc.InitTenantBarrier(ctx, &platformv1.InitTenantBarrierRequest{
		TenantId:  tenantID,
		Threshold: threshold,
		Shares:    shares,
	}); err != nil {
		return &ErrInitTenantBarrierFailed{ID: tenantID, Cause: err}
	}
	return nil
}

// UnsealTenantBarrier unseals a per-tenant barrier with the provided key
// material. An empty key falls back to the deterministic init credential.
func (c *Client) UnsealTenantBarrier(ctx context.Context, tenantID string, key []byte) error {
	if _, err := c.grpc.UnsealTenantBarrier(ctx, &platformv1.UnsealTenantBarrierRequest{
		TenantId: tenantID,
		Key:      key,
	}); err != nil {
		return &ErrUnsealTenantBarrierFailed{ID: tenantID, Cause: err}
	}
	return nil
}

// SealTenantBarrier seals a per-tenant barrier. Subsequent reads/writes
// against the tenant namespace fail until unsealed again.
func (c *Client) SealTenantBarrier(ctx context.Context, tenantID string) error {
	if _, err := c.grpc.SealTenantBarrier(ctx, &platformv1.SealTenantBarrierRequest{
		TenantId: tenantID,
	}); err != nil {
		return &ErrSealTenantBarrierFailed{ID: tenantID, Cause: err}
	}
	return nil
}

// GetTenantBarrierStatus reports the current sealed/initialized state and
// active strategy metadata of a per-tenant barrier. Uninitialized barriers
// return Sealed=true, Initialized=false rather than erroring.
func (c *Client) GetTenantBarrierStatus(ctx context.Context, tenantID string) (*platformv1.TenantBarrierStatus, error) {
	resp, err := c.grpc.GetTenantBarrierStatus(ctx, &platformv1.GetTenantBarrierStatusRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, &ErrGetTenantBarrierStatusFailed{ID: tenantID, Cause: err}
	}
	return resp.GetBarrierStatus(), nil
}

// Domain-typed convenience methods
//
// These methods return domain types instead of proto types, enabling callers
// to avoid importing platformv1 directly.

// GetDomain retrieves a tenant by ID and returns a domain Tenant.
func (c *Client) GetDomain(ctx context.Context, tenantID string) (*Tenant, error) {
	proto, err := c.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return tenantFromProto(proto), nil
}

// GetByNameDomain retrieves a tenant by name and returns a domain Tenant.
func (c *Client) GetByNameDomain(ctx context.Context, name string) (*Tenant, error) {
	proto, err := c.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return tenantFromProto(proto), nil
}

// ListDomain retrieves tenants and returns domain Tenant slices.
func (c *Client) ListDomain(ctx context.Context, limit, offset int32) ([]*Tenant, int32, error) {
	protos, total, err := c.List(ctx, limit, offset, nil)
	if err != nil {
		return nil, 0, err
	}
	result := make([]*Tenant, len(protos))
	for i, p := range protos {
		result[i] = tenantFromProto(p)
	}
	return result, total, nil
}

// CreateDomain creates a new tenant using domain parameters and returns a domain Tenant.
func (c *Client) CreateDomain(ctx context.Context, params *CreateParams) (*Tenant, error) {
	req := createParamsToProto(params)
	proto, err := c.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	return tenantFromProto(proto), nil
}

// UpdateQuotasDomain updates tenant quotas using domain parameters.
func (c *Client) UpdateQuotasDomain(ctx context.Context, params *UpdateQuotasParams) error {
	req := updateQuotasParamsToProto(params)
	return c.UpdateQuotas(ctx, req)
}
