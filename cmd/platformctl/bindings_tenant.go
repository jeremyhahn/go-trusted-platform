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

package main

import (
	"log/slog"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TenantBinding exposes tenant service methods to the Wails frontend.
type TenantBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewTenantBinding creates a new TenantBinding.
func NewTenantBinding(logger *slog.Logger, conn *ConnectionBinding) *TenantBinding {
	return &TenantBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *TenantBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// ListTenants returns a paginated list of tenants.
func (b *TenantBinding) ListTenants(limit int32, offset int32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().ListTenants(b.conn.ctx, &platformv1.ListTenantsRequest{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetTenant retrieves a tenant by ID.
func (b *TenantBinding) GetTenant(tenantID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().GetTenant(b.conn.ctx, &platformv1.GetTenantRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// CreateTenant creates a new tenant.
func (b *TenantBinding) CreateTenant(name string, displayName string, vlanRangeStart uint32, vlanRangeEnd uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().CreateTenant(b.conn.ctx, &platformv1.CreateTenantRequest{
		Name:           name,
		DisplayName:    displayName,
		VlanRangeStart: vlanRangeStart,
		VlanRangeEnd:   vlanRangeEnd,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// UpdateTenant updates an existing tenant.
func (b *TenantBinding) UpdateTenant(tenantID string, displayName string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().UpdateTenant(b.conn.ctx, &platformv1.UpdateTenantRequest{
		TenantId:    tenantID,
		DisplayName: displayName,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// DeleteTenant deletes a tenant by ID.
func (b *TenantBinding) DeleteTenant(tenantID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().DeleteTenant(b.conn.ctx, &platformv1.DeleteTenantRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// SuspendTenant suspends a tenant by ID.
func (b *TenantBinding) SuspendTenant(tenantID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().SuspendTenant(b.conn.ctx, &platformv1.SuspendTenantRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// ResumeTenant resumes a suspended tenant by ID.
func (b *TenantBinding) ResumeTenant(tenantID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().ResumeTenant(b.conn.ctx, &platformv1.ResumeTenantRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetQuotas retrieves the quotas for a tenant.
func (b *TenantBinding) GetQuotas(tenantID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().GetQuotas(b.conn.ctx, &platformv1.GetQuotasRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// UpdateQuotas updates the quotas for a tenant.
func (b *TenantBinding) UpdateQuotas(tenantID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().UpdateQuotas(b.conn.ctx, &platformv1.UpdateQuotasRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetUsage retrieves the resource usage for a tenant.
func (b *TenantBinding) GetUsage(tenantID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Tenant().GetUsage(b.conn.ctx, &platformv1.GetUsageRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}
