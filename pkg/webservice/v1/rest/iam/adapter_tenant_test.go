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

package iam

import (
	"context"
	"errors"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// provisionIAM is an iamsdk.Client serving only what tenant creation reaches:
// tenant Create and Delete, and role Reconcile. It records which tenants exist
// and which were reconciled.
type provisionIAM struct {
	iamsdk.Client
	tenants      map[string]bool
	reconciled   []string
	createErr    error
	reconcileErr error
	deleteErr    error
}

func newProvisionIAM(existing ...string) *provisionIAM {
	p := &provisionIAM{tenants: map[string]bool{}}
	for _, id := range existing {
		p.tenants[id] = true
	}
	return p
}

func (p *provisionIAM) Tenant() iamsdk.TenantClient { return provisionTenants{p: p} }
func (p *provisionIAM) Role() iamsdk.RoleClient     { return provisionRoles{p: p} }

type provisionTenants struct {
	iamsdk.TenantClient
	p *provisionIAM
}

func (t provisionTenants) Create(_ context.Context, req *iamsdk.CreateTenantRequest) (*iamsdk.Tenant, error) {
	if t.p.createErr != nil {
		return nil, t.p.createErr
	}
	if t.p.tenants[req.ID] {
		return nil, sdkerrors.NewAlreadyExists("iam.tenant.create", req.ID+" already exists")
	}
	t.p.tenants[req.ID] = true
	return &iamsdk.Tenant{ID: req.ID, Name: req.Name}, nil
}

func (t provisionTenants) Delete(_ context.Context, tenantID string) error {
	if t.p.deleteErr != nil {
		return t.p.deleteErr
	}
	delete(t.p.tenants, tenantID)
	return nil
}

type provisionRoles struct {
	iamsdk.RoleClient
	p *provisionIAM
}

func (r provisionRoles) Reconcile(_ context.Context, tenantID string) (*iamsdk.ReconcileRolesResponse, error) {
	if r.p.reconcileErr != nil {
		return nil, r.p.reconcileErr
	}
	r.p.reconciled = append(r.p.reconciled, tenantID)
	return &iamsdk.ReconcileRolesResponse{TenantID: tenantID}, nil
}

func TestCreateTenantWithDefaultRoles_NewTenant(t *testing.T) {
	iam := newProvisionIAM()

	tenant, err := CreateTenantWithDefaultRoles(context.Background(), iam, &iamsdk.CreateTenantRequest{ID: "acme", Name: "Acme"})

	require.NoError(t, err)
	assert.Equal(t, "acme", tenant.ID)
	assert.Equal(t, []string{"acme"}, iam.reconciled)
}

func TestCreateTenantWithDefaultRoles_ExistingTenantIsSeeded(t *testing.T) {
	iam := newProvisionIAM("acme")

	tenant, err := CreateTenantWithDefaultRoles(context.Background(), iam, &iamsdk.CreateTenantRequest{ID: "acme"})

	assert.Nil(t, tenant)
	assert.Equal(t, sdkerrors.CodeAlreadyExists, sdkerrors.Code(err), "err %v", err)
	assert.Equal(t, []string{"acme"}, iam.reconciled, "an existing tenant is given its default roles")
	assert.True(t, iam.tenants["acme"])
}

func TestCreateTenantWithDefaultRoles_Errors(t *testing.T) {
	ctx := context.Background()
	req := &iamsdk.CreateTenantRequest{ID: "acme"}
	down := sdkerrors.NewUnavailable("iam.role.reconcile", "down")

	t.Run("create failure", func(t *testing.T) {
		iam := newProvisionIAM()
		iam.createErr = sdkerrors.NewForbidden("iam.tenant.create", "no")
		_, err := CreateTenantWithDefaultRoles(ctx, iam, req)
		assert.Equal(t, sdkerrors.CodeForbidden, sdkerrors.Code(err), "err %v", err)
		assert.Empty(t, iam.reconciled)
	})

	t.Run("new tenant reconcile failure rolls back", func(t *testing.T) {
		iam := newProvisionIAM()
		iam.reconcileErr = down
		_, err := CreateTenantWithDefaultRoles(ctx, iam, req)
		assert.ErrorIs(t, err, down)
		assert.False(t, iam.tenants["acme"], "the roleless tenant survived")
	})

	t.Run("rollback failure is reported with its cause", func(t *testing.T) {
		iam := newProvisionIAM()
		iam.reconcileErr = down
		iam.deleteErr = errors.New("delete refused")
		_, err := CreateTenantWithDefaultRoles(ctx, iam, req)
		var rollback ErrTenantRollbackFailed
		require.ErrorAs(t, err, &rollback)
		assert.Equal(t, "acme", rollback.TenantID)
		assert.ErrorIs(t, err, down)
		assert.Contains(t, err.Error(), "delete refused")
	})

	t.Run("existing tenant reconcile failure keeps it", func(t *testing.T) {
		iam := newProvisionIAM("acme")
		iam.reconcileErr = down
		_, err := CreateTenantWithDefaultRoles(ctx, iam, req)
		assert.ErrorIs(t, err, down)
		assert.True(t, iam.tenants["acme"], "an existing tenant is never deleted")
	})
}

func TestQuicBaaSIAMAdapter_CreateTenantProvisionsRoles(t *testing.T) {
	iam := newProvisionIAM()
	adapter := &QuicBaaSIAMAdapter{client: iam}

	resp, err := adapter.CreateTenant(context.Background(), &CreateTenantRequest{ID: "acme", Name: "Acme"})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.ID)
	assert.Equal(t, []string{"acme"}, iam.reconciled)

	_, err = adapter.CreateTenant(context.Background(), nil)
	assert.Error(t, err)
}
