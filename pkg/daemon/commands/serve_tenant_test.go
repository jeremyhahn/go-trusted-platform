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

package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// stubTenantClient satisfies iam.TenantClient. Construction never calls it;
// any method a test reaches panics on the nil embedded interface, which is
// the failure we want if construction starts doing I/O.
type stubTenantClient struct{ iam.TenantClient }

// stubRoleClient satisfies tenant.RoleReconciler the same way.
type stubRoleClient struct{ iam.RoleClient }

func TestNewIAMOnlyTenantManager_BuildsWithoutOptionalSubsystems(t *testing.T) {
	mgr, err := newIAMOnlyTenantManager(stubTenantClient{}, stubRoleClient{})
	require.NoError(t, err)
	assert.NotNil(t, mgr)
}

func TestNewIAMOnlyTenantManager_RefusesMissingIAMClient(t *testing.T) {
	mgr, err := newIAMOnlyTenantManager(nil, stubRoleClient{})
	require.Error(t, err)
	assert.Nil(t, mgr)
}

func TestNewIAMOnlyTenantManager_RefusesMissingRoleClient(t *testing.T) {
	// Without a role client a new tenant would be created with no roles,
	// and every user mirrored into it would fail (#641).
	mgr, err := newIAMOnlyTenantManager(stubTenantClient{}, nil)
	require.Error(t, err)
	assert.Nil(t, mgr)
}

func TestPlatformTenantManager_NilAppWiresNothing(t *testing.T) {
	assert.Nil(t, platformTenantManager(logging.NewLogger(0, nil), nil))
}

func TestPlatformTenantManager_NoSDKClientWiresNothing(t *testing.T) {
	// An App whose QuicBaaS SDK client was never started has no IAM tenant
	// client to build on; the daemon then runs without tenant transports
	// rather than with a manager that fails every call.
	assert.Nil(t, platformTenantManager(logging.NewLogger(0, nil), &app.App{}))
}

func TestPlatformTenantID_NamesTheAppTenant(t *testing.T) {
	// The TenantService admits this tenant across tenants, as the REST
	// tenant guards do; it must be the tenant the App runs as.
	assert.Equal(t, "system-tenant", platformTenantID(&app.App{TenantID: "system-tenant"}))
}

func TestPlatformTenantID_NilAppNamesNone(t *testing.T) {
	// No App means no system tenant, so no tenant-bound caller may act
	// across tenants.
	assert.Empty(t, platformTenantID(nil))
}
