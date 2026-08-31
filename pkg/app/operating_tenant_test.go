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

package app

import (
	"context"
	"errors"
	"testing"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnsureOperatingTenant_IdempotentAfterAdoption proves the ensure path
// short-circuits once the operating tenant was adopted: no SDK access
// happens (the test App has no factory, so any attempt would fail), and
// the adopted TenantID stands.
func TestEnsureOperatingTenant_IdempotentAfterAdoption(t *testing.T) {
	app := &App{TenantID: "system", tenantAdopted: true}
	require.NoError(t, app.EnsureOperatingTenant(context.Background()))
	assert.Equal(t, "system", app.TenantID)
	assert.True(t, app.tenantAdopted)
}

// TestEnsureOperatingTenant_GracefulWithoutIAM proves the lean-build
// contract: with no SDK/IAM available, ensure is a graceful no-op — the
// configured TenantID stands and the app is NOT marked adopted, so a later
// call (once IAM exists) still performs the adoption.
func TestEnsureOperatingTenant_GracefulWithoutIAM(t *testing.T) {
	app := &App{TenantID: "default", Logger: logging.DefaultLogger()}
	require.NoError(t, app.EnsureOperatingTenant(context.Background()))
	assert.Equal(t, "default", app.TenantID, "the bootstrap placeholder stands on lean builds")
	assert.False(t, app.tenantAdopted, "a no-op must not be recorded as an adoption")
}

// TestIsIAMUnavailable_ClassifiesLeanBuildErrors proves the adoption guard
// treats exactly the SDK's "server has no IAM" responses as the lean-build
// no-op: the embedded transport's service-not-configured error (the real
// error an IAM-less server returns for IAM.Tenant verbs) and UNIMPLEMENTED,
// but never a live IAM failure — not-found, or the ambiguous UNAVAILABLE
// that remote transports also produce for transient outages.
func TestIsIAMUnavailable_ClassifiesLeanBuildErrors(t *testing.T) {
	assert.True(t, isIAMUnavailable(embedded.NewServiceNotConfiguredError("IAM.Tenant")),
		"the embedded IAM-disabled response must be a graceful no-op")
	assert.True(t, isIAMUnavailable(sdkerrors.NewUnimplemented("iam.tenant.Get", "not built")))
	assert.False(t, isIAMUnavailable(sdkerrors.NewUnavailable("iam.tenant.Get", "down")),
		"UNAVAILABLE is ambiguous with a live outage on remote transports and must stay fatal")
	assert.False(t, isIAMUnavailable(sdkerrors.NewNotFound("iam.tenant.Get", "system tenant missing")),
		"a live IAM's not-found must stay fatal")
	assert.False(t, isIAMUnavailable(errors.New("dial tcp: connection refused")),
		"an unclassified error must stay fatal")
}
