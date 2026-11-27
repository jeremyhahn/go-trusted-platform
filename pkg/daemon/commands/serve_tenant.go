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
	"log/slog"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// platformTenantManager builds the platform tenant.Manager the daemon serves
// tenants through on every transport -- the gRPC and Unix TenantService, the
// QUIC tenant handler and /api/v1/tenants on REST all read
// daemon.Config.PlatformTenantManager. It returns nil, after logging why, when
// the QuicBaaS SDK IAM tenant client is not available.
//
// Both serve paths call it. Only the webservices path used to build the
// manager, so a daemon-only platformd registered TenantService and then
// answered every call with "tenant manager not initialized", served no
// /api/v1/tenants route and refused tenant requests on QUIC (#730).
//
// The per-tenant barrier backend is wired from the SDK's QRDB tenant client,
// so the barrier status, init, unseal and seal routes reach a real backend;
// without that client they stay dark and list not-configured. In embedded
// deployments the QRDB composition now installs the node's tenant servicer
// behind that client (pkg/storage/quicbaas/sdk_embedded_qrdb.go), so the
// barrier calls reach it rather than a nil servicer. DEK isolation
// and the VLAN, quota and bridge subsystems stay off until they are
// constructed at startup too (#721).
func platformTenantManager(logger *logging.Logger, a *app.App) *tenant.Manager {
	if a == nil {
		return nil
	}
	sdk := a.QuicBaaSSDKClient()
	if sdk == nil {
		logger.Warn("platform tenant manager not wired: QuicBaaS SDK client unavailable")
		return nil
	}
	iamClient := sdk.Identity().IAM()
	if iamClient == nil {
		logger.Warn("platform tenant manager not wired: QuicBaaS IAM client unavailable")
		return nil
	}
	var bc tenant.TenantBarrierClient
	if svc := sdk.TenantMgmtService(); svc == nil {
		logger.Warn("platform tenant barrier not wired: QuicBaaS tenant service unavailable")
	} else if tc, err := svc.Tenant(); err != nil {
		logger.Warn("platform tenant barrier not wired: QRDB tenant client unavailable", "error", err)
	} else {
		bc = tenant.NewTenantBarrierClient(tc)
	}
	mgr, err := newIAMOnlyTenantManager(iamClient.Tenant(), iamClient.Role(), bc)
	if err != nil {
		logger.Warn("failed to construct platform tenant manager", "error", err)
		return nil
	}
	logger.Info("platform tenant manager wired", "barrier", mgr.BarrierConfigured())
	return mgr
}

// platformTenantID returns the platform's operating tenant — the firstboot
// system tenant pkg/app adopts when it starts the QuicBaaS factory, and the
// tenant the REST tenant guards admit across tenants. The daemon hands it to
// the TenantService so gRPC, QUIC and MCP admit the same caller. Empty when
// there is no App.
func platformTenantID(a *app.App) string {
	if a == nil {
		return ""
	}
	return a.TenantID
}

// newIAMOnlyTenantManager constructs a tenant.Manager over the IAM tenant
// client with the subsystems that are not yet constructed at startup turned
// off, so NewManager does not refuse it for a missing DEK, VLAN or bridge
// dependency. bc is the per-tenant barrier backend; nil leaves the barrier
// routes dark (BarrierConfigured false).
func newIAMOnlyTenantManager(tc iam.TenantClient, rc tenant.RoleReconciler, bc tenant.TenantBarrierClient) (*tenant.Manager, error) {
	cfg := tenant.DefaultConfig()
	cfg.EnableDEKIsolation = false
	return tenant.NewManager(&tenant.ManagerConfig{
		IAMTenantClient:     tc,
		IAMRoleClient:       rc,
		TenantBarrierClient: bc,
		Config:              cfg,
		Logger:              slog.Default(),
	})
}
