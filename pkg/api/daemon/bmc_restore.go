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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
)

// =============================================================================
// BMCRestorer interface
// =============================================================================

// BMCRestorer performs the BMC factory-certificate restore ceremony. It is
// satisfied by *app.App and injected into the REST handler so the transport
// uses the same logic without importing pkg/app directly.
type BMCRestorer interface {
	// RestoreBMC runs the factory-certificate restore ceremony for the device
	// identified by deviceID using bmcCfg.
	RestoreBMC(ctx context.Context, deviceID uint64, bmcCfg *bmc.Config) (*app.BMCRestoreResult, error)

	// BMCTLSProvider returns a bmc.TLSProvider backed by the platform's
	// trust resolver (ClassBMC). Returns nil when no resolver is available.
	BMCTLSProvider() bmc.TLSProvider
}

// ErrBMCRestorerNotConfigured indicates the BMC restorer is not wired into
// the daemon. Returned by all RestoreBMC entry points when the App is absent.
type ErrBMCRestorerNotConfigured struct{}

// Error returns the error message.
func (ErrBMCRestorerNotConfigured) Error() string {
	return "bmc restorer not configured (daemon started without App)"
}

// =============================================================================
// REST BMCRestorerServicer adapter
// =============================================================================

// restBMCRestorerAdapter adapts a BMCRestorer (which uses app.* types) into
// the bmcwebsvc.BMCRestorerServicer interface (which uses webservice-local
// types) so the REST handler stays decoupled from pkg/app.
type restBMCRestorerAdapter struct {
	restorer BMCRestorer
}

// Compile-time check.
var _ bmcwebsvc.BMCRestorerServicer = (*restBMCRestorerAdapter)(nil)

// newRESTBMCRestorerAdapter wraps a BMCRestorer as a bmcwebsvc.BMCRestorerServicer.
func newRESTBMCRestorerAdapter(r BMCRestorer) *restBMCRestorerAdapter {
	return &restBMCRestorerAdapter{restorer: r}
}

// RestoreBMC implements bmcwebsvc.BMCRestorerServicer. It calls the underlying
// BMCRestorer and maps the result back to the webservice-local RestoreResult.
func (a *restBMCRestorerAdapter) RestoreBMC(ctx context.Context, deviceID uint64, bmcCfg *bmc.Config) (*bmcwebsvc.RestoreResult, error) {
	result, err := a.restorer.RestoreBMC(ctx, deviceID, bmcCfg)
	if err != nil {
		return nil, err
	}
	return appRestoreResultToREST(result), nil
}

// BMCTLSProvider implements bmcwebsvc.BMCRestorerServicer.
func (a *restBMCRestorerAdapter) BMCTLSProvider() bmc.TLSProvider {
	return a.restorer.BMCTLSProvider()
}

// appRestoreResultToREST converts app.BMCRestoreResult to the webservice-local
// RestoreResult so the REST handler can serialize it without importing pkg/app.
func appRestoreResultToREST(r *app.BMCRestoreResult) *bmcwebsvc.RestoreResult {
	if r == nil {
		return &bmcwebsvc.RestoreResult{}
	}
	steps := make([]bmcwebsvc.EnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = bmcwebsvc.EnrollStep{
			Name:   s.Name,
			OK:     s.OK,
			Detail: s.Detail,
		}
	}
	return &bmcwebsvc.RestoreResult{
		DeviceID: r.DeviceID,
		Endpoint: r.Endpoint,
		Hostname: r.Hostname,
		NewCertMeta: bmcwebsvc.FactoryCertMeta{
			Subject:      r.NewCertMeta.Subject,
			Issuer:       r.NewCertMeta.Issuer,
			SerialNumber: r.NewCertMeta.SerialNumber,
			NotBefore:    r.NewCertMeta.NotBefore,
			NotAfter:     r.NewCertMeta.NotAfter,
			SPKISHA256:   r.NewCertMeta.SPKISHA256,
			SHA256:       r.NewCertMeta.SHA256,
			CapturedAt:   r.NewCertMeta.CapturedAt,
		},
		NewCertPEM: r.NewCertPEM,
		Steps:      steps,
	}
}
