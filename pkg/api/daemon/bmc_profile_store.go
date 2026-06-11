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
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
)

// =============================================================================
// ProfileStore adapter
// =============================================================================

// ErrBMCProfileNilConfig indicates that the DeviceProfile has no BMC config.
type ErrBMCProfileNilConfig struct {
	ProfileID uint64
}

// Error returns the error message.
func (e ErrBMCProfileNilConfig) Error() string {
	return fmt.Sprintf("device profile %d has no BMC configuration", e.ProfileID)
}

// deviceProfileStore adapts a device.DeviceProfileService and an optional
// app.App into the bmc.ProfileStore interface. It translates DeviceProfile.BMC
// (entities.BMCConfig) into the *bmc.Config that the bmc.Service requires,
// and optionally wires in a TLS provider from the app's trust resolver.
type deviceProfileStore struct {
	profileSvc  device.DeviceProfileService
	tlsProvider bmc.TLSProvider // may be nil
}

// Compile-time check.
var _ bmc.ProfileStore = (*deviceProfileStore)(nil)

// newDeviceProfileStore constructs a deviceProfileStore. tlsProvider may be
// nil; when non-nil it is injected into every *bmc.Config returned by Get so
// daemon-mode BMC operations route TLS through the platform trust resolver.
func newDeviceProfileStore(profileSvc device.DeviceProfileService, tlsProvider bmc.TLSProvider) *deviceProfileStore {
	return &deviceProfileStore{
		profileSvc:  profileSvc,
		tlsProvider: tlsProvider,
	}
}

// Get retrieves the DeviceProfile by id, extracts its BMC sub-config, and
// maps it into a *bmc.Config. Returns bmc.ErrProfileNotFound when the profile
// is absent or has no BMC configuration.
func (s *deviceProfileStore) Get(ctx context.Context, id uint64) (*bmc.Config, error) {
	profile, err := s.profileSvc.Get(ctx, id)
	if err != nil {
		return nil, bmc.ErrProfileNotFound{ProfileID: id}
	}
	if profile.BMC == nil {
		return nil, bmc.ErrProfileNotFound{ProfileID: id}
	}
	return profileBMCToConfig(profile, s.tlsProvider), nil
}

// profileBMCToConfig maps entities.BMCConfig into *bmc.Config. The tlsProvider
// is injected when non-nil; this overrides any static TLS settings so every
// daemon connection uses the class-BMC trust chain. The profile ID is the
// device ID for enrollment purposes (DeviceProfile and Device share the same
// ID namespace for BMC-managed devices enrolled this way).
func profileBMCToConfig(profile *entities.DeviceProfile, tlsProvider bmc.TLSProvider) *bmc.Config {
	eb := profile.BMC
	cfg := &bmc.Config{
		Address:  eb.Address,
		Port:     eb.EffectivePort(),
		Username: eb.Username,
		Password: eb.Password,
		Protocol: bmc.Protocol(eb.Protocol),
		TLS:      tlsProvider,
	}
	return cfg
}

// =============================================================================
// BMCEnroller interface
// =============================================================================

// BMCEnroller performs the BMC enrollment ceremony. It is satisfied by
// *app.App and injected into the gRPC service, REST handler, MCP provider,
// and QUIC handler so every transport uses the same logic.
type BMCEnroller interface {
	// EnrollBMC performs the BMC enrollment ceremony for the device
	// identified by deviceID using bmcCfg and the given opts.
	EnrollBMC(ctx context.Context, deviceID uint64, bmcCfg *bmc.Config, opts *app.BMCEnrollOptions) (*app.BMCEnrollResult, error)

	// BMCTLSProvider returns a bmc.TLSProvider backed by the platform's
	// trust resolver (ClassBMC). Returns nil when no resolver is available.
	BMCTLSProvider() bmc.TLSProvider
}

// ErrBMCEnrollerNotConfigured indicates the BMC enroller is not wired into
// the daemon. Returned by all EnrollBMC entry points when the App is absent.
type ErrBMCEnrollerNotConfigured struct{}

// Error returns the error message.
func (ErrBMCEnrollerNotConfigured) Error() string {
	return "bmc enroller not configured (daemon started without App)"
}

// =============================================================================
// REST ProfileLookup adapter
// =============================================================================

// profileLookupAdapter adapts a device.DeviceProfileService into the
// bmcwebsvc.ProfileLookup interface so the REST handler can resolve
// *bmc.Config from a profileID without importing device directly.
type profileLookupAdapter struct {
	profileSvc device.DeviceProfileService
}

// BMCConfig implements bmcwebsvc.ProfileLookup.
func (a *profileLookupAdapter) BMCConfig(ctx context.Context, profileID uint64, tlsProvider bmc.TLSProvider) (*bmc.Config, error) {
	if a.profileSvc == nil {
		return nil, bmc.ErrProfileNotFound{ProfileID: profileID}
	}
	profile, err := a.profileSvc.Get(ctx, profileID)
	if err != nil {
		return nil, bmc.ErrProfileNotFound{ProfileID: profileID}
	}
	if profile.BMC == nil {
		return nil, bmc.ErrProfileNotFound{ProfileID: profileID}
	}
	return profileBMCToConfig(profile, tlsProvider), nil
}

// =============================================================================
// REST BMCEnrollerServicer adapter
// =============================================================================

// restBMCEnrollerAdapter adapts a BMCEnroller (which uses app.* types) into
// the bmcwebsvc.BMCEnrollerServicer interface (which uses webservice-local
// types) so the REST handler stays decoupled from pkg/app.
type restBMCEnrollerAdapter struct {
	enroller BMCEnroller
}

// Compile-time check.
var _ bmcwebsvc.BMCEnrollerServicer = (*restBMCEnrollerAdapter)(nil)

// newRESTBMCEnrollerAdapter wraps a BMCEnroller as a bmcwebsvc.BMCEnrollerServicer.
func newRESTBMCEnrollerAdapter(e BMCEnroller) *restBMCEnrollerAdapter {
	return &restBMCEnrollerAdapter{enroller: e}
}

// EnrollBMC implements bmcwebsvc.BMCEnrollerServicer. It converts the webservice-
// local EnrollOptions to app.BMCEnrollOptions, calls the underlying BMCEnroller,
// and maps the result back to the webservice-local EnrollResult.
func (a *restBMCEnrollerAdapter) EnrollBMC(ctx context.Context, deviceID uint64, bmcCfg *bmc.Config, opts *bmcwebsvc.EnrollOptions) (*bmcwebsvc.EnrollResult, error) {
	appOpts := restEnrollOptsToApp(opts)
	result, err := a.enroller.EnrollBMC(ctx, deviceID, bmcCfg, appOpts)
	if err != nil {
		return nil, err
	}
	return appEnrollResultToREST(result), nil
}

// BMCTLSProvider implements bmcwebsvc.BMCEnrollerServicer.
func (a *restBMCEnrollerAdapter) BMCTLSProvider() bmc.TLSProvider {
	return a.enroller.BMCTLSProvider()
}

// restEnrollOptsToApp converts the webservice-local EnrollOptions to the
// app.BMCEnrollOptions type expected by the BMCEnroller.
func restEnrollOptsToApp(opts *bmcwebsvc.EnrollOptions) *app.BMCEnrollOptions {
	if opts == nil {
		return &app.BMCEnrollOptions{}
	}
	return &app.BMCEnrollOptions{
		ReplaceCertificate: opts.ReplaceCertificate,
		RotatePassword:     opts.RotatePassword,
		DNSRegister:        opts.DNSRegister,
		DANEPublish:        opts.DANEPublish,
	}
}

// appEnrollResultToREST converts app.BMCEnrollResult to the webservice-local
// EnrollResult so the REST handler can serialize it without importing pkg/app.
func appEnrollResultToREST(r *app.BMCEnrollResult) *bmcwebsvc.EnrollResult {
	if r == nil {
		return &bmcwebsvc.EnrollResult{}
	}
	steps := make([]bmcwebsvc.EnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = bmcwebsvc.EnrollStep{
			Name:   s.Name,
			OK:     s.OK,
			Detail: s.Detail,
		}
	}
	return &bmcwebsvc.EnrollResult{
		DeviceID:      r.DeviceID,
		Endpoint:      r.Endpoint,
		Hostname:      r.Hostname,
		DNSName:       r.DNSName,
		PinSPKISHA256: r.PinSPKISHA256,
		FactoryCertPEM: r.FactoryCertPEM,
		FactoryCertMeta: bmcwebsvc.FactoryCertMeta{
			Subject:      r.FactoryCertMeta.Subject,
			Issuer:       r.FactoryCertMeta.Issuer,
			SerialNumber: r.FactoryCertMeta.SerialNumber,
			NotBefore:    r.FactoryCertMeta.NotBefore,
			NotAfter:     r.FactoryCertMeta.NotAfter,
			SPKISHA256:   r.FactoryCertMeta.SPKISHA256,
			SHA256:       r.FactoryCertMeta.SHA256,
			CapturedAt:   r.FactoryCertMeta.CapturedAt,
		},
		NewCertPEM: r.NewCertPEM,
		CACertPEM:  r.CACertPEM,
		Steps:      steps,
	}
}
