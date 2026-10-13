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

package backends

import (
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ErrCeremonyBackendRequiresSDK is returned when a daemon is wired without a
// QuicBaaS SDK client. The ceremony backend delegates every call to the SDK,
// so the daemon refuses to start rather than answer each ceremony call with
// "not configured".
type ErrCeremonyBackendRequiresSDK struct{}

// Error implements the error interface.
func (ErrCeremonyBackendRequiresSDK) Error() string {
	return "ceremony: the ceremony backend requires the QuicBaaS SDK client, and the platform has none"
}

// SDKBackendTarget is the daemon surface the SDK backend wiring writes to.
type SDKBackendTarget interface {
	SetCeremonyBackend(b daemon.CeremonyBackend)
}

// SDKBackendSources is what the ceremony backend is built from.
type SDKBackendSources struct {
	// SDK is the QuicBaaS SDK client the ceremony backend delegates to.
	SDK quicbaassdk.Client
	// Admin mints the admin bundle CeremonyService.Init returns.
	Admin AdminBundleIssuer
}

// PlatformSDKBackendSources returns the sources for a running platform: its
// SDK client and the admin bundle issuer over its CA, minting for admin. A nil
// SDK client yields no sources, which WireSDKBackends refuses.
func PlatformSDKBackendSources(sdk quicbaassdk.Client, ca quicbaasca.CACertificateAuthority, admin AdminIdentity) SDKBackendSources {
	if sdk == nil {
		return SDKBackendSources{}
	}
	return SDKBackendSources{SDK: sdk, Admin: NewAdminBundleIssuer(PlatformCertIssuer(ca, sdk), admin)}
}

// PlatformAdminIdentity is the system-admin identity of a platform: its
// configured SPIFFE trust domain and the system tenant it adopts as its
// operating tenant. The tenant is the fixed system id, not a.TenantID: /init
// mints the bundle while the barrier is still sealed, before the adoption
// that sets a.TenantID can run.
func PlatformAdminIdentity(a *app.App) AdminIdentity {
	identity := AdminIdentity{TenantID: app.SystemTenantID}
	if a != nil && a.QuicBaaSConfig != nil {
		identity.TrustDomain = a.QuicBaaSConfig.SPIFFETrustDomain
	}
	return identity
}

// WireSDKBackends gives a daemon's ceremony service its production backend on
// every transport. Runtime FIDO2 is intentionally left unwired until the SDK
// exposes the daemon backend shape; callers receive daemon.ErrFIDO2NotConfigured
// instead of a local CTAP2/KV implementation.
func WireSDKBackends(target SDKBackendTarget, src SDKBackendSources, logger *logging.Logger) error {
	if src.SDK == nil {
		return ErrCeremonyBackendRequiresSDK{}
	}
	target.SetCeremonyBackend(NewCeremonyBackend(logger, src.SDK, src.Admin))
	return nil
}

// WireEmbeddedHost is the daemon.EmbeddedHostOptions.WireBackends of every
// embedded host: it gives the hosted daemon the backends platformd wires,
// from the platform the host initialized. Without an SDK client it fails,
// and the host does not start, as platformd does not.
func WireEmbeddedHost(d *daemon.Daemon, a *app.App) error {
	return WireSDKBackends(d, PlatformSDKBackendSources(a.QuicBaaSSDKClient(), a.CA, PlatformAdminIdentity(a)), a.Logger)
}
