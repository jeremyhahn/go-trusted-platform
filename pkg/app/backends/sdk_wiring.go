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
	"context"
	"fmt"
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
	SetLUKSBackend(b daemon.LUKSBackend)
	SetLUKSRootChecker(rc daemon.RootChecker)
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

// WireSDKBackends gives a daemon's ceremony and LUKS services their production
// backends on every transport, and the LUKS service its effective-UID root
// checker. A refused wiring (no SDK client) wires nothing. Runtime FIDO2 is
// intentionally left unwired until the SDK exposes the daemon backend shape;
// callers receive daemon.ErrFIDO2NotConfigured instead of a local CTAP2/KV
// implementation.
func WireSDKBackends(target SDKBackendTarget, src SDKBackendSources, logger *logging.Logger) error {
	if src.SDK == nil {
		return ErrCeremonyBackendRequiresSDK{}
	}
	target.SetCeremonyBackend(NewCeremonyBackend(logger, src.SDK, src.Admin))
	// The LUKS backend needs no SDK: it drives go-luks2 on the host, with
	// the TPM handler the host can open. The root checker reads the
	// effective UID; without it the service refuses every mutation.
	//
	// FIDO2 enrollment stays off: the default handler binds the 64-byte
	// go-xkms derived key, which neither the fido2-manual reader (raw
	// 32-byte hmac-secret) nor the initrd FIDO2 strategy (no credential or
	// salt) can produce, so an enrolled slot would not unlock at boot.
	// EnrollFIDO2 answers ErrLUKSHardwareUnavailable until a boot path
	// consumes the slot.
	luks := NewLUKSBackend(logger, WithDefaultLUKSHandlers())
	luks.SetFIDO2Handler(nil)
	luks.SetTPMHandler(pcrCheckedTPMHandler(luks.tpm))
	target.SetLUKSBackend(luks)
	target.SetLUKSRootChecker(DefaultRootChecker())
	return nil
}

// maxTPMPCRIndex is the highest PCR index a TPM 2.0 PC-client bank holds.
const maxTPMPCRIndex = 23

// pcrCheckedTPMHandler wraps h so Seal refuses an empty PCR list and any
// index outside 0..maxTPMPCRIndex before the sealer runs or a slot is
// written. A nil h stays nil, so TPM enrollment stays off.
func pcrCheckedTPMHandler(h LUKSTPMHandler) LUKSTPMHandler {
	if h == nil {
		return nil
	}
	return pcrCheckedTPM{next: h}
}

type pcrCheckedTPM struct{ next LUKSTPMHandler }

func (p pcrCheckedTPM) Seal(ctx context.Context, handle string, pcrs []int32) ([]byte, []byte, error) {
	if len(pcrs) == 0 {
		return nil, nil, fmt.Errorf("%w: at least one pcr index is required", daemon.ErrLUKSPCRInvalid)
	}
	for _, idx := range pcrs {
		if idx < 0 || idx > maxTPMPCRIndex {
			return nil, nil, fmt.Errorf("%w: pcr index %d is outside 0..%d", daemon.ErrLUKSPCRInvalid, idx, maxTPMPCRIndex)
		}
	}
	return p.next.Seal(ctx, handle, pcrs)
}

// WireEmbeddedHost is the daemon.EmbeddedHostOptions.WireBackends of every
// embedded host: it gives the hosted daemon the backends platformd wires,
// from the platform the host initialized. Without an SDK client it fails,
// and the host does not start, as platformd does not.
func WireEmbeddedHost(d *daemon.Daemon, a *app.App) error {
	return WireSDKBackends(d, PlatformSDKBackendSources(a.QuicBaaSSDKClient(), a.CA, PlatformAdminIdentity(a)), a.Logger)
}
