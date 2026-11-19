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
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
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
	// TPM is the platform's selected TPM the LUKS TPM enrolment seals over;
	// nil keeps the SDK default device.
	TPM TPMOpener
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
	// The LUKS backend needs no SDK: it drives go-luks2 on the host. The root checker reads the
	// effective UID; without it the service refuses every mutation.
	//
	// FIDO2 enrollment uses the default handler when an authenticator
	// library opens: it derives the keyslot key with hmac-secret and writes
	// a fido2-manual token (credential, salt, RP, UV) naming the slot. The
	// initrd FIDO2 strategy finds the slot from that token and derives the
	// same key at boot. Without a handler EnrollFIDO2 answers
	// ErrLUKSFIDO2NotWired.
	//
	// TPM enrolment is on (ruling 673): the default handler seals a slot
	// passphrase and writes a systemd-tpm2 token, and the initrd
	// TPMTokenStrategy (pkg/initrd, registered by tpm-pcr) reads that token and
	// unseals it at boot, ahead of the ESP-sealed TPM-PCR strategy. The
	// handler is wrapped by pcrCheckedTPMHandler so an empty or
	// out-of-range PCR list is refused before the sealer runs or a slot is
	// written. The handler seals over src.TPM, the platform's selected TPM
	// (the initrd unseals over the same Platform.TPM); a nil src.TPM keeps
	// the SDK default device. With PlatformTPMOpener, a TPM character device
	// gives each enrolment its own connection to that device (the resource
	// manager keeps it apart from the platform's own TPM work), and an
	// in-process simulator lends the platform's transport (single-user test
	// hardware). With no TPM transport the handler stays nil.
	luks := NewLUKSBackend(logger, WithLUKSTPMOpener(src.TPM), WithDefaultLUKSHandlers())
	luks.SetTPMHandler(pcrCheckedTPMHandler(luks.TPMHandler()))
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
	src := PlatformSDKBackendSources(a.QuicBaaSSDKClient(), a.CA, PlatformAdminIdentity(a))
	src.TPM = PlatformTPMOpener(func() xkmssdk.TrustedPlatformModule { return a.TPM })
	return WireSDKBackends(d, src, a.Logger)
}
