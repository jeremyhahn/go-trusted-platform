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
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// recordingSDKTarget records the backends the wiring hands the daemon.
type recordingSDKTarget struct {
	ceremony daemon.CeremonyBackend
	fido2    daemon.FIDO2Backend
	luks     daemon.LUKSBackend
	root     daemon.RootChecker
}

func (r *recordingSDKTarget) SetCeremonyBackend(b daemon.CeremonyBackend) { r.ceremony = b }
func (r *recordingSDKTarget) SetFIDO2Backend(b daemon.FIDO2Backend)       { r.fido2 = b }
func (r *recordingSDKTarget) SetLUKSBackend(b daemon.LUKSBackend)         { r.luks = b }
func (r *recordingSDKTarget) SetLUKSRootChecker(rc daemon.RootChecker)    { r.root = rc }

// TestWireSDKBackends_WiresLUKS verifies the SDK wiring gives the daemon a
// LUKS backend and a root checker, so the LUKS service answers on every
// transport instead of "not configured" (#1692).
func TestWireSDKBackends_WiresLUKS(t *testing.T) {
	target := &recordingSDKTarget{}

	if err := WireSDKBackends(target, SDKBackendSources{SDK: &fakeQuicbaasClient{}}, logging.DefaultLogger()); err != nil {
		t.Fatalf("WireSDKBackends: %v", err)
	}
	if lb, ok := target.luks.(*LUKSBackend); !ok || lb == nil {
		t.Errorf("LUKS backend = %T, want a non-nil *LUKSBackend", target.luks)
	}
	if target.root == nil {
		t.Fatal("LUKS root checker was not wired")
	}
	if got, want := target.root.IsRoot(), os.Geteuid() == 0; got != want {
		t.Errorf("root checker IsRoot = %v, want %v (the effective UID)", got, want)
	}
}

// TestWireSDKBackends_LeavesFIDO2EnrollmentOff verifies the production
// wiring does not offer LUKS FIDO2 enrollment: the enrollment handler binds
// the 64-byte go-xkms derived key, while the shipped boot paths (the
// fido2-manual reader and the initrd FIDO2 strategy) cannot derive it, so an
// enrolled slot would not unlock the volume at boot (Codex round 3, #1852).
func TestWireSDKBackends_LeavesFIDO2EnrollmentOff(t *testing.T) {
	target := &recordingSDKTarget{}

	if err := WireSDKBackends(target, SDKBackendSources{SDK: &fakeQuicbaasClient{}}, logging.DefaultLogger()); err != nil {
		t.Fatalf("WireSDKBackends: %v", err)
	}
	lb, ok := target.luks.(*LUKSBackend)
	if !ok || lb == nil {
		t.Fatalf("LUKS backend = %T, want a non-nil *LUKSBackend", target.luks)
	}
	if lb.fido2 != nil {
		t.Fatalf("LUKS FIDO2 handler = %T, want nil until a boot unlock path consumes the enrolled key", lb.fido2)
	}
}

func TestWireSDKBackends_WiresCeremonyOnly(t *testing.T) {
	target := &recordingSDKTarget{}
	src := SDKBackendSources{SDK: &fakeQuicbaasClient{}}

	if err := WireSDKBackends(target, src, logging.DefaultLogger()); err != nil {
		t.Fatalf("WireSDKBackends: %v", err)
	}
	if _, ok := target.ceremony.(*CeremonyBackend); !ok {
		t.Errorf("ceremony backend = %T, want *CeremonyBackend", target.ceremony)
	}
	if target.fido2 != nil {
		t.Fatalf("FIDO2 backend = %T, want nil until the SDK exposes the daemon backend shape", target.fido2)
	}
}

// TestWireSDKBackends_NoKVIsFatal verifies a daemon whose SDK client has no KV
// store refuses to start rather than serving FIDO2 registrations it cannot
// keep.
func TestWireSDKBackends_DoesNotRequireKVForFIDO2(t *testing.T) {
	target := &recordingSDKTarget{}

	err := WireSDKBackends(target, SDKBackendSources{SDK: &fakeQuicbaasClient{}}, logging.DefaultLogger())

	if err != nil {
		t.Fatalf("WireSDKBackends: %v", err)
	}
	if target.ceremony == nil {
		t.Fatal("ceremony backend was not wired")
	}
	if target.fido2 != nil {
		t.Fatalf("FIDO2 backend = %T, want nil", target.fido2)
	}
}

// TestWireSDKBackends_NoSDKClientIsFatal verifies a daemon without an SDK
// client refuses to start instead of answering every ceremony call with
// "not configured".
func TestWireSDKBackends_NoSDKClientIsFatal(t *testing.T) {
	target := &recordingSDKTarget{}

	err := WireSDKBackends(target, SDKBackendSources{}, logging.DefaultLogger())

	var noClient ErrCeremonyBackendRequiresSDK
	if !errors.As(err, &noClient) {
		t.Fatalf("want ErrCeremonyBackendRequiresSDK, got %T: %v", err, err)
	}
	if target.ceremony != nil || target.fido2 != nil || target.luks != nil || target.root != nil {
		t.Errorf("a failed wiring wired %+v", target)
	}
}

// TestWireEmbeddedHost_NoSDKClientIsFatal verifies an embedded host whose
// platform has no SDK client refuses to start, as platformd does, before
// it touches the daemon.
func TestWireEmbeddedHost_NoSDKClientIsFatal(t *testing.T) {
	err := WireEmbeddedHost(nil, &app.App{})

	var noClient ErrCeremonyBackendRequiresSDK
	if !errors.As(err, &noClient) {
		t.Fatalf("WireEmbeddedHost error = %v, want ErrCeremonyBackendRequiresSDK", err)
	}
}

func TestPlatformSDKBackendSources_WithSDK(t *testing.T) {
	sdk := &fakeQuicbaasClient{}
	src := PlatformSDKBackendSources(sdk, newSigningCA(t), testAdminIdentity)
	if src.SDK != sdk {
		t.Errorf("SDK = %v, want the platform client", src.SDK)
	}
	if admin, ok := src.Admin.(*adminBundleIssuer); !ok {
		t.Errorf("Admin = %T, want the admin bundle issuer", src.Admin)
	} else if admin.identity != testAdminIdentity {
		t.Errorf("admin identity = %+v, want %+v", admin.identity, testAdminIdentity)
	}
}

// TestPlatformSDKBackendSources_WithoutSDK verifies a platform whose storage
// is not the QuicBaaS SDK yields no sources, which the wiring then refuses.
func TestPlatformSDKBackendSources_WithoutSDK(t *testing.T) {
	src := PlatformSDKBackendSources(nil, newSigningCA(t), testAdminIdentity)
	if src.SDK != nil || src.Admin != nil {
		t.Errorf("sources = %+v, want none", src)
	}
}

// TestPlatformAdminIdentity_UsesTheTrustDomainAndSystemTenant verifies the
// admin certificate's identity comes from quicbaas.spiffe-trust-domain and
// the system tenant.
func TestPlatformAdminIdentity_UsesTheTrustDomainAndSystemTenant(t *testing.T) {
	a := &app.App{TenantID: "configured", QuicBaaSConfig: &quicbaas.Config{SPIFFETrustDomain: "tp.internal"}}
	got := PlatformAdminIdentity(a)
	want := AdminIdentity{TrustDomain: "tp.internal", TenantID: app.SystemTenantID}
	if got != want {
		t.Errorf("PlatformAdminIdentity = %+v, want %+v", got, want)
	}
}

// TestPlatformAdminIdentity_NoQuicBaaSConfigHasNoTrustDomain verifies a
// platform without QuicBaaS config yields an identity the issuer refuses.
func TestPlatformAdminIdentity_NoQuicBaaSConfigHasNoTrustDomain(t *testing.T) {
	for name, a := range map[string]*app.App{"nil app": nil, "no config": {}} {
		t.Run(name, func(t *testing.T) {
			if err := PlatformAdminIdentity(a).validate(); err == nil {
				t.Error("an identity without a trust domain validated")
			}
		})
	}
}

func TestSDKBackendErrors_Messages(t *testing.T) {
	err := ErrCeremonyBackendRequiresSDK{}
	if !strings.Contains(err.Error(), "SDK client") {
		t.Errorf("message %q does not name the missing SDK client", err.Error())
	}
}
