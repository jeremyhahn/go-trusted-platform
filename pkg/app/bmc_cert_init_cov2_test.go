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

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	service "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"

	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// ---------------------------------------------------------------------------
// CertManagementScheduler (0% → 100%)
//
// When daoFactory is nil, QuicBaaSService() returns nil and therefore
// CertManagementScheduler returns nil.
// ---------------------------------------------------------------------------

func TestW1bCertManagementScheduler_NilFactory(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	got := app.CertManagementScheduler()
	if got != nil {
		t.Errorf("CertManagementScheduler() = %v, want nil when daoFactory is nil", got)
	}
}

// ---------------------------------------------------------------------------
// InitCertManagement (0% → ~80%)
//
// Full success (BMC deploy + RegisterCertRenewal) requires a live BMC and is
// integration-only. The early error paths and the no-BMC-config path are
// unit-testable.
// ---------------------------------------------------------------------------

// TestW1bInitCertManagement_NilScheduler verifies ErrCertRenewalMissingScheduler.
func TestW1bInitCertManagement_NilScheduler(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	err := app.InitCertManagement(context.Background(), nil, "node-A")
	if !errors.Is(err, ErrCertRenewalMissingScheduler) {
		t.Errorf("err = %v, want ErrCertRenewalMissingScheduler", err)
	}
}

// TestW1bInitCertManagement_EmptyNodeID verifies ErrInitBMCCertMissingNodeID.
func TestW1bInitCertManagement_EmptyNodeID(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	err := app.InitCertManagement(context.Background(), newFakeScheduler(), "")
	if !errors.Is(err, ErrInitBMCCertMissingNodeID) {
		t.Errorf("err = %v, want ErrInitBMCCertMissingNodeID", err)
	}
}

// TestW1bInitCertManagement_NoBMCConfig exercises the no-BMC-config branch
// which falls through to RegisterCertRenewal. The fake scheduler accepts the
// handler and job without error.
func TestW1bInitCertManagement_NoBMCConfig(t *testing.T) {
	sched := newFakeScheduler()
	app := &App{
		Logger:    logging.DefaultLogger(),
		BMCConfig: nil, // no BMC
	}
	err := app.InitCertManagement(context.Background(), sched, "node-A")
	if err != nil {
		t.Fatalf("InitCertManagement with no BMC config: %v", err)
	}
}

// TestW1bInitCertManagement_WithBMCConfigNilCA exercises the BMC-config branch
// which calls initBMCCertManagement. With CA == nil, initBMCCertManagement
// returns ErrMissingLocalCAIssuer which is propagated.
func TestW1bInitCertManagement_WithBMCConfigNilCA(t *testing.T) {
	sched := newFakeScheduler()
	app := &App{
		Logger: logging.DefaultLogger(),
		BMCConfig: &bmc.Config{
			Address:  "1.2.3.4",
			Port:     623,
			Protocol: bmc.ProtocolIPMI,
			Certificate: &common.Identity{
				Subject: xkmsca.CASubject{CommonName: "bmc01.internal"},
			},
		},
		CA: nil, // no local CA
	}
	err := app.InitCertManagement(context.Background(), sched, "node-A")
	if err == nil {
		t.Fatal("expected error when CA is nil")
	}
	// ErrMissingLocalCAIssuer propagated through initBMCCertManagement.
	if !errors.Is(err, ErrMissingLocalCAIssuer) {
		t.Errorf("err = %v, want ErrMissingLocalCAIssuer", err)
	}
}

// ---------------------------------------------------------------------------
// buildBMCRenewalHooks (0% → ~70%)
//
// The DANE-enabled path requires a live ensureDANEPublisher which needs
// app.DNSService and app.DNSConfig.DANE — integration-only. The no-DANE
// paths (DANE nil / DNSConfig nil / daoFactory nil for pinUpdater) are
// unit-testable.
// ---------------------------------------------------------------------------

// TestW1bBuildBMCRenewalHooks_NilDNSConfig verifies that both hooks are
// callable and return nil when DANE is not configured and pin store is
// unavailable.
func TestW1bBuildBMCRenewalHooks_NilDNSConfig(t *testing.T) {
	leaf := testIssuedCertificate()
	app := &App{
		Logger:    logging.DefaultLogger(),
		BMCConfig: &bmc.Config{Address: "1.2.3.4"},
		// DNSConfig nil → dp is nil, internalZone is ""
		// daoFactory nil → pinUpdater is nil
	}
	onIssued, onDeployed := app.buildBMCRenewalHooks()
	if onIssued == nil {
		t.Fatal("expected non-nil onIssued closure")
	}
	if onDeployed == nil {
		t.Fatal("expected non-nil onDeployed closure")
	}
	// Both hooks should be no-ops (DANE nil, pinUpdater nil).
	if err := onIssued(context.Background(), leaf); err != nil {
		t.Errorf("onIssued: %v", err)
	}
	if err := onDeployed(context.Background(), leaf, nil); err != nil {
		t.Errorf("onDeployed: %v", err)
	}
}

// TestW1bBuildBMCRenewalHooks_NilBMCConfig verifies that both hooks are
// callable when BMCConfig is nil (bmcHost is "").
func TestW1bBuildBMCRenewalHooks_NilBMCConfig(t *testing.T) {
	leaf := testIssuedCertificate()
	app := &App{
		Logger:    logging.DefaultLogger(),
		BMCConfig: nil,
	}
	onIssued, onDeployed := app.buildBMCRenewalHooks()
	if err := onIssued(context.Background(), leaf); err != nil {
		t.Errorf("onIssued with nil BMCConfig: %v", err)
	}
	if err := onDeployed(context.Background(), leaf, nil); err != nil {
		t.Errorf("onDeployed with nil BMCConfig: %v", err)
	}
}

// ---------------------------------------------------------------------------
// buildBMCDNSNameLoader (0% → ~60%)
//
// The ServiceRegistry() path (non-empty bmcHost) would require a live
// daoFactory → integration-only. The empty-bmcHost fast return IS testable.
// ---------------------------------------------------------------------------

// TestW1bBuildBMCDNSNameLoader_EmptyHost verifies that an empty bmcHost
// causes the loader to return "" immediately without touching the service
// registry.
func TestW1bBuildBMCDNSNameLoader_EmptyHost(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	loader := app.buildBMCDNSNameLoader("")
	if loader == nil {
		t.Fatal("expected non-nil loader closure")
	}
	got := loader(context.Background())
	if got != "" {
		t.Errorf("loader with empty bmcHost = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// bmcPinUpdater (0% → ~50%)
//
// The non-nil *quicbaas.Factory path needs a live embedded server →
// integration-only. The nil daoFactory fast-exit IS testable.
// ---------------------------------------------------------------------------

// TestW1bBMCPinUpdater_NilDAOFactory verifies that bmcPinUpdater returns nil
// (no pin store available) when daoFactory is nil.
func TestW1bBMCPinUpdater_NilDAOFactory(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	updater := app.bmcPinUpdater()
	if updater != nil {
		t.Error("bmcPinUpdater() should return nil when daoFactory is nil")
	}
}

// ---------------------------------------------------------------------------
// InitCertManagement – BMCConfig present but Certificate nil (90.9% → 100%)
//
// When app.BMCConfig != nil but app.BMCConfig.Certificate == nil, the BMC
// branch guard (`app.BMCConfig != nil && app.BMCConfig.Certificate != nil`)
// evaluates to false and execution falls through to RegisterCertRenewal —
// the same path as the no-BMC case. This exercises the previously untested
// "BMC config present but cert disabled" combination.
// ---------------------------------------------------------------------------

// TestW1bInitCertManagement_BMCConfigNilCertificate verifies that a BMCConfig
// without a Certificate block falls through to RegisterCertRenewal (no error).
func TestW1bInitCertManagement_BMCConfigNilCertificate(t *testing.T) {
	sched := newFakeScheduler()
	app := &App{
		Logger: logging.DefaultLogger(),
		BMCConfig: &bmc.Config{
			Address:     "1.2.3.4",
			Port:        623,
			Protocol:    bmc.ProtocolIPMI,
			Certificate: nil, // cert management disabled → falls through to RegisterCertRenewal
		},
	}
	err := app.InitCertManagement(context.Background(), sched, "node-A")
	if err != nil {
		t.Fatalf("InitCertManagement with nil BMCConfig.Certificate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// buildBMCDNSNameLoader – non-empty host, nil DeviceService (23.1% → ~55%)
//
// When bmcHost is non-empty the closure proceeds past the early return.
// With app.serviceRegistry set to a zero-value *service.Registry, the closure
// calls ServiceRegistry() (returns the non-nil zero-value registry) and then
// DeviceService() which returns nil on a zero-value registry, triggering the
// `if svc == nil { return "" }` path. This covers the main function body
// without requiring a live device service.
// ---------------------------------------------------------------------------

// TestW1bBuildBMCDNSNameLoader_NonEmptyHostNilDeviceService verifies that the
// loader returns "" when bmcHost is non-empty but DeviceService is unavailable.
func TestW1bBuildBMCDNSNameLoader_NonEmptyHostNilDeviceService(t *testing.T) {
	app := &App{
		Logger:          logging.DefaultLogger(),
		serviceRegistry: &service.Registry{}, // DeviceService() returns nil on zero-value
	}
	loader := app.buildBMCDNSNameLoader("1.2.3.4")
	if loader == nil {
		t.Fatal("expected non-nil loader closure")
	}
	got := loader(context.Background())
	if got != "" {
		t.Errorf("loader with nil DeviceService = %q, want empty string", got)
	}
}
