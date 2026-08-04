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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	service "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// ---------------------------------------------------------------------------
// w1b-prefixed fakes (unique to this file to avoid collisions)
// ---------------------------------------------------------------------------

// w1bResolverCAErr returns a configurable error from CAPool and a normal
// TLSConfig so tests can drive the InternalCAPool error branches.
type w1bResolverCAErr struct {
	caPoolErr error
}

func (r *w1bResolverCAErr) TLSConfig(_ context.Context, _ trust.Class, _ string) (*tls.Config, error) {
	return &tls.Config{MinVersion: tls.VersionTLS12}, nil
}

func (r *w1bResolverCAErr) CAPool(_ context.Context, _ trust.Class, _ string) (*x509.CertPool, error) {
	return nil, r.caPoolErr
}

func (r *w1bResolverCAErr) CABundlePEM(_ context.Context, _ trust.Class) ([]byte, error) {
	return nil, nil
}

var _ trust.Resolver = (*w1bResolverCAErr)(nil)

// w1bResolverCAPool returns a fresh pool from CAPool.
type w1bResolverCAPool struct{}

func (r *w1bResolverCAPool) TLSConfig(_ context.Context, _ trust.Class, _ string) (*tls.Config, error) {
	return &tls.Config{MinVersion: tls.VersionTLS12}, nil
}

func (r *w1bResolverCAPool) CAPool(_ context.Context, _ trust.Class, _ string) (*x509.CertPool, error) {
	return x509.NewCertPool(), nil
}

func (r *w1bResolverCAPool) CABundlePEM(_ context.Context, _ trust.Class) ([]byte, error) {
	return nil, nil
}

var _ trust.Resolver = (*w1bResolverCAPool)(nil)

// ---------------------------------------------------------------------------
// resolverTLSProvider.TLSConfig (0% → 100%)
// ---------------------------------------------------------------------------

func TestW1bResolverTLSProvider_TLSConfig_Success(t *testing.T) {
	p := &resolverTLSProvider{resolver: &fakeResolver{}, class: trust.ClassBMC}
	cfg, err := p.TLSConfig(context.Background(), "host:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Error("expected non-nil TLS config")
	}
}

func TestW1bResolverTLSProvider_TLSConfig_Error(t *testing.T) {
	wantErr := errors.New("resolver unavailable")
	p := &resolverTLSProvider{
		resolver: &fakeResolver{tlsErr: wantErr},
		class:    trust.ClassBMC,
	}
	_, err := p.TLSConfig(context.Background(), "host:443")
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

// ---------------------------------------------------------------------------
// TrustResolver (72.7% → 100%)
// ---------------------------------------------------------------------------

// TestW1bTrustResolver_CacheHit verifies that a pre-set trustResolver is
// returned without rebuilding it.
func TestW1bTrustResolver_CacheHit(t *testing.T) {
	cached := &fakeResolver{}
	app := &App{
		Logger:        logging.DefaultLogger(),
		trustResolver: cached,
	}
	got := app.TrustResolver()
	if got != cached {
		t.Errorf("TrustResolver() = %v, want cached resolver", got)
	}
}

// TestW1bTrustResolver_NilTrustConfig verifies that nil TrustConfig returns nil.
func TestW1bTrustResolver_NilTrustConfig(t *testing.T) {
	app := &App{
		Logger:      logging.DefaultLogger(),
		TrustConfig: nil,
	}
	if got := app.TrustResolver(); got != nil {
		t.Errorf("TrustResolver() = %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// BMCTLSProvider (0% → 100%)
// ---------------------------------------------------------------------------

// TestW1bBMCTLSProvider_NilResolver verifies nil is returned when TrustConfig
// is absent (resolver cannot be built).
func TestW1bBMCTLSProvider_NilResolver(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	if got := app.BMCTLSProvider(); got != nil {
		t.Errorf("BMCTLSProvider() = %v, want nil", got)
	}
}

// TestW1bBMCTLSProvider_NonNilResolver verifies a provider is returned when a
// resolver is available (set via the cache field so no live resolver build).
func TestW1bBMCTLSProvider_NonNilResolver(t *testing.T) {
	app := &App{
		Logger:        logging.DefaultLogger(),
		trustResolver: &fakeResolver{},
	}
	got := app.BMCTLSProvider()
	if got == nil {
		t.Fatal("expected non-nil BMCTLSProvider")
	}
	// Verify the returned provider uses the cached resolver.
	cfg, err := got.TLSConfig(context.Background(), "host:443")
	if err != nil {
		t.Fatalf("BMCTLSProvider.TLSConfig: %v", err)
	}
	if cfg == nil {
		t.Error("expected non-nil TLS config from provider")
	}
}

// ---------------------------------------------------------------------------
// InternalCAPool (80% → 100%)
// ---------------------------------------------------------------------------

// TestW1bInternalCAPool_NilResolver verifies (nil, nil) when no resolver is
// available.
func TestW1bInternalCAPool_NilResolver(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	pool, err := app.InternalCAPool(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool != nil {
		t.Error("expected nil pool when resolver unavailable")
	}
}

// TestW1bInternalCAPool_ErrClassNotConfigured verifies (nil, nil) when the
// resolver returns ErrClassNotConfigured (internal scope not configured).
func TestW1bInternalCAPool_ErrClassNotConfigured(t *testing.T) {
	notCfg := &trust.ErrClassNotConfigured{Class: trust.ClassInternal}
	app := &App{
		Logger:        logging.DefaultLogger(),
		trustResolver: &w1bResolverCAErr{caPoolErr: notCfg},
	}
	pool, err := app.InternalCAPool(context.Background())
	if err != nil {
		t.Fatalf("ErrClassNotConfigured should yield (nil, nil), got err=%v", err)
	}
	if pool != nil {
		t.Error("expected nil pool for ErrClassNotConfigured")
	}
}

// TestW1bInternalCAPool_OtherError verifies a non-ErrClassNotConfigured
// error from CAPool is surfaced to the caller.
func TestW1bInternalCAPool_OtherError(t *testing.T) {
	wantErr := errors.New("ca pool unavailable")
	app := &App{
		Logger:        logging.DefaultLogger(),
		trustResolver: &w1bResolverCAErr{caPoolErr: wantErr},
	}
	_, err := app.InternalCAPool(context.Background())
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

// TestW1bInternalCAPool_Success verifies a valid pool is returned when the
// resolver can build it.
func TestW1bInternalCAPool_Success(t *testing.T) {
	app := &App{
		Logger:        logging.DefaultLogger(),
		trustResolver: &w1bResolverCAPool{},
	}
	pool, err := app.InternalCAPool(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Error("expected non-nil pool on success path")
	}
}

// ---------------------------------------------------------------------------
// effectiveEnrollmentOpts – missing RotatePassword and DANEPublish overrides
// (86.7% → 100%)
// ---------------------------------------------------------------------------

// TestW1bEffectiveEnrollmentOpts_AllFlagOverrides exercises every optional
// pointer field including RotatePassword and DANEPublish.
func TestW1bEffectiveEnrollmentOpts_AllFlagOverrides(t *testing.T) {
	trueVal := true
	falseVal := false
	cfg := &bmc.Config{Address: "host"}
	opts := &BMCEnrollOptions{
		ReplaceCertificate: &trueVal,
		RotatePassword:     &falseVal,
		DNSRegister:        &trueVal,
		DANEPublish:        &trueVal,
	}
	flags := effectiveEnrollmentOpts(cfg, opts)
	if !flags.ReplaceCertificate {
		t.Error("ReplaceCertificate should be true")
	}
	if flags.RotatePassword {
		t.Error("RotatePassword should be false (overridden)")
	}
	if !flags.DNSRegister {
		t.Error("DNSRegister should be true")
	}
	if !flags.DANEPublish {
		t.Error("DANEPublish should be true")
	}
}

// TestW1bEffectiveEnrollmentOpts_RotatePasswordOverride exercises the
// RotatePassword pointer-override path in isolation.
func TestW1bEffectiveEnrollmentOpts_RotatePasswordOverride(t *testing.T) {
	trueVal := true
	cfg := &bmc.Config{Address: "host"}
	opts := &BMCEnrollOptions{RotatePassword: &trueVal}
	flags := effectiveEnrollmentOpts(cfg, opts)
	if !flags.RotatePassword {
		t.Error("RotatePassword should be true after override")
	}
}

// TestW1bEffectiveEnrollmentOpts_DANEPublishOverride exercises the DANEPublish
// pointer-override path in isolation.
func TestW1bEffectiveEnrollmentOpts_DANEPublishOverride(t *testing.T) {
	trueVal := true
	cfg := &bmc.Config{Address: "host"}
	opts := &BMCEnrollOptions{DANEPublish: &trueVal}
	flags := effectiveEnrollmentOpts(cfg, opts)
	if !flags.DANEPublish {
		t.Error("DANEPublish should be true after override")
	}
}

// ---------------------------------------------------------------------------
// loadDeviceForEnroll / saveDeviceForEnroll (0% → ~60%)
//
// The "service registry not available" branch requires ServiceRegistry() to
// return nil. ServiceRegistry() either succeeds or calls FatalError — it
// never returns nil — so that branch is unreachable in unit tests (seam
// needed: ServiceRegistry() should accept an injected registry or return an
// error rather than fatalling). The "device service not available" branch IS
// reachable by setting app.serviceRegistry to a zero-value &service.Registry{}
// (which has a nil DeviceService field).
// ---------------------------------------------------------------------------

// TestW1bLoadDeviceForEnroll_NilDeviceService covers the "device service not
// available" error path by pre-setting the serviceRegistry to a zero-value
// Registry whose DeviceService() returns nil.
func TestW1bLoadDeviceForEnroll_NilDeviceService(t *testing.T) {
	app := &App{
		Logger:          logging.DefaultLogger(),
		serviceRegistry: &service.Registry{},
	}
	_, err := app.loadDeviceForEnroll(context.Background(), 42)
	if err == nil {
		t.Fatal("expected error when device service is nil")
	}
	var loadErr ErrBMCEnrollDeviceLoad
	if !errors.As(err, &loadErr) {
		t.Errorf("err type = %T, want ErrBMCEnrollDeviceLoad", err)
	}
	if loadErr.DeviceID != 42 {
		t.Errorf("DeviceID = %d, want 42", loadErr.DeviceID)
	}
}

// TestW1bSaveDeviceForEnroll_NilDeviceService covers the "device service not
// available" error path for saveDeviceForEnroll.
func TestW1bSaveDeviceForEnroll_NilDeviceService(t *testing.T) {
	app := &App{
		Logger:          logging.DefaultLogger(),
		serviceRegistry: &service.Registry{},
	}
	dev := &entities.Device{ID: 7}
	err := app.saveDeviceForEnroll(context.Background(), dev)
	if err == nil {
		t.Fatal("expected error when device service is nil")
	}
	var saveErr ErrBMCEnrollDeviceSave
	if !errors.As(err, &saveErr) {
		t.Errorf("err type = %T, want ErrBMCEnrollDeviceSave", err)
	}
	if saveErr.DeviceID != 7 {
		t.Errorf("DeviceID = %d, want 7", saveErr.DeviceID)
	}
}

// ---------------------------------------------------------------------------
// updateTOFUPin (0% → ~50%)
//
// The non-nil *quicbaas.Factory path requires a live embedded server and
// is integration-only. The nil daoFactory fast-exit IS unit-testable.
// ---------------------------------------------------------------------------

// TestW1bUpdateTOFUPin_NilDAOFactory verifies that updateTOFUPin is a no-op
// (returns nil) when daoFactory is nil — the most common case in unit tests.
func TestW1bUpdateTOFUPin_NilDAOFactory(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	// daoFactory is nil by default on a zero-value App.
	err := app.updateTOFUPin(context.Background(), "host", 443, "spki", "fp")
	if err != nil {
		t.Errorf("updateTOFUPin with nil daoFactory: %v", err)
	}
}

// ---------------------------------------------------------------------------
// EnrollBMC (0% → ~40%)
//
// The full happy path requires a live BMC; tested in integration.
// Nil-config and nil-resolver paths ARE unit-testable.
// ---------------------------------------------------------------------------

// TestW1bEnrollBMC_NilConfig verifies that a nil bmcCfg returns ErrNilConfig.
func TestW1bEnrollBMC_NilConfig(t *testing.T) {
	app := &App{
		Logger:        logging.DefaultLogger(),
		trustResolver: &fakeResolver{},
	}
	_, err := app.EnrollBMC(context.Background(), 1, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil bmcCfg")
	}
	var nilCfg bmc.ErrNilConfig
	if !errors.As(err, &nilCfg) {
		t.Errorf("err type = %T, want bmc.ErrNilConfig", err)
	}
}

// TestW1bEnrollBMC_NoTrustResolver verifies ErrBMCEnrollNoTrustResolver is
// returned when the App has no trust config (resolver is nil).
func TestW1bEnrollBMC_NoTrustResolver(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	cfg := &bmc.Config{Address: "host", Port: 623, Protocol: bmc.ProtocolIPMI}
	_, err := app.EnrollBMC(context.Background(), 1, cfg, nil)
	if err == nil {
		t.Fatal("expected error when trust resolver is unavailable")
	}
	var noResolver ErrBMCEnrollNoTrustResolver
	if !errors.As(err, &noResolver) {
		t.Errorf("err type = %T, want ErrBMCEnrollNoTrustResolver", err)
	}
}

// ---------------------------------------------------------------------------
// TrustResolver – NewResolver failure path (81.8% → 100%)
//
// ClassBMC does not allow StrategyNoise. Providing that combination forces
// config.Validate() to fail inside NewResolver, which causes TrustResolver
// to log a warning and return nil — covering the `if err != nil { return nil }`
// branch that is otherwise unreachable when TrustConfig is valid.
// ---------------------------------------------------------------------------

// TestW1bTrustResolver_NewResolverFails verifies that TrustResolver returns nil
// when trust.NewResolver rejects the config (invalid per-class strategy).
func TestW1bTrustResolver_NewResolverFails(t *testing.T) {
	// StrategyNoise is allowed for ClassDefault but NOT for ClassBMC.
	// Validate() will return ErrStrategyNotAllowed, causing NewResolver to fail.
	app := &App{
		Logger: logging.DefaultLogger(),
		TrustConfig: &trust.Config{
			BMC: &trust.ScopeConfig{
				Strategies: []trust.Strategy{trust.StrategyNoise},
			},
		},
	}
	got := app.TrustResolver()
	if got != nil {
		t.Errorf("TrustResolver() = non-nil, want nil when NewResolver fails")
	}
}
