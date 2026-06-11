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

package trust

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/bootstrap"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// validHexPin is a syntactically valid 64-hex-char SHA-256 SPKI pin.
var validHexPin = strings.Repeat("ab", 32)

func testLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

// testCAPEM generates a self-signed CA certificate PEM for pool tests.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Trust Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// fakePinStore returns a fixed pin or error for any endpoint.
type fakePinStore struct {
	pin string
	err error
}

func (s *fakePinStore) SPKIPin(_ context.Context, _ string) (string, error) {
	return s.pin, s.err
}

// fakeBundleProvider returns a fixed bundle or error and counts calls.
type fakeBundleProvider struct {
	bundle []byte
	err    error
	calls  atomic.Int64
}

func (p *fakeBundleProvider) CABundle(_ context.Context) ([]byte, error) {
	p.calls.Add(1)
	return p.bundle, p.err
}

func newTestResolver(t *testing.T, cfg *Config, opts ...Option) Resolver {
	t.Helper()
	resolver, err := NewResolver(cfg, testLogger(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func TestNewResolver_NilConfig(t *testing.T) {
	_, err := NewResolver(nil, testLogger())
	if !errors.Is(err, ErrNilConfig{}) {
		t.Fatalf("expected ErrNilConfig, got %v", err)
	}
}

func TestNewResolver_NilLogger(t *testing.T) {
	_, err := NewResolver(DefaultConfig(), nil)
	if !errors.Is(err, ErrNilLogger{}) {
		t.Fatalf("expected ErrNilLogger, got %v", err)
	}
}

func TestNewResolver_InvalidConfig(t *testing.T) {
	cfg := &Config{Default: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	_, err := NewResolver(cfg, testLogger())
	var notAllowed *ErrStrategyNotAllowed
	if !errors.As(err, &notAllowed) {
		t.Fatalf("expected ErrStrategyNotAllowed, got %v", err)
	}
}

func TestTLSConfig_ClassNotConfigured(t *testing.T) {
	resolver := newTestResolver(t, DefaultConfig())
	_, err := resolver.TLSConfig(t.Context(), ClassBMC, "")
	var notConfigured *ErrClassNotConfigured
	if !errors.As(err, &notConfigured) {
		t.Fatalf("expected ErrClassNotConfigured, got %v", err)
	}
	if notConfigured.Class != ClassBMC {
		t.Errorf("expected bmc class, got %s", notConfigured.Class)
	}
}

func TestTLSConfig_SPKI(t *testing.T) {
	cfg := &Config{Default: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{Pin: validHexPin},
	}}
	resolver := newTestResolver(t, cfg)
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassDefault, "peer.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	// Custom-verifier pattern: pin verification is the sole verifier.
	if !tlsCfg.InsecureSkipVerify {
		t.Error("expected custom-verifier pattern (InsecureSkipVerify with VerifyPeerCertificate)")
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("expected VerifyPeerCertificate to be set")
	}
}

func TestTLSConfig_SPKI_InvalidPin(t *testing.T) {
	cfg := &Config{Default: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{Pin: "not-a-valid-pin"},
	}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.TLSConfig(t.Context(), ClassDefault, "peer.example.com:443")
	var noStrategy *ErrNoStrategySucceeded
	if !errors.As(err, &noStrategy) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %v", err)
	}
	if len(noStrategy.Attempts) != 1 || noStrategy.Attempts[0].Strategy != StrategySPKI {
		t.Errorf("expected single spki attempt, got %+v", noStrategy.Attempts)
	}
}

func TestTLSConfig_Embedded(t *testing.T) {
	cfg := &Config{Default: &ScopeConfig{Strategies: []Strategy{StrategyEmbedded}}}
	resolver := newTestResolver(t, cfg)
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassDefault, "")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 minimum, got %d", tlsCfg.MinVersion)
	}
	if tlsCfg.RootCAs != nil {
		t.Error("expected nil RootCAs (system trust store)")
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("embedded strategy must use standard verification")
	}
}

func TestTLSConfig_CAFile(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, testCAPEM(t), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{BMC: &ScopeConfig{
		Strategies: []Strategy{StrategyCAFile},
		CAFile:     caFile,
	}}
	resolver := newTestResolver(t, cfg)
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassBMC, "bmc.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected RootCAs from CA file")
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("ca-file strategy must use standard verification")
	}
}

func TestTLSConfig_CAFile_Missing(t *testing.T) {
	cfg := &Config{BMC: &ScopeConfig{
		Strategies: []Strategy{StrategyCAFile},
		CAFile:     filepath.Join(t.TempDir(), "missing.pem"),
	}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.TLSConfig(t.Context(), ClassBMC, "bmc.example.com:443")
	var noStrategy *ErrNoStrategySucceeded
	if !errors.As(err, &noStrategy) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %v", err)
	}
	var caFileErr *ErrCAFileRead
	if !errors.As(err, &caFileErr) {
		t.Fatalf("expected ErrCAFileRead in attempt chain, got %v", err)
	}
}

func TestTLSConfig_PlatformCA(t *testing.T) {
	provider := &fakeBundleProvider{bundle: testCAPEM(t)}
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	resolver := newTestResolver(t, cfg, WithPlatformCA(provider))
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassInternal, "svc.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected RootCAs from platform CA provider")
	}
}

func TestTLSConfig_PlatformCA_NoProvider(t *testing.T) {
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.TLSConfig(t.Context(), ClassInternal, "")
	if !errors.Is(err, ErrPlatformCAUnavailable{}) {
		t.Fatalf("expected ErrPlatformCAUnavailable in chain, got %v", err)
	}
}

func TestTLSConfig_PinStorePrecedence(t *testing.T) {
	// Scope has no static pin; the store supplies the endpoint pin.
	store := &fakePinStore{pin: validHexPin}
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategySPKI}}}
	resolver := newTestResolver(t, cfg, WithPinStore(store))
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassBMC, "bmc.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("expected pinned TLS config from pin store")
	}
}

func TestTLSConfig_PinStoreMissFallsBackToScopePin(t *testing.T) {
	store := &fakePinStore{err: &ErrPinNotFound{Endpoint: "bmc.example.com:443"}}
	cfg := &Config{BMC: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{Pin: validHexPin},
	}}
	resolver := newTestResolver(t, cfg, WithPinStore(store))
	if _, err := resolver.TLSConfig(t.Context(), ClassBMC, "bmc.example.com:443"); err != nil {
		t.Fatalf("expected fallback to scope pin, got %v", err)
	}
}

func TestTLSConfig_PinStoreErrorPropagates(t *testing.T) {
	storeErr := errors.New("store offline")
	store := &fakePinStore{err: storeErr}
	cfg := &Config{BMC: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{Pin: validHexPin},
	}}
	resolver := newTestResolver(t, cfg, WithPinStore(store))
	_, err := resolver.TLSConfig(t.Context(), ClassBMC, "bmc.example.com:443")
	if !errors.Is(err, storeErr) {
		t.Fatalf("expected store error to propagate, got %v", err)
	}
}

func TestTLSConfig_NoPinAnywhere(t *testing.T) {
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategySPKI}}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.TLSConfig(t.Context(), ClassBMC, "bmc.example.com:443")
	var pinErr *ErrPinNotFound
	if !errors.As(err, &pinErr) {
		t.Fatalf("expected ErrPinNotFound in chain, got %v", err)
	}
	if pinErr.Endpoint != "bmc.example.com:443" {
		t.Errorf("expected endpoint in error, got %q", pinErr.Endpoint)
	}
}

func TestTLSConfig_FallbackChain(t *testing.T) {
	// First strategy (spki, no pin) fails; second (ca-file) succeeds.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, testCAPEM(t), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{BMC: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI, StrategyCAFile},
		CAFile:     caFile,
	}}
	resolver := newTestResolver(t, cfg)
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassBMC, "bmc.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected ca-file fallback to produce RootCAs")
	}
}

func TestTLSConfig_UnconfiguredStrategiesSkipped(t *testing.T) {
	// noise (no config) fails as a runtime attempt; the chain falls
	// through to embedded.
	cfg := &Config{Default: &ScopeConfig{
		Strategies: []Strategy{StrategyNoise, StrategyEmbedded},
	}}
	resolver := newTestResolver(t, cfg)
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassDefault, "")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.RootCAs != nil || tlsCfg.InsecureSkipVerify {
		t.Error("expected embedded fallback config")
	}

	bmcCfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyCAFile}}}
	bmcResolver := newTestResolver(t, bmcCfg)
	_, err = bmcResolver.TLSConfig(t.Context(), ClassBMC, "bmc.example.com:443")
	// The generic resolver returns ErrInvalidConfig via ErrNoStrategySucceeded;
	// the platform wrapper surfaces it as ErrNoStrategySucceeded too.
	var noStrategy *ErrNoStrategySucceeded
	if !errors.As(err, &noStrategy) {
		t.Fatalf("expected ErrNoStrategySucceeded for empty ca-file, got %v", err)
	}
}

func TestTLSConfig_DANE_InvalidEndpoint(t *testing.T) {
	cfg := &Config{Default: &ScopeConfig{Strategies: []Strategy{StrategyDANE}}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.TLSConfig(t.Context(), ClassDefault, "no-port-here")
	var endpointErr *ErrEndpointInvalid
	if !errors.As(err, &endpointErr) {
		t.Fatalf("expected ErrEndpointInvalid in chain, got %v", err)
	}
}

func TestCAPool_ClassNotConfigured(t *testing.T) {
	resolver := newTestResolver(t, DefaultConfig())
	_, err := resolver.CAPool(t.Context(), ClassInternal, "")
	var notConfigured *ErrClassNotConfigured
	if !errors.As(err, &notConfigured) {
		t.Fatalf("expected ErrClassNotConfigured, got %v", err)
	}
}

func TestCAPool_CAFile(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, testCAPEM(t), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{BMC: &ScopeConfig{
		Strategies: []Strategy{StrategyCAFile},
		CAFile:     caFile,
	}}
	resolver := newTestResolver(t, cfg)
	pool, err := resolver.CAPool(t.Context(), ClassBMC, "bmc.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestCAPool_Embedded(t *testing.T) {
	cfg := &Config{Default: &ScopeConfig{Strategies: []Strategy{StrategyEmbedded}}}
	resolver := newTestResolver(t, cfg)
	pool, err := resolver.CAPool(t.Context(), ClassDefault, "")
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected system cert pool")
	}
}

func TestCAPool_CachesPerClassEndpoint(t *testing.T) {
	provider := &fakeBundleProvider{bundle: testCAPEM(t)}
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	resolver := newTestResolver(t, cfg, WithPlatformCA(provider))

	first, err := resolver.CAPool(t.Context(), ClassInternal, "svc.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.CAPool(t.Context(), ClassInternal, "svc.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("expected cached pool to be returned on second call")
	}
	if calls := provider.calls.Load(); calls != 1 {
		t.Errorf("expected exactly 1 provider call, got %d", calls)
	}

	// A different endpoint is a separate cache entry.
	if _, err := resolver.CAPool(t.Context(), ClassInternal, "other.example.com:8443"); err != nil {
		t.Fatal(err)
	}
	if calls := provider.calls.Load(); calls != 2 {
		t.Errorf("expected 2 provider calls after new endpoint, got %d", calls)
	}
}

func TestCABundlePEM_Embedded(t *testing.T) {
	cfg := &Config{Default: &ScopeConfig{Strategies: []Strategy{StrategyEmbedded}}}
	resolver := newTestResolver(t, cfg)
	pem, err := resolver.CABundlePEM(t.Context(), ClassDefault)
	if err != nil {
		t.Fatal(err)
	}
	if pem != nil {
		t.Error("expected nil PEM for embedded strategy (OS trust store is authoritative)")
	}
}

func TestCABundlePEM_CAFile(t *testing.T) {
	caPEM := testCAPEM(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{BMC: &ScopeConfig{
		Strategies: []Strategy{StrategyCAFile},
		CAFile:     caFile,
	}}
	resolver := newTestResolver(t, cfg)
	pemResult, err := resolver.CABundlePEM(t.Context(), ClassBMC)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pemResult, caPEM) {
		t.Error("expected CA file bytes")
	}
}

func TestCABundlePEM_PlatformCA(t *testing.T) {
	caPEM := testCAPEM(t)
	provider := &fakeBundleProvider{bundle: caPEM}
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	resolver := newTestResolver(t, cfg, WithPlatformCA(provider))
	pemResult, err := resolver.CABundlePEM(t.Context(), ClassInternal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pemResult, caPEM) {
		t.Error("expected provider bundle bytes")
	}
}

func TestCABundlePEM_PlatformCA_EmptyBundle(t *testing.T) {
	provider := &fakeBundleProvider{bundle: nil}
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	resolver := newTestResolver(t, cfg, WithPlatformCA(provider))
	_, err := resolver.CABundlePEM(t.Context(), ClassInternal)
	if !errors.Is(err, ErrCABundleEmpty{}) {
		t.Fatalf("expected ErrCABundleEmpty in chain, got %v", err)
	}
}

func TestCABundlePEM_FetchFailure(t *testing.T) {
	// SPKI fetch with no server URL fails inside the SDK without any
	// network activity; the resolver must surface it through
	// ErrFetchFailed inside ErrNoStrategySucceeded.
	cfg := &Config{Default: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{Pin: validHexPin},
	}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.CABundlePEM(t.Context(), ClassDefault)
	var fetchErr *ErrFetchFailed
	if !errors.As(err, &fetchErr) {
		t.Fatalf("expected ErrFetchFailed in chain, got %v", err)
	}
	if !errors.Is(err, bootstrap.ErrServerURLRequired) {
		t.Fatalf("expected ErrServerURLRequired cause, got %v", err)
	}
}

// =============================================================================
// Platform-ca normalization: end-to-end verification that platform-ca in the
// strategy list reaches the generic resolver as provider-ca.
// =============================================================================

func TestPlatformCA_Normalization_RoundTrip(t *testing.T) {
	// Verify that platform-ca in the strategies list successfully routes
	// through the provider-ca normalization to the injected provider.
	caPEM := testCAPEM(t)
	provider := &fakeBundleProvider{bundle: caPEM}
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	resolver := newTestResolver(t, cfg, WithPlatformCA(provider))

	// CABundlePEM should call the provider exactly once.
	result, err := resolver.CABundlePEM(t.Context(), ClassInternal)
	if err != nil {
		t.Fatalf("platform-ca normalization failed: %v", err)
	}
	if !bytes.Equal(result, caPEM) {
		t.Error("platform-ca did not return provider bundle")
	}
	if calls := provider.calls.Load(); calls != 1 {
		t.Errorf("expected exactly 1 provider call, got %d", calls)
	}
}

func TestPlatformCA_Normalization_NoProvider(t *testing.T) {
	// Without a provider, the resolver must return ErrPlatformCAUnavailable.
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.CABundlePEM(t.Context(), ClassInternal)
	if !errors.Is(err, ErrPlatformCAUnavailable{}) {
		t.Fatalf("expected ErrPlatformCAUnavailable, got %v", err)
	}
}

// =============================================================================
// TOFU strategy passthrough
// =============================================================================

func TestNewResolver_TOFU_RequiresPinStore(t *testing.T) {
	// When tofu is listed in a class chain and no WithTOFUPinStore is
	// supplied, NewResolver must return ErrTOFUPinStoreRequired.
	cfg := &Config{Default: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}}
	_, err := NewResolver(cfg, testLogger())
	if !errors.Is(err, ErrTOFUPinStoreRequired{}) {
		t.Fatalf("expected ErrTOFUPinStoreRequired, got %v", err)
	}
}

func TestNewResolver_TOFU_BMC_RequiresPinStore(t *testing.T) {
	// Same check for the bmc class, which also allows tofu.
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}}
	_, err := NewResolver(cfg, testLogger())
	if !errors.Is(err, ErrTOFUPinStoreRequired{}) {
		t.Fatalf("expected ErrTOFUPinStoreRequired for bmc class, got %v", err)
	}
}

// =============================================================================
// Class allowlist enforcement
// =============================================================================

func TestAllowlist_TOFU_AllowedForDefault(t *testing.T) {
	// TOFU requires a pin store but must be allowed for the default class.
	cfg := &Config{Default: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}}
	// Platform-level validate must pass (allowlist); pin-store absence is a
	// generic-level error returned by New, not by Validate.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tofu must be allowed for default class, got %v", err)
	}
}

func TestAllowlist_TOFU_AllowedForBMC(t *testing.T) {
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tofu must be allowed for bmc class, got %v", err)
	}
}

func TestAllowlist_TOFU_NotAllowedForInternal(t *testing.T) {
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}}
	err := cfg.Validate()
	var notAllowed *ErrStrategyNotAllowed
	if !errors.As(err, &notAllowed) {
		t.Fatalf("expected ErrStrategyNotAllowed for tofu on internal class, got %v", err)
	}
	if notAllowed.Class != ClassInternal || notAllowed.Strategy != StrategyTOFU {
		t.Errorf("unexpected ErrStrategyNotAllowed: %+v", notAllowed)
	}
}

func TestAllowlist_Noise_NotAllowedForBMC(t *testing.T) {
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyNoise}}}
	err := cfg.Validate()
	var notAllowed *ErrStrategyNotAllowed
	if !errors.As(err, &notAllowed) {
		t.Fatalf("expected ErrStrategyNotAllowed for noise on bmc class, got %v", err)
	}
	if notAllowed.Strategy != StrategyNoise {
		t.Errorf("expected noise strategy in error, got %s", notAllowed.Strategy)
	}
}

func TestAllowlist_DANE_NotAllowedForInternal(t *testing.T) {
	cfg := &Config{Internal: &ScopeConfig{Strategies: []Strategy{StrategyDANE}}}
	err := cfg.Validate()
	var notAllowed *ErrStrategyNotAllowed
	if !errors.As(err, &notAllowed) {
		t.Fatalf("expected ErrStrategyNotAllowed for dane on internal class, got %v", err)
	}
}

func TestAllowlist_PlatformCA_NotAllowedForDefault(t *testing.T) {
	cfg := &Config{Default: &ScopeConfig{Strategies: []Strategy{StrategyPlatformCA}}}
	err := cfg.Validate()
	var notAllowed *ErrStrategyNotAllowed
	if !errors.As(err, &notAllowed) {
		t.Fatalf("expected ErrStrategyNotAllowed for platform-ca on default class, got %v", err)
	}
}
