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
	cfg := &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyCAFile}}}
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
	cfg := &Config{Bootstrap: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{Pin: validHexPin},
	}}
	resolver := newTestResolver(t, cfg)
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassBootstrap, "peer.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	// Custom-verifier pattern: pin verification is the sole verifier. Since
	// go-truststrap v0.2.0-alpha the verifier is VerifyConnection, not
	// VerifyPeerCertificate — the latter is skipped on a resumed TLS session,
	// which would let a resumed connection bypass the pin entirely.
	if !tlsCfg.InsecureSkipVerify {
		t.Error("expected custom-verifier pattern (InsecureSkipVerify with VerifyConnection)")
	}
	if tlsCfg.VerifyConnection == nil {
		t.Error("expected VerifyConnection to be set")
	}
	if !tlsCfg.SessionTicketsDisabled {
		t.Error("expected session tickets disabled so every connection re-verifies the pin")
	}
}

func TestTLSConfig_SPKI_InvalidPin(t *testing.T) {
	cfg := &Config{Bootstrap: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{Pin: "not-a-valid-pin"},
	}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.TLSConfig(t.Context(), ClassBootstrap, "peer.example.com:443")
	var noStrategy *ErrNoStrategySucceeded
	if !errors.As(err, &noStrategy) {
		t.Fatalf("expected ErrNoStrategySucceeded, got %v", err)
	}
	if len(noStrategy.Attempts) != 1 || noStrategy.Attempts[0].Strategy != StrategySPKI {
		t.Errorf("expected single spki attempt, got %+v", noStrategy.Attempts)
	}
}

func TestTLSConfig_Embedded(t *testing.T) {
	cfg := &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyEmbedded}}}
	resolver := newTestResolver(t, cfg)
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassBootstrap, "")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 minimum, got %d", tlsCfg.MinVersion)
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

func TestTLSConfig_PinStorePrecedence(t *testing.T) {
	// Scope has no static pin; the store supplies the endpoint pin.
	store := &fakePinStore{pin: validHexPin}
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategySPKI}}}
	resolver := newTestResolver(t, cfg, WithPinStore(store))
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassBMC, "bmc.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.VerifyConnection == nil {
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
	cfg := &Config{Bootstrap: &ScopeConfig{
		Strategies: []Strategy{StrategyNoise, StrategyEmbedded},
	}}
	resolver := newTestResolver(t, cfg)
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassBootstrap, "")
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
	cfg := &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyDANE}}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.TLSConfig(t.Context(), ClassBootstrap, "no-port-here")
	var endpointErr *ErrEndpointInvalid
	if !errors.As(err, &endpointErr) {
		t.Fatalf("expected ErrEndpointInvalid in chain, got %v", err)
	}
}

func TestCAPool_ClassNotConfigured(t *testing.T) {
	resolver := newTestResolver(t, DefaultConfig())
	_, err := resolver.CAPool(t.Context(), ClassBMC, "")
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
	cfg := &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyEmbedded}}}
	resolver := newTestResolver(t, cfg)
	pool, err := resolver.CAPool(t.Context(), ClassBootstrap, "")
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected system cert pool")
	}
}

func TestCAPool_CachesPerClassEndpoint(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "bmc-ca.pem")
	if err := os.WriteFile(caFile, testCAPEM(t), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyCAFile}, CAFile: caFile}}
	resolver := newTestResolver(t, cfg)

	first, err := resolver.CAPool(t.Context(), ClassBMC, "bmc.example.com:443")
	if err != nil {
		t.Fatal(err)
	}

	// With the bundle gone, only a cached pool can still answer.
	if err := os.Remove(caFile); err != nil {
		t.Fatal(err)
	}
	second, err := resolver.CAPool(t.Context(), ClassBMC, "bmc.example.com:443")
	if err != nil {
		t.Fatalf("expected the cached pool for the same endpoint, got %v", err)
	}
	if first != second {
		t.Error("expected cached pool to be returned on second call")
	}

	// A different endpoint is a separate cache entry, so it must resolve
	// afresh — and fail, because the bundle is gone.
	if _, err := resolver.CAPool(t.Context(), ClassBMC, "other-bmc.example.com:443"); err == nil {
		t.Error("expected a new endpoint to miss the cache and fail without the bundle")
	}
}

func TestCABundlePEM_Embedded(t *testing.T) {
	cfg := &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyEmbedded}}}
	resolver := newTestResolver(t, cfg)
	pem, err := resolver.CABundlePEM(t.Context(), ClassBootstrap)
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

func TestCABundlePEM_FetchFailure(t *testing.T) {
	// SPKI fetch with no server URL fails inside the SDK without any
	// network activity; the resolver must surface it through
	// ErrFetchFailed inside ErrNoStrategySucceeded.
	cfg := &Config{Bootstrap: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{Pin: validHexPin},
	}}
	resolver := newTestResolver(t, cfg)
	_, err := resolver.CABundlePEM(t.Context(), ClassBootstrap)
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

// =============================================================================
// TOFU strategy passthrough
// =============================================================================

func TestNewResolver_TOFU_RequiresPinStore(t *testing.T) {
	// When tofu is listed in a class chain and no WithTOFUPinStore is
	// supplied, NewResolver must return ErrTOFUPinStoreRequired.
	cfg := &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}}
	_, err := NewResolver(cfg, testLogger())
	if !errors.Is(err, ErrTOFUPinStoreRequired{}) {
		t.Fatalf("expected ErrTOFUPinStoreRequired, got %v", err)
	}
}

func TestNewResolver_TOFU_BMC_RequiresPinStore(t *testing.T) {
	// tofu is allowed for bmc again: go-xkms#139 (v0.12.0-alpha) made the
	// TLS path an endpoint verifier that pins the leaf SPKI on first
	// contact, which is precisely what a BMC needs — it presents a
	// self-signed certificate and serves no CA bundle. What it still
	// requires is somewhere to PERSIST the pin, so the failure here must be
	// the pin-store error, not the allowlist: a tofu with nowhere to record
	// what it saw would re-trust a new key on every connection, which is
	// not trust-on-first-use at all.
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}}
	_, err := NewResolver(cfg, testLogger())
	if !errors.Is(err, ErrTOFUPinStoreRequired{}) {
		t.Fatalf("expected ErrTOFUPinStoreRequired for tofu on bmc class, got %v", err)
	}
	var notAllowed *ErrStrategyNotAllowed
	if errors.As(err, &notAllowed) {
		t.Fatalf("tofu must no longer be rejected by the bmc allowlist: %+v", notAllowed)
	}
}

// =============================================================================
// Class allowlist enforcement
// =============================================================================

func TestAllowlist_TOFU_AllowedForDefault(t *testing.T) {
	// TOFU requires a pin store but must be allowed for the default class.
	cfg := &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}}
	// Platform-level validate must pass (allowlist); pin-store absence is a
	// generic-level error returned by New, not by Validate.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tofu must be allowed for default class, got %v", err)
	}
}

func TestAllowlist_TOFU_AllowedForBMC(t *testing.T) {
	// This assertion is the inverse of what it was under #83, and
	// deliberately so. tofu was barred from the bmc class while it was
	// implemented purely as a CA-bundle fetch — a BMC serves Redfish and
	// never a bundle, so it could not verify one. go-xkms#139
	// (v0.12.0-alpha) added the endpoint-pinning TLS path whose changelog
	// names this exact case, so the reason for the exclusion is gone and
	// the allowlist must now accept it.
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyTOFU}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tofu must be allowed for the bmc class since go-xkms#139, got %v", err)
	}
	if !StrategyAllowedForClass(ClassBMC, StrategyTOFU) {
		t.Error("StrategyAllowedForClass must agree with Validate: tofu is allowed for bmc")
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

// TestAllowlist_PlatformCA_IsNotAStrategy pins the redesign: the platform CA
// is the Anchor, so no class may list platform-ca as a strategy.
func TestAllowlist_PlatformCA_IsNotAStrategy(t *testing.T) {
	for _, class := range classes {
		cfg := &Config{}
		scope := &ScopeConfig{Strategies: []Strategy{Strategy("platform-ca")}}
		switch class {
		case ClassBootstrap:
			cfg.Bootstrap = scope
		case ClassBMC:
			cfg.BMC = scope
		}
		var notAllowed *ErrStrategyNotAllowed
		if err := cfg.Validate(); !errors.As(err, &notAllowed) {
			t.Errorf("class %q: expected ErrStrategyNotAllowed for platform-ca, got %v", class, err)
		}
	}
}
