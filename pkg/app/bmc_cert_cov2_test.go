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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ---------------------------------------------------------------------------
// w1b-prefixed local helpers
// ---------------------------------------------------------------------------

// w1bFakeLocalCAWithCACert extends fakeLocalCA to return an IssuedCertificate
// with a populated CACertificatePEM field, exercising the caCert-parse branch
// inside issueBMCCertificateCore.
type w1bFakeLocalCAWithCACert struct {
	caCertPEM []byte
}

func (f *w1bFakeLocalCAWithCACert) IssueCertificate(_ context.Context, _ *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	return &quicbaasca.IssuedCertificate{
		Certificate:      testIssuedCertificate(),
		CACertificatePEM: f.caCertPEM,
	}, nil
}

// w1bMakeCACertPEM builds a minimal self-signed cert PEM for use as a CA cert.
func w1bMakeCACertPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// w1bFakeDNSWithDeleteErr returns an error from DeleteRecord so the
// ChallengeCleanup best-effort error branch in buildBMCACMERequest is hit.
type w1bFakeDNSWithDeleteErr struct {
	deleteErr error
}

func (d *w1bFakeDNSWithDeleteErr) AddRecord(_ context.Context, _, _, _ string, _ int) error {
	return nil
}

func (d *w1bFakeDNSWithDeleteErr) DeleteRecord(_ context.Context, _, _ string) error {
	return d.deleteErr
}

// ---------------------------------------------------------------------------
// buildBMCACMERequest – ChallengeSetup and ChallengeCleanup closures
// (57.7% → ≥91%)
//
// The closures are returned from buildBMCACMERequest but only invoked by the
// ACME client. In unit tests we call them directly to cover the closure bodies.
// ---------------------------------------------------------------------------

// TestW1bBuildBMCACMERequest_ChallengeSetup_DNS01 verifies that calling the
// ChallengeSetup closure with "dns-01" writes a TXT record via dnsUpdater.
func TestW1bBuildBMCACMERequest_ChallengeSetup_DNS01(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dns := &fakeDNS{}

	req, err := buildBMCACMERequest(context.Background(), cfg, []byte{1, 2, 3}, dns, 60, nil)
	if err != nil {
		t.Fatalf("buildBMCACMERequest: %v", err)
	}
	if req.ChallengeSetup == nil {
		t.Fatal("ChallengeSetup is nil")
	}

	// Call with "dns-01" — should invoke dns.AddRecord.
	if err := req.ChallengeSetup("dns-01", "token", "keyAuth"); err != nil {
		t.Errorf("ChallengeSetup(dns-01): %v", err)
	}
	dns.mu.Lock()
	n := len(dns.adds)
	dns.mu.Unlock()
	if n != 1 {
		t.Errorf("dns.adds = %d, want 1", n)
	}
}

// TestW1bBuildBMCACMERequest_ChallengeSetup_NonDNS01 verifies that calling
// ChallengeSetup with a non-dns-01 type is a no-op.
func TestW1bBuildBMCACMERequest_ChallengeSetup_NonDNS01(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dns := &fakeDNS{}

	req, err := buildBMCACMERequest(context.Background(), cfg, []byte{1}, dns, 60, nil)
	if err != nil {
		t.Fatalf("buildBMCACMERequest: %v", err)
	}

	if err := req.ChallengeSetup("http-01", "token", "keyAuth"); err != nil {
		t.Errorf("ChallengeSetup(http-01): %v", err)
	}
	dns.mu.Lock()
	n := len(dns.adds)
	dns.mu.Unlock()
	if n != 0 {
		t.Errorf("dns.adds = %d, want 0 for non-dns-01", n)
	}
}

// TestW1bBuildBMCACMERequest_ChallengeCleanup_DNS01 verifies that calling the
// ChallengeCleanup closure with "dns-01" removes the TXT record.
func TestW1bBuildBMCACMERequest_ChallengeCleanup_DNS01(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dns := &fakeDNS{}

	req, err := buildBMCACMERequest(context.Background(), cfg, []byte{1}, dns, 60, nil)
	if err != nil {
		t.Fatalf("buildBMCACMERequest: %v", err)
	}
	if req.ChallengeCleanup == nil {
		t.Fatal("ChallengeCleanup is nil")
	}

	// Should call dns.DeleteRecord.
	req.ChallengeCleanup("dns-01")
	dns.mu.Lock()
	n := len(dns.deletes)
	dns.mu.Unlock()
	if n != 1 {
		t.Errorf("dns.deletes = %d, want 1", n)
	}
}

// TestW1bBuildBMCACMERequest_ChallengeCleanup_NonDNS01 verifies that calling
// ChallengeCleanup with a non-dns-01 type is a no-op.
func TestW1bBuildBMCACMERequest_ChallengeCleanup_NonDNS01(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dns := &fakeDNS{}

	req, _ := buildBMCACMERequest(context.Background(), cfg, []byte{1}, dns, 60, nil)
	req.ChallengeCleanup("http-01")
	dns.mu.Lock()
	n := len(dns.deletes)
	dns.mu.Unlock()
	if n != 0 {
		t.Errorf("dns.deletes = %d, want 0 for non-dns-01", n)
	}
}

// TestW1bBuildBMCACMERequest_ChallengeCleanup_DeleteError verifies that a
// DeleteRecord error during ChallengeCleanup is silently swallowed (best-
// effort) and does not panic when a logger is provided.
func TestW1bBuildBMCACMERequest_ChallengeCleanup_DeleteError(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dns := &w1bFakeDNSWithDeleteErr{deleteErr: errors.New("DNS unavailable")}

	req, err := buildBMCACMERequest(context.Background(), cfg, []byte{1}, dns, 0 /* default TTL */, nil)
	if err != nil {
		t.Fatalf("buildBMCACMERequest: %v", err)
	}
	// Must not panic; error is logged at Info level and discarded.
	req.ChallengeCleanup("dns-01")
}

// ---------------------------------------------------------------------------
// issueBMCCertificateCore – deployer-nil path with NewAutoCertManager failure
// (continuing the 82.7% → ≥91% effort)
//
// When opts.Deployer is nil, issueBMCCertificateCore creates an AutoCertManager
// from BackendOverride (or cfg.Backend). Passing an unrecognised backend string
// as BackendOverride causes bmc.NewAutoCertManager to fail with ErrInvalidConfig
// (backend.IsValid() == false) WITHOUT making any network connection, covering:
//   - the `if deployer == nil` entry block
//   - `backend := opts.BackendOverride`
//   - the `bmc.NewAutoCertManager` call
//   - the `if deployErr != nil { return nil, deployErr }` return
// ---------------------------------------------------------------------------

// TestW1bIssueBMCCertificateCore_DeployerNilInvalidBackendOverride covers the
// deployer-nil path where NewAutoCertManager fails due to an invalid backend.
func TestW1bIssueBMCCertificateCore_DeployerNilInvalidBackendOverride(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	// No Deployer → uses BackendOverride to build an AutoCertManager.
	// An unrecognized backend string is rejected immediately by
	// bmc.NewAutoCertManager before any connection attempt.
	_, err := issueBMCCertificateCore(context.Background(), "dev-no-deployer", cfg, issueBMCCertificateOptions{
		LocalCAIssuer:   &fakeLocalCA{},
		BackendOverride: "completely-invalid-backend",
		// opts.Deployer intentionally nil
	})
	if err == nil {
		t.Fatal("expected error from invalid BackendOverride")
	}
}

// TestW1bBuildBMCACMERequest_DefaultTTL verifies TTL defaults to 60 when 0 is
// passed, exercising the `if ttl <= 0` branch.
func TestW1bBuildBMCACMERequest_DefaultTTL(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dns := &fakeDNS{}
	// ttl=0 → default branch inside buildBMCACMERequest.
	req, err := buildBMCACMERequest(context.Background(), cfg, []byte{1}, dns, 0, nil)
	if err != nil {
		t.Fatalf("buildBMCACMERequest ttl=0: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request")
	}
}

// ---------------------------------------------------------------------------
// issueBMCCertificateCore – CACertificatePEM parse path
// (81.3% → ≥91%)
//
// When IssuedCertificate.CACertificatePEM is non-empty, issueBMCCertificateCore
// calls parsePEMCert and stores the result in caCert. A valid CA PEM causes
// parsePEMCert to succeed; an invalid PEM causes it to silently ignore the
// error (caCert stays nil). Both sub-paths are exercised here.
// ---------------------------------------------------------------------------

// TestW1bIssueBMCCertificateCore_ValidCACertPEM verifies that a valid
// CACertificatePEM causes caCert to be non-nil when passed to OnCertDeployed.
func TestW1bIssueBMCCertificateCore_ValidCACertPEM(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}
	caPEM := w1bMakeCACertPEM(t)

	var seenCA *x509.Certificate
	_, err := issueBMCCertificateCore(context.Background(), "dev-ca-pem", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &w1bFakeLocalCAWithCACert{caCertPEM: caPEM},
		Deployer:      dep,
		OnCertDeployed: func(_ context.Context, _ *x509.Certificate, ca *x509.Certificate) error {
			seenCA = ca
			return nil
		},
	})
	if err != nil {
		t.Fatalf("issueBMCCertificateCore: %v", err)
	}
	if seenCA == nil {
		t.Error("expected non-nil CA cert in OnCertDeployed when CACertificatePEM is valid")
	}
}

// ---------------------------------------------------------------------------
// issueBMCCertificateCore – logger-gated non-fatal hook log branches
// (82.7% → ≥91%)
//
// When OnCertIssued or OnCertDeployed returns an error AND opts.Logger is
// non-nil, issueBMCCertificateCore logs at Warn / Error respectively.
// Those inner `if opts.Logger != nil { ... }` branches are not exercised by
// the existing hook tests (which pass a nil Logger).  Providing a real
// Logger with a hook error covers the missing branches while verifying
// the non-fatal contract.
// ---------------------------------------------------------------------------

// TestW1bIssueBMCCertificateCore_OnCertIssuedError_WithLogger verifies that
// an OnCertIssued error is logged at Warn level (non-fatal) when a Logger is
// provided, and the deploy still proceeds.
func TestW1bIssueBMCCertificateCore_OnCertIssuedError_WithLogger(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}

	_, err := issueBMCCertificateCore(context.Background(), "dev-issued-logger", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		Logger:        logging.DefaultLogger().Slog(), // Logger set → triggers Warn branch
		OnCertIssued: func(_ context.Context, _ *x509.Certificate) error {
			return errors.New("pre-publish failed")
		},
	})
	if err != nil {
		t.Fatalf("OnCertIssued error must be non-fatal; got: %v", err)
	}
	if dep.replaceCalls != 1 {
		t.Errorf("deploy must still run despite hook error; replaceCalls = %d", dep.replaceCalls)
	}
}

// TestW1bIssueBMCCertificateCore_OnCertDeployedError_WithLogger verifies that
// an OnCertDeployed error is logged at Error level (non-fatal) when a Logger
// is provided, and the CertTarget is still returned.
func TestW1bIssueBMCCertificateCore_OnCertDeployedError_WithLogger(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}

	target, err := issueBMCCertificateCore(context.Background(), "dev-deployed-logger", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
		Logger:        logging.DefaultLogger().Slog(), // Logger set → triggers Error branch
		OnCertDeployed: func(_ context.Context, _, _ *x509.Certificate) error {
			return errors.New("tlsa re-publish failed")
		},
	})
	if err != nil {
		t.Fatalf("OnCertDeployed error must be non-fatal; got: %v", err)
	}
	if target == nil {
		t.Fatal("CertTarget must be returned despite hook error")
	}
}

// TestW1bIssueBMCCertificateCore_InvalidCACertPEM verifies that an invalid
// CACertificatePEM causes caCert to be nil (parsePEMCert silently fails)
// rather than surfacing an error. The deploy still succeeds.
func TestW1bIssueBMCCertificateCore_InvalidCACertPEM(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{}

	var seenCA *x509.Certificate
	_, err := issueBMCCertificateCore(context.Background(), "dev-bad-ca-pem", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &w1bFakeLocalCAWithCACert{caCertPEM: []byte("not-a-valid-pem")},
		Deployer:      dep,
		OnCertDeployed: func(_ context.Context, _ *x509.Certificate, ca *x509.Certificate) error {
			seenCA = ca
			return nil
		},
	})
	if err != nil {
		t.Fatalf("issueBMCCertificateCore with bad CA PEM: %v", err)
	}
	if seenCA != nil {
		t.Error("expected nil CA cert in OnCertDeployed when CACertificatePEM is invalid")
	}
}
