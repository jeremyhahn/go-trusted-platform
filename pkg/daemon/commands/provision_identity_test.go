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

package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	certclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/certificate"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Test fixtures
// =============================================================================

// fakeIssuer is a daemonCertIssuer that mints CSR-less certs in-process
// from a configured root CA. Each Issue call increments a counter so tests
// can assert how many times the issuer was hit (the §8 #7 one-shot
// requirement).
type fakeIssuer struct {
	root         *x509.Certificate
	rootKey      *ecdsa.PrivateKey
	caBundlePEM  []byte
	notBeforeOff time.Duration
	notAfterOff  time.Duration

	calls         int
	failOnRole    string
	bundleErr     error
	getBundleHits int
}

// newFakeIssuer builds a self-signed root and an issuer wired to that root.
// It intentionally does not require any quicbaas SDK transport so the test
// suite stays in-memory.
func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, template, template, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("self-sign root: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	return &fakeIssuer{
		root:         root,
		rootKey:      rootKey,
		caBundlePEM:  bundle,
		notBeforeOff: -time.Minute,
		notAfterOff:  365 * 24 * time.Hour,
	}
}

// IssueCertificate mints a leaf cert+key signed by the fake root.
func (f *fakeIssuer) IssueCertificate(ctx context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error) {
	f.calls++
	if f.failOnRole != "" && req.Usage == f.failOnRole {
		return nil, fmt.Errorf("fakeIssuer: simulated issuance failure for usage=%s", req.Usage)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(f.calls + 100)),
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
		},
		DNSNames:    append([]string(nil), req.DNSNames...),
		NotBefore:   now.Add(f.notBeforeOff),
		NotAfter:    now.Add(f.notAfterOff),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, ip := range req.IPAddresses {
		// store IPs verbatim (string-form is fine for test purposes).
		tmpl.DNSNames = append(tmpl.DNSNames, ip)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, f.root, &leafKey.PublicKey, f.rootKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &certclient.IssueCertificateResponse{
		CertificatePEM: string(certPEM),
		PrivateKeyPEM:  string(keyPEM),
		SerialNumber:   tmpl.SerialNumber.String(),
		NotBefore:      tmpl.NotBefore,
		NotAfter:       tmpl.NotAfter,
	}, nil
}

// GetCABundle returns the fake root in PEM form.
func (f *fakeIssuer) GetCABundle(ctx context.Context, req *certclient.GetCABundleRequest) (*certclient.GetCABundleResponse, error) {
	f.getBundleHits++
	if f.bundleErr != nil {
		return nil, f.bundleErr
	}
	return &certclient.GetCABundleResponse{BundlePEM: string(f.caBundlePEM)}, nil
}

// fakeTrustPool wraps the fake issuer's root into a caTrustPoolProvider.
type fakeTrustPool struct {
	root *x509.Certificate
	err  error
}

// CABundleCertPool returns a pool seeded with the fake root, or an error
// if the test asked for one.
func (f *fakeTrustPool) CABundleCertPool() (*x509.CertPool, error) {
	if f.err != nil {
		return nil, f.err
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.root)
	return pool, nil
}

// =============================================================================
// Helpers
// =============================================================================

// newTestLogger returns a logger that discards output so tests stay quiet.
func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, nil)
}

// readBundlePEM reads a persisted bundle from disk and returns its bytes.
func readBundlePEM(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle %s: %v", path, err)
	}
	return b
}

// =============================================================================
// Tests
// =============================================================================

func TestProvisionDaemonIdentity_FreshIssue(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	issuer := newFakeIssuer(t)
	ca := &fakeTrustPool{root: issuer.root}

	id, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, daemonSANs{
		DNS: []string{"unit-test.example"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == nil {
		t.Fatal("expected ProvisionedIdentity, got nil")
	}
	if id.Reused {
		t.Error("expected Reused=false for fresh issuance")
	}
	if id.ServerCert.Leaf == nil {
		t.Error("expected ServerCert.Leaf populated")
	}
	if id.AdminTrustPool == nil {
		t.Error("expected AdminTrustPool populated")
	}
	if _, err := os.Stat(id.ServerBundlePath); err != nil {
		t.Errorf("server bundle not persisted: %v", err)
	}
	if _, err := os.Stat(id.AdminBundlePath); err != nil {
		t.Errorf("admin bundle not persisted: %v", err)
	}
	if _, err := os.Stat(id.CABundlePath); err != nil {
		t.Errorf("ca bundle not persisted: %v", err)
	}
	// IssueCertificate is called twice (server, admin) on a fresh init.
	if issuer.calls != 2 {
		t.Errorf("expected 2 issuance calls, got %d", issuer.calls)
	}
}

func TestProvisionDaemonIdentity_ReusesPersistedIdentity(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	issuer := newFakeIssuer(t)
	ca := &fakeTrustPool{root: issuer.root}
	sans := daemonSANs{DNS: []string{"unit-test.example"}}

	first, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, sans)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if issuer.calls != 2 {
		t.Fatalf("expected 2 calls after first provision, got %d", issuer.calls)
	}
	originalServer := readBundlePEM(t, first.ServerBundlePath)
	originalAdmin := readBundlePEM(t, first.AdminBundlePath)

	// Second call must reuse — issuer counter does not advance.
	second, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, sans)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if !second.Reused {
		t.Error("expected Reused=true on second provision")
	}
	if issuer.calls != 2 {
		t.Errorf("expected issuer call count to remain at 2, got %d", issuer.calls)
	}
	// Bundles untouched on disk.
	if !equalBytes(originalServer, readBundlePEM(t, second.ServerBundlePath)) {
		t.Error("server bundle changed across reuse")
	}
	if !equalBytes(originalAdmin, readBundlePEM(t, second.AdminBundlePath)) {
		t.Error("admin bundle changed across reuse")
	}
}

func TestProvisionDaemonIdentity_ReissuesNearExpiry(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	issuer := newFakeIssuer(t)
	ca := &fakeTrustPool{root: issuer.root}
	sans := daemonSANs{DNS: []string{"unit-test.example"}}

	// Issue with cert that expires 10 days from now (well inside the
	// 30-day renewal threshold).
	issuer.notAfterOff = 10 * 24 * time.Hour

	if _, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, sans); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if issuer.calls != 2 {
		t.Fatalf("expected 2 calls after first provision, got %d", issuer.calls)
	}

	// Switch the issuer back to a sane validity so the re-issue produces
	// a bundle in the renewal window.
	issuer.notAfterOff = 365 * 24 * time.Hour

	second, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, sans)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if second.Reused {
		t.Error("expected Reused=false when persisted cert is near expiry")
	}
	if issuer.calls != 4 {
		t.Errorf("expected 4 issuance calls after re-issue, got %d", issuer.calls)
	}
}

func TestProvisionDaemonIdentity_ReissuesWhenSANsChange(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	issuer := newFakeIssuer(t)
	ca := &fakeTrustPool{root: issuer.root}

	if _, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, daemonSANs{
		DNS: []string{"old-host.example"},
	}); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if issuer.calls != 2 {
		t.Fatalf("expected 2 calls after first provision, got %d", issuer.calls)
	}

	second, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, daemonSANs{
		DNS: []string{"old-host.example", "new-host.example"},
	})
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if second.Reused {
		t.Error("expected Reused=false when required SANs grew")
	}
	if issuer.calls != 4 {
		t.Errorf("expected re-issue to trigger 2 more calls (4 total), got %d", issuer.calls)
	}
}

func TestProvisionDaemonIdentity_ReissuesWhenServerBundleMissing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	issuer := newFakeIssuer(t)
	ca := &fakeTrustPool{root: issuer.root}
	sans := daemonSANs{DNS: []string{"unit-test.example"}}

	first, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, sans)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if err := os.Remove(first.ServerBundlePath); err != nil {
		t.Fatalf("remove server bundle: %v", err)
	}

	second, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, sans)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if second.Reused {
		t.Error("expected Reused=false when server bundle deleted")
	}
	if issuer.calls != 4 {
		t.Errorf("expected re-issue, got %d total issuance calls", issuer.calls)
	}
}

func TestProvisionDaemonIdentity_PropagatesIssuerError(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	issuer := newFakeIssuer(t)
	issuer.failOnRole = "server"
	ca := &fakeTrustPool{root: issuer.root}

	_, err := provisionDaemonIdentity(ctx, newTestLogger(), issuer, ca, dir, daemonSANs{})
	if err == nil {
		t.Fatal("expected error from issuer, got nil")
	}
	var typed ErrProvisionIssue
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionIssue, got %T (%v)", err, err)
	}
	if typed.Role != "server" {
		t.Errorf("expected Role=server, got %s", typed.Role)
	}
}

func TestProvisionDaemonIdentity_ErrorsWhenCANil(t *testing.T) {
	_, err := provisionDaemonIdentity(context.Background(), newTestLogger(), newFakeIssuer(t), nil, t.TempDir(), daemonSANs{})
	if err == nil {
		t.Fatal("expected error when CA provider is nil")
	}
	var typed ErrProvisionMissingCA
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingCA, got %T (%v)", err, err)
	}
}

func TestProvisionDaemonIdentity_ErrorsWhenSDKMissing(t *testing.T) {
	// CA provider is fine, but no persisted bundle and no issuer means
	// the function cannot make progress and must error explicitly.
	_, err := provisionDaemonIdentity(context.Background(), newTestLogger(), nil, &fakeTrustPool{root: newFakeIssuer(t).root}, t.TempDir(), daemonSANs{})
	if err == nil {
		t.Fatal("expected error when SDK issuer is nil")
	}
	var typed ErrProvisionMissingSDK
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingSDK, got %T (%v)", err, err)
	}
}

func TestProvisionDaemonIdentity_PersistFailureSurfaced(t *testing.T) {
	// Use a directory path that cannot be written to — tempdir/ro/file
	// where ro is a regular file, so filepath.Join produces a path whose
	// parent is not a directory.
	tmp := t.TempDir()
	notADir := filepath.Join(tmp, "ro")
	if err := os.WriteFile(notADir, []byte("x"), 0600); err != nil {
		t.Fatalf("seed not-a-dir: %v", err)
	}

	issuer := newFakeIssuer(t)
	ca := &fakeTrustPool{root: issuer.root}

	_, err := provisionDaemonIdentity(context.Background(), newTestLogger(), issuer, ca, notADir, daemonSANs{})
	if err == nil {
		t.Fatal("expected persist error, got nil")
	}
	var typed ErrProvisionPersist
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionPersist, got %T (%v)", err, err)
	}
}

func TestCertWithinRenewalWindow(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"already expired", now.Add(-time.Hour), false},
		{"inside renewal window", now.Add(10 * 24 * time.Hour), false},
		{"outside renewal window", now.Add(60 * 24 * time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := &x509.Certificate{NotAfter: tc.notAfter}
			got := certWithinRenewalWindow(leaf, renewalThreshold)
			if got != tc.want {
				t.Errorf("certWithinRenewalWindow(%v) = %v, want %v", tc.notAfter, got, tc.want)
			}
		})
	}
}

func TestCertCoversDNSNames(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"a.example", "b.example"}}
	if !certCoversDNSNames(leaf, []string{"a.example"}) {
		t.Error("expected required subset to be covered")
	}
	if !certCoversDNSNames(leaf, nil) {
		t.Error("empty required slice should always be covered")
	}
	if certCoversDNSNames(leaf, []string{"c.example"}) {
		t.Error("missing required name should not be covered")
	}
}

func TestDaemonCertSANs_AddsLoopback(t *testing.T) {
	dns, ips := daemonCertSANs(daemonSANs{DNS: []string{"node-01"}, IPs: []string{"10.0.0.1"}})
	wantDNS := []string{"localhost", "platformd.localhost", "node-01"}
	if len(dns) != len(wantDNS) {
		t.Fatalf("dns len = %d, want %d", len(dns), len(wantDNS))
	}
	for i, n := range wantDNS {
		if dns[i] != n {
			t.Errorf("dns[%d] = %s, want %s", i, dns[i], n)
		}
	}
	wantIPs := []string{"127.0.0.1", "::1", "10.0.0.1"}
	if len(ips) != len(wantIPs) {
		t.Fatalf("ips len = %d, want %d", len(ips), len(wantIPs))
	}
	for i, n := range wantIPs {
		if ips[i] != n {
			t.Errorf("ips[%d] = %s, want %s", i, ips[i], n)
		}
	}
}

// equalBytes compares two byte slices for equality.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
