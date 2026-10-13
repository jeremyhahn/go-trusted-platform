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

//go:build integration

package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	certclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/certificate"
)

// fakeIssuer is an appbackends.CertIssuer that mints client certificates
// signed by a test root, failing for the usage named in failOnRole.
type fakeIssuer struct {
	root       *testRoot
	calls      int
	failOnRole string
}

// newFakeIssuer returns an issuer over root.
func newFakeIssuer(root *testRoot) *fakeIssuer {
	return &fakeIssuer{root: root}
}

// IssueCertificate mints a client cert + PEM key signed by the root.
func (f *fakeIssuer) IssueCertificate(_ context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error) {
	f.calls++
	if f.failOnRole != "" && req.Usage == f.failOnRole {
		return nil, errFake{op: "issue " + req.Usage}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cert, err := f.root.sign(&x509.Certificate{
		SerialNumber: big.NewInt(int64(f.calls + 1000)),
		Subject:      pkix.Name{CommonName: req.CommonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, &key.PublicKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &certclient.IssueCertificateResponse{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		PrivateKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		SerialNumber:   cert.SerialNumber.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
	}, nil
}

// GetCABundle returns the test root as the CA bundle.
func (f *fakeIssuer) GetCABundle(_ context.Context, _ *certclient.GetCABundleRequest) (*certclient.GetCABundleResponse, error) {
	return &certclient.GetCABundleResponse{
		BundlePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.cert.Raw})),
	}, nil
}

// TestHarnessAdminBundle_SetInIntegrationBuild asserts the integration
// build wires the hook applyDaemonTLSIdentity calls for the harness.
func TestHarnessAdminBundle_SetInIntegrationBuild(t *testing.T) {
	if harnessAdminBundle == nil {
		t.Fatal("the integration build must set the harness admin bundle hook")
	}
}

// TestWriteHarnessAdminBundle_WritesVerifiableAdminCredential asserts the
// harness receives a CN=admin client certificate, with its key, that
// chains to the platform CA, in a file only its owner can read.
func TestWriteHarnessAdminBundle_WritesVerifiableAdminCredential(t *testing.T) {
	dir := t.TempDir()
	issuer := newFakeIssuer(newTestRoot(t))

	if err := writeHarnessAdminBundle(context.Background(), newTestLogger(), issuer, dir); err != nil {
		t.Fatalf("writeHarnessAdminBundle: %v", err)
	}

	path := filepath.Join(dir, harnessAdminBundleName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("bundle mode = %o, want 0600", mode)
	}
	cert, err := tls.LoadX509KeyPair(path, path)
	if err != nil {
		t.Fatalf("bundle is not a cert + key pair: %v", err)
	}
	if cn := cert.Leaf.Subject.CommonName; cn != "admin" {
		t.Errorf("bundle CN = %q, want admin", cn)
	}
	pool := x509.NewCertPool()
	pool.AddCert(issuer.root.cert)
	if err := verifyChain(cert.Leaf, pool); err != nil {
		t.Errorf("bundle does not chain to the platform CA: %v", err)
	}
}

func TestWriteHarnessAdminBundle_NilIssuer(t *testing.T) {
	err := writeHarnessAdminBundle(context.Background(), newTestLogger(), nil, t.TempDir())
	var typed ErrProvisionMissingSDK
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingSDK, got %T (%v)", err, err)
	}
}

func TestWriteHarnessAdminBundle_IssuerFailure(t *testing.T) {
	dir := t.TempDir()
	issuer := newFakeIssuer(newTestRoot(t))
	issuer.failOnRole = "client"

	err := writeHarnessAdminBundle(context.Background(), newTestLogger(), issuer, dir)
	var typed ErrProvisionIssue
	if !errors.As(err, &typed) || typed.Role != "admin" {
		t.Fatalf("expected ErrProvisionIssue{Role: admin}, got %T (%v)", err, err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, harnessAdminBundleName)); !os.IsNotExist(statErr) {
		t.Errorf("a failed issuance must leave no bundle, stat err = %v", statErr)
	}
}

func TestWriteHarnessAdminBundle_PersistFailure(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, []byte("x"), 0600); err != nil {
		t.Fatalf("seed not-a-dir: %v", err)
	}

	err := writeHarnessAdminBundle(context.Background(), newTestLogger(), newFakeIssuer(newTestRoot(t)), notADir)
	var typed ErrProvisionPersist
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionPersist, got %T (%v)", err, err)
	}
}
