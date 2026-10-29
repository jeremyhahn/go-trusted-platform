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

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	appbackends "github.com/jeremyhahn/go-trusted-platform/pkg/app/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
)

// harnessTestIdentity is the operator identity the system bundle is minted
// with in these tests.
var harnessTestIdentity = appbackends.AdminIdentity{TrustDomain: "platform.test", TenantID: app.SystemTenantID}

// fakeIssuer is an appbackends.CertIssuer that mints client certificates
// signed by a test root, with the requested tenant as the subject O, failing
// for the tenant named in failOnTenant.
type fakeIssuer struct {
	root         *testRoot
	calls        int
	failOnTenant string
}

// newFakeIssuer returns an issuer over root.
func newFakeIssuer(root *testRoot) *fakeIssuer {
	return &fakeIssuer{root: root}
}

// IssueCertificate mints a client cert + PEM key signed by the root.
func (f *fakeIssuer) IssueCertificate(_ context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error) {
	f.calls++
	if f.failOnTenant != "" && req.Organization == f.failOnTenant {
		return nil, errFake{op: "issue for " + req.Organization}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cert, err := f.root.sign(&x509.Certificate{
		SerialNumber: big.NewInt(int64(f.calls + 1000)),
		Subject:      pkix.Name{CommonName: req.CommonName, Organization: []string{req.Organization}},
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

	if err := writeHarnessAdminBundle(context.Background(), newTestLogger(), issuer, harnessTestIdentity, dir); err != nil {
		t.Fatalf("writeHarnessAdminBundle: %v", err)
	}

	bundles := map[string]string{
		harnessAdminBundleName:  app.SystemTenantID,
		harnessTenantBundleName: harnessTenantID,
	}
	for name, wantTenant := range bundles {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
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
			if org := cert.Leaf.Subject.Organization; len(org) != 1 || org[0] != wantTenant {
				t.Errorf("bundle O = %v, want [%s]", org, wantTenant)
			}
			pool := x509.NewCertPool()
			pool.AddCert(issuer.root.cert)
			if err := verifyChain(cert.Leaf, pool); err != nil {
				t.Errorf("bundle does not chain to the platform CA: %v", err)
			}
		})
	}
}

func TestWriteHarnessAdminBundle_NilIssuer(t *testing.T) {
	err := writeHarnessAdminBundle(context.Background(), newTestLogger(), nil, harnessTestIdentity, t.TempDir())
	var typed ErrProvisionMissingSDK
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingSDK, got %T (%v)", err, err)
	}
}

func TestWriteHarnessAdminBundle_IssuerFailure(t *testing.T) {
	cases := []struct {
		name         string
		failOnTenant string
		wantRole     string
	}{
		{name: "tenant bundle", failOnTenant: harnessTenantID, wantRole: "tenant admin"},
		{name: "admin bundle", failOnTenant: app.SystemTenantID, wantRole: "admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			issuer := newFakeIssuer(newTestRoot(t))
			issuer.failOnTenant = tc.failOnTenant

			err := writeHarnessAdminBundle(context.Background(), newTestLogger(), issuer, harnessTestIdentity, dir)
			var typed ErrProvisionIssue
			if !errors.As(err, &typed) || typed.Role != tc.wantRole {
				t.Fatalf("expected ErrProvisionIssue{Role: %s}, got %T (%v)", tc.wantRole, err, err)
			}
			// The harness waits on client-bundle.pem: it must not appear
			// when either issuance fails.
			if _, statErr := os.Stat(filepath.Join(dir, harnessAdminBundleName)); !os.IsNotExist(statErr) {
				t.Errorf("a failed issuance must leave no admin bundle, stat err = %v", statErr)
			}
		})
	}
}

func TestWriteHarnessAdminBundle_PersistFailure(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, []byte("x"), 0600); err != nil {
		t.Fatalf("seed not-a-dir: %v", err)
	}

	err := writeHarnessAdminBundle(context.Background(), newTestLogger(), newFakeIssuer(newTestRoot(t)), harnessTestIdentity, notADir)
	var typed ErrProvisionPersist
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionPersist, got %T (%v)", err, err)
	}
}

// TestWriteHarnessAdminBundle_IncompleteIdentity asserts an operator identity
// without a trust domain fails before any system bundle is written.
func TestWriteHarnessAdminBundle_IncompleteIdentity(t *testing.T) {
	dir := t.TempDir()
	identity := appbackends.AdminIdentity{TenantID: app.SystemTenantID}

	err := writeHarnessAdminBundle(context.Background(), newTestLogger(), newFakeIssuer(newTestRoot(t)), identity, dir)
	var issue ErrProvisionIssue
	// The tenant bundle is issued first and shares the trust domain, so it
	// is the one that fails.
	if !errors.As(err, &issue) || issue.Role != "tenant admin" {
		t.Fatalf("expected ErrProvisionIssue{Role: tenant admin}, got %T (%v)", err, err)
	}
	var incomplete *appbackends.ErrAdminIdentityIncomplete
	if !errors.As(issue.Cause, &incomplete) || incomplete.Field != "trust domain" {
		t.Fatalf("expected *ErrAdminIdentityIncomplete{trust domain}, got %T (%v)", issue.Cause, issue.Cause)
	}
	for _, name := range []string{harnessTenantBundleName, harnessAdminBundleName} {
		if _, statErr := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(statErr) {
			t.Errorf("an incomplete identity must leave no %s, stat err = %v", name, statErr)
		}
	}
}

// TestWriteHarnessAdminBundle_SystemBundleCarriesOperatorSPIFFEID mints
// through the platform's local CA issuer and asserts the written system
// bundle's leaf is the operator certificate: O = system tenant and exactly
// the URI spiffe://<trust domain>/tenant/<system tenant>/user/admin.
func TestWriteHarnessAdminBundle_SystemBundleCarriesOperatorSPIFFEID(t *testing.T) {
	dir := t.TempDir()
	issuer := appbackends.PlatformCertIssuer(issuancetest.NewCA(t), nil)

	if err := writeHarnessAdminBundle(context.Background(), newTestLogger(), issuer, harnessTestIdentity, dir); err != nil {
		t.Fatalf("writeHarnessAdminBundle: %v", err)
	}

	path := filepath.Join(dir, harnessAdminBundleName)
	cert, err := tls.LoadX509KeyPair(path, path)
	if err != nil {
		t.Fatalf("bundle is not a cert + key pair: %v", err)
	}
	if org := cert.Leaf.Subject.Organization; len(org) != 1 || org[0] != app.SystemTenantID {
		t.Errorf("bundle O = %v, want [%s]", org, app.SystemTenantID)
	}
	want := "spiffe://" + harnessTestIdentity.TrustDomain + "/tenant/" + app.SystemTenantID + "/user/admin"
	if uris := cert.Leaf.URIs; len(uris) != 1 || uris[0].String() != want {
		t.Errorf("bundle URIs = %v, want exactly [%s]", uris, want)
	}
}

// TestWriteHarnessAdminBundle_TenantBundleCarriesTenantSPIFFEID proves the
// tenant bundle is a tenant principal the mTLS transports admit (Codex 8279
// P1-f): its one subject O is the harness tenant and its URI is that
// tenant's admin user.
func TestWriteHarnessAdminBundle_TenantBundleCarriesTenantSPIFFEID(t *testing.T) {
	dir := t.TempDir()
	issuer := appbackends.PlatformCertIssuer(issuancetest.NewCA(t), nil)

	if err := writeHarnessAdminBundle(context.Background(), newTestLogger(), issuer, harnessTestIdentity, dir); err != nil {
		t.Fatalf("writeHarnessAdminBundle: %v", err)
	}

	path := filepath.Join(dir, harnessTenantBundleName)
	cert, err := tls.LoadX509KeyPair(path, path)
	if err != nil {
		t.Fatalf("tenant bundle is not a cert + key pair: %v", err)
	}
	if org := cert.Leaf.Subject.Organization; len(org) != 1 || org[0] != "harness-tenant" {
		t.Errorf("tenant bundle O = %v, want [harness-tenant]", org)
	}
	want := "spiffe://platform.test/tenant/harness-tenant/user/admin"
	if uris := cert.Leaf.URIs; len(uris) != 1 || uris[0].String() != want {
		t.Errorf("tenant bundle URIs = %v, want exactly [%s]", uris, want)
	}
}
