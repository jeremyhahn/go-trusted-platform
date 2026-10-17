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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	certclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/certificate"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

var testAdminIdentity = AdminIdentity{TrustDomain: "tp.internal", TenantID: "system"}

// recordingIssuer stands in for the SDK issuer: it records the request and
// answers with a fixed bundle.
type recordingIssuer struct {
	req *certclient.IssueCertificateRequest
}

func (r *recordingIssuer) IssueCertificate(_ context.Context, req *certclient.IssueCertificateRequest) (*certclient.IssueCertificateResponse, error) {
	r.req = req
	return &certclient.IssueCertificateResponse{CertificatePEM: "cert", PrivateKeyPEM: "key"}, nil
}

func (r *recordingIssuer) GetCABundle(context.Context, *certclient.GetCABundleRequest) (*certclient.GetCABundleResponse, error) {
	return &certclient.GetCABundleResponse{}, nil
}

// signingCA signs CSRs with an in-memory root; the rest of the CA surface is
// unused by the local issuer.
type signingCA struct {
	quicbaasca.CACertificateAuthority
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	err     error
}

func newSigningCA(t *testing.T) *signingCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	return &signingCA{root: root, rootKey: key}
}

func (c *signingCA) SignCSR(_ context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error) {
	if c.err != nil {
		return nil, c.err
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.ExtKeyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.root, csr.PublicKey, c.rootKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func (c *signingCA) CABundle() ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.root.Raw}), nil
}

func TestPlatformCertIssuer_PrefersLocalCA(t *testing.T) {
	if got := PlatformCertIssuer(newSigningCA(t), &fakeQuicbaasClient{}); got == nil {
		t.Fatal("got nil issuer")
	} else if _, ok := got.(*localCACertIssuer); !ok {
		t.Errorf("issuer = %T, want the local CA issuer", got)
	}
}

func TestPlatformCertIssuer_FallsBackToSDK(t *testing.T) {
	if got := PlatformCertIssuer(nil, &fakeQuicbaasClient{}); got == nil {
		t.Fatal("got nil issuer")
	} else if _, ok := got.(*sdkCertIssuer); !ok {
		t.Errorf("issuer = %T, want the SDK issuer", got)
	}
}

func TestPlatformCertIssuer_NilWhenNeitherAvailable(t *testing.T) {
	if got := PlatformCertIssuer(nil, nil); got != nil {
		t.Errorf("no CA and no SDK: got %T, want nil", got)
	}
}

// TestAdminBundleIssuer_MintsAdminClientCert proves the /init admin bundle
// is a CN=admin client certificate signed by the platform CA, with the key
// that matches it.
func TestAdminBundleIssuer_MintsAdminClientCert(t *testing.T) {
	ca := newSigningCA(t)
	bundle, err := NewAdminBundleIssuer(PlatformCertIssuer(ca, nil), testAdminIdentity).IssueAdminBundle(context.Background())
	if err != nil {
		t.Fatalf("IssueAdminBundle: %v", err)
	}
	certBlock, _ := pem.Decode([]byte(bundle.CertPEM))
	if certBlock == nil {
		t.Fatal("admin bundle certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse admin cert: %v", err)
	}
	if cert.Subject.CommonName != "admin" {
		t.Errorf("CommonName = %q, want admin", cert.Subject.CommonName)
	}
	// The mTLS transports bind a certificate to the tenant its subject O
	// names; the root admin must land in the system tenant.
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != app.SystemTenantID {
		t.Errorf("Organization = %v, want [%s]", cert.Subject.Organization, app.SystemTenantID)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want client auth only", cert.ExtKeyUsage)
	}
	if err := cert.CheckSignatureFrom(ca.root); err != nil {
		t.Errorf("admin cert not signed by the platform CA: %v", err)
	}
	keyBlock, _ := pem.Decode([]byte(bundle.KeyPEM))
	if keyBlock == nil {
		t.Fatal("admin bundle key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse admin key: %v", err)
	}
	if !key.(*ecdsa.PrivateKey).PublicKey.Equal(cert.PublicKey) {
		t.Error("admin key does not match the certificate")
	}
}

func TestAdminBundleIssuer_PropagatesCAError(t *testing.T) {
	ca := newSigningCA(t)
	ca.err = errors.New("ca offline")
	_, err := NewAdminBundleIssuer(PlatformCertIssuer(ca, nil), testAdminIdentity).IssueAdminBundle(context.Background())
	var issue *ErrCertIssue
	if !errors.As(err, &issue) || !errors.Is(err, ca.err) {
		t.Fatalf("want ErrCertIssue wrapping the CA error, got %T: %v", err, err)
	}
	if issue.Usage != "client" {
		t.Errorf("Usage = %q, want client", issue.Usage)
	}
}

func TestNewAdminBundleIssuer_NilIssuerIsNilInterface(t *testing.T) {
	if got := NewAdminBundleIssuer(nil, testAdminIdentity); got != nil {
		t.Errorf("NewAdminBundleIssuer(nil) = %v, want a nil interface", got)
	}
}

// TestAdminBundleIssuer_AsksTheCAForTheSystemAdminSPIFFEID proves the local CA
// is asked to stamp spiffe://<domain>/tenant/<tenant>/user/admin.
func TestAdminBundleIssuer_AsksTheCAForTheSystemAdminSPIFFEID(t *testing.T) {
	ca := issuancetest.NewCA(t)
	if _, err := NewAdminBundleIssuer(PlatformCertIssuer(ca, nil), testAdminIdentity).IssueAdminBundle(context.Background()); err != nil {
		t.Fatalf("IssueAdminBundle: %v", err)
	}
	opts := ca.Opts
	if opts == nil {
		t.Fatal("the CA was never asked to sign")
	}
	if opts.SPIFFETrustDomain != "tp.internal" || opts.TenantID != "system" || opts.SPIFFEName != common.AdminUsername {
		t.Errorf("SPIFFE options = (%q, %q, %q), want (tp.internal, system, %s)",
			opts.SPIFFETrustDomain, opts.TenantID, opts.SPIFFEName, common.AdminUsername)
	}
	if opts.SPIFFEKind != "" {
		t.Errorf("SPIFFEKind = %q, want the CA's user default", opts.SPIFFEKind)
	}
}

// TestAdminBundleIssuer_RefusesAnIncompleteIdentity proves no admin
// certificate is minted that admin-claim would refuse.
func TestAdminBundleIssuer_RefusesAnIncompleteIdentity(t *testing.T) {
	cases := map[string]AdminIdentity{
		"trust domain": {TenantID: "system"},
		"tenant":       {TrustDomain: "tp.internal"},
	}
	for field, identity := range cases {
		t.Run(field, func(t *testing.T) {
			ca := issuancetest.NewCA(t)
			_, err := NewAdminBundleIssuer(PlatformCertIssuer(ca, nil), identity).IssueAdminBundle(context.Background())
			var incomplete *ErrAdminIdentityIncomplete
			if !errors.As(err, &incomplete) || incomplete.Field != field {
				t.Fatalf("want ErrAdminIdentityIncomplete{%s}, got %T: %v", field, err, err)
			}
			if ca.Opts != nil {
				t.Error("the CA was asked to sign an admin certificate without its identity")
			}
		})
	}
}

// TestAdminBundleIssuer_SDKIssuerGetsTheAdminRequest covers the issuer used
// when no local CA is loaded.
func TestAdminBundleIssuer_SDKIssuerGetsTheAdminRequest(t *testing.T) {
	issuer := &recordingIssuer{}
	bundle, err := NewAdminBundleIssuer(issuer, testAdminIdentity).IssueAdminBundle(context.Background())
	if err != nil {
		t.Fatalf("IssueAdminBundle: %v", err)
	}
	if issuer.req == nil || issuer.req.CommonName != common.AdminUsername || issuer.req.Usage != "client" {
		t.Fatalf("request = %+v, want the admin client request", issuer.req)
	}
	if issuer.req.Organization != app.SystemTenantID {
		t.Errorf("request Organization = %q, want the system tenant %q", issuer.req.Organization, app.SystemTenantID)
	}
	if bundle.CertPEM != "cert" || bundle.KeyPEM != "key" {
		t.Errorf("bundle = %+v, want the issuer's answer", bundle)
	}
}

func TestLocalCACertIssuer_RejectsNilRequest(t *testing.T) {
	_, err := PlatformCertIssuer(newSigningCA(t), nil).IssueCertificate(context.Background(), nil)
	var nilReq *ErrCertRequestNil
	if !errors.As(err, &nilReq) {
		t.Fatalf("want ErrCertRequestNil, got %T: %v", err, err)
	}
}

func TestLocalCACertIssuer_GetCABundle(t *testing.T) {
	ca := newSigningCA(t)
	resp, err := PlatformCertIssuer(ca, nil).GetCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetCABundle: %v", err)
	}
	block, _ := pem.Decode([]byte(resp.BundlePEM))
	if block == nil || !ca.root.Equal(&x509.Certificate{Raw: block.Bytes}) {
		t.Errorf("bundle does not carry the CA root: %q", resp.BundlePEM)
	}
}

func TestLocalCACertIssuer_GetCABundlePropagatesError(t *testing.T) {
	ca := newSigningCA(t)
	ca.err = errors.New("no bundle")
	if _, err := PlatformCertIssuer(ca, nil).GetCABundle(context.Background(), nil); !errors.Is(err, ca.err) {
		t.Fatalf("want the CA error, got %v", err)
	}
}

func TestCertIssuerErrors_Messages(t *testing.T) {
	cases := map[string]error{
		"request is nil":                    &ErrCertRequestNil{},
		"issue client certificate: refused": &ErrCertIssue{Usage: "client", Cause: errors.New("refused")},
		"SPIFFE identity has no tenant":     &ErrAdminIdentityIncomplete{Field: "tenant"},
	}
	for want, err := range cases {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%T message %q does not contain %q", err, err.Error(), want)
		}
	}
}
