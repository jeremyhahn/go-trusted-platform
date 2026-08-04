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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	acmeclient "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme/client"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// --- fakes ---

type fakeACME struct {
	mu      sync.Mutex
	err     error
	lastReq *acmeclient.CertificateRequest
	callCnt int
	retCert *x509.Certificate
}

func (f *fakeACME) RequestCertificate(_ context.Context, req *acmeclient.CertificateRequest) (*x509.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCnt++
	f.lastReq = req
	if f.err != nil {
		return nil, f.err
	}
	if f.retCert != nil {
		return f.retCert, nil
	}
	return testIssuedCertificate(), nil
}

type fakeLocalCA struct {
	mu      sync.Mutex
	err     error
	lastReq *quicbaasca.CACertificateRequest
	callCnt int
	retCert *x509.Certificate
}

func (f *fakeLocalCA) IssueCertificate(_ context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCnt++
	f.lastReq = req
	if f.err != nil {
		return nil, f.err
	}
	if f.retCert != nil {
		return &quicbaasca.IssuedCertificate{Certificate: f.retCert}, nil
	}
	return &quicbaasca.IssuedCertificate{Certificate: testIssuedCertificate()}, nil
}

type fakeDNS struct {
	mu      sync.Mutex
	adds    []string
	deletes []string
}

func (f *fakeDNS) AddRecord(_ context.Context, name, kind, value string, ttl int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds = append(f.adds, name+"|"+kind+"|"+value)
	return nil
}

func (f *fakeDNS) DeleteRecord(_ context.Context, name, kind string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, name+"|"+kind)
	return nil
}

type fakeDeployer struct {
	mu           sync.Mutex
	replaceErr   error
	closeErr     error
	certPEMSeen  []byte
	keyPEMSeenBs []byte // copy of key bytes for assertion
	replaceCalls int
	closeCalls   int
}

func (d *fakeDeployer) ReplaceWebCertificate(_ context.Context, certPEM []byte, keyPEM *memguard.Secret) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.replaceCalls++
	if d.replaceErr != nil {
		return d.replaceErr
	}
	d.certPEMSeen = append([]byte(nil), certPEM...)
	d.keyPEMSeenBs = append([]byte(nil), keyPEM.Bytes()...)
	return nil
}

func (d *fakeDeployer) GetWebCertificate(context.Context) (*x509.Certificate, error) {
	return testIssuedCertificate(), nil
}

func (d *fakeDeployer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closeCalls++
	return d.closeErr
}

// testIssuedCertificate returns a real x509 certificate so tests can
// exercise cert PEM encoding paths with actual DER bytes.
func testIssuedCertificate() *x509.Certificate {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.internal"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// --- helpers under test ---

func TestGenerateBMCKeyPair_DefaultECDSA(t *testing.T) {
	priv, keyPEM, err := generateBMCKeyPair(nil)
	if err != nil {
		t.Fatalf("generateBMCKeyPair: %v", err)
	}
	defer keyPEM.Destroy()
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Errorf("default key is not *ecdsa.PrivateKey: %T", priv)
	}
	if !bytesContainsPEMBlock(keyPEM.Bytes(), "PRIVATE KEY") {
		t.Error("key PEM missing PRIVATE KEY block")
	}
}

func TestGenerateBMCKeyPair_ExplicitECDSAP384(t *testing.T) {
	cfg := &common.KeyConfig{
		KeyAlgorithm: "ECDSA",
		ECCConfig:    &common.ECCConfig{Curve: "P-384"},
	}
	priv, keyPEM, err := generateBMCKeyPair(cfg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	defer keyPEM.Destroy()
	ec, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("not *ecdsa.PrivateKey: %T", priv)
	}
	if ec.Curve.Params().Name != "P-384" {
		t.Errorf("curve = %q, want P-384", ec.Curve.Params().Name)
	}
}

func TestGenerateBMCKeyPair_ECDSAP521(t *testing.T) {
	cfg := &common.KeyConfig{
		KeyAlgorithm: "EC",
		ECCConfig:    &common.ECCConfig{Curve: "P-521"},
	}
	_, keyPEM, err := generateBMCKeyPair(cfg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	defer keyPEM.Destroy()
}

func TestGenerateBMCKeyPair_UnknownCurve(t *testing.T) {
	cfg := &common.KeyConfig{
		KeyAlgorithm: "ECDSA",
		ECCConfig:    &common.ECCConfig{Curve: "P-999"},
	}
	_, _, err := generateBMCKeyPair(cfg)
	var want ErrUnsupportedKeyCurve
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrUnsupportedKeyCurve", err)
	}
}

func TestGenerateBMCKeyPair_RSA(t *testing.T) {
	cfg := &common.KeyConfig{
		KeyAlgorithm: "RSA",
		RSAConfig:    &common.RSAConfig{KeySize: 2048},
	}
	priv, keyPEM, err := generateBMCKeyPair(cfg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	defer keyPEM.Destroy()
	r, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("not *rsa.PrivateKey: %T", priv)
	}
	if r.N.BitLen() < 2000 || r.N.BitLen() > 2056 {
		t.Errorf("RSA key size = %d bits, want ~2048", r.N.BitLen())
	}
}

func TestGenerateBMCKeyPair_UnsupportedAlgorithm(t *testing.T) {
	cfg := &common.KeyConfig{KeyAlgorithm: "Ed25519"}
	_, _, err := generateBMCKeyPair(cfg)
	var want ErrUnsupportedKeyAlgorithm
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrUnsupportedKeyAlgorithm", err)
	}
}

func TestNamedCurve(t *testing.T) {
	cases := []struct {
		in     string
		ok     bool
		expect string
	}{
		{"", true, "P-256"},
		{"P-256", true, "P-256"},
		{"P-384", true, "P-384"},
		{"P-521", true, "P-521"},
		{"P-999", false, ""},
	}
	for _, tc := range cases {
		c, err := namedCurve(tc.in)
		if tc.ok && err != nil {
			t.Errorf("namedCurve(%q) err = %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("namedCurve(%q) expected error", tc.in)
		}
		if tc.ok && c.Params().Name != tc.expect {
			t.Errorf("namedCurve(%q).Name = %q, want %q", tc.in, c.Params().Name, tc.expect)
		}
	}
}

// --- buildBMCSubjectAltNames ---

func TestBuildBMCSubjectAltNames_ExplicitSANS(t *testing.T) {
	sans := &quicbaasca.CASubjectAlternativeNames{DNS: []string{"a", "b"}}
	cfg := &bmc.Config{
		Certificate: &common.Identity{
			SANS:    sans,
			Subject: quicbaasca.CASubject{CommonName: "ignored"},
		},
	}
	got := buildBMCSubjectAltNames(cfg, "ops@x.com")
	if got != sans {
		t.Error("explicit SANS should be returned as-is")
	}
}

func TestBuildBMCSubjectAltNames_DerivedFromCN(t *testing.T) {
	cfg := &bmc.Config{
		Certificate: &common.Identity{
			Subject: quicbaasca.CASubject{CommonName: "bmc01.internal"},
		},
	}
	got := buildBMCSubjectAltNames(cfg, "ops@x.com")
	if len(got.DNS) != 1 || got.DNS[0] != "bmc01.internal" {
		t.Errorf("DNS = %v, want [bmc01.internal]", got.DNS)
	}
	if len(got.Email) != 1 || got.Email[0] != "ops@x.com" {
		t.Errorf("Email = %v, want [ops@x.com]", got.Email)
	}
}

func TestBuildBMCSubjectAltNames_NilConfig(t *testing.T) {
	if got := buildBMCSubjectAltNames(nil, "x"); got == nil {
		t.Error("returned nil")
	}
	cfg := &bmc.Config{Certificate: nil}
	if got := buildBMCSubjectAltNames(cfg, "x"); got == nil {
		t.Error("returned nil for cert-disabled config")
	}
}

// --- casdkSubjectToPKIXName ---

func TestCASDKSubjectToPKIXName(t *testing.T) {
	n := casdkSubjectToPKIXName(quicbaasca.CASubject{
		CommonName:   "cn",
		Organization: "org",
		Country:      "US",
		Province:     "CA",
		Locality:     "SF",
		Address:      "1 St",
		PostalCode:   "94110",
	})
	if n.CommonName != "cn" {
		t.Errorf("cn = %q", n.CommonName)
	}
	if len(n.Organization) != 1 || n.Organization[0] != "org" {
		t.Errorf("org = %v", n.Organization)
	}
}

func TestCASDKSubjectToPKIXName_EmptyFields(t *testing.T) {
	n := casdkSubjectToPKIXName(quicbaasca.CASubject{CommonName: "cn"})
	if n.Organization != nil {
		t.Errorf("empty org should be nil, got %v", n.Organization)
	}
	if n.Country != nil {
		t.Errorf("empty country should be nil")
	}
}

// --- buildBMCCSR ---

func TestBuildBMCCSR_SignsWithPrivKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := minimalCertConfig("bmc01.internal")
	csrDER, err := buildBMCCSR(cfg, priv, "")
	if err != nil {
		t.Fatalf("buildBMCCSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "bmc01.internal" {
		t.Errorf("cn = %q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "bmc01.internal" {
		t.Errorf("DNSNames = %v", csr.DNSNames)
	}
}

func TestBuildBMCCSR_IncludesIPs(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := &bmc.Config{
		Certificate: &common.Identity{
			Subject: quicbaasca.CASubject{CommonName: "bmc01.internal"},
			SANS: &quicbaasca.CASubjectAlternativeNames{
				DNS: []string{"bmc01.internal"},
				IPs: []string{"10.0.0.1", "not-an-ip", "192.168.1.1"},
			},
		},
	}
	csrDER, err := buildBMCCSR(cfg, priv, "")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)
	if len(csr.IPAddresses) != 2 {
		t.Errorf("IP SANs = %d, want 2 (bad IPs skipped)", len(csr.IPAddresses))
	}
}

func TestBuildBMCCSR_CertDisabled(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := buildBMCCSR(&bmc.Config{}, priv, "")
	if !errors.Is(err, ErrBMCCertDisabled) {
		t.Errorf("err = %v, want ErrBMCCertDisabled", err)
	}
}

// --- buildBMCACMERequest ---

func TestBuildBMCACMERequest_OK(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	csrDER := []byte{1, 2, 3}
	dns := &fakeDNS{}

	req, err := buildBMCACMERequest(context.Background(), cfg, csrDER, dns, 60, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if req.AuthzType != "dns" || req.AuthzValue != "bmc01.internal" {
		t.Errorf("authz = %s/%s", req.AuthzType, req.AuthzValue)
	}
	if req.ChallengeType != "dns-01" {
		t.Errorf("challenge = %q", req.ChallengeType)
	}
	if string(req.CSR) != string(csrDER) {
		t.Error("CSR not passed through")
	}
	if req.ChallengeSetup == nil || req.ChallengeCleanup == nil {
		t.Error("missing challenge setup/cleanup closures")
	}
}

func TestBuildBMCACMERequest_MissingACME(t *testing.T) {
	cfg := &bmc.Config{Certificate: &common.Identity{Subject: quicbaasca.CASubject{CommonName: "x"}}}
	_, err := buildBMCACMERequest(context.Background(), cfg, nil, &fakeDNS{}, 60, nil)
	if !errors.Is(err, ErrMissingACMEConfig) {
		t.Errorf("err = %v, want ErrMissingACMEConfig", err)
	}
}

func TestBuildBMCACMERequest_HTTP01Rejected(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	cfg.Certificate.ACME.Challenge = "http-01"
	_, err := buildBMCACMERequest(context.Background(), cfg, nil, &fakeDNS{}, 60, nil)
	var want ErrInvalidChallengeType
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidChallengeType", err)
	}
}

func TestBuildBMCACMERequest_AuthzFromCN(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	cfg.Certificate.ACME.AuthzValue = "" // force CN fallback
	req, err := buildBMCACMERequest(context.Background(), cfg, nil, &fakeDNS{}, 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.AuthzValue != "bmc01.internal" {
		t.Errorf("authz = %q, want CN fallback", req.AuthzValue)
	}
}

func TestBuildBMCACMERequest_NoAuthzNoCN(t *testing.T) {
	cfg := minimalCertConfig("")
	cfg.Certificate.ACME.AuthzValue = ""
	_, err := buildBMCACMERequest(context.Background(), cfg, nil, &fakeDNS{}, 60, nil)
	if !errors.Is(err, ErrMissingAuthzValue) {
		t.Errorf("err = %v, want ErrMissingAuthzValue", err)
	}
}

// --- buildBMCLocalCARequest ---

func TestBuildBMCLocalCARequest_DefaultValid(t *testing.T) {
	cfg := minimalCertConfig("x")
	cfg.Certificate.Valid = 0
	r := buildBMCLocalCARequest(cfg, "ops@x.com")
	if r.Valid != defaultBMCCertValidDays {
		t.Errorf("valid = %d, want %d", r.Valid, defaultBMCCertValidDays)
	}
}

func TestBuildBMCLocalCARequest_ExplicitValid(t *testing.T) {
	cfg := minimalCertConfig("x")
	cfg.Certificate.Valid = 30
	r := buildBMCLocalCARequest(cfg, "")
	if r.Valid != 30 {
		t.Errorf("valid = %d", r.Valid)
	}
}

// --- issueBMCCertificateCore ---

func TestIssueBMCCertificateCore_ACMEPath(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	acme := &fakeACME{}
	local := &fakeLocalCA{}
	dns := &fakeDNS{}
	dep := &fakeDeployer{}

	target, err := issueBMCCertificateCore(context.Background(), "dev-1", cfg, issueBMCCertificateOptions{
		ACMEIssuer:    acme,
		LocalCAIssuer: local,
		DNSUpdater:    dns,
		Deployer:      dep,
	})
	if err != nil {
		t.Fatalf("issueBMCCertificateCore: %v", err)
	}
	if target.Name != "bmc.dev-1" {
		t.Errorf("target.Name = %q", target.Name)
	}
	if target.Kind != CertKindBMC {
		t.Errorf("target.Kind = %q", target.Kind)
	}
	if acme.callCnt != 1 {
		t.Errorf("acme.callCnt = %d", acme.callCnt)
	}
	if local.callCnt != 0 {
		t.Error("local CA called when ACME configured")
	}
	if dep.replaceCalls != 1 {
		t.Errorf("deploy calls = %d", dep.replaceCalls)
	}
	if !bytesContainsPEMBlock(dep.certPEMSeen, "CERTIFICATE") {
		t.Error("deployer did not receive cert PEM")
	}
	if !bytesContainsPEMBlock(dep.keyPEMSeenBs, "PRIVATE KEY") {
		t.Error("deployer did not receive key PEM")
	}
}

func TestIssueBMCCertificateCore_LocalCAFallback(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	local := &fakeLocalCA{}
	dep := &fakeDeployer{}

	target, err := issueBMCCertificateCore(context.Background(), "dev-2", cfg, issueBMCCertificateOptions{
		// No ACMEIssuer -> local CA path.
		LocalCAIssuer: local,
		Deployer:      dep,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if local.callCnt != 1 {
		t.Errorf("local.callCnt = %d", local.callCnt)
	}
	if target == nil {
		t.Fatal("nil target")
	}
}

func TestIssueBMCCertificateCore_NilConfig(t *testing.T) {
	_, err := issueBMCCertificateCore(context.Background(), "x", nil, issueBMCCertificateOptions{LocalCAIssuer: &fakeLocalCA{}})
	var want bmc.ErrNilConfig
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrNilConfig", err)
	}
}

func TestIssueBMCCertificateCore_ConfigInvalid(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	cfg.Certificate.ACME.Challenge = "http-01"
	_, err := issueBMCCertificateCore(context.Background(), "x", cfg, issueBMCCertificateOptions{LocalCAIssuer: &fakeLocalCA{}})
	if err == nil {
		t.Fatal("expected config validation failure")
	}
}

func TestIssueBMCCertificateCore_CertDisabled(t *testing.T) {
	cfg := &bmc.Config{
		Address: "1.2.3.4", Port: 623, Protocol: bmc.ProtocolIPMI,
	}
	_, err := issueBMCCertificateCore(context.Background(), "x", cfg, issueBMCCertificateOptions{LocalCAIssuer: &fakeLocalCA{}})
	if !errors.Is(err, ErrBMCCertDisabled) {
		t.Errorf("err = %v, want ErrBMCCertDisabled", err)
	}
}

func TestIssueBMCCertificateCore_MissingLocalCA(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	_, err := issueBMCCertificateCore(context.Background(), "x", cfg, issueBMCCertificateOptions{
		// no LocalCAIssuer
	})
	if !errors.Is(err, ErrMissingLocalCAIssuer) {
		t.Errorf("err = %v, want ErrMissingLocalCAIssuer", err)
	}
}

func TestIssueBMCCertificateCore_ACMEError(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	acme := &fakeACME{err: errors.New("ACME sad")}
	local := &fakeLocalCA{}
	dep := &fakeDeployer{}
	_, err := issueBMCCertificateCore(context.Background(), "dev-3", cfg, issueBMCCertificateOptions{
		ACMEIssuer:    acme,
		LocalCAIssuer: local,
		DNSUpdater:    &fakeDNS{},
		Deployer:      dep,
	})
	var want ErrBMCACMEIssuance
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrBMCACMEIssuance", err)
	}
}

func TestIssueBMCCertificateCore_LocalCAError(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	local := &fakeLocalCA{err: errors.New("CA sad")}
	_, err := issueBMCCertificateCore(context.Background(), "dev-4", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: local,
		Deployer:      &fakeDeployer{},
	})
	var want ErrBMCLocalIssuance
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrBMCLocalIssuance", err)
	}
}

func TestIssueBMCCertificateCore_DeployError(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	dep := &fakeDeployer{replaceErr: errors.New("deploy sad")}
	_, err := issueBMCCertificateCore(context.Background(), "dev-5", cfg, issueBMCCertificateOptions{
		LocalCAIssuer: &fakeLocalCA{},
		Deployer:      dep,
	})
	var want ErrBMCDeploy
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrBMCDeploy", err)
	}
}

func TestIssueBMCCertificateCore_TargetReissueRecurs(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	local := &fakeLocalCA{}
	dep := &fakeDeployer{}
	opts := issueBMCCertificateOptions{LocalCAIssuer: local, Deployer: dep}
	target, err := issueBMCCertificateCore(context.Background(), "dev-6", cfg, opts)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if err := target.Reissue(context.Background()); err != nil {
		t.Fatalf("Reissue: %v", err)
	}
	if local.callCnt != 2 {
		t.Errorf("callCnt after Reissue = %d, want 2", local.callCnt)
	}
}

func TestIssueBMCCertificateCore_BackendOverride(t *testing.T) {
	cfg := minimalCertConfig("bmc01.internal")
	cfg.Backend = bmc.CertBackendRedfish
	dep := &fakeDeployer{}
	_, err := issueBMCCertificateCore(context.Background(), "dev-7", cfg, issueBMCCertificateOptions{
		LocalCAIssuer:   &fakeLocalCA{},
		Deployer:        dep,
		BackendOverride: bmc.CertBackendSMCCGI,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// Backend override would only be visible in constructed AutoCertManager,
	// which we bypass via Deployer. Presence test is sufficient.
}

// --- errors ---

func TestBMCCertErrors_Messages(t *testing.T) {
	cases := []error{
		ErrBMCCertDisabled,
		ErrMissingACMEConfig,
		ErrMissingAuthzValue,
		ErrMissingLocalCAIssuer,
		ErrInvalidChallengeType{Got: "http-01"},
		ErrUnsupportedKeyAlgorithm{Algorithm: "X"},
		ErrUnsupportedKeyCurve{Curve: "P-999"},
		ErrKeyGenerate{Cause: errors.New("c")},
		ErrCSRCreate{Cause: errors.New("c")},
		ErrBMCACMEIssuance{DeviceID: "d", Cause: errors.New("c")},
		ErrBMCLocalIssuance{DeviceID: "d", Cause: errors.New("c")},
		ErrBMCDeploy{DeviceID: "d", Cause: errors.New("c")},
	}
	for _, e := range cases {
		if e.Error() == "" {
			t.Errorf("empty error from %T", e)
		}
	}
	inner := errors.New("inner")
	wrapped := []error{
		ErrKeyGenerate{Cause: inner},
		ErrCSRCreate{Cause: inner},
		ErrBMCACMEIssuance{Cause: inner},
		ErrBMCLocalIssuance{Cause: inner},
		ErrBMCDeploy{Cause: inner},
	}
	for _, e := range wrapped {
		if !errors.Is(e, inner) {
			t.Errorf("%T does not unwrap", e)
		}
	}
}

// --- helpers ---

func minimalCertConfig(cn string) *bmc.Config {
	return &bmc.Config{
		Address:  "1.2.3.4",
		Port:     623,
		Username: "admin",
		Password: "x",
		Protocol: bmc.ProtocolIPMI,
		Certificate: &common.Identity{
			Subject: quicbaasca.CASubject{CommonName: cn},
			ACME: &common.ACMEIdentityConfig{
				AuthzType:  "dns",
				AuthzValue: cn,
				Challenge:  "dns-01",
			},
		},
		Key: &common.KeyConfig{
			KeyAlgorithm: "ECDSA",
			CN:           cn,
		},
	}
}

// bytesContainsPEMBlock reports whether b contains a PEM block of the
// given type.
func bytesContainsPEMBlock(b []byte, blockType string) bool {
	if b == nil {
		return false
	}
	rest := b
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type == blockType {
			return true
		}
		rest = next
	}
}
