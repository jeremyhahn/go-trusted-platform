// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// These exercise the target's Current callback against a REAL TLS handshake.
//
// The structural tests assert only that Current is non-nil, which is why the
// hostname-verification defect survived them: a webservice certificate is issued
// for its DNS identity, but the sweep dials 127.0.0.1. With ServerName unset,
// crypto/tls verifies against "127.0.0.1", every handshake fails before NotAfter
// is read, and the sweep reports each target failed and reissues nothing —
// renewal is wired and still renews nothing.

const testServiceCN = "api.example.com"

// newTestCA returns a self-signed CA plus a leaf issued for cn.
func newTestCA(t *testing.T, cn string) (caCert *x509.Certificate, caPool *x509.CertPool, leafTLS tls.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn}, // DNS identity only — deliberately NOT 127.0.0.1
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}

	caPool = x509.NewCertPool()
	caPool.AddCert(caCert)
	return caCert, caPool, tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
		Leaf:        mustParse(t, leafDER),
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return c
}

// servingCA hands buildWebServiceCertTarget the real test root, so the target's
// verification runs against the same CA that signed the served leaf.
type servingCA struct {
	quicbaasca.CACertificateAuthority
	root *x509.Certificate
	pool *x509.CertPool
}

func (f *servingCA) TrustedRoot() (*x509.Certificate, error) { return f.root, nil }
func (f *servingCA) TrustedRootCertPool(*x509.Certificate) (*x509.CertPool, error) {
	return f.pool, nil
}

// startTLSServer serves leaf on 127.0.0.1 and returns its port.
func startTLSServer(t *testing.T, leaf tls.Certificate) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{leaf}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Force the handshake, then drop it; the client only needs the cert.
			go func() {
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
				conn.Close()
			}()
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return port
}

func TestWebServiceCertTarget_CurrentReadsTheServedCertificate(t *testing.T) {
	root, pool, leaf := newTestCA(t, testServiceCN)
	port := startTLSServer(t, leaf)

	app := &App{Logger: logging.DefaultLogger(), CA: &servingCA{root: root, pool: pool}}
	target, err := buildWebServiceCertTarget(context.Background(), "api",
		&v1.Config{TLSPort: port}, &xkmssdk.KeyAttributes{CN: testServiceCN}, app)
	if err != nil {
		t.Fatalf("buildWebServiceCertTarget: %v", err)
	}

	got, err := target.Current(context.Background())
	if err != nil {
		t.Fatalf("Current failed against a live TLS server presenting a valid "+
			"CA-signed certificate for %q. The renewal sweep reads NotAfter through "+
			"this call, so it would mark the target failed and never reissue: %v",
			testServiceCN, err)
	}
	if got.Subject.CommonName != testServiceCN {
		t.Errorf("Current returned CN %q, want %q", got.Subject.CommonName, testServiceCN)
	}
	if !got.NotAfter.After(time.Now()) {
		t.Error("Current returned a certificate that is already expired")
	}
}

func TestWebServiceCertTarget_CurrentRejectsAMismatchedIdentity(t *testing.T) {
	// The server presents a certificate for a DIFFERENT name. Verification must
	// still be enforced — the fix sets ServerName, it does not disable checking.
	root, pool, _ := newTestCA(t, testServiceCN)
	_, _, otherLeaf := newTestCA(t, "someone-else.example.com")
	port := startTLSServer(t, otherLeaf)

	app := &App{Logger: logging.DefaultLogger(), CA: &servingCA{root: root, pool: pool}}
	target, err := buildWebServiceCertTarget(context.Background(), "api",
		&v1.Config{TLSPort: port}, &xkmssdk.KeyAttributes{CN: testServiceCN}, app)
	if err != nil {
		t.Fatalf("buildWebServiceCertTarget: %v", err)
	}

	if _, err := target.Current(context.Background()); err == nil {
		t.Error("Current accepted a certificate issued to a different identity by an " +
			"unknown CA; the sweep would then read NotAfter from whatever is on that " +
			"port and treat it as this service's certificate")
	}
}

// --- verification roots must follow the issuance mode ---

func acmeClientApp(directory string) *App {
	a := &App{Logger: logging.DefaultLogger()}
	if directory != "" {
		a.ACMEConfig = &trustedca.ACMEConfig{Client: &trustedca.ACMEClientYAMLConfig{DirectoryURL: directory}}
	}
	return a
}

func TestWebServiceUsesPublicACME(t *testing.T) {
	withChallenge := &v1.Config{}
	withChallenge.Certificate.ACME = &v1.ACMEIdentityConfig{Challenge: "http-01"}

	noChallenge := &v1.Config{}

	cases := map[string]struct {
		app        *App
		cfg        *v1.Config
		useLocalCA bool
		want       bool
	}{
		"acme challenge + configured directory": {acmeClientApp("https://acme.example/dir"), withChallenge, false, true},
		"local ACME server wins":                {acmeClientApp("https://acme.example/dir"), withChallenge, true, false},
		"no challenge declared":                 {acmeClientApp("https://acme.example/dir"), noChallenge, false, false},
		"challenge but no directory":            {acmeClientApp(""), withChallenge, false, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.app.webServiceUsesPublicACME(tc.cfg, tc.useLocalCA); got != tc.want {
				t.Errorf("webServiceUsesPublicACME = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWebServiceVerifyRoots_FollowsTheIssuanceMode(t *testing.T) {
	root, platformPool, leaf := newTestCA(t, testServiceCN)
	leafCert := leaf.Leaf

	// Local issuance: the platform pool is used unchanged.
	local := acmeClientApp("")
	got, err := local.webServiceVerifyRoots(&v1.Config{}, root, platformPool)
	if err != nil {
		t.Fatalf("local mode: %v", err)
	}
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots: got, DNSName: testServiceCN,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("a platform-issued certificate must verify in local mode: %v", err)
	}

	// Public-ACME issuance: the system pool is used, and the platform root is
	// still included — a public-ACME webservice can be serving a locally-issued
	// certificate before its first order completes, and the sweep must be able
	// to read that one in order to replace it.
	acmeCfg := &v1.Config{}
	acmeCfg.Certificate.ACME = &v1.ACMEIdentityConfig{Challenge: "http-01"}
	acmeApp := acmeClientApp("https://acme.example/dir")

	got, err = acmeApp.webServiceVerifyRoots(acmeCfg, root, platformPool)
	if err != nil {
		t.Fatalf("acme mode: %v", err)
	}
	// The decisive assertion: in public-ACME mode the pool must NOT be the
	// platform pool. A leaf signed by the platform root verifies against either
	// one, so checking only that would pass even if the mode were ignored --
	// and ignoring the mode is exactly the defect (a publicly-issued
	// certificate then fails "unknown authority" on every sweep, forever).
	if got.Equal(platformPool) {
		t.Fatal("public-ACME mode returned the platform pool unchanged; a " +
			"certificate issued by the public ACME directory would fail " +
			"verification on every sweep and never be renewed")
	}
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots: got, DNSName: testServiceCN,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("the platform root must remain trusted in public-ACME mode, so a "+
			"not-yet-migrated certificate can still be read and renewed: %v", err)
	}
}
