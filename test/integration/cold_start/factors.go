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

package cold_start

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// MintTestMTLSCertResult bundles the artifacts produced by mintTestMTLSCert.
type MintTestMTLSCertResult struct {
	CertPEM []byte
	KeyPEM  []byte
	// BundlePath is the on-disk path to the combined cert+key bundle.
	BundlePath string
}

// mintTestMTLSCert produces a self-signed P-256 client certificate that
// can be enrolled as an mTLS factor for the cold-start scenario. The
// certificate is intentionally short-lived (24h) and self-signed: the
// daemon enrolls factors based on the cert's subject + SPKI, not the
// signer chain.
//
// The function writes a single combined bundle to <dir>/<name>.pem and
// returns the result. Tests should pass dir = t.TempDir() so the
// artifact lives only for the test scope.
func mintTestMTLSCert(dir, name, subject string) (*MintTestMTLSCertResult, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &ErrAdminBundleInvalid{Reason: "generate key: " + err.Error()}
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, &ErrAdminBundleInvalid{Reason: "serial: " + err.Error()}
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, &ErrAdminBundleInvalid{Reason: "create cert: " + err.Error()}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, &ErrAdminBundleInvalid{Reason: "marshal key: " + err.Error()}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	bundlePath := filepath.Join(dir, name+".pem")
	bundle := append(append([]byte(nil), certPEM...), keyPEM...)
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return nil, &ErrAdminBundleInvalid{Reason: "write bundle: " + err.Error()}
	}

	return &MintTestMTLSCertResult{
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		BundlePath: bundlePath,
	}, nil
}

// FIDO2StubAdd is the FIDO2 factor enrollment helper. The cold-start
// suite cannot exercise a real authenticator without #143-b (FIDO2 stub
// authenticator). The helper returns ErrAuthenticatorStubMissing so the
// caller fails with a clear pointer to the blocking task.
func FIDO2StubAdd() error {
	return &ErrAuthenticatorStubMissing{Method: "fido2"}
}

// PIVStubAdd is the PIV factor enrollment helper. Blocked on #143-c.
func PIVStubAdd() error {
	return &ErrAuthenticatorStubMissing{Method: "piv"}
}

// FIDO2StubLogin is the FIDO2 login helper. Blocked on #143-b.
func FIDO2StubLogin() error {
	return &ErrAuthenticatorStubMissing{Method: "fido2"}
}

// PIVStubLogin is the PIV login helper. Blocked on #143-c.
func PIVStubLogin() error {
	return &ErrAuthenticatorStubMissing{Method: "piv"}
}
