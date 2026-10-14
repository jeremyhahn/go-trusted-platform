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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
)

// simulatedIDevID is a TPM, running in the in-process go-tpm-tools simulator,
// that holds a provisioned IAK and an IDevID minted on top of it the way
// enrollment mints one on a device. No host TPM device is opened.
type simulatedIDevID struct {
	TPM     xkmssdk.TrustedPlatformModule
	Config  *xkmssdk.TPMConfig
	Attrs   *xkmssdk.KeyAttributes
	Backend xkmssdk.TPMKeyBackend
}

// newSimulatedIDevID provisions a simulator and creates an IDevID with the
// key profile the shipped device templates carry (RSA-2048, SHA256-RSA).
//
// go-tpm-tools allows one simulator per process and hands the next caller a
// lock only Close releases, so the Close cleanup is registered before anything
// else can fail.
func newSimulatedIDevID(t *testing.T) *simulatedIDevID {
	t.Helper()

	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sim.Close()) })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	storage, err := xkmssdk.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)
	backend := xkmssdk.NewFileBackend(logger, storage)

	config := simulatedIDevIDConfig()
	tpm, err := xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Backend:   backend,
		Config:    config,
		FQDN:      "device-01.example.com",
		Logger:    logger,
		Transport: transport.FromReadWriter(sim),
	})
	if err == xkmssdk.ErrTPMNotInitialized {
		require.NoError(t, tpm.Provision(nil))
	} else {
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, tpm.Close()) })

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)
	ekPub, err := tpm.EKRSA()
	require.NoError(t, err)

	idevidAttrs, _, err := tpm.CreateIDevID(iakAttrs, selfSignedCertificate(t, ekPub), nil)
	require.NoError(t, err)

	return &simulatedIDevID{TPM: tpm, Config: config, Attrs: idevidAttrs, Backend: backend}
}

// simulatedIDevIDConfig mirrors the TPM section of the shipped device
// templates, with the handles go-xkms's own simulator suites use.
func simulatedIDevIDConfig() *xkmssdk.TPMConfig {
	rsa2048 := func() *xkmssdk.RSAConfig { return &xkmssdk.RSAConfig{KeySize: 2048} }
	return &xkmssdk.TPMConfig{
		Hash: "SHA-256",
		EK: &xkmssdk.EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: xkmssdk.DEFAULT_PASSWORD,
			RSAConfig:     rsa2048(),
		},
		IdentityProvisioningStrategy: "IAK_IDEVID_SINGLE_PASS",
		IAK: &xkmssdk.IAKConfig{
			CN:                 "device-01",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81010002,
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          rsa2048(),
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
		},
		IDevID: &xkmssdk.IDevIDConfig{
			CN:                 "device-01",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Model:              "control-plane",
			RSAConfig:          rsa2048(),
			Serial:             "tp-cp-01",
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
		},
		PlatformPCR:     16,
		PlatformPCRBank: "sha256",
		GoldenPCRs:      []uint{0, 7},
		SSRK: &xkmssdk.SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: xkmssdk.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig:     rsa2048(),
		},
		PlatformSRK: &xkmssdk.PlatformSRKConfig{
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}
}

// testIssuer is a throwaway CA that issues the device certificate the way the
// platform CA does at enrollment: over a public key it never held.
type testIssuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test platform CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testIssuer{cert: cert, key: key}
}

// issueClient issues a TLS client certificate with the given common name for pub.
func (ca *testIssuer) issueClient(t *testing.T, cn string, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// issueServer issues the loopback TLS server certificate the platform CA
// issues a control plane's web service, with a key of its own.
func (ca *testIssuer) issueServer(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "control plane"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (ca *testIssuer) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// selfSignedCertificate stands in for the manufacturer's EK certificate, which
// CreateIDevID embeds in the TCG-CSR-IDEVID but does not verify.
func selfSignedCertificate(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "simulated EK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// newMTLSServer starts a TLS 1.3 server that requires a client certificate
// chaining to clientCAs and answers with the verified peer's common name.
func newMTLSServer(t *testing.T, clientCAs *x509.CertPool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
		require.NoError(t, err)
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestTPMSigner_IDevIDSignsTLS13ClientCertificateVerify answers #149's first
// question: can the IDevID key, through the platform's TPM signer, sign a
// TLS 1.3 CertificateVerify that a server requiring client certificates
// accepts?
//
// The signer is built the way a device builds it: key attributes from the
// IDevID configuration, the public half from the TPM's persistent IDevID.
func TestTPMSigner_IDevIDSignsTLS13ClientCertificateVerify(t *testing.T) {
	idevid := newSimulatedIDevID(t)
	attrs, err := xkmssdk.IDevIDAttributesFromConfig(*idevid.Config.IDevID)
	require.NoError(t, err)
	pub, err := idevid.TPM.IDevID()
	require.NoError(t, err)
	tpmSigner, err := platform.NewTPMSigner(idevid.TPM, attrs, idevid.Backend)
	require.NoError(t, err)
	signer := certSigner{Signer: tpmSigner, pub: pub}

	ca := newTestIssuer(t)
	cert := ca.issueClient(t, "tp-cp-01", signer.Public())
	srv := newMTLSServer(t, ca.pool())

	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
		Leaf:        cert,
	}}

	resp, err := client.Get(srv.URL)
	require.NoError(t, err, "the TLS 1.3 handshake must complete with the IDevID signing CertificateVerify")
	t.Cleanup(func() { require.NoError(t, resp.Body.Close()) })

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "tp-cp-01", string(body), "the server must have verified the IDevID certificate")
}
