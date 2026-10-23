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

package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/require"
)

// newSimulatedHostTPM opens go-tpm-tools' simulator the way openXKMSTPM opens
// the host TPM, with no key backend, and mints an IDevID on it.
func newSimulatedHostTPM(t *testing.T) *xkmsTPM {
	t.Helper()

	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sim.Close()) })

	config := simulatedHostTPMConfig()
	tpm, err := xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Config:    config,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	_, _, err = tpm.CreateIDevID(iakAttrs, selfSignedEKCertificate(t, ekPub), nil)
	require.NoError(t, err)

	return &xkmsTPM{TrustedPlatformModule: tpm, idevid: config.IDevID}
}

func simulatedHostTPMConfig() *xkmssdk.TPMConfig {
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
			CN:                 "laptop-1-iak",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81010002,
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          rsa2048(),
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
		},
		IDevID: &xkmssdk.IDevIDConfig{
			CN:                 "laptop-1",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Model:              "laptop",
			RSAConfig:          rsa2048(),
			Serial:             "laptop-1",
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
	}
}

// selfSignedEKCertificate stands in for the manufacturer's EK certificate,
// which CreateIDevID only embeds in the enrollment request.
func selfSignedEKCertificate(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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

// The agent opens the TPM with no key backend, so its IDevID signer has none
// either: the signature must still come from the TPM-resident IDevID key.
func TestXKMSTPM_IDevIDSignerSignsWithTheTPMKey(t *testing.T) {
	tpm := newSimulatedHostTPM(t)

	signer, err := tpm.IDevIDSigner()
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("CertificateVerify"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	pub, err := tpm.IDevID()
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok, "the simulated IDevID is RSA")
	require.NoError(t, rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig))
}
