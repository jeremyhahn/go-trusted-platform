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

package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
)

// publicKeyClient is a KMS that reports a public key.
type publicKeyClient struct {
	quicbaassdk.KMSClient
	public []byte
	err    error
}

func (c *publicKeyClient) GetPublicKey(_ context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &kms.GetPublicKeyResponse{KeyID: keyID, PublicKey: c.public}, nil
}

func pkixDER(t *testing.T, public any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	require.NoError(t, err)
	return der
}

// TestKeyCSR_CertifiesTheKMSKey is the fleet-certificate chain end to end:
// the KMS signs a CSR for its own key, the CA certifies that CSR, and the
// certificate holds the KMS key — so NewKMSSigner, which takes its public key
// from the certificate, signs a boot.sig that verifies.
func TestKeyCSR_CertifiesTheKMSKey(t *testing.T) {
	fleetKey := issuancetest.RSAKey(t)
	signKMS := &secureboottest.KMS{Key: fleetKey}
	keys := &publicKeyClient{public: pkixDER(t, &fleetKey.PublicKey)}

	csrPEM, err := createKeyCSR(context.Background(), keys, signKMS, "rpi/fleet")
	require.NoError(t, err)
	assert.Equal(t, "rpi/fleet", signKMS.LastReq.GetKeyId(), "the KMS did not sign the CSR")

	ca := issuancetest.NewCA(t)
	cert, err := issuance.SignCSR(context.Background(), ca, issuance.ClientKMS(keys), &issuance.CSR{
		PEM:       csrPEM,
		ValidDays: 30,
	})
	require.NoError(t, err)
	require.True(t, fleetKey.PublicKey.Equal(cert.PublicKey), "the certificate does not hold the KMS key")
	assert.Equal(t, "rpi/fleet", cert.Subject.CommonName)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, cert.ExtKeyUsage)

	certs := &secureboottest.CA{Certs: map[string]*x509.Certificate{"rpi/fleet": cert}}
	signer, _, err := secureboot.NewKMSSigner(context.Background(), signKMS, certs, "kms://rpi/fleet", "")
	require.NoError(t, err)
	image := []byte("boot.img")
	bootSig, err := rpibootsig.Sign(signer, image, rpibootsig.SignOptions{Timestamp: time.Unix(1700000000, 0)})
	require.NoError(t, err)

	certKey := cert.PublicKey.(*rsa.PublicKey)
	otpHash, err := rpibootsig.KeyHash(certKey)
	require.NoError(t, err)
	_, err = rpibootsig.Verify(bootSig, image, certKey, otpHash)
	require.NoError(t, err, "boot.sig does not verify under the certified key")
}

func TestKeyCSR_AcceptsAPEMPublicKey(t *testing.T) {
	fleetKey := issuancetest.RSAKey(t)
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER(t, &fleetKey.PublicKey)})

	csrPEM, err := createKeyCSR(context.Background(), &publicKeyClient{public: public}, &secureboottest.KMS{Key: fleetKey}, "rpi/fleet")
	require.NoError(t, err)
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.True(t, fleetKey.PublicKey.Equal(csr.PublicKey))
}

func TestKeyCSR_Errors(t *testing.T) {
	fleetKey := issuancetest.RSAKey(t)
	otherKey := issuancetest.RSAKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	fleetDER := pkixDER(t, &fleetKey.PublicKey)

	cases := []struct {
		name string
		keys *publicKeyClient
		kms  *secureboottest.KMS
		step string
	}{
		{"KMS cannot report the key", &publicKeyClient{err: errors.New("no such key")}, &secureboottest.KMS{Key: fleetKey}, "fetching the public key"},
		{"malformed public key", &publicKeyClient{public: []byte("junk")}, &secureboottest.KMS{Key: fleetKey}, "parsing the public key"},
		{"KMS refuses to sign", &publicKeyClient{public: fleetDER}, &secureboottest.KMS{Key: fleetKey, Err: errors.New("sealed")}, "signing the request"},
		{"KMS signs with another key", &publicKeyClient{public: fleetDER}, &secureboottest.KMS{Key: otherKey}, "signing the request"},
		{"key type the KMS signs differently", &publicKeyClient{public: pkixDER(t, &ecKey.PublicKey)}, &secureboottest.KMS{Key: fleetKey}, "signing the request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := createKeyCSR(context.Background(), tc.keys, tc.kms, "rpi/fleet")
			var csrErr ErrKeyCSRFailed
			require.ErrorAs(t, err, &csrErr)
			assert.Equal(t, tc.step, csrErr.Step)
			assert.Equal(t, "rpi/fleet", csrErr.KeyID)
		})
	}

	_, err = createKeyCSR(context.Background(), &publicKeyClient{public: fleetDER}, &secureboottest.KMS{Key: fleetKey}, "")
	var csrErr ErrKeyCSRFailed
	require.ErrorAs(t, err, &csrErr)
	assert.Equal(t, "opening the key", csrErr.Step)
}

func TestNewKeyCSRCommand(t *testing.T) {
	cmd := newKeyCSRCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })

	assert.Equal(t, "csr <key-id>", cmd.Use)
	assert.NotNil(t, cmd.Flags().Lookup("out"))
	cmd.SetArgs([]string{})
	assert.ErrorContains(t, cmd.Execute(), "accepts 1 arg(s)")
}
