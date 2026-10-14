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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attestationservice "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/service"
)

// fakeTPM quotes like a TPM: a TPMS_ATTEST over the requested PCRs with the
// nonce as qualifying data, signed by an in-memory attestation key. It is the
// pkg/attestation/service fakeQuoter plus the IDevID the client needs.
type fakeTPM struct {
	iak    *ecdsa.PrivateKey
	values map[int][]byte

	idevid    *x509.Certificate
	idevidKey crypto.Signer

	quoteErr  error
	certErr   error
	signerErr error
	closeErr  error

	quoted []uint
	closed bool
}

func newFakeTPM(t *testing.T) *fakeTPM {
	t.Helper()
	iak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	values := map[int][]byte{}
	for idx := range 24 {
		v := sha256.Sum256([]byte{byte(idx)})
		values[idx] = v[:]
	}
	cert := deviceCertificate(t, "laptop-1")
	return &fakeTPM{iak: iak, values: values, idevid: cert.Leaf, idevidKey: cert.PrivateKey.(crypto.Signer)}
}

func (f *fakeTPM) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	f.quoted = slices.Clone(pcrs)
	if f.quoteErr != nil {
		return xkmssdk.Quote{}, f.quoteErr
	}
	sorted := slices.Sorted(slices.Values(pcrs))
	h := sha256.New()
	for _, idx := range sorted {
		h.Write(f.values[int(idx)])
	}
	attest := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("fake-iak")},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(sorted...),
			}}},
			PCRDigest: tpm2.TPM2BDigest{Buffer: h.Sum(nil)},
		}),
	}
	quoted := tpm2.Marshal(attest)
	digest := sha256.Sum256(quoted)
	sig, err := f.iak.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return xkmssdk.Quote{}, err
	}
	return xkmssdk.Quote{Quoted: quoted, Signature: sig, Nonce: nonce}, nil
}

func (f *fakeTPM) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) {
	bank := xkmssdk.PCRBank{Algorithm: "SHA256"}
	for _, p := range pcrList {
		bank.PCRs = append(bank.PCRs, xkmssdk.PCR{ID: int32(p), Value: f.values[int(p)]})
	}
	return []xkmssdk.PCRBank{bank}, nil
}

func (f *fakeTPM) IAK() (crypto.PublicKey, error) { return f.iak.Public(), nil }

func (f *fakeTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{SignatureAlgorithm: x509.ECDSAWithSHA256}, nil
}

func (f *fakeTPM) IDevIDCertificate() (*x509.Certificate, error) {
	if f.certErr != nil {
		return nil, f.certErr
	}
	return f.idevid, nil
}

func (f *fakeTPM) IDevIDSigner() (crypto.Signer, error) {
	if f.signerErr != nil {
		return nil, f.signerErr
	}
	return f.idevidKey, nil
}

func (f *fakeTPM) Close() error {
	f.closed = true
	return f.closeErr
}

// publiclessSigner is a TPM signer whose attributes carry no public bytes,
// as platform.TPMSigner is on an enrolled node.
type publiclessSigner struct{ crypto.Signer }

func (publiclessSigner) Public() crypto.PublicKey { return nil }

func (f *fakeTPM) deviceConfig() TPMDeviceConfig {
	return TPMDeviceConfig{ID: "laptop-1", TPM: f, Chain: []*x509.Certificate{f.idevid}, Signer: f.idevidKey}
}

func TestNewTPMDevice_PresentsTheIDevID(t *testing.T) {
	tpm := newFakeTPM(t)
	device, err := NewTPMDevice(tpm.deviceConfig())
	require.NoError(t, err)

	assert.Equal(t, "laptop-1", device.ID())
	cert, err := device.Certificate()
	require.NoError(t, err)
	require.Len(t, cert.Certificate, 1)
	assert.Equal(t, tpm.idevid.Raw, cert.Certificate[0])
	assert.Same(t, tpm.idevid, cert.Leaf)

	// The TLS key signs with the IDevID key: a CertificateVerify made
	// with it verifies under the certificate's public key.
	signer, ok := cert.PrivateKey.(crypto.Signer)
	require.True(t, ok)
	digest := sha256.Sum256([]byte("certificate verify"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(tpm.idevid.PublicKey.(*ecdsa.PublicKey), digest[:], sig))
}

func TestNewTPMDevice_RejectsAnIncompleteIdentity(t *testing.T) {
	tpm := newFakeTPM(t)
	other := deviceCertificate(t, "someone-else")
	cases := map[string]struct {
		mutate func(*TPMDeviceConfig)
		field  string
	}{
		"no TPM":           {func(c *TPMDeviceConfig) { c.TPM = nil }, "tpm"},
		"no chain":         {func(c *TPMDeviceConfig) { c.Chain = nil }, "IDevID certificate"},
		"nil leaf":         {func(c *TPMDeviceConfig) { c.Chain = []*x509.Certificate{nil} }, "IDevID certificate"},
		"no signer":        {func(c *TPMDeviceConfig) { c.Signer = nil }, "IDevID signer"},
		"another key":      {func(c *TPMDeviceConfig) { c.Signer = other.PrivateKey.(crypto.Signer) }, "IDevID signer"},
		"not comparable":   {func(c *TPMDeviceConfig) { c.Signer = opaqueSigner{} }, "IDevID signer"},
		"another leaf key": {func(c *TPMDeviceConfig) { c.Chain = []*x509.Certificate{other.Leaf} }, "IDevID signer"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := tpm.deviceConfig()
			tc.mutate(&cfg)
			_, err := NewTPMDevice(cfg)
			var invalid *ErrInvalidOptions
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, tc.field, invalid.Field)
		})
	}
}

// opaqueSigner reports a public key that cannot be compared.
type opaqueSigner struct{}

func (opaqueSigner) Public() crypto.PublicKey { return "not a key" }

func (opaqueSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("opaque")
}

func TestTPMDevice_CertificateReportsTheLeafKeyForAPubliclessSigner(t *testing.T) {
	tpm := newFakeTPM(t)
	cfg := tpm.deviceConfig()
	cfg.Signer = publiclessSigner{tpm.idevidKey}
	device, err := NewTPMDevice(cfg)
	require.NoError(t, err)

	cert, err := device.Certificate()
	require.NoError(t, err)
	// A nil Public makes crypto/tls send no client certificate at all.
	signer := cert.PrivateKey.(crypto.Signer)
	assert.True(t, tpm.idevid.PublicKey.(*ecdsa.PublicKey).Equal(signer.Public()))
}

func TestTPMDevice_QuoteCarriesTheNonceAndTheIDevID(t *testing.T) {
	tpm := newFakeTPM(t)
	cfg := tpm.deviceConfig()
	cfg.PCRs = []int{0, 7}
	device, err := NewTPMDevice(cfg)
	require.NoError(t, err)

	att, err := device.Quote(context.Background(), []byte("nonce-1"))
	require.NoError(t, err)
	assert.Equal(t, []byte("nonce-1"), att.Nonce)
	assert.Equal(t, tpm.idevid.Raw, att.IDevIDCertificate)
	assert.NotEmpty(t, att.QuoteData)
	assert.NotEmpty(t, att.Signature)
	assert.Equal(t, []uint{0, 7}, tpm.quoted)
	indices := make([]int, 0, len(att.PCRs))
	for _, pcr := range att.PCRs {
		indices = append(indices, pcr.Index)
	}
	assert.Equal(t, []int{0, 7}, indices)
}

func TestTPMDevice_QuoteDefaultsToTheManifestPCRs(t *testing.T) {
	tpm := newFakeTPM(t)
	device, err := NewTPMDevice(tpm.deviceConfig())
	require.NoError(t, err)

	_, err = device.Quote(context.Background(), []byte("nonce-1"))
	require.NoError(t, err)
	assert.NotEmpty(t, tpm.quoted)
}

func TestTPMDevice_QuoteFailure(t *testing.T) {
	tpm := newFakeTPM(t)
	tpm.quoteErr = errors.New("TPM_RC_LOCKOUT")
	device, err := NewTPMDevice(tpm.deviceConfig())
	require.NoError(t, err)

	_, err = device.Quote(context.Background(), []byte("nonce-1"))
	var failed attestationservice.ErrHostQuoteFailed
	require.ErrorAs(t, err, &failed)
	assert.ErrorIs(t, err, tpm.quoteErr)
}
