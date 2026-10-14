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

//go:build codec_msgpack

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const certifyParityHandle = 0x81000001

// certifyingTPM is a signingTPM that also certifies keys. certified records
// each handle asked for, so a refusal can prove the TPM was never reached.
type certifyingTPM struct {
	*signingTPM
	certified []uint32
}

func newCertifyingTPM(t testing.TB) *certifyingTPM {
	return &certifyingTPM{signingTPM: newSigningTPM(t)}
}

// CertifyKey answers as a TPM would: the attested key is certified under
// the IAK with the caller's nonce.
func (s *certifyingTPM) CertifyKey(keyAttrs *xkmssdk.KeyAttributes, nonce []byte, _ xkmssdk.TPMKeyBackend) (*xkmssdk.CertifyResult, error) {
	s.certified = append(s.certified, uint32(keyAttrs.TPMAttributes.Handle))
	iak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(s.t, err)
	attested, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(s.t, err)
	return &xkmssdk.CertifyResult{
		CertifyInfo:        []byte("TPMS_ATTEST"),
		Signature:          []byte("signature"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		AttestingKeyPublic: &iak.PublicKey,
		AttestedKeyPublic:  &attested.PublicKey,
		Nonce:              nonce,
	}, nil
}

// Config has no IDevID configured, so every key is certified as an
// ordinary persistent key.
func (s *certifyingTPM) Config() *xkmssdk.TPMConfig { return nil }

func (f *tpmParityFixture) allTransports() map[string]tpmTransport {
	transports := f.boundTransports()
	for name, open := range f.unboundTransports() {
		transports[name] = open
	}
	return transports
}

func TestTPMCertifyParity_EveryTransportReturnsTheAttestation(t *testing.T) {
	f := newTPMParityFixture(t)
	nonce := []byte("certify parity")
	for name, open := range f.allTransports() {
		t.Run(name, func(t *testing.T) {
			resp, err := f.client(t, open).Certify(context.Background(), certifyParityHandle, "", nonce)

			require.NoError(t, err)
			assert.Equal(t, []byte("TPMS_ATTEST"), resp.GetCertifyInfo())
			assert.Equal(t, []byte("signature"), resp.GetSignature())
			assert.Equal(t, x509.ECDSAWithSHA256.String(), resp.GetSignatureAlgorithm())
			assert.Equal(t, nonce, resp.GetNonce())
			_, err = x509.ParsePKIXPublicKey(resp.GetAttestingKeyPublic())
			require.NoError(t, err, "the attesting key travels as PKIX DER")
			_, err = x509.ParsePKIXPublicKey(resp.GetAttestedKeyPublic())
			require.NoError(t, err, "the attested key travels as PKIX DER")
		})
	}
}

func TestTPMCertifyParity_EveryTransportRefusesABadHandle(t *testing.T) {
	f := newTPMParityFixture(t)
	for name, open := range f.allTransports() {
		t.Run(name, func(t *testing.T) {
			client := f.client(t, open)

			_, err := client.Certify(context.Background(), 0, "", nil)
			assert.Equal(t, codes.InvalidArgument, status.Code(err), err)

			_, err = client.Certify(context.Background(), 0x80000001, "", nil)
			assert.Equal(t, codes.InvalidArgument, status.Code(err), err)
		})
	}
	assert.Empty(t, f.tpm.certified, "the TPM must not be asked to certify")
}

func TestTPMCertifyParity_DaemonRESTNeedsTPMRead(t *testing.T) {
	f := newTPMParityFixture(t)

	_, err := f.client(t, f.daemonRESTConn("tpm:write")).Certify(context.Background(), certifyParityHandle, "", nil)

	assert.Equal(t, codes.PermissionDenied, status.Code(err), err)
	assert.Empty(t, f.tpm.certified, "the TPM must not be asked to certify")
}

func TestTPMGRPCService_Certify(t *testing.T) {
	tpm := newCertifyingTPM(t)
	svc := NewTPMGRPCService(logging.DefaultLogger())
	svc.SetTPM2Service(tpm)

	resp, err := svc.Certify(context.Background(), &platformv1.CertifyRequest{KeyHandle: certifyParityHandle, Nonce: []byte("n")})

	require.NoError(t, err)
	assert.Equal(t, []byte("n"), resp.GetNonce())
	assert.Equal(t, []uint32{certifyParityHandle}, tpm.certified)
}

func TestTPMGRPCService_CertifyErrors(t *testing.T) {
	t.Run("no TPM", func(t *testing.T) {
		svc := NewTPMGRPCService(logging.DefaultLogger())
		_, err := svc.Certify(context.Background(), &platformv1.CertifyRequest{KeyHandle: certifyParityHandle})
		assert.Equal(t, codes.Unavailable, status.Code(err), err)
	})
	t.Run("nonce too large", func(t *testing.T) {
		tpm := newCertifyingTPM(t)
		svc := NewTPMGRPCService(logging.DefaultLogger())
		svc.SetTPM2Service(tpm)
		_, err := svc.Certify(context.Background(), &platformv1.CertifyRequest{KeyHandle: certifyParityHandle, Nonce: make([]byte, 65)})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err)
		assert.Empty(t, tpm.certified)
	})
}
