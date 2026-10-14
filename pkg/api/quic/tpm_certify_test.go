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

package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	tpmgo "github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certifyMockTPM answers CertifyKey with a canned result or error and
// records the handle it was asked to certify.
type certifyMockTPM struct {
	xkmssdk.TrustedPlatformModule

	result    *xkmssdk.CertifyResult
	err       error
	gotHandle tpmgo.TPMHandle
	gotNonce  []byte
}

func (m *certifyMockTPM) CertifyKey(keyAttrs *xkmssdk.KeyAttributes, nonce []byte, _ xkmssdk.TPMKeyBackend) (*xkmssdk.CertifyResult, error) {
	m.gotHandle = keyAttrs.TPMAttributes.Handle
	m.gotNonce = nonce
	return m.result, m.err
}

func (m *certifyMockTPM) Config() *xkmssdk.TPMConfig { return nil }

func certifyResponse(t *testing.T, tpm xkmssdk.TrustedPlatformModule, payload []byte) *quicwire.Response {
	t.Helper()
	h := NewTPM2Handler(logging.DefaultLogger())
	if tpm != nil {
		h.SetTPM2Service(tpm)
	}
	return h.HandleMessage(context.Background(), &quicwire.Request{
		Payload: append([]byte{quicwire.SubOpTPM2Certify}, payload...),
	})
}

func TestTPM2Handler_CertifyReturnsTheAttestation(t *testing.T) {
	iak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certified, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	nonce := []byte("quic-certify-nonce")
	tpm := &certifyMockTPM{result: &xkmssdk.CertifyResult{
		CertifyInfo:        []byte("TPMS_ATTEST"),
		Signature:          []byte("signature"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		AttestingKeyPublic: &iak.PublicKey,
		AttestedKeyPublic:  &certified.PublicKey,
		Nonce:              nonce,
	}}

	resp := certifyResponse(t, tpm, mustEncode(t, &quicwire.TPM2CertifyRequest{KeyHandle: 0x81000001, Nonce: nonce}))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	assert.Equal(t, tpmgo.TPMHandle(0x81000001), tpm.gotHandle)
	assert.Equal(t, nonce, tpm.gotNonce)
	var out quicwire.TPM2CertifyResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
	assert.Equal(t, []byte("TPMS_ATTEST"), out.CertifyInfo)
	assert.Equal(t, []byte("signature"), out.Signature)
	assert.Equal(t, x509.ECDSAWithSHA256.String(), out.SignatureAlgorithm)
	assert.Equal(t, nonce, out.Nonce)
	attesting, err := x509.ParsePKIXPublicKey(out.AttestingKeyPublic)
	require.NoError(t, err)
	assert.True(t, iak.PublicKey.Equal(attesting), "the attesting key must be the IAK")
	attested, err := x509.ParsePKIXPublicKey(out.AttestedKeyPublic)
	require.NoError(t, err)
	assert.True(t, certified.PublicKey.Equal(attested), "the attested key must be the certified key")
}

func TestTPM2Handler_CertifyErrors(t *testing.T) {
	missing := &certifyMockTPM{err: fmt.Errorf("read public: %w", tpmgo.TPMRCHandle)}
	tests := []struct {
		name    string
		tpm     xkmssdk.TrustedPlatformModule
		payload []byte
		want    byte
	}{
		{"no TPM", nil, mustEncode(t, &quicwire.TPM2CertifyRequest{KeyHandle: 0x81000001}), quicwire.StatusUnavailable},
		{"undecodable payload", &certifyMockTPM{}, []byte{0xFF, 0x00}, quicwire.StatusInvalidRequest},
		{"handle zero", &certifyMockTPM{}, mustEncode(t, &quicwire.TPM2CertifyRequest{}), quicwire.StatusInvalidArgument},
		{"transient handle", &certifyMockTPM{}, mustEncode(t, &quicwire.TPM2CertifyRequest{KeyHandle: 0x80000001}), quicwire.StatusInvalidArgument},
		{"missing key", missing, mustEncode(t, &quicwire.TPM2CertifyRequest{KeyHandle: 0x81FFFFF0}), quicwire.StatusNotFound},
		{"SDK failure", &certifyMockTPM{err: errors.New("IAK not provisioned")}, mustEncode(t, &quicwire.TPM2CertifyRequest{KeyHandle: 0x81000001}), quicwire.StatusInternalError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := certifyResponse(t, tt.tpm, tt.payload)
			assert.Equal(t, tt.want, resp.Status, string(resp.Payload))
		})
	}
}
