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

package quic

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyShapedCA issues each certificate for a fresh key of exactly the RSA
// size or ECDSA curve the request's key attributes name, as the CA's key
// store does, and keeps the last certificate it issued.
type keyShapedCA struct {
	*mockCA
	issued *x509.Certificate
}

func (m *keyShapedCA) IssueCertificate(_ context.Context, req *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	key, err := shapedKey(req.KeyAttributes)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: req.Subject.CommonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, m.intermCert, key.Public(), m.privateKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	m.issued = cert
	return &xkmsca.IssuedCertificate{Certificate: cert}, nil
}

func shapedKey(attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	if attrs.RSAAttributes != nil {
		return rsa.GenerateKey(rand.Reader, attrs.RSAAttributes.KeySize)
	}
	return ecdsa.GenerateKey(attrs.ECCAttributes.Curve, rand.Reader)
}

// TestCAHandler_ReportsTheIssuedKeySizeAndCurve pins that a QUIC issue
// response and certificate summary name the issued key's RSA size and ECDSA
// curve, not only its family, in the exact names the SDK's cawire decodes
// and the QUIC issue request accepts (Codex 8200).
func TestCAHandler_ReportsTheIssuedKeySizeAndCurve(t *testing.T) {
	tests := []struct {
		name string
		alg  platformv1.KeyAlgorithm
	}{
		{name: "RSA-4096", alg: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096},
		{name: "ECDSA-P384", alg: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &keyShapedCA{mockCA: newMockCA()}
			handler := NewCAHandler(logging.DefaultLogger(), ca, nil)

			payload, err := quicwire.EncodePayload(&CAIssueRequest{
				Subject:      &Subject{CommonName: "test.example.com"},
				ValidDays:    1,
				KeyAlgorithm: tt.name,
			})
			require.NoError(t, err)

			resp := handler.HandleRequest(context.Background(), &quicwire.Request{
				Opcode:  quicwire.OpCAIssue,
				Payload: payload,
			})
			require.Equal(t, quicwire.StatusOK, resp.Status)

			var issueResp CAIssueResponse
			require.NoError(t, quicwire.DecodePayload(resp.Payload, &issueResp))
			require.NotNil(t, issueResp.Certificate)
			require.NotNil(t, ca.issued)

			assert.Equal(t, tt.alg, issuance.PublicKeyAlgorithm(ca.issued.PublicKey))
			assert.Equal(t, tt.name, issueResp.Certificate.KeyAlgorithm)
			assert.Equal(t, tt.name, handler.certToSummary(ca.issued).KeyAlgorithm)

			roundTrip, err := issueKeyAlgorithm(issueResp.Certificate.KeyAlgorithm)
			require.NoError(t, err)
			assert.Equal(t, tt.alg, roundTrip)
		})
	}
}

// TestIssuedKeyAlgorithm_UnissuableKeyIsUnknown pins that a key of a size
// the platform does not issue is UNKNOWN rather than a neighbouring size.
func TestIssuedKeyAlgorithm_UnissuableKeyIsUnknown(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	assert.Equal(t, "UNKNOWN", issuedKeyAlgorithm(&x509.Certificate{PublicKey: &key.PublicKey}))
}
