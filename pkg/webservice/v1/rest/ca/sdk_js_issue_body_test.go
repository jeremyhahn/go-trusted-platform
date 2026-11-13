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

package ca

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// TestIssueCertificate_JavaScriptSDKBody feeds the router the exact body the
// JavaScript SDK's issueCertificate sends (sdk/javascript/src/services/
// ca-service.ts). The decoder is protojson: the request must be wrapped in
// "request", the key algorithm must be its full enum name and is_ca must be
// "isCa", or the CA issues a leaf with the default ECDSA key.
func TestIssueCertificate_JavaScriptSDKBody(t *testing.T) {
	var issued *xkmsca.CACertificateRequest
	mockCA := &mockCertificateAuthority{
		initialized: true,
		issueCertificateFn: func(_ context.Context, request *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
			issued = request
			return &xkmsca.IssuedCertificate{Certificate: createTestCertificate(request.Subject.CommonName)}, nil
		},
	}
	router := newTestRouter(NewCARouter(newTestLogger(), mockCA, &mockHttpWriter{}))

	body := []byte(`{"request":{"subject":{"commonName":"sub.example.com"},` +
		`"keyAlgorithm":"KEY_ALGORITHM_RSA_4096","certificateType":"CERTIFICATE_TYPE_CA",` +
		`"isCa":true,"maxPathLen":1,"validDays":30}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	require.NotNil(t, issued, "the CA was not asked to issue")
	assert.Equal(t, "sub.example.com", issued.Subject.CommonName)
	require.NotNil(t, issued.KeyAttributes)
	assert.Equal(t, x509.RSA, issued.KeyAttributes.KeyAlgorithm)
	assert.True(t, issued.IsCA)
	assert.Equal(t, 1, issued.MaxPathLen)
	assert.Equal(t, 30, issued.Valid)
}

// TestIssueCertificate_ShortEnumNameIsLost pins why the SDK maps names: the
// short key algorithm the SDK used to send is discarded by protojson, so the
// CA falls back to its default algorithm instead of the one asked for.
func TestIssueCertificate_ShortEnumNameIsLost(t *testing.T) {
	var issued *xkmsca.CACertificateRequest
	mockCA := &mockCertificateAuthority{
		initialized: true,
		issueCertificateFn: func(_ context.Context, request *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
			issued = request
			return &xkmsca.IssuedCertificate{Certificate: createTestCertificate(request.Subject.CommonName)}, nil
		},
	}
	router := newTestRouter(NewCARouter(newTestLogger(), mockCA, &mockHttpWriter{}))

	body := []byte(`{"request":{"subject":{"commonName":"sub.example.com"},"keyAlgorithm":"RSA_4096"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, issued)
	require.NotNil(t, issued.KeyAttributes)
	assert.Equal(t, x509.ECDSA, issued.KeyAttributes.KeyAlgorithm)
}

// TestIssueCertificate_KeySizeAndCurveReachTheCA pins that the requested RSA
// key size and ECDSA curve reach the CA on the issued KeyAttributes: without
// RSAAttributes or ECCAttributes the keystore falls back to RSA-2048 or P-256,
// so a request for RSA-4096 or P-384 would silently get a weaker key.
func TestIssueCertificate_KeySizeAndCurveReachTheCA(t *testing.T) {
	cases := []struct {
		alg     string
		x509Alg x509.PublicKeyAlgorithm
		rsaBits int
		curve   elliptic.Curve
	}{
		{alg: "KEY_ALGORITHM_RSA_2048", x509Alg: x509.RSA, rsaBits: 2048},
		{alg: "KEY_ALGORITHM_RSA_3072", x509Alg: x509.RSA, rsaBits: 3072},
		{alg: "KEY_ALGORITHM_RSA_4096", x509Alg: x509.RSA, rsaBits: 4096},
		{alg: "KEY_ALGORITHM_ECDSA_P256", x509Alg: x509.ECDSA, curve: elliptic.P256()},
		{alg: "KEY_ALGORITHM_ECDSA_P384", x509Alg: x509.ECDSA, curve: elliptic.P384()},
		{alg: "KEY_ALGORITHM_ECDSA_P521", x509Alg: x509.ECDSA, curve: elliptic.P521()},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			var issued *xkmsca.CACertificateRequest
			mockCA := &mockCertificateAuthority{
				initialized: true,
				issueCertificateFn: func(_ context.Context, request *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
					issued = request
					return &xkmsca.IssuedCertificate{Certificate: createTestCertificate(request.Subject.CommonName)}, nil
				},
			}
			router := newTestRouter(NewCARouter(newTestLogger(), mockCA, &mockHttpWriter{}))

			body := []byte(`{"request":{"subject":{"commonName":"sub.example.com"},"keyAlgorithm":"` + tc.alg + `"}}`)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusCreated, rec.Code)
			require.NotNil(t, issued, "the CA was not asked to issue")
			attrs := issued.KeyAttributes
			require.NotNil(t, attrs)
			assert.Equal(t, tc.x509Alg, attrs.KeyAlgorithm)
			if tc.rsaBits != 0 {
				require.NotNil(t, attrs.RSAAttributes, "RSA key size not carried to the CA")
				assert.Equal(t, tc.rsaBits, attrs.RSAAttributes.KeySize)
				assert.Nil(t, attrs.ECCAttributes)
			} else {
				require.NotNil(t, attrs.ECCAttributes, "ECDSA curve not carried to the CA")
				assert.Equal(t, tc.curve, attrs.ECCAttributes.Curve)
				assert.Nil(t, attrs.RSAAttributes)
			}
		})
	}
}

// TestIssueCertificate_UnsupportedKeyAlgorithmRejected pins that a key
// algorithm the handler cannot map is refused with 400, not issued.
func TestIssueCertificate_UnsupportedKeyAlgorithmRejected(t *testing.T) {
	called := false
	mockCA := &mockCertificateAuthority{
		initialized: true,
		issueCertificateFn: func(_ context.Context, request *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
			called = true
			return &xkmsca.IssuedCertificate{Certificate: createTestCertificate(request.Subject.CommonName)}, nil
		},
	}
	router := newTestRouter(NewCARouter(newTestLogger(), mockCA, &mockHttpWriter{}))

	body := []byte(`{"request":{"subject":{"commonName":"sub.example.com"},"keyAlgorithm":999}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.False(t, called, "the CA was asked to issue an unsupported key algorithm")
}
