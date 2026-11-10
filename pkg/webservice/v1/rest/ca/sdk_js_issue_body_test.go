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
	require.NotNil(t, issued.KeyAttributes.RSAAttributes)
	assert.Equal(t, 4096, issued.KeyAttributes.RSAAttributes.KeySize)
	assert.Nil(t, issued.KeyAttributes.ECCAttributes)
	assert.True(t, issued.IsCA)
	assert.Equal(t, 1, issued.MaxPathLen)
	assert.Equal(t, 30, issued.Valid)
}

// TestIssueCertificate_KeySizeAndCurve sends every key algorithm through the
// router and checks the key size or curve the CA is asked to generate.
func TestIssueCertificate_KeySizeAndCurve(t *testing.T) {
	tests := []struct {
		name         string
		keyAlgorithm string
		wantAlg      x509.PublicKeyAlgorithm
		wantKeySize  int
		wantCurve    string
	}{
		{name: "unspecified defaults to P-256", wantAlg: x509.ECDSA, wantCurve: "P-256"},
		{name: "RSA 2048", keyAlgorithm: "KEY_ALGORITHM_RSA_2048", wantAlg: x509.RSA, wantKeySize: 2048},
		{name: "RSA 3072", keyAlgorithm: "KEY_ALGORITHM_RSA_3072", wantAlg: x509.RSA, wantKeySize: 3072},
		{name: "RSA 4096", keyAlgorithm: "KEY_ALGORITHM_RSA_4096", wantAlg: x509.RSA, wantKeySize: 4096},
		{name: "ECDSA P-256", keyAlgorithm: "KEY_ALGORITHM_ECDSA_P256", wantAlg: x509.ECDSA, wantCurve: "P-256"},
		{name: "ECDSA P-384", keyAlgorithm: "KEY_ALGORITHM_ECDSA_P384", wantAlg: x509.ECDSA, wantCurve: "P-384"},
		{name: "ECDSA P-521", keyAlgorithm: "KEY_ALGORITHM_ECDSA_P521", wantAlg: x509.ECDSA, wantCurve: "P-521"},
		{name: "Ed25519", keyAlgorithm: "KEY_ALGORITHM_ED25519", wantAlg: x509.Ed25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var issued *xkmsca.CACertificateRequest
			mockCA := &mockCertificateAuthority{
				initialized: true,
				issueCertificateFn: func(_ context.Context, request *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
					issued = request
					return &xkmsca.IssuedCertificate{Certificate: createTestCertificate(request.Subject.CommonName)}, nil
				},
			}
			router := newTestRouter(NewCARouter(newTestLogger(), mockCA, &mockHttpWriter{}))

			keyAlgorithm := ""
			if tt.keyAlgorithm != "" {
				keyAlgorithm = `"keyAlgorithm":"` + tt.keyAlgorithm + `",`
			}
			body := []byte(`{"request":{"subject":{"commonName":"sub.example.com"},` +
				keyAlgorithm + `"certificateType":"CERTIFICATE_TYPE_CA",` +
				`"isCa":true,"maxPathLen":1,"validDays":30}}`)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusCreated, rec.Code)
			require.NotNil(t, issued, "the CA was not asked to issue")
			require.NotNil(t, issued.KeyAttributes)
			assert.Equal(t, tt.wantAlg, issued.KeyAttributes.KeyAlgorithm)

			if tt.wantKeySize != 0 {
				require.NotNil(t, issued.KeyAttributes.RSAAttributes)
				assert.Equal(t, tt.wantKeySize, issued.KeyAttributes.RSAAttributes.KeySize)
			} else {
				assert.Nil(t, issued.KeyAttributes.RSAAttributes)
			}
			if tt.wantCurve != "" {
				require.NotNil(t, issued.KeyAttributes.ECCAttributes)
				require.NotNil(t, issued.KeyAttributes.ECCAttributes.Curve)
				assert.Equal(t, tt.wantCurve, issued.KeyAttributes.ECCAttributes.Curve.Params().Name)
			} else {
				assert.Nil(t, issued.KeyAttributes.ECCAttributes)
			}
		})
	}
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
