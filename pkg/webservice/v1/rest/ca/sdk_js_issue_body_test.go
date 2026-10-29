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
	require.NotNil(t, issued.KeyAttributes.RSAAttributes, "the RSA size did not reach the key store")
	assert.Equal(t, 4096, issued.KeyAttributes.RSAAttributes.KeySize)
	assert.Nil(t, issued.KeyAttributes.ECCAttributes)
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
	require.NotNil(t, issued.KeyAttributes.ECCAttributes, "the default curve was not set")
	assert.Equal(t, elliptic.P256(), issued.KeyAttributes.ECCAttributes.Curve)
	assert.Nil(t, issued.KeyAttributes.RSAAttributes)
}
