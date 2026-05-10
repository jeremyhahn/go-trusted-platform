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
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// GetBootstrapBundle Handler Tests
// =============================================================================

func TestGetBootstrapBundle_Success(t *testing.T) {
	t.Run("returns raw PEM with correct content type", func(t *testing.T) {
		expectedPEM := []byte("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----")
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				return expectedPEM, nil
			},
		}
		handlers, _ := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bootstrap", nil)
		rec := httptest.NewRecorder()

		handlers.GetBootstrapBundle(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, contentTypePEM, rec.Header().Get("Content-Type"))
		assert.Equal(t, string(expectedPEM), rec.Body.String())
	})

	t.Run("respects store_type query parameter", func(t *testing.T) {
		var capturedStoreType xkmssdk.StoreType
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				capturedStoreType = storeType
				return []byte("PEM"), nil
			},
		}
		handlers, _ := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bootstrap?store_type=software", nil)
		rec := httptest.NewRecorder()

		handlers.GetBootstrapBundle(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, xkmssdk.StoreSoftware, capturedStoreType)
	})

	t.Run("respects algorithm query parameter", func(t *testing.T) {
		var capturedAlg x509.PublicKeyAlgorithm
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				capturedAlg = keyAlgorithm
				return []byte("PEM"), nil
			},
		}
		handlers, _ := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bootstrap?algorithm=RSA", nil)
		rec := httptest.NewRecorder()

		handlers.GetBootstrapBundle(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, x509.RSA, capturedAlg)
	})
}

func TestGetBootstrapBundle_CANotInitialized(t *testing.T) {
	t.Run("returns 503 when CA is nil", func(t *testing.T) {
		handlers, _ := newTestHandlers(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bootstrap", nil)
		rec := httptest.NewRecorder()

		handlers.GetBootstrapBundle(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "certificate authority not initialized")
	})
}

func TestGetBootstrapBundle_EmptyBundle(t *testing.T) {
	t.Run("returns 404 when bundle is empty", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				return []byte{}, nil
			},
		}
		handlers, _ := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bootstrap", nil)
		rec := httptest.NewRecorder()

		handlers.GetBootstrapBundle(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
		require.Contains(t, rec.Body.String(), "CA bundle not found")
	})

	t.Run("returns 404 when bundle is nil", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				return nil, nil
			},
		}
		handlers, _ := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bootstrap", nil)
		rec := httptest.NewRecorder()

		handlers.GetBootstrapBundle(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestGetBootstrapBundle_Error(t *testing.T) {
	t.Run("returns 500 when CA bundle retrieval fails", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{
			initialized: true,
			caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				return nil, errors.New("internal CA error")
			},
		}
		handlers, _ := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bootstrap", nil)
		rec := httptest.NewRecorder()

		handlers.GetBootstrapBundle(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		require.Contains(t, rec.Body.String(), "bootstrap bundle retrieval failed")
	})

	t.Run("returns 400 for invalid algorithm parameter", func(t *testing.T) {
		mockCA := &mockCertificateAuthority{initialized: true}
		handlers, _ := newTestHandlers(mockCA)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bootstrap?algorithm=INVALID", nil)
		rec := httptest.NewRecorder()

		handlers.GetBootstrapBundle(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "invalid key algorithm")
	})
}
