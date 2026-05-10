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

package bootstrap

import (
	"crypto/x509"
	"errors"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCABundler implements the CABundler interface for testing.
type mockCABundler struct {
	bundleFn func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error)
}

func (m *mockCABundler) CABundleFiltered(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	if m.bundleFn != nil {
		return m.bundleFn(storeType, keyAlgorithm)
	}
	return nil, nil
}

func TestCABundleAdapter_Success(t *testing.T) {
	t.Run("returns full CA bundle", func(t *testing.T) {
		expectedPEM := []byte("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----")
		var capturedStore xkmssdk.StoreType
		var capturedAlg x509.PublicKeyAlgorithm

		mock := &mockCABundler{
			bundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				capturedStore = storeType
				capturedAlg = keyAlgorithm
				return expectedPEM, nil
			},
		}

		adapter := NewCABundleAdapter(mock)
		bundle, err := adapter.CABundle()

		require.NoError(t, err)
		assert.Equal(t, expectedPEM, bundle)
		assert.Equal(t, xkmssdk.StoreUnknown, capturedStore)
		assert.Equal(t, x509.PublicKeyAlgorithm(0), capturedAlg)
	})
}

func TestCABundleAdapter_Empty(t *testing.T) {
	t.Run("returns error when CA is nil", func(t *testing.T) {
		adapter := NewCABundleAdapter(nil)
		bundle, err := adapter.CABundle()

		require.Error(t, err)
		assert.Nil(t, bundle)
		assert.IsType(t, ErrCABundleEmpty{}, err)
	})

	t.Run("propagates CA error", func(t *testing.T) {
		mock := &mockCABundler{
			bundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
				return nil, errors.New("CA unavailable")
			},
		}

		adapter := NewCABundleAdapter(mock)
		bundle, err := adapter.CABundle()

		require.Error(t, err)
		assert.Nil(t, bundle)
		assert.Equal(t, "CA unavailable", err.Error())
	})
}
