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

package vtpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestDecodeGetBundleJSON(t *testing.T) {
	t.Run("bare bundle", func(t *testing.T) {
		resp, err := DecodeGetBundleJSON([]byte(
			`{"id":"b1","mode":"template","manifest":{"hostname":"node-1","ek_algorithm":"ECC"}}`))

		require.NoError(t, err)
		assert.Equal(t, "b1", resp.GetBundle().GetId())
		assert.Equal(t, platformv1.BundleMode_BUNDLE_MODE_TEMPLATE, resp.GetBundle().GetMode())
		assert.Equal(t, "node-1", resp.GetBundle().GetManifest().GetHostname())
		assert.Equal(t, platformv1.EKAlgorithm_EK_ALGORITHM_ECC, resp.GetBundle().GetManifest().GetEkAlgorithm())
	})
	t.Run("malformed JSON", func(t *testing.T) {
		_, err := DecodeGetBundleJSON([]byte(`{"id":`))

		var decodeErr *ErrWireDecode
		require.ErrorAs(t, err, &decodeErr)
		assert.Equal(t, "get bundle", decodeErr.Message)
	})
	t.Run("unknown bundle mode", func(t *testing.T) {
		_, err := DecodeGetBundleJSON([]byte(`{"id":"b1","mode":"cloned"}`))

		var unknown *ErrUnknownWireValue
		require.ErrorAs(t, err, &unknown)
		assert.Equal(t, "cloned", unknown.Value)
	})
}

func TestDecodeValidateBundleJSON(t *testing.T) {
	t.Run("valid bundle", func(t *testing.T) {
		resp, err := DecodeValidateBundleJSON([]byte(`{"valid":true}`))

		require.NoError(t, err)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.True(t, resp.GetValid())
		assert.Empty(t, resp.GetErrors())
	})
	t.Run("invalid bundle keeps its errors", func(t *testing.T) {
		resp, err := DecodeValidateBundleJSON([]byte(
			`{"valid":false,"errors":["nvram missing","ek cert expired"]}`))

		require.NoError(t, err)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.False(t, resp.GetValid())
		assert.Equal(t, []string{"nvram missing", "ek cert expired"}, resp.GetErrors())
	})
	t.Run("daemon reply carries a timestamp", func(t *testing.T) {
		resp, err := DecodeValidateBundleJSON([]byte(
			`{"valid":false,"errors":["bad"],"timestamp":"2025-01-02T03:04:05Z"}`))

		require.NoError(t, err)
		assert.False(t, resp.GetValid())
		assert.Equal(t, []string{"bad"}, resp.GetErrors())
	})
	t.Run("malformed JSON", func(t *testing.T) {
		_, err := DecodeValidateBundleJSON([]byte(`{"valid":"yes"}`))

		var decodeErr *ErrWireDecode
		require.ErrorAs(t, err, &decodeErr)
		assert.Equal(t, "validate bundle", decodeErr.Message)
	})
}
