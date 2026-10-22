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

//go:build integration

package kms

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestMCPHashAlgorithm(t *testing.T) {
	tests := map[string]platformv1.HashAlgorithm{
		"":        platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
		"SHA256":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		"SHA-384": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
		"sha512":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
	}
	for name, want := range tests {
		got, err := mcpHashAlgorithm(name)
		require.NoError(t, err, name)
		assert.Equal(t, int32(want), got, name)
	}
}

func TestMCPHashAlgorithm_Unsupported(t *testing.T) {
	// The kms_* tools answer SHA-1 with InvalidArgument, so the adapter
	// refuses it before the call rather than sending a number the server
	// would reject.
	for _, name := range []string{"SHA1", "MD5", "bogus"} {
		_, err := mcpHashAlgorithm(name)
		var invalid ErrMCPInvalidOption
		require.True(t, errors.As(err, &invalid), name)
		assert.Equal(t, "HashAlgorithm", invalid.Option)
		assert.Equal(t, name, invalid.Value)
		assert.Contains(t, err.Error(), name)
	}
}

func TestMCPKeyStatus(t *testing.T) {
	assert.Equal(t, int32(platformv1.KeyStatus_KEY_STATUS_ENABLED), mcpKeyStatus(true))
	assert.Equal(t, int32(platformv1.KeyStatus_KEY_STATUS_DISABLED), mcpKeyStatus(false))
	assert.NotEqual(t, mcpKeyStatus(true), mcpKeyStatus(false),
		"enable and disable must send different kms_update_key_status numbers")
}
