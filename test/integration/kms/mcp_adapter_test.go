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
	"context"
	"errors"
	"testing"
	"time"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
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

func TestMCPSecretStatus(t *testing.T) {
	assert.Equal(t, baasservice.SecretStatusEnabled, mcpSecretStatus(true))
	assert.Equal(t, baasservice.SecretStatusDisabled, mcpSecretStatus(false))
}

func TestMCPSecretVersions(t *testing.T) {
	created := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	expires := created.Add(time.Hour)
	resp := &baasservice.ListSecretVersionsResponse{
		Versions: []*baasservice.SecretVersion{
			{Version: 1, CreatedAt: created, CreatedBy: "a"},
			nil,
			{Version: 2, CreatedAt: created, CreatedBy: "b", ExpiresAt: &expires},
		},
		HasMore:    true,
		NextCursor: "c",
	}

	result := mcpSecretVersions("n", resp)
	assert.Equal(t, "n", result.SecretID)
	require.Len(t, result.Versions, 2, "a nil version is skipped")
	assert.Equal(t, SecretVersionInfo{Version: 1, CreatedAt: created, CreatedBy: "a"}, result.Versions[0])
	assert.Equal(t, SecretVersionInfo{Version: 2, CreatedAt: created, CreatedBy: "b", ExpiresAt: expires}, result.Versions[1])
	assert.True(t, result.HasMore)
	assert.Equal(t, "c", result.NextCursor)
}

func TestMCPSecretsRefusesArgumentsTheToolsLack(t *testing.T) {
	// Both refusals happen before any tool call, so a bare adapter suffices.
	adapter := &MCPAdapter{}
	ctx := context.Background()
	var noSurface surface.ErrNoSurface

	for _, opts := range []SecretsRotateOptions{
		{Name: "n", NewData: []byte("x"), TenantID: "t"},
		{Name: "n", NewData: []byte("x"), KeyID: "k"},
		{Name: "n", NewData: []byte("x"), Algorithm: "AES256_GCM"},
	} {
		_, err := adapter.SecretsRotate(ctx, opts)
		require.True(t, errors.As(err, &noSurface), "want ErrNoSurface, got %v", err)
		assert.Equal(t, "SecretsRotate", noSurface.Operation)
		assert.Equal(t, mcpNoSecretRotateKeySelection, noSurface.Reason)
	}

	_, err := adapter.SecretsVersions(ctx, "n", SecretsVersionsOptions{Cursor: "c"})
	require.True(t, errors.As(err, &noSurface), "want ErrNoSurface, got %v", err)
	assert.Equal(t, "SecretsVersions", noSurface.Operation)
	assert.Equal(t, mcpNoSecretVersionsCursor, noSurface.Reason)
}
