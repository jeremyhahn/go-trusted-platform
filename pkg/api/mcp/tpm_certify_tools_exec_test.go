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

package mcp

import (
	"context"
	"encoding/base64"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

func TestExecuteTPMCertify_ForwardsArguments(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.ExecuteTool(context.Background(), "platform_tpm_certify", map[string]interface{}{
		"key_handle":   float64(0x81000001),
		"key_password": "key-secret",
		"nonce":        base64.StdEncoding.EncodeToString([]byte("freshness")),
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, tpmCall{index: 0x81000001, password: "key-secret", data: []byte("freshness")}, svc.tpmCall)
}

func TestExecuteTPMCertify_NonceIsOptional(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(context.Background(), "platform_tpm_certify", map[string]interface{}{
		"key_handle": float64(0x81000001),
	})

	require.NoError(t, err)
	assert.Empty(t, svc.tpmCall.data)
}

func TestExecuteTPMCertify_RejectsBadArguments(t *testing.T) {
	tests := []struct {
		name string
		args map[string]interface{}
	}{
		{"handle above uint32", map[string]interface{}{"key_handle": float64(math.MaxUint32) + 1}},
		{"negative handle", map[string]interface{}{"key_handle": float64(-1)}},
		{"handle not a number", map[string]interface{}{"key_handle": "0x81000001"}},
		{"nonce not base64", map[string]interface{}{"key_handle": float64(0x81000001), "nonce": "!!"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newMockServiceProvider()
			registry := NewToolRegistry(svc, newTestLogger())

			_, err := registry.ExecuteTool(context.Background(), "platform_tpm_certify", tt.args)

			require.Error(t, err)
			assert.Equal(t, mcpwire.InvalidParams, toolErrorCode(err))
			assert.Equal(t, tpmCall{}, svc.tpmCall, "a rejected argument never reaches the service")
		})
	}
}
