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

// The PCR extend and NV tools parse and forward their arguments; the range,
// index and data checks belong to the shared tpmpcr / tpmnv layer behind the
// service, so the executor hands even an out-of-range PCR to the service.

func TestExecuteTPMExtendPCR_ForwardsArguments(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(context.Background(), "platform_tpm_pcr_extend", map[string]interface{}{
		"pcr_index": float64(24),
		"hash_alg":  "sha384",
		"data":      base64.StdEncoding.EncodeToString([]byte("measurement")),
	})

	require.NoError(t, err)
	assert.Equal(t, tpmCall{pcr: 24, hashAlg: "sha384", data: []byte("measurement")}, svc.tpmCall)
}

func TestExecuteTPMNVTools_ForwardArguments(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte("nv-data"))
	tests := []struct {
		tool string
		args map[string]interface{}
		want tpmCall
	}{
		{
			"platform_tpm_nv_read",
			map[string]interface{}{"index": float64(0x01500001), "size": float64(32), "offset": float64(8), "password": "pw"},
			tpmCall{index: 0x01500001, size: 32, offset: 8, password: "pw"},
		},
		{
			"platform_tpm_nv_write",
			map[string]interface{}{"index": float64(0x01500001), "data": data, "offset": float64(4), "password": "pw"},
			tpmCall{index: 0x01500001, data: []byte("nv-data"), offset: 4, password: "pw"},
		},
		{
			"platform_tpm_nv_delete",
			map[string]interface{}{"index": float64(0x01500001), "parent_password": "owner"},
			tpmCall{index: 0x01500001, password: "owner"},
		},
		{
			"platform_tpm_nv_read",
			map[string]interface{}{},
			tpmCall{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			svc := newMockServiceProvider()
			registry := NewToolRegistry(svc, newTestLogger())

			_, err := registry.ExecuteTool(context.Background(), tt.tool, tt.args)

			require.NoError(t, err)
			assert.Equal(t, tt.want, svc.tpmCall)
		})
	}
}

func TestExecuteTPMNVTools_RejectOutOfRangeArguments(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"index above uint32", "platform_tpm_nv_read", map[string]interface{}{"index": float64(math.MaxUint32) + 1}},
		{"negative index", "platform_tpm_nv_delete", map[string]interface{}{"index": float64(-1)}},
		{"size above uint16", "platform_tpm_nv_read", map[string]interface{}{"index": float64(1), "size": float64(math.MaxUint16) + 1}},
		{"fractional offset", "platform_tpm_nv_write", map[string]interface{}{"index": float64(1), "offset": 1.5, "data": "eA=="}},
		{"index not a number", "platform_tpm_nv_write", map[string]interface{}{"index": "0x01500001", "data": "eA=="}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newMockServiceProvider()
			registry := NewToolRegistry(svc, newTestLogger())

			_, err := registry.ExecuteTool(context.Background(), tt.tool, tt.args)

			var invalid ErrInvalidArgument
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, mcpwire.InvalidParams, toolErrorCode(err))
			assert.Equal(t, tpmCall{}, svc.tpmCall, "a rejected argument never reaches the service")
		})
	}
}

func TestUintArgUpTo(t *testing.T) {
	value, err := uintArgUpTo(map[string]interface{}{"n": float64(65535)}, "n", math.MaxUint16)
	require.NoError(t, err)
	assert.Equal(t, uint64(65535), value)

	_, err = uintArgUpTo(map[string]interface{}{"n": float64(65536)}, "n", math.MaxUint16)
	assert.EqualError(t, err, "n must be at most 65535")
}
