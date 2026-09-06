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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// platform_tpm_srk took no handle at all, so it called SSRKAttributes
// for every invocation and the PlatformSRK was unreachable over MCP.
// Issue #475.
//
// A test invoking the tool with no arguments cannot reach that defect:
// dropping the handle and defaulting to the SSRK give the same answer.
// These pass a handle and assert it arrived.

func execGetSRK(t *testing.T, args map[string]interface{}) (*mockServiceProvider, interface{}, error) {
	t.Helper()
	svc := &mockServiceProvider{}
	r := NewToolRegistry(svc, logging.DefaultLogger())
	result, err := r.executeTPMGetSRK(context.Background(), args)
	return svc, result, err
}

// TestTPMGetSRKPassesThePlatformHandle is the regression: the handle the
// caller supplied must reach the service, and the platform key must come
// back rather than the SSRK.
func TestTPMGetSRKPassesThePlatformHandle(t *testing.T) {
	svc, result, err := execGetSRK(t, map[string]interface{}{"handle": float64(0x81000002)})
	require.NoError(t, err)

	assert.Equal(t, uint32(0x81000002), svc.lastSRKHandle,
		"the tool must pass the caller's handle to the service, not drop it")
	assert.Contains(t, marshalToString(t, result), "2164260866",
		"the platform key must come back, not the SSRK")
}

// TestTPMGetSRKAcceptsHexString covers the spelling every doc, CLI flag
// and log line in this repo uses. getInt64 would return 0 here, which is
// the SSRK — a silently wrong key.
func TestTPMGetSRKAcceptsHexString(t *testing.T) {
	svc, _, err := execGetSRK(t, map[string]interface{}{"handle": "0x81000002"})
	require.NoError(t, err)
	assert.Equal(t, uint32(0x81000002), svc.lastSRKHandle,
		"a hex handle must resolve, not silently default to the SSRK")
}

// TestTPMGetSRKRejectsMalformedHandle is the loud-failure half: an
// unreadable handle must be an error, because defaulting it to 0 would
// answer with the SSRK, which is a key the caller did not ask for.
func TestTPMGetSRKRejectsMalformedHandle(t *testing.T) {
	for _, bad := range []interface{}{"cafe", "", -1, 1 << 33, 1.5, true} {
		_, _, err := execGetSRK(t, map[string]interface{}{"handle": bad})
		if bad == "" {
			// An empty string is an omitted argument, not a malformed one.
			assert.NoError(t, err)
			continue
		}
		assert.Error(t, err, "handle %v must be rejected, not defaulted to the SSRK", bad)
	}
}

// TestTPMGetSRKWithoutHandleStillReturnsSSRK pins the compatibility the
// change preserves: the argument is optional.
func TestTPMGetSRKWithoutHandleStillReturnsSSRK(t *testing.T) {
	for name, args := range map[string]map[string]interface{}{
		"absent": {},
		"nil":    {"handle": nil},
		"zero":   {"handle": float64(0)},
	} {
		t.Run(name, func(t *testing.T) {
			svc, _, err := execGetSRK(t, args)
			require.NoError(t, err)
			assert.Equal(t, uint32(0), svc.lastSRKHandle)
		})
	}
}

// TestTPMSRKToolDeclaresHandle asserts the tool's schema advertises the
// argument. A handler that accepts a parameter no schema mentions is
// unreachable to any client that reads the schema, which is all of them.
func TestTPMSRKToolDeclaresHandle(t *testing.T) {
	r := NewToolRegistry(&mockServiceProvider{}, logging.DefaultLogger())
	for _, tool := range r.ListTools() {
		if tool.Name != "platform_tpm_srk" {
			continue
		}
		props, ok := tool.InputSchema["properties"].(map[string]interface{})
		require.True(t, ok, "platform_tpm_srk has no properties block")
		assert.Contains(t, props, "handle",
			"platform_tpm_srk must declare the handle argument it now honours")
		return
	}
	t.Fatal("platform_tpm_srk tool is not registered")
}

func marshalToString(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}
