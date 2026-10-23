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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDEKPath = "tenants/a/dek"

var errDEKBackendDown = errors.New("dek backend down")

// TestDEKTools checks each dek_* tool decodes its arguments into the
// provider call and answers the provider's result.
func TestDEKTools(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		svc := newMockServiceProvider()
		var captured *DEKCreateRequest
		svc.dekCreateFunc = func(_ context.Context, req *DEKCreateRequest) (interface{}, error) {
			captured = req
			return map[string]interface{}{"path": req.Path}, nil
		}
		result, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "dek_create", map[string]interface{}{
			"path":            testDEKPath,
			"algorithm":       float64(3),
			"description":     "orders",
			"max_operations":  float64(1000),
			"max_bytes":       float64(4096),
			"warning_percent": float64(80),
			"tags":            map[string]interface{}{"team": "orders"},
		})
		require.NoError(t, err)
		require.NotNil(t, captured)
		assert.Equal(t, DEKCreateRequest{
			Path:           testDEKPath,
			Algorithm:      3,
			Description:    "orders",
			MaxOperations:  1000,
			MaxBytes:       4096,
			WarningPercent: 80,
			Tags:           map[string]string{"team": "orders"},
		}, *captured)
		assert.Equal(t, map[string]interface{}{"path": testDEKPath}, result)
	})

	t.Run("List", func(t *testing.T) {
		svc := newMockServiceProvider()
		var captured *DEKListRequest
		svc.dekListFunc = func(_ context.Context, req *DEKListRequest) (interface{}, error) {
			captured = req
			return map[string]interface{}{"next_cursor": "c2"}, nil
		}
		result, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "dek_list", map[string]interface{}{
			"prefix": "tenants/", "recursive": true, "limit": float64(10), "cursor": "c1",
		})
		require.NoError(t, err)
		assert.Equal(t, DEKListRequest{Prefix: "tenants/", Recursive: true, Limit: 10, Cursor: "c1"}, *captured)
		assert.Equal(t, map[string]interface{}{"next_cursor": "c2"}, result)
	})

	t.Run("Get", func(t *testing.T) {
		svc := newMockServiceProvider()
		var got string
		svc.dekGetFunc = func(_ context.Context, path string) (interface{}, error) {
			got = path
			return map[string]interface{}{"path": path}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "dek_get", map[string]interface{}{"path": testDEKPath})
		require.NoError(t, err)
		assert.Equal(t, testDEKPath, got)
	})

	t.Run("Status", func(t *testing.T) {
		svc := newMockServiceProvider()
		var got string
		svc.dekStatusFunc = func(_ context.Context, path string) (interface{}, error) {
			got = path
			return map[string]interface{}{"needs_rotation": true}, nil
		}
		result, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "dek_status", map[string]interface{}{"path": testDEKPath})
		require.NoError(t, err)
		assert.Equal(t, testDEKPath, got)
		assert.Equal(t, map[string]interface{}{"needs_rotation": true}, result)
	})

	t.Run("Rotate", func(t *testing.T) {
		svc := newMockServiceProvider()
		var gotPath string
		var gotBackground bool
		svc.dekRotateFunc = func(_ context.Context, path string, background bool) (interface{}, error) {
			gotPath, gotBackground = path, background
			return map[string]interface{}{"new_version": float64(2)}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "dek_rotate", map[string]interface{}{
			"path": testDEKPath, "background": true,
		})
		require.NoError(t, err)
		assert.Equal(t, testDEKPath, gotPath)
		assert.True(t, gotBackground)
	})

	t.Run("Delete", func(t *testing.T) {
		svc := newMockServiceProvider()
		var captured *DEKDeleteRequest
		svc.dekDeleteFunc = func(_ context.Context, req *DEKDeleteRequest) (interface{}, error) {
			captured = req
			return map[string]interface{}{"success": true}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "dek_delete", map[string]interface{}{
			"path": testDEKPath, "force": true, "migrate_to": "tenants/a/dek2",
		})
		require.NoError(t, err)
		assert.Equal(t, DEKDeleteRequest{Path: testDEKPath, Force: true, MigrateTo: "tenants/a/dek2"}, *captured)
	})
}

// TestDEKToolsErrors checks a missing path is refused before the provider
// runs and a provider failure reaches the caller.
func TestDEKToolsErrors(t *testing.T) {
	for _, tool := range []string{"dek_create", "dek_get", "dek_status", "dek_rotate", "dek_delete"} {
		t.Run(tool+" without path", func(t *testing.T) {
			svc := newMockServiceProvider()
			ran := false
			svc.dekCreateFunc = func(context.Context, *DEKCreateRequest) (interface{}, error) { ran = true; return nil, nil }
			svc.dekGetFunc = func(context.Context, string) (interface{}, error) { ran = true; return nil, nil }
			svc.dekStatusFunc = func(context.Context, string) (interface{}, error) { ran = true; return nil, nil }
			svc.dekRotateFunc = func(context.Context, string, bool) (interface{}, error) { ran = true; return nil, nil }
			svc.dekDeleteFunc = func(context.Context, *DEKDeleteRequest) (interface{}, error) { ran = true; return nil, nil }

			_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), tool, map[string]interface{}{})
			assert.ErrorIs(t, err, ErrDEKPathRequired)
			assert.False(t, ran, "provider must not run without a path")
		})
	}

	failing := newMockServiceProvider()
	failing.dekCreateFunc = func(context.Context, *DEKCreateRequest) (interface{}, error) { return nil, errDEKBackendDown }
	failing.dekListFunc = func(context.Context, *DEKListRequest) (interface{}, error) { return nil, errDEKBackendDown }
	failing.dekGetFunc = func(context.Context, string) (interface{}, error) { return nil, errDEKBackendDown }
	failing.dekStatusFunc = func(context.Context, string) (interface{}, error) { return nil, errDEKBackendDown }
	failing.dekRotateFunc = func(context.Context, string, bool) (interface{}, error) { return nil, errDEKBackendDown }
	failing.dekDeleteFunc = func(context.Context, *DEKDeleteRequest) (interface{}, error) { return nil, errDEKBackendDown }
	registry := newKMSToolTestRegistry(failing)
	for _, tool := range []string{"dek_create", "dek_list", "dek_get", "dek_status", "dek_rotate", "dek_delete"} {
		t.Run(tool+" provider failure", func(t *testing.T) {
			_, err := executeKMSToolViaDispatch(t, registry, tool, map[string]interface{}{"path": testDEKPath})
			assert.ErrorIs(t, err, errDEKBackendDown)
		})
	}
}
