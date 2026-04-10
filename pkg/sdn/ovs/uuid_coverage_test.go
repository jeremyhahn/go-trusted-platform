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

package ovs

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetOpenVSwitchUUIDErrorPaths tests error paths in getOpenVSwitchUUID
func TestGetOpenVSwitchUUIDErrorPaths(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("getOpenVSwitchUUID parses UUID from array format", func(t *testing.T) {
		uuid, err := client.getOpenVSwitchUUID(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, uuid)

		// Should be a valid UUID format
		assert.Len(t, uuid, 36) // Standard UUID length with dashes
	})

	t.Run("getOpenVSwitchUUID fails when server is down", func(t *testing.T) {
		// Close the server so lazy connect cannot re-establish
		server.Close()
		// Disconnect the client
		err := client.Disconnect()
		require.NoError(t, err)
		// Now the lazy connect in call() will fail because the server socket is gone
		_, err = client.getOpenVSwitchUUID(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestListDatabasesUnmarshalPath tests the unmarshal path
func TestListDatabasesUnmarshalPath(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("ListDatabases successfully unmarshals result", func(t *testing.T) {
		dbs, err := client.ListDatabases(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, dbs)
		assert.Contains(t, dbs, DefaultDatabase)
	})
}

// TestGetSchemaUnmarshalPath tests the unmarshal path
func TestGetSchemaUnmarshalPath(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("GetSchema successfully unmarshals result", func(t *testing.T) {
		schema, err := client.GetSchema(ctx)
		require.NoError(t, err)
		assert.NotNil(t, schema)
		assert.Equal(t, DefaultDatabase, schema.Name)
		assert.NotNil(t, schema.Tables)
	})
}

// TestEchoUnmarshalPath tests the unmarshal path
func TestEchoUnmarshalPath(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("Echo successfully unmarshals result", func(t *testing.T) {
		data := []interface{}{"test", float64(123), true}
		result, err := client.Echo(ctx, data)
		require.NoError(t, err)
		assert.Equal(t, data, result)
	})
}

// TestSelectEmptyResult tests Select returning empty result
func TestSelectEmptyResult(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("Select with condition that matches nothing", func(t *testing.T) {
		rows, err := client.Select(ctx, "Bridge",
			[]Condition{NewCondition("name", "==", "nonexistent-bridge-xyz-999")},
			nil)
		require.NoError(t, err)
		assert.Empty(t, rows)
	})

	t.Run("Select all from empty table", func(t *testing.T) {
		rows, err := client.Select(ctx, "Port", nil, []string{"name"})
		require.NoError(t, err)
		// When a table is empty, the Rows field with omitempty tag is excluded from JSON,
		// and unmarshals as nil. Both nil and empty slice are valid for empty results.
		assert.Empty(t, rows) // Works for both nil and empty slice
	})
}
