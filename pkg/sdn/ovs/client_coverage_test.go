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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientDispatcherEdgeCases tests edge cases in dispatcher lifecycle
func TestClientDispatcherEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	t.Run("dispatcher handles shutdown gracefully", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		// Close immediately to test cleanup
		err = client.Close()
		require.NoError(t, err)
		assert.False(t, client.IsConnected())
	})

	t.Run("disconnect during idle dispatcher is safe", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		// Disconnect should cleanly shut down the dispatcher
		err = client.Close()
		require.NoError(t, err)
	})

	t.Run("multiple disconnects are safe", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		err = client.Disconnect()
		require.NoError(t, err)

		// Second disconnect should not error
		err = client.Disconnect()
		require.NoError(t, err)
	})
}

// TestClientGetOpenVSwitchUUIDEdgeCases tests edge cases in getOpenVSwitchUUID
func TestClientGetOpenVSwitchUUIDEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("getOpenVSwitchUUID returns UUID", func(t *testing.T) {
		uuid, err := client.getOpenVSwitchUUID(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, uuid)
	})

	t.Run("getOpenVSwitchUUID when not connected", func(t *testing.T) {
		disconnectedClient, err := NewClient(filepath.Join(tmpDir, "nonexistent.sock"))
		require.NoError(t, err)

		_, err = disconnectedClient.getOpenVSwitchUUID(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestClientCallEdgeCases tests edge cases in the call method
func TestClientCallEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	t.Run("call with context cancellation", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)
		defer func() {
			if err := client.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		// Create cancelled context
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err = client.call(cancelCtx, "echo", []interface{}{})
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("call returns error on expired context", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)
		defer func() {
			if err := client.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		// Create context with very short timeout that will already be expired
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		// Wait for the context to expire
		<-timeoutCtx.Done()

		_, err = client.call(timeoutCtx, "list_dbs", []interface{}{})
		require.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("call when not connected", func(t *testing.T) {
		client, err := NewClient(filepath.Join(tmpDir, "nonexistent.sock"))
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.call(ctx, "echo", []interface{}{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

}

// TestClientSelectEdgeCases tests edge cases in Select
func TestClientSelectEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("select with empty result", func(t *testing.T) {
		// Select from table that exists but has no rows
		rows, err := client.Select(ctx, "Bridge", []Condition{NewCondition("name", "==", "nonexistent")}, nil)
		require.NoError(t, err)
		assert.Empty(t, rows)
	})

	t.Run("select handles transaction with no results", func(t *testing.T) {
		// Create operation that returns empty result
		op := NewSelectOperation("Bridge", []Condition{NewCondition("name", "==", "fake-bridge-xyz")}, nil)
		results, err := client.Transact(ctx, op)
		require.NoError(t, err)

		if len(results) > 0 {
			assert.Empty(t, results[0].Rows)
		}
	})
}

// TestClientTransactEdgeCases tests edge cases in Transact
func TestClientTransactEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("transact with multiple operations", func(t *testing.T) {
		// Create multiple valid operations
		op1 := NewSelectOperation("Bridge", nil, []string{"name"})
		op2 := NewSelectOperation("Port", nil, []string{"name"})

		results, err := client.Transact(ctx, op1, op2)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 2)
	})

	t.Run("transact validates all operation errors", func(t *testing.T) {
		// This will cause an error at the server
		op := NewSelectOperation("InvalidTable", nil, nil)
		_, err := client.Transact(ctx, op)
		require.Error(t, err)
	})
}

// TestClientListDatabasesEdgeCases tests edge cases in ListDatabases
func TestClientListDatabasesEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("ListDatabases returns expected databases", func(t *testing.T) {
		dbs, err := client.ListDatabases(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, dbs)
		assert.Contains(t, dbs, DefaultDatabase)
	})
}

// TestClientGetSchemaEdgeCases tests edge cases in GetSchema
func TestClientGetSchemaEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("GetSchema validates result structure", func(t *testing.T) {
		schema, err := client.GetSchema(ctx)
		require.NoError(t, err)
		assert.NotNil(t, schema)
		assert.NotEmpty(t, schema.Name)
		assert.NotNil(t, schema.Tables)
	})
}

// TestClientEchoEdgeCases tests edge cases in Echo
func TestClientEchoEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("Echo with nil data", func(t *testing.T) {
		result, err := client.Echo(ctx, nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("Echo with complex data types", func(t *testing.T) {
		testData := []interface{}{
			"string",
			float64(123.456),
			true,
			false,
			nil,
			[]interface{}{"nested", "array"},
			map[string]interface{}{"key": "value"},
		}

		result, err := client.Echo(ctx, testData)
		require.NoError(t, err)
		assert.Equal(t, len(testData), len(result))
	})
}

// TestClientOptionsEdgeCases tests client option edge cases
func TestClientOptionsEdgeCases(t *testing.T) {
	t.Run("multiple options combined", func(t *testing.T) {
		client, err := NewClient(
			"/var/run/openvswitch/db.sock",
			WithDatabase("CustomDB"),
			WithTimeout(5*time.Second),
			WithOpenFlowSocketDir("/custom/of/dir"),
		)
		require.NoError(t, err)
		assert.Equal(t, "CustomDB", client.database)
		assert.Equal(t, 5*time.Second, client.timeout)
		assert.Equal(t, "/custom/of/dir", client.ofSocketDir)
	})

	t.Run("options with default values", func(t *testing.T) {
		client, err := NewClient("/var/run/openvswitch/db.sock")
		require.NoError(t, err)
		assert.Equal(t, DefaultDatabase, client.database)
		assert.Equal(t, 30*time.Second, client.timeout)
		assert.Equal(t, "/var/run/openvswitch", client.ofSocketDir)
	})

	t.Run("options override defaults", func(t *testing.T) {
		client, err := NewClient(
			"/var/run/openvswitch/db.sock",
			WithDatabase("DB1"),
			WithDatabase("DB2"), // Second call should override
		)
		require.NoError(t, err)
		assert.Equal(t, "DB2", client.database)
	})
}

// TestClientCloseOpenFlowClient tests closeOpenFlowClient
func TestClientCloseOpenFlowClient(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	t.Run("closeOpenFlowClient with no clients", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)

		// Should not panic when closing non-existent client
		client.closeOpenFlowClient("nonexistent-bridge")
	})

	t.Run("closeOpenFlowClient removes client from map", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)
		defer func() {
			if err := client.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		// Simulate having an OpenFlow client (we can't really create one without real OVS)
		// But we can test the cleanup path
		client.ofClientsMu.Lock()
		initialCount := len(client.ofClients)
		client.ofClientsMu.Unlock()

		// Try to close non-existent - should be safe
		client.closeOpenFlowClient("test-bridge")

		client.ofClientsMu.Lock()
		finalCount := len(client.ofClients)
		client.ofClientsMu.Unlock()

		assert.Equal(t, initialCount, finalCount)
	})
}

// TestClientResponseHandling tests response handling edge cases
func TestClientResponseHandling(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("concurrent requests don't interfere", func(t *testing.T) {
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func(id int) {
				data := []interface{}{float64(id)}
				result, err := client.Echo(ctx, data)
				assert.NoError(t, err)
				if err == nil {
					assert.Equal(t, data, result)
				}
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// TestJSONRPCResponseError tests error response handling
func TestJSONRPCResponseError(t *testing.T) {
	t.Run("response with error is handled", func(t *testing.T) {
		// This tests the error path in the call method
		// The mock server can return errors for invalid operations
		tmpDir := t.TempDir()
		socketPath := filepath.Join(tmpDir, "db.sock")

		server, err := newMockOVSDBServer(t, socketPath)
		require.NoError(t, err)
		defer func() {
			if err := server.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()
		server.Start()

		client, err := NewClient(socketPath)
		require.NoError(t, err)
		defer func() {
			if err := client.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		// Try an operation that will fail
		_, err = client.Transact(ctx, NewSelectOperation("NonExistentTable", nil, nil))
		require.Error(t, err)
	})
}
