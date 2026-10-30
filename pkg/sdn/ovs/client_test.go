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
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name       string
		socketPath string
		opts       []ClientOption
		wantErr    bool
		errType    error
	}{
		{
			name:       "valid socket path",
			socketPath: "/var/run/openvswitch/db.sock",
			wantErr:    false,
		},
		{
			name:       "empty socket path",
			socketPath: "",
			wantErr:    true,
			errType:    ErrInvalidSocket,
		},
		{
			name:       "with database option",
			socketPath: "/var/run/openvswitch/db.sock",
			opts:       []ClientOption{WithDatabase("TestDB")},
			wantErr:    false,
		},
		{
			name:       "with timeout option",
			socketPath: "/var/run/openvswitch/db.sock",
			opts:       []ClientOption{WithTimeout(10 * time.Second)},
			wantErr:    false,
		},
		{
			name:       "with openflow socket dir option",
			socketPath: "/var/run/openvswitch/db.sock",
			opts:       []ClientOption{WithOpenFlowSocketDir("/tmp/of")},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.socketPath, tt.opts...)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				require.NotNil(t, client)
				assert.Equal(t, tt.socketPath, client.socketPath)
				assert.NotNil(t, client.done)
				assert.NotNil(t, client.ofClients)
			}
		})
	}
}

func TestClient_Connect(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	// Start mock server
	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	server.Start()

	// Test successful connection
	t.Run("successful connection", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err = client.Connect(ctx)
		require.NoError(t, err)
		assert.True(t, client.IsConnected())
		assert.NotNil(t, client.conn)
		assert.NotNil(t, client.encoder)
		assert.NotNil(t, client.decoder)
	})

	// Test already connected
	t.Run("already connected", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)
		defer client.Close()

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		// Second connect should return immediately
		err = client.Connect(ctx)
		require.NoError(t, err)
		assert.True(t, client.IsConnected())
	})

	// Test connection to non-existent socket
	t.Run("connection failed", func(t *testing.T) {
		invalidSocket := filepath.Join(tmpDir, "nonexistent.sock")
		client, err := NewClient(invalidSocket)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err = client.Connect(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
		assert.False(t, client.IsConnected())
	})

	// Test connection timeout
	t.Run("connection timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		invalidSocket := filepath.Join(tmpDir, "timeout.sock")
		client, err := NewClient(invalidSocket)
		require.NoError(t, err)

		err = client.Connect(ctx)
		require.Error(t, err)
	})
}

func TestClient_Disconnect(t *testing.T) {
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

	t.Run("disconnect connected client", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)
		require.True(t, client.IsConnected())

		err = client.Disconnect()
		require.NoError(t, err)
		assert.False(t, client.IsConnected())
		assert.True(t, client.closed.Load())
	})

	t.Run("disconnect already disconnected client", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)

		err = client.Disconnect()
		require.NoError(t, err)
		assert.False(t, client.IsConnected())
	})

	t.Run("close is alias for disconnect", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		err = client.Close()
		require.NoError(t, err)
		assert.False(t, client.IsConnected())
	})
}

// TestClient_Disconnect_DoesNotDeadlockAgainstAPendingCall (#1183): Disconnect
// closes the socket under a call whose reply the dispatcher is still reading.
// The read fails and the dispatcher marks the client disconnected; that must
// not need c.mu, which Disconnect holds while it waits for the dispatcher.
func TestClient_Disconnect_DoesNotDeadlockAgainstAPendingCall(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "db.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	// The server reads one request and never replies to it.
	received := make(chan net.Conn, 1)
	go func() {
		defer close(received)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		var request map[string]interface{}
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			_ = conn.Close()
			return
		}
		received <- conn
	}()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	require.NoError(t, client.Connect(context.Background()))

	callErr := make(chan error, 1)
	go func() {
		_, err := client.Echo(context.Background(), []interface{}{"pending"})
		callErr <- err
	}()

	serverConn, ok := <-received
	require.True(t, ok, "the server never received the call")
	t.Cleanup(func() { _ = serverConn.Close() })

	require.NoError(t, client.Disconnect())
	assert.False(t, client.IsConnected())
	assert.Error(t, <-callErr, "the pending call must fail once the client disconnects")
}

func TestClient_ListDatabases(t *testing.T) {
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
	defer client.Close()

	t.Run("list databases when connected", func(t *testing.T) {
		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		dbs, err := client.ListDatabases(ctx)
		require.NoError(t, err)
		assert.Contains(t, dbs, DefaultDatabase)
	})

	t.Run("list databases when not connected", func(t *testing.T) {
		client2, err := NewClient(filepath.Join(tmpDir, "nonexistent.sock"))
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client2.ListDatabases(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_GetSchema(t *testing.T) {
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
	defer client.Close()

	t.Run("get schema when connected", func(t *testing.T) {
		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		schema, err := client.GetSchema(ctx)
		require.NoError(t, err)
		assert.NotNil(t, schema)
		assert.Equal(t, DefaultDatabase, schema.Name)
		assert.Contains(t, schema.Tables, "Bridge")
		assert.Contains(t, schema.Tables, "Port")
		assert.Contains(t, schema.Tables, "Interface")
	})

	t.Run("get schema when not connected", func(t *testing.T) {
		client2, err := NewClient(filepath.Join(tmpDir, "nonexistent.sock"))
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client2.GetSchema(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_Echo(t *testing.T) {
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
	defer client.Close()

	t.Run("echo when connected", func(t *testing.T) {
		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		testData := []interface{}{"test", float64(123), true}
		result, err := client.Echo(ctx, testData)
		require.NoError(t, err)
		assert.Equal(t, testData, result)
	})

	t.Run("echo empty data", func(t *testing.T) {
		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		result, err := client.Echo(ctx, []interface{}{})
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("echo when not connected", func(t *testing.T) {
		client2, err := NewClient(filepath.Join(tmpDir, "nonexistent.sock"))
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client2.Echo(ctx, []interface{}{"test"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_Transact(t *testing.T) {
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
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("successful select transaction", func(t *testing.T) {
		op := NewSelectOperation("Bridge", nil, []string{"name"})
		results, err := client.Transact(ctx, op)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Len(t, results[0].Rows, 0)
		assert.Empty(t, results[0].Rows) // No bridges exist initially
	})

	t.Run("successful insert transaction", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "test-bridge",
		}
		op := NewInsertOperation("Bridge", row, "test-uuid")
		results, err := client.Transact(ctx, op)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.NotNil(t, results[0].UUID)
	})

	t.Run("transaction with error", func(t *testing.T) {
		op := NewSelectOperation("NonExistentTable", nil, nil)
		_, err := client.Transact(ctx, op)
		require.Error(t, err)
	})

	t.Run("transaction when not connected", func(t *testing.T) {
		client2, err := NewClient(filepath.Join(tmpDir, "nonexistent.sock"))
		require.NoError(t, err)

		op := NewSelectOperation("Bridge", nil, nil)
		_, err = client2.Transact(ctx, op)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_Select(t *testing.T) {
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

	// Add test bridge to mock database
	server.AddBridge("br-test", "test-bridge-uuid")

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("select all rows", func(t *testing.T) {
		rows, err := client.Select(ctx, "Bridge", nil, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, rows)
	})

	t.Run("select with where clause", func(t *testing.T) {
		where := []Condition{NewCondition("name", "==", "br-test")}
		rows, err := client.Select(ctx, "Bridge", where, nil)
		require.NoError(t, err)
		assert.Len(t, rows, 1)
	})

	t.Run("select specific columns", func(t *testing.T) {
		columns := []string{"_uuid", "name"}
		rows, err := client.Select(ctx, "Bridge", nil, columns)
		require.NoError(t, err)
		assert.NotEmpty(t, rows)
		for _, row := range rows {
			assert.Contains(t, row, "_uuid")
			assert.Contains(t, row, "name")
		}
	})

	t.Run("select when not connected", func(t *testing.T) {
		client2, err := NewClient(filepath.Join(tmpDir, "nonexistent.sock"))
		require.NoError(t, err)

		_, err = client2.Select(ctx, "Bridge", nil, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_IsConnected(t *testing.T) {
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
	defer client.Close()

	t.Run("initially not connected", func(t *testing.T) {
		assert.False(t, client.IsConnected())
	})

	t.Run("connected after Connect", func(t *testing.T) {
		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)
		assert.True(t, client.IsConnected())
	})

	t.Run("not connected after Disconnect", func(t *testing.T) {
		err = client.Disconnect()
		require.NoError(t, err)
		assert.False(t, client.IsConnected())
	})
}

func TestClient_ContextCancellation(t *testing.T) {
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
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("cancelled context returns error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := client.ListDatabases(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestClient_ConcurrentOperations(t *testing.T) {
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
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("concurrent echo requests", func(t *testing.T) {
		const numGoroutines = 10
		errChan := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				data := []interface{}{float64(id)}
				result, err := client.Echo(ctx, data)
				if err != nil {
					errChan <- err
					return
				}
				if len(result) != 1 || result[0] != float64(id) {
					errChan <- assert.AnError
					return
				}
				errChan <- nil
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			err := <-errChan
			assert.NoError(t, err)
		}
	})
}
