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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMarkDisconnected_Connected verifies markDisconnected sets connected to
// false when the client is connected and not closed.
func TestMarkDisconnected_Connected(t *testing.T) {
	c := &Client{
		connected: true,
		closed:    false,
	}
	c.markDisconnected()
	assert.False(t, c.connected)
}

// TestMarkDisconnected_AlreadyDisconnected verifies markDisconnected is a
// no-op when already disconnected.
func TestMarkDisconnected_AlreadyDisconnected(t *testing.T) {
	c := &Client{
		connected: false,
		closed:    false,
	}
	c.markDisconnected()
	assert.False(t, c.connected)
}

// TestMarkDisconnected_Closed verifies markDisconnected does not change state
// when the client is closed.
func TestMarkDisconnected_Closed(t *testing.T) {
	c := &Client{
		connected: true,
		closed:    true,
	}
	c.markDisconnected()
	assert.True(t, c.connected)
}

// TestHandleRequest_CancelledContext verifies that handleRequest returns
// a context error when the request context is already cancelled.
func TestHandleRequest_CancelledContext(t *testing.T) {
	c := &Client{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := make(chan callResult, 1)
	req := callRequest{
		ctx:    ctx,
		method: "test",
		result: result,
	}

	c.handleRequest(req)

	res := <-result
	require.Error(t, res.err)
	assert.Equal(t, context.Canceled, res.err)
}

// TestHandleRequest_EncodeError verifies that handleRequest correctly handles
// an encoder write failure (broken connection).
func TestHandleRequest_EncodeError(t *testing.T) {
	server, client := net.Pipe()
	server.Close()

	c := &Client{
		conn:    client,
		encoder: json.NewEncoder(client),
		decoder: json.NewDecoder(client),
	}
	defer client.Close()

	ctx := context.Background()
	result := make(chan callResult, 1)
	req := callRequest{
		ctx:    ctx,
		method: "test",
		result: result,
	}

	c.handleRequest(req)

	res := <-result
	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), "failed to send request")
	assert.False(t, c.connected)
}

// TestHandleRequest_SuccessResponse verifies handleRequest processes a valid
// JSON-RPC response correctly.
func TestHandleRequest_SuccessResponse(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	c := &Client{
		conn:    clientConn,
		encoder: json.NewEncoder(clientConn),
		decoder: json.NewDecoder(clientConn),
	}

	// Start a goroutine to read the request and send a response
	done := make(chan struct{})
	go func() {
		defer close(done)
		decoder := json.NewDecoder(serverConn)
		encoder := json.NewEncoder(serverConn)

		var req JSONRPCRequest
		if err := decoder.Decode(&req); err != nil {
			return
		}

		resp := JSONRPCResponse{
			ID:     req.ID,
			Result: json.RawMessage(`["Open_vSwitch"]`),
		}
		encoder.Encode(resp)
	}()

	ctx := context.Background()
	result := make(chan callResult, 1)
	req := callRequest{
		ctx:    ctx,
		method: "list_dbs",
		result: result,
	}

	c.handleRequest(req)

	res := <-result
	require.NoError(t, res.err)
	assert.NotNil(t, res.response)
	<-done
	serverConn.Close()
	clientConn.Close()
}

// TestHandleRequest_ErrorResponse verifies handleRequest returns an error
// when the server sends a JSON-RPC error response.
func TestHandleRequest_ErrorResponse(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	c := &Client{
		conn:    clientConn,
		encoder: json.NewEncoder(clientConn),
		decoder: json.NewDecoder(clientConn),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		decoder := json.NewDecoder(serverConn)
		encoder := json.NewEncoder(serverConn)

		var req JSONRPCRequest
		if err := decoder.Decode(&req); err != nil {
			return
		}

		resp := JSONRPCResponse{
			ID: req.ID,
			Error: &RPCError{
				Message: "table not found",
			},
		}
		encoder.Encode(resp)
	}()

	ctx := context.Background()
	result := make(chan callResult, 1)
	req := callRequest{
		ctx:    ctx,
		method: "transact",
		result: result,
	}

	c.handleRequest(req)

	res := <-result
	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), "OVSDB error")
	assert.Contains(t, res.err.Error(), "table not found")
	<-done
	serverConn.Close()
	clientConn.Close()
}

// TestHandleRequest_DecodeError verifies handleRequest handles a broken
// response (connection closed during read).
func TestHandleRequest_DecodeError(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	c := &Client{
		conn:    clientConn,
		encoder: json.NewEncoder(clientConn),
		decoder: json.NewDecoder(clientConn),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		decoder := json.NewDecoder(serverConn)

		var req JSONRPCRequest
		if err := decoder.Decode(&req); err != nil {
			return
		}

		// Close without sending a valid response
		serverConn.Close()
	}()

	ctx := context.Background()
	result := make(chan callResult, 1)
	req := callRequest{
		ctx:    ctx,
		method: "echo",
		result: result,
	}

	c.handleRequest(req)

	res := <-result
	require.Error(t, res.err)
	assert.Error(t, res.err)
	<-done
	clientConn.Close()
}

// TestHandleRequest_WithDeadline verifies handleRequest sets and clears
// read deadlines when the context has a deadline.
func TestHandleRequest_WithDeadline(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	c := &Client{
		conn:    clientConn,
		encoder: json.NewEncoder(clientConn),
		decoder: json.NewDecoder(clientConn),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		decoder := json.NewDecoder(serverConn)
		encoder := json.NewEncoder(serverConn)

		var req JSONRPCRequest
		if err := decoder.Decode(&req); err != nil {
			return
		}

		resp := JSONRPCResponse{
			ID:     req.ID,
			Result: json.RawMessage(`["ok"]`),
		}
		encoder.Encode(resp)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := make(chan callResult, 1)
	req := callRequest{
		ctx:    ctx,
		method: "echo",
		result: result,
	}

	c.handleRequest(req)

	res := <-result
	require.NoError(t, res.err)
	assert.NotNil(t, res.response)
	<-done
	serverConn.Close()
	clientConn.Close()
}

// TestGetOpenFlowClient_StaleClient verifies that getOpenFlowClient handles
// a disconnected cached client by trying to create a new one.
func TestGetOpenFlowClient_StaleClient(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath, WithOpenFlowSocketDir(tmpDir))
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, client.Connect(ctx))

	mockOF := &openflow.Client{}
	client.ofClientsMu.Lock()
	client.ofClients["br-test"] = mockOF
	client.ofClientsMu.Unlock()

	_, err = client.getOpenFlowClient(ctx, "br-test")
	assert.Error(t, err)
}

// TestCloseOpenFlowClient_Empty verifies closeOpenFlowClient is a no-op
// when there are no OpenFlow clients for the given bridge.
func TestCloseOpenFlowClient_Empty(t *testing.T) {
	c := &Client{
		ofClients: make(map[string]*openflow.Client),
	}
	c.closeOpenFlowClient("nonexistent-bridge")
}

// TestDisconnect_AlreadyClosed verifies Disconnect handles already-closed state.
func TestDisconnect_AlreadyClosed(t *testing.T) {
	c := &Client{
		closed:    true,
		done:      make(chan struct{}),
		ofClients: make(map[string]*openflow.Client),
	}
	err := c.Disconnect()
	assert.NoError(t, err)
}
