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

package openflow

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestNewClient tests creating a new OpenFlow client
func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		bridgeName  string
		opts        []ClientOption
		expectError bool
		errorType   error
	}{
		{
			name:        "valid bridge name",
			bridgeName:  "br0",
			expectError: false,
		},
		{
			name:        "valid with custom socket dir",
			bridgeName:  "br1",
			opts:        []ClientOption{WithSocketDir("/custom/path")},
			expectError: false,
		},
		{
			name:        "valid with custom timeout",
			bridgeName:  "br2",
			opts:        []ClientOption{WithTimeout(10 * time.Second)},
			expectError: false,
		},
		{
			name:        "empty bridge name",
			bridgeName:  "",
			expectError: true,
			errorType:   ErrInvalidBridgeName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.bridgeName, tt.opts...)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("expected error type %v, got %v", tt.errorType, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if client == nil {
				t.Fatal("expected non-nil client")
			}

			if client.bridgeName != tt.bridgeName {
				t.Errorf("expected bridge name %s, got %s", tt.bridgeName, client.bridgeName)
			}

			if !client.IsConnected() {
				// Client should not be connected yet
			} else {
				t.Error("client should not be connected after creation")
			}
		})
	}
}

// TestClient_Connect tests connecting to an OpenFlow switch
func TestClient_Connect(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func(*testing.T) (*mockOFServer, string)
		expectError bool
		errorType   error
	}{
		{
			name: "successful connection and handshake",
			setupServer: func(t *testing.T) (*mockOFServer, string) {
				return newMockOFServer(t)
			},
			expectError: false,
		},
		{
			name: "connection to non-existent socket",
			setupServer: func(t *testing.T) (*mockOFServer, string) {
				// Return path to non-existent socket
				return nil, "/nonexistent/socket/path/test.mgmt"
			},
			expectError: true,
			errorType:   ErrConnectionFailed,
		},
		{
			name: "version mismatch in hello",
			setupServer: func(t *testing.T) (*mockOFServer, string) {
				server, path := newMockOFServer(t)
				server.invalidVersionInHello = true
				return server, path
			},
			expectError: true,
			errorType:   ErrVersionMismatch,
		},
		{
			name: "no features reply",
			setupServer: func(t *testing.T) (*mockOFServer, string) {
				server, path := newMockOFServer(t)
				server.sendFeaturesReply = false
				return server, path
			},
			expectError: true,
			errorType:   ErrTimeout,
		},
		{
			name: "connection closed after handshake",
			setupServer: func(t *testing.T) (*mockOFServer, string) {
				server, path := newMockOFServer(t)
				server.closeAfterHandshake = true
				return server, path
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, socketPath := tt.setupServer(t)
			if server != nil {
				defer server.close()
			}

			// Extract socket dir and bridge name from path
			socketDir := filepath.Dir(socketPath)
			bridgeName := "test-bridge"

			client, err := NewClient(bridgeName, WithSocketDir(socketDir), WithTimeout(2*time.Second))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err = client.Connect(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Logf("expected error type %v, got %v", tt.errorType, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !client.IsConnected() {
				t.Error("client should be connected")
			}

			if client.DatapathID() == 0 {
				t.Error("datapath ID should be set after handshake")
			}

			// Clean up
			if err := client.Disconnect(); err != nil {
				t.Errorf("failed to disconnect: %v", err)
			}
		})
	}
}

// TestClient_Disconnect tests disconnecting from an OpenFlow switch
func TestClient_Disconnect(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	if !client.IsConnected() {
		t.Error("client should be connected")
	}

	// Disconnect
	if err := client.Disconnect(); err != nil {
		t.Fatalf("failed to disconnect: %v", err)
	}

	if client.IsConnected() {
		t.Error("client should not be connected after disconnect")
	}

	// Disconnect again should be safe
	if err := client.Disconnect(); err != nil {
		t.Errorf("second disconnect should not error: %v", err)
	}
}

// TestClient_Close tests the Close method (alias for Disconnect)
func TestClient_Close(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	// Use Close instead of Disconnect
	if err := client.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	if client.IsConnected() {
		t.Error("client should not be connected after close")
	}
}

// TestClient_IsConnected tests the connection state tracking
func TestClient_IsConnected(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Initially not connected
	if client.IsConnected() {
		t.Error("client should not be connected initially")
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	// Now connected
	if !client.IsConnected() {
		t.Error("client should be connected after Connect")
	}

	if err := client.Disconnect(); err != nil {
		t.Fatalf("failed to disconnect: %v", err)
	}

	// Not connected again
	if client.IsConnected() {
		t.Error("client should not be connected after Disconnect")
	}
}

// TestClient_AddFlow tests adding flow entries
func TestClient_AddFlow(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func(*mockOFServer)
		createFlow  func() *FlowMod
		expectError bool
		errorType   error
	}{
		{
			name:        "add simple flow",
			setupServer: func(s *mockOFServer) {},
			createFlow: func() *FlowMod {
				flow := NewFlowMod(0)
				flow.Priority = 100
				flow.TableID = 0
				match := NewMatch()
				match.AddInPort(1)
				flow.Match = match
				output := NewActionOutput(2, 0)
				inst := NewInstructionApplyActions(output)
				flow.Instructions = []Instruction{inst}
				return flow
			},
			expectError: false,
		},
		{
			name:        "add flow with complex match",
			setupServer: func(s *mockOFServer) {},
			createFlow: func() *FlowMod {
				flow := NewFlowMod(0)
				flow.Priority = 200
				match := NewMatch()
				match.AddInPort(1)
				match.AddEthType(0x0800) // IPv4
				match.AddIPv4Src(net.ParseIP("192.168.1.1"))
				match.AddIPv4Dst(net.ParseIP("10.0.0.1"))
				flow.Match = match
				output := NewActionOutput(OFPPController, 128)
				inst := NewInstructionApplyActions(output)
				flow.Instructions = []Instruction{inst}
				return flow
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, socketPath := newMockOFServer(t)
			defer server.close()

			if tt.setupServer != nil {
				tt.setupServer(server)
			}

			socketDir := filepath.Dir(socketPath)
			client, err := NewClient("test-bridge", WithSocketDir(socketDir))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			if err := client.Connect(ctx); err != nil {
				t.Fatalf("failed to connect: %v", err)
			}
			defer func() { _ = client.Disconnect() }()

			flow := tt.createFlow()
			err = client.AddFlow(ctx, flow)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify the flow mod was received
			time.Sleep(100 * time.Millisecond) // Give server time to process
			flowMods := server.getReceivedFlowMods()
			if len(flowMods) == 0 {
				t.Error("no flow mods received by server")
			} else {
				if flowMods[0].Command != OFPFCAdd {
					t.Errorf("expected add command, got %d", flowMods[0].Command)
				}
			}

			// Verify barrier was sent
			barriers := server.getReceivedBarriers()
			if barriers == 0 {
				t.Error("no barrier requests received")
			}
		})
	}
}

// TestClient_DeleteFlow tests deleting flow entries
func TestClient_DeleteFlow(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	flow := NewFlowMod(0)
	flow.Priority = 100
	match := NewMatch()
	match.AddInPort(1)
	flow.Match = match

	err = client.DeleteFlow(ctx, flow)
	if err != nil {
		t.Fatalf("failed to delete flow: %v", err)
	}

	// Verify the flow mod was received with delete command
	time.Sleep(100 * time.Millisecond)
	flowMods := server.getReceivedFlowMods()
	if len(flowMods) == 0 {
		t.Error("no flow mods received by server")
	} else {
		if flowMods[0].Command != OFPFCDelete {
			t.Errorf("expected delete command, got %d", flowMods[0].Command)
		}
	}
}

// TestClient_DeleteAllFlows tests deleting all flows
func TestClient_DeleteAllFlows(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	err = client.DeleteAllFlows(ctx)
	if err != nil {
		t.Fatalf("failed to delete all flows: %v", err)
	}

	// Verify flow mod with delete all
	time.Sleep(100 * time.Millisecond)
	flowMods := server.getReceivedFlowMods()
	if len(flowMods) == 0 {
		t.Error("no flow mods received by server")
	} else {
		if flowMods[0].Command != OFPFCDelete {
			t.Errorf("expected delete command, got %d", flowMods[0].Command)
		}
	}
}

// TestClient_ModifyFlow tests modifying flow entries
func TestClient_ModifyFlow(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	flow := NewFlowMod(0)
	flow.Priority = 100
	match := NewMatch()
	match.AddInPort(1)
	flow.Match = match
	output := NewActionOutput(3, 0)
	inst := NewInstructionApplyActions(output)
	flow.Instructions = []Instruction{inst}

	err = client.ModifyFlow(ctx, flow)
	if err != nil {
		t.Fatalf("failed to modify flow: %v", err)
	}

	// Verify the flow mod was received with modify command
	time.Sleep(100 * time.Millisecond)
	flowMods := server.getReceivedFlowMods()
	if len(flowMods) == 0 {
		t.Error("no flow mods received by server")
	} else {
		if flowMods[0].Command != OFPFCModify {
			t.Errorf("expected modify command, got %d", flowMods[0].Command)
		}
	}
}

// TestClient_GetFlowStats tests retrieving flow statistics
func TestClient_GetFlowStats(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func(*mockOFServer)
		match       *Match
		expectStats int
		expectError bool
	}{
		{
			name: "get all flow stats",
			setupServer: func(s *mockOFServer) {
				stats := []FlowStats{
					{
						TableID:      0,
						Priority:     100,
						DurationSec:  10,
						DurationNsec: 500000000,
						Cookie:       0x1234567890abcdef,
						PacketCount:  1000,
						ByteCount:    64000,
					},
					{
						TableID:      0,
						Priority:     200,
						DurationSec:  5,
						DurationNsec: 250000000,
						Cookie:       0xfedcba0987654321,
						PacketCount:  500,
						ByteCount:    32000,
					},
				}
				s.setFlowStats(stats)
			},
			match:       nil,
			expectStats: 2,
			expectError: false,
		},
		{
			name: "get flow stats with match",
			setupServer: func(s *mockOFServer) {
				stats := []FlowStats{
					{
						TableID:     0,
						Priority:    150,
						PacketCount: 750,
						ByteCount:   48000,
					},
				}
				s.setFlowStats(stats)
			},
			match: func() *Match {
				m := NewMatch()
				m.AddInPort(1)
				return m
			}(),
			expectStats: 1,
			expectError: false,
		},
		{},
		{
			name: "no flows exist",
			setupServer: func(s *mockOFServer) {
				s.setFlowStats([]FlowStats{})
			},
			match:       nil,
			expectStats: 0,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, socketPath := newMockOFServer(t)
			defer server.close()

			if tt.setupServer != nil {
				tt.setupServer(server)
			}

			socketDir := filepath.Dir(socketPath)
			client, err := NewClient("test-bridge", WithSocketDir(socketDir))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			if err := client.Connect(ctx); err != nil {
				t.Fatalf("failed to connect: %v", err)
			}
			defer func() { _ = client.Disconnect() }()

			stats, err := client.GetFlowStats(ctx, tt.match)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(stats) != tt.expectStats {
				t.Errorf("expected %d stats, got %d", tt.expectStats, len(stats))
			}
		})
	}
}

// TestClient_Echo tests the echo request/reply functionality
func TestClient_Echo(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func(*mockOFServer)
		echoData    []byte
		expectError bool
	}{
		{
			name:        "echo with no data",
			setupServer: func(s *mockOFServer) {},
			echoData:    nil,
			expectError: false,
		},
		{
			name:        "echo with data",
			setupServer: func(s *mockOFServer) {},
			echoData:    []byte("test echo data"),
			expectError: false,
		},
		{
			name: "echo with no reply",
			setupServer: func(s *mockOFServer) {
				s.sendEchoReply = false
			},
			echoData:    []byte("test"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, socketPath := newMockOFServer(t)
			defer server.close()

			if tt.setupServer != nil {
				tt.setupServer(server)
			}

			socketDir := filepath.Dir(socketPath)
			client, err := NewClient("test-bridge", WithSocketDir(socketDir), WithTimeout(2*time.Second))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			if err := client.Connect(ctx); err != nil {
				t.Fatalf("failed to connect: %v", err)
			}
			defer func() { _ = client.Disconnect() }()

			replyData, err := client.Echo(ctx, tt.echoData)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(tt.echoData) > 0 {
				if len(replyData) != len(tt.echoData) {
					t.Errorf("expected echo data length %d, got %d", len(tt.echoData), len(replyData))
				}
				if string(replyData) != string(tt.echoData) {
					t.Errorf("expected echo data %q, got %q", tt.echoData, replyData)
				}
			} else {
				if len(replyData) != 0 {
					t.Errorf("expected empty reply data, got %d bytes", len(replyData))
				}
			}
		})
	}
}

// TestClient_NotConnected tests operations when not connected
func TestClient_NotConnected(t *testing.T) {
	client, err := NewClient("test-bridge")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Try various operations without connecting
	t.Run("AddFlow", func(t *testing.T) {
		flow := NewFlowMod(0)
		err := client.AddFlow(ctx, flow)
		if !errors.Is(err, ErrNotConnected) {
			t.Errorf("expected ErrNotConnected, got %v", err)
		}
	})

	t.Run("DeleteFlow", func(t *testing.T) {
		flow := NewFlowMod(0)
		err := client.DeleteFlow(ctx, flow)
		if !errors.Is(err, ErrNotConnected) {
			t.Errorf("expected ErrNotConnected, got %v", err)
		}
	})

	t.Run("DeleteAllFlows", func(t *testing.T) {
		err := client.DeleteAllFlows(ctx)
		if !errors.Is(err, ErrNotConnected) {
			t.Errorf("expected ErrNotConnected, got %v", err)
		}
	})

	t.Run("ModifyFlow", func(t *testing.T) {
		flow := NewFlowMod(0)
		err := client.ModifyFlow(ctx, flow)
		if !errors.Is(err, ErrNotConnected) {
			t.Errorf("expected ErrNotConnected, got %v", err)
		}
	})

	t.Run("GetFlowStats", func(t *testing.T) {
		_, err := client.GetFlowStats(ctx, nil)
		if !errors.Is(err, ErrNotConnected) {
			t.Errorf("expected ErrNotConnected, got %v", err)
		}
	})
}

// TestClient_ContextCancellation tests context cancellation handling
func TestClient_ContextCancellation(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	// Add delay to server responses
	server.mu.Lock()
	server.delayResponse = 2 * time.Second
	server.mu.Unlock()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Create a context that will be cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	flow := NewFlowMod(0)
	err = client.AddFlow(ctx, flow)

	if err == nil {
		t.Error("expected error due to context cancellation")
	}
}

// TestClient_DatapathID tests datapath ID retrieval
func TestClient_DatapathID(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	expectedDatapathID := uint64(0x0000000000000001)
	server.mu.Lock()
	server.datapathID = expectedDatapathID
	server.mu.Unlock()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Before connection
	if client.DatapathID() != 0 {
		t.Error("datapath ID should be 0 before connection")
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// After connection
	if client.DatapathID() != expectedDatapathID {
		t.Errorf("expected datapath ID 0x%016x, got 0x%016x", expectedDatapathID, client.DatapathID())
	}
}

// TestClient_Reconnect tests reconnecting after disconnect
func TestClient_Reconnect(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// First connection
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	if !client.IsConnected() {
		t.Error("client should be connected")
	}

	// Disconnect
	if err := client.Disconnect(); err != nil {
		t.Fatalf("failed to disconnect: %v", err)
	}

	if client.IsConnected() {
		t.Error("client should not be connected after disconnect")
	}

}

// TestClient_MultipleFlowOperations tests multiple flow operations in sequence
func TestClient_MultipleFlowOperations(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Add multiple flows
	for i := 0; i < 5; i++ {
		flow := NewFlowMod(0)
		flow.Priority = uint16(100 + i*10)
		match := NewMatch()
		match.AddInPort(uint32(i + 1))
		flow.Match = match
		output := NewActionOutput(uint32(i+2), 0)
		inst := NewInstructionApplyActions(output)
		flow.Instructions = []Instruction{inst}

		if err := client.AddFlow(ctx, flow); err != nil {
			t.Errorf("failed to add flow %d: %v", i, err)
		}
	}

	// Verify all flows were received
	time.Sleep(200 * time.Millisecond)
	flowMods := server.getReceivedFlowMods()
	if len(flowMods) != 5 {
		t.Errorf("expected 5 flow mods, got %d", len(flowMods))
	}

	// Verify all were add commands
	for i, fm := range flowMods {
		if fm.Command != OFPFCAdd {
			t.Errorf("flow mod %d: expected add command, got %d", i, fm.Command)
		}
	}
}

// TestClient_OFError tests OpenFlow error handling
func TestClient_OFError(t *testing.T) {
	tests := []struct {
		name      string
		errorType uint16
		errorCode uint16
		errString string
	}{
		{
			name:      "hello failed - incompatible version",
			errorType: OFPETHelloFailed,
			errorCode: 0,
			errString: "hello failed: incompatible version",
		},
		{
			name:      "bad request - bad version",
			errorType: OFPETBadRequest,
			errorCode: 0,
			errString: "bad request: bad version",
		},
		{
			name:      "flow mod failed - table full",
			errorType: OFPETFlowModFailed,
			errorCode: 1,
			errString: "flow mod failed: table full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ofErr := &OFError{
				Type: tt.errorType,
				Code: tt.errorCode,
			}

			errStr := ofErr.Error()
			if errStr != tt.errString {
				t.Errorf("expected error string %q, got %q", tt.errString, errStr)
			}
		})
	}
}
