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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name:        "successful connection and handshake",
			setupServer: newMockOFServer,
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

			// Wait for the flow mod to actually arrive, rather than
			// sleeping 100ms and hoping (#262).
			server.awaitFlowMods(t, 1)
			flowMods := server.getReceivedFlowMods()
			if len(flowMods) == 0 {
				t.Error("no flow mods received by server")
			} else if flowMods[0].Command != OFPFCAdd {
				t.Errorf("expected add command, got %d", flowMods[0].Command)
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
	server.awaitFlowMods(t, 1)
	flowMods := server.getReceivedFlowMods()
	if len(flowMods) == 0 {
		t.Error("no flow mods received by server")
	} else if flowMods[0].Command != OFPFCDelete {
		t.Errorf("expected delete command, got %d", flowMods[0].Command)
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
	server.awaitFlowMods(t, 1)
	flowMods := server.getReceivedFlowMods()
	if len(flowMods) == 0 {
		t.Error("no flow mods received by server")
	} else if flowMods[0].Command != OFPFCDelete {
		t.Errorf("expected delete command, got %d", flowMods[0].Command)
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
	server.awaitFlowMods(t, 1)
	flowMods := server.getReceivedFlowMods()
	if len(flowMods) == 0 {
		t.Error("no flow mods received by server")
	} else if flowMods[0].Command != OFPFCModify {
		t.Errorf("expected modify command, got %d", flowMods[0].Command)
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
			} else if len(replyData) != 0 {
				t.Errorf("expected empty reply data, got %d bytes", len(replyData))
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

	// Verify all flows were received. Waiting for the fifth is what makes
	// the count assertion below meaningful: a sleep could return with four
	// in flight and report a wrong count as a failure (#262).
	server.awaitFlowMods(t, 5)
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
		{
			name:      "meter mod failed - meter exists",
			errorType: OFPETMeterModFailed,
			errorCode: OFPMMFCMeterExists,
			errString: "meter mod failed: meter exists",
		},
		{
			name:      "meter mod failed - unlisted code",
			errorType: OFPETMeterModFailed,
			errorCode: 99,
			errString: "meter mod failed: unknown error",
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

func TestClient_ConnectEnablesPacketIn(t *testing.T) {
	server, _ := connectMock(t)

	assert.Equal(t, OFPCMLNoBuffer, server.getMissSendLen(),
		"a service connection gets no packet-in until miss_send_len is raised")
}

func TestClient_ConnectFailsWhenSwitchKeepsPacketInDisabled(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()
	server.ignoreSetConfig = true
	client, err := NewClient("test-bridge", WithSocketDir(filepath.Dir(socketPath)), WithTimeout(2*time.Second))
	require.NoError(t, err)

	err = client.Connect(context.Background())

	var disabled *ErrPacketInDisabled
	require.True(t, errors.As(err, &disabled), "got %v", err)
	assert.False(t, client.IsConnected())
}

func TestClient_ConnectPreservesFragmentPolicy(t *testing.T) {
	const fragDrop uint16 = 1 // OFPC_FRAG_DROP
	server, socketPath := newMockOFServer(t)
	defer server.close()
	server.setFragFlags(fragDrop)
	client, err := NewClient("test-bridge", WithSocketDir(filepath.Dir(socketPath)), WithTimeout(2*time.Second))
	require.NoError(t, err)
	require.NoError(t, client.Connect(context.Background()))
	defer func() { _ = client.Disconnect() }()

	assert.Equal(t, []uint16{fragDrop}, server.getSetConfigs(),
		"enabling packet-in must keep the bridge's switch-wide fragment policy")
	assert.Equal(t, OFPCMLNoBuffer, server.getMissSendLen())
}

func TestClient_ConnectKeepsNormalFragmentPolicy(t *testing.T) {
	server, _ := connectMock(t)

	assert.Equal(t, []uint16{OFPCFragNormal}, server.getSetConfigs())
}

func TestClient_ReaderMarksConnectionLostWhenSwitchCloses(t *testing.T) {
	server, client := connectMock(t)

	server.dropConnection()

	require.Eventually(t, func() bool { return !client.IsConnected() }, 2*time.Second, 5*time.Millisecond,
		"a switch that closes the socket must not leave the client reporting connected")
	err := client.SendPacketOut(context.Background(), NewPacketOut(3, nil, []byte{0xaa}))
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClient_ConnectRecoversAfterSwitchClosed(t *testing.T) {
	server, client := connectMock(t)
	server.dropConnection()
	require.Eventually(t, func() bool { return !client.IsConnected() }, 2*time.Second, 5*time.Millisecond)

	require.NoError(t, client.Connect(context.Background()))

	_, err := client.Echo(context.Background(), nil)
	require.NoError(t, err, "the reconnected client must serve requests")
	assert.Equal(t, OFPCMLNoBuffer, server.getMissSendLen())
}

func TestClient_ConnectWaitsForTheLostConnectionsReader(t *testing.T) {
	ctx := context.Background()
	server, client := connectMock(t)
	server.awaitAccept(t)
	server.mu.Lock()
	server.sendBarrierReply = false
	server.mu.Unlock()
	stale := make(chan error, 1)
	go func() { stale <- client.barrier(ctx) }()
	require.Eventually(t, func() bool { return server.getReceivedBarriers() == 1 }, 2*time.Second, 5*time.Millisecond)

	// Holding pendingMu stops the old reader inside connectionLost, after it
	// marks the client disconnected and before it fails its requests.
	client.pendingMu.Lock()
	server.dropConnection()
	require.Eventually(t, func() bool { return !client.IsConnected() }, 2*time.Second, 5*time.Millisecond)
	reconnected := make(chan error, 1)
	go func() { reconnected <- client.Connect(ctx) }()
	server.awaitAccept(t)
	client.pendingMu.Unlock()

	require.NoError(t, <-reconnected)
	assert.ErrorIs(t, <-stale, ErrConnectionClosed, "the lost connection's request fails")
	_, err := client.Echo(ctx, nil)
	require.NoError(t, err, "the old reader must not close the new connection or fail its requests")
}

func TestClient_PendingRequestFailsWhenSwitchCloses(t *testing.T) {
	server, client := connectMock(t)
	server.mu.Lock()
	server.sendBarrierReply = false
	server.mu.Unlock()
	errCh := make(chan error, 1)
	go func() { errCh <- client.barrier(context.Background()) }()
	require.Eventually(t, func() bool { return server.getReceivedBarriers() == 1 }, 2*time.Second, 5*time.Millisecond)

	server.dropConnection()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, ErrConnectionClosed)
	case <-time.After(time.Second):
		t.Fatal("a request waiting on a lost connection must fail promptly, not run out its timeout")
	}
}

func TestClient_BarrierOnLostConnectionIsNotConfirmedByTheReconnect(t *testing.T) {
	ctx := context.Background()
	server, client := connectMock(t)
	server.awaitAccept(t)
	// A write confirmed on this connection is followed by a reconnect before
	// its barrier goes out.
	lost := client.session.Load()
	server.dropConnection()
	require.Eventually(t, func() bool { return !client.IsConnected() }, 2*time.Second, 5*time.Millisecond)
	require.NoError(t, client.Connect(ctx))
	server.awaitAccept(t)
	barriers := server.getReceivedBarriers()

	err := client.barrierOn(ctx, lost)

	assert.ErrorIs(t, err, ErrConnectionClosed, "the reconnect's barrier reply must not confirm the lost connection's write")
	assert.Equal(t, barriers, server.getReceivedBarriers(), "no barrier may go to the new connection")
}

func TestClient_WriteConfirmedWaitsOnTheConnectionItWroteTo(t *testing.T) {
	ctx := context.Background()
	server, client := connectMock(t)

	flow := NewFlowMod(0)
	flow.Header.Xid = client.nextXid()
	data, err := flow.MarshalBinary()
	require.NoError(t, err)

	require.NoError(t, client.writeConfirmed(ctx, data, "failed to send"))

	assert.Equal(t, 1, server.getReceivedBarriers())
}

func TestClient_WriteConfirmedRequiresConnection(t *testing.T) {
	client, err := NewClient("test-bridge", WithTimeout(time.Second))
	require.NoError(t, err)

	err = client.writeConfirmed(context.Background(), []byte{0}, "failed to send")

	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClient_SendPacketOutReportsSwitchRejection(t *testing.T) {
	server, client := connectMock(t)
	server.failPacketOuts(OFPETBadAction, 4) // OFPBAC_BAD_OUT_PORT

	err := client.SendPacketOut(context.Background(), NewPacketOut(3, []Action{NewActionOutput(9, 0)}, []byte{0xaa}))

	var ofErr *OFError
	require.True(t, errors.As(err, &ofErr), "a rejected packet-out must not report success: %v", err)
	assert.Equal(t, uint16(OFPETBadAction), ofErr.Type)
	assert.Equal(t, uint16(4), ofErr.Code)
}

func TestClient_SubscribePacketInDeliversSwitchPacketIns(t *testing.T) {
	server, client := connectMock(t)
	subscription, err := client.SubscribePacketIn(4)
	require.NoError(t, err)
	defer subscription.Cancel()
	match := NewMatch()
	match.AddInPort(3)

	server.sendPacketIn(packetInBody(t, match, []byte{0xde, 0xad}))

	select {
	case packet := <-subscription.C():
		assert.Equal(t, uint64(0xabc), packet.Cookie)
		assert.Equal(t, []byte{0xde, 0xad}, packet.Data)
	case <-time.After(5 * time.Second):
		t.Fatal("packet-in was not delivered")
	}
}

func TestClient_SubscribePacketInCountsQueueFullDrops(t *testing.T) {
	server, client := connectMock(t)
	subscription, err := client.SubscribePacketIn(1)
	require.NoError(t, err)
	defer subscription.Cancel()
	match := NewMatch()
	match.AddInPort(3)

	server.sendPacketIn(packetInBody(t, match, []byte{1}))
	server.sendPacketIn(packetInBody(t, match, []byte{2}))

	require.Eventually(t, func() bool { return subscription.Dropped() == 1 }, 5*time.Second, time.Millisecond)
	assert.Equal(t, []byte{1}, (<-subscription.C()).Data)
}

func TestClient_SubscribePacketInRejectsBadQueue(t *testing.T) {
	_, client := connectMock(t)

	_, err := client.SubscribePacketIn(0)

	var invalid *ErrInvalidPacketInConfig
	assert.True(t, errors.As(err, &invalid), "got %v", err)
}

func TestClient_SubscribePacketInCancelUnregisters(t *testing.T) {
	server, client := connectMock(t)
	subscription, err := client.SubscribePacketIn(1)
	require.NoError(t, err)
	match := NewMatch()
	match.AddInPort(3)

	subscription.Cancel()
	server.sendPacketIn(packetInBody(t, match, []byte{1}))
	// The echo round trip orders after the packet-in on the connection.
	_, err = client.Echo(context.Background(), nil)
	require.NoError(t, err)

	_, open := <-subscription.C()
	assert.False(t, open)
	assert.Zero(t, subscription.Dropped())
}

func TestClient_SendPacketOutWritesPacket(t *testing.T) {
	server, client := connectMock(t)

	err := client.SendPacketOut(context.Background(), NewPacketOut(3, []Action{NewActionOutput(OFPPInPort, 0)}, []byte{0xaa}))
	require.NoError(t, err)
	_, err = client.Echo(context.Background(), nil)
	require.NoError(t, err)

	packetOuts := server.getReceivedPacketOuts()
	require.Len(t, packetOuts, 1)
	assert.Equal(t, byte(0xaa), packetOuts[0][len(packetOuts[0])-1])
}

func TestClient_SendPacketOutHonoursContext(t *testing.T) {
	server, client := connectMock(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := client.SendPacketOut(ctx, NewPacketOut(3, nil, []byte{0xaa}))

	assert.ErrorIs(t, err, context.Canceled)
	_, err = client.Echo(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, server.getReceivedPacketOuts(), "a cancelled send must write nothing")
}

func TestClient_SetMeterAddsMeter(t *testing.T) {
	server, client := connectMock(t)

	require.NoError(t, client.SetMeter(context.Background(), 709, 512, 64))

	mods := server.getMeterMods()
	require.Len(t, mods, 1)
	assert.Equal(t, OFPMCAdd, mods[0].Command)
	assert.Equal(t, uint32(709), mods[0].MeterID)
	assert.Equal(t, 1, server.getReceivedBarriers(), "the meter mod is confirmed by a barrier")
}

func TestClient_SetMeterModifiesExistingMeter(t *testing.T) {
	server, client := connectMock(t)
	require.NoError(t, client.SetMeter(context.Background(), 709, 100, 10))

	require.NoError(t, client.SetMeter(context.Background(), 709, 512, 64))

	mods := server.getMeterMods()
	require.Len(t, mods, 3)
	assert.Equal(t, OFPMCAdd, mods[1].Command, "the restart first tries ADD")
	assert.Equal(t, OFPMCModify, mods[2].Command, "METER_EXISTS falls back to MODIFY")
	band, ok := mods[2].Bands[0].(*MeterBandDrop)
	require.True(t, ok)
	assert.Equal(t, uint32(512), band.Rate, "the current rate applies")
}

func TestClient_SetMeterReportsUnsupportedDatapath(t *testing.T) {
	server, client := connectMock(t)
	server.mu.Lock()
	server.metersUnsupported = true
	server.mu.Unlock()

	err := client.SetMeter(context.Background(), 709, 512, 64)

	var unsupported *ErrMeterUnsupported
	require.True(t, errors.As(err, &unsupported), "got %v", err)
	assert.Equal(t, uint32(709), unsupported.MeterID)
}

func TestClient_DeleteMeterReportsSwitchError(t *testing.T) {
	_, client := connectMock(t)

	err := client.DeleteMeter(context.Background(), 709)

	var ofErr *OFError
	require.True(t, errors.As(err, &ofErr), "got %v", err)
	assert.Equal(t, OFPMMFCUnknownMeter, ofErr.Code)
}

func TestClient_GetMeterStats(t *testing.T) {
	server, client := connectMock(t)
	server.mu.Lock()
	server.meterStats[709] = MeterStats{MeterID: 709, Bands: []MeterBandStats{{PacketCount: 5, ByteCount: 400}}}
	server.mu.Unlock()

	stats, err := client.GetMeterStats(context.Background(), 709)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), stats.BandPackets())
}

func TestClient_GetMeterStatsReportsMissingMeter(t *testing.T) {
	_, client := connectMock(t)

	_, err := client.GetMeterStats(context.Background(), 709)

	var notFound *ErrMeterNotFound
	assert.True(t, errors.As(err, &notFound), "got %v", err)
}

// connectMock connects a client to a fresh mock switch, closing both when
// the test ends.
func connectMock(t *testing.T) (*mockOFServer, *Client) {
	t.Helper()
	server, socketPath := newMockOFServer(t)
	t.Cleanup(server.close)
	client, err := NewClient("test-bridge", WithSocketDir(filepath.Dir(socketPath)), WithTimeout(2*time.Second))
	require.NoError(t, err)
	require.NoError(t, client.Connect(context.Background()))
	t.Cleanup(func() { _ = client.Disconnect() })
	return server, client
}
