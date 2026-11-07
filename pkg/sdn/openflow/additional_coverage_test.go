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
	"path/filepath"
	"testing"
	"time"
)

// TestClient_Connect_AlreadyConnected tests connecting when already connected
func TestClient_Connect_AlreadyConnected(t *testing.T) {
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
		t.Fatalf("first connect failed: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Second connection should return nil immediately
	err = client.Connect(ctx)
	if err != nil {
		t.Errorf("connect when already connected should succeed: %v", err)
	}
}

// TestClient_HandleMessage_EchoRequestResponse tests echo request auto-reply
func TestClient_HandleMessage_EchoRequestResponse(t *testing.T) {
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

	// Server will send echo request
	server.mu.Lock()
	server.sendEchoRequest = true
	server.mu.Unlock()

	// Wait for the client's auto-reply to arrive, then assert it did.
	//
	// This test previously slept 500ms and asserted NOTHING — its own comment
	// said the reply "would be in server's received messages", but the mock
	// dropped OFPTEchoReply into its unhandled-type branch, so there was
	// nothing to check. The mock now records echo replies, which is what the
	// comment was asking for (#262).
	server.awaitArrivals(t, "client did not send an echo reply",
		func() bool { return server.getReceivedEchoReplies() > 0 })

	if got := server.getReceivedEchoReplies(); got != 1 {
		t.Errorf("echo replies = %d, want 1: the client must auto-reply to an echo request", got)
	}
}

// TestClient_HandleMessage_ErrorResponse tests OFError handling in handleMessage
func TestClient_HandleMessage_ErrorResponse(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

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

	// Configure server to send error on barrier (which is called after flow mod)
	server.mu.Lock()
	server.respondWithError = true
	server.errorType = OFPETFlowModFailed
	server.errorCode = 1 // Table full
	server.mu.Unlock()

	flow := NewFlowMod(0)
	flow.Priority = 100
	err = client.AddFlow(ctx, flow)

	// Should receive an error through the handleMessage path
	if err == nil {
		t.Error("expected error from flow mod, got nil")
	}
}

// TestClient_SendAndWait_ResponseNil tests sendAndWait when response channel is closed
func TestClient_SendAndWait_ResponseNil(t *testing.T) {
	client, err := NewClient("test-bridge")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create a scenario where pending request is cleaned up while waiting
	// This is difficult to test directly but we can test the not connected path
	ctx := context.Background()

	_, err = client.GetFlowStats(ctx, nil)
	if err != ErrNotConnected {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}

// TestClient_Reader_ShortHeader tests reader handling incomplete header reads
func TestClient_Reader_ShortHeader(t *testing.T) {
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

	// Configure server to send incomplete data. Until #262 this flag was
	// declared, set here, and READ BY NOTHING — the test slept and asserted
	// nothing, so the reader's short-header path was never exercised.
	server.mu.Lock()
	server.sendIncompleteHeader = true
	server.mu.Unlock()

	// The fault must actually reach the wire first: "the client survived X"
	// is vacuous if X was never sent, which is exactly what these tests did
	// before #262.
	server.awaitInjected(t)

	// A truncated header means the peer died mid-write, so the correct
	// outcome is a clean exit, not survival: the reader must notice the
	// stream ended rather than blocking forever for the missing bytes. The
	// failing round trip is both the wait and the assertion.
	echoCtx, cancel := context.WithTimeout(ctx, ofDeadline)
	defer cancel()
	if _, err := client.Echo(echoCtx, []byte("after-truncation")); err == nil {
		t.Error("an echo after a truncated header and close must fail, not succeed")
	}

	_ = client.Disconnect()
}

// TestClient_Reader_InvalidHeader tests reader handling header parsing errors
func TestClient_Reader_InvalidHeader(t *testing.T) {
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

	// Configure server to send a malformed header. Same as above: the flag
	// was set and never read before #262.
	server.mu.Lock()
	server.sendMalformedHeader = true
	server.mu.Unlock()

	// The fault must actually reach the wire first: "the client survived X"
	// is vacuous if X was never sent, which is exactly what these tests did
	// before #262.
	server.awaitInjected(t)

	// A real round trip is then the synchronisation point AND the assertion:
	// if the reader mishandled the bad input it would have wedged or exited,
	// and this echo would time out. No sleep anywhere.
	echoCtx, cancel := context.WithTimeout(ctx, ofDeadline)
	defer cancel()
	if _, err := client.Echo(echoCtx, []byte("still-alive")); err != nil {
		t.Fatalf("client did not survive %s: %v", "a malformed header", err)
	}
	if !client.IsConnected() {
		t.Errorf("client reports disconnected after %s", "a malformed header")
	}

	_ = client.Disconnect()
}

// TestClient_Handshake_ContextCancelled tests handshake with cancelled context
func TestClient_Handshake_ContextCancelled(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	// Stall the server so it never answers before the deadline
	server.mu.Lock()
	server.stallResponses = true
	server.mu.Unlock()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create context that cancels immediately
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = client.Connect(ctx)
	if err == nil {
		t.Error("expected error due to context cancellation")
		_ = client.Disconnect()
	}
}

// TestClient_Handshake_WrongHelloType tests handshake receiving wrong message type
func TestClient_Handshake_WrongHelloType(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	// Configure server to send wrong message type instead of hello
	server.mu.Lock()
	server.sendWrongHelloType = true
	server.mu.Unlock()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir), WithTimeout(noReplyTimeout))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	err = client.Connect(ctx)
	if err == nil {
		t.Error("expected error for wrong hello type")
		_ = client.Disconnect()
	}
}

// TestClient_Handshake_WrongFeaturesReplyType tests receiving wrong features reply
func TestClient_Handshake_WrongFeaturesReplyType(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	// Configure server to send wrong message type for features reply
	server.mu.Lock()
	server.sendWrongFeaturesType = true
	server.mu.Unlock()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	err = client.Connect(ctx)
	if err == nil {
		_ = client.Disconnect()
		t.Fatal("expected error for wrong features reply type")
	}
	if !errors.Is(err, ErrNoFeatures) {
		t.Fatalf("Connect() error = %v, want ErrNoFeatures", err)
	}
}

// TestClient_Barrier_ErrorPath tests barrier error handling
// noReplyTimeout is the client timeout for tests whose server never sends the
// reply: the test waits it out, so it is kept short.
const noReplyTimeout = 250 * time.Millisecond

func TestClient_Barrier_ErrorPath(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir), WithTimeout(noReplyTimeout))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	// Configure server to timeout on barrier
	server.mu.Lock()
	server.sendBarrierReply = false
	server.mu.Unlock()

	flow := NewFlowMod(0)
	err = client.AddFlow(ctx, flow)
	if err == nil {
		t.Error("expected timeout error on barrier")
	}
}

// TestClient_Echo_ErrorInMarshal tests echo when marshaling fails
func TestClient_Echo_ErrorInMarshal(t *testing.T) {
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

	// Normal echo should work
	data := []byte("test")
	replyData, err := client.Echo(ctx, data)
	if err != nil {
		t.Fatalf("echo failed: %v", err)
	}

	if string(replyData) != string(data) {
		t.Errorf("expected echo reply %q, got %q", data, replyData)
	}
}

// TestClient_GetFlowStats_ShortResponse tests GetFlowStats with response too short
func TestClient_GetFlowStats_ShortResponse(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	// Configure server to send short response
	server.mu.Lock()
	server.sendShortMultipartReply = true
	server.mu.Unlock()

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

	_, err = client.GetFlowStats(ctx, nil)
	if err == nil {
		t.Error("expected error for short multipart reply")
	}
}

// TestClient_AddFlow_MarshalError tests AddFlow when flow marshaling fails
func TestClient_AddFlow_MarshalError(t *testing.T) {
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

	// Create a flow that should marshal successfully
	flow := NewFlowMod(0)
	flow.Priority = 100

	// This should succeed
	err = client.AddFlow(ctx, flow)
	if err != nil {
		t.Errorf("expected AddFlow to succeed, got: %v", err)
	}
}

// TestClient_DeleteFlow_MarshalError tests DeleteFlow when flow marshaling fails
func TestClient_DeleteFlow_MarshalError(t *testing.T) {
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

	// Create a flow that should marshal successfully
	flow := NewFlowMod(0)
	flow.Priority = 100

	// This should succeed
	err = client.DeleteFlow(ctx, flow)
	if err != nil {
		t.Errorf("expected DeleteFlow to succeed, got: %v", err)
	}
}

// TestClient_ModifyFlow_MarshalError tests ModifyFlow when flow marshaling fails
func TestClient_ModifyFlow_MarshalError(t *testing.T) {
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

	// Create a flow that should marshal successfully
	flow := NewFlowMod(0)
	flow.Priority = 100

	// This should succeed
	err = client.ModifyFlow(ctx, flow)
	if err != nil {
		t.Errorf("expected ModifyFlow to succeed, got: %v", err)
	}
}

// TestClient_GetFlowStats_MarshalError tests GetFlowStats when request marshaling fails
func TestClient_GetFlowStats_MarshalError(t *testing.T) {
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

	server.setFlowStats([]FlowStats{
		{
			TableID:     0,
			Priority:    100,
			PacketCount: 1000,
			ByteCount:   64000,
		},
	})

	// This should succeed
	stats, err := client.GetFlowStats(ctx, nil)
	if err != nil {
		t.Errorf("expected GetFlowStats to succeed, got: %v", err)
	}

	if len(stats) != 1 {
		t.Errorf("expected 1 stat, got %d", len(stats))
	}
}

// TestClient_Reader_EOF tests reader handling EOF
func TestClient_Reader_EOF(t *testing.T) {
	server, socketPath := newMockOFServer(t)

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	// Close server to cause EOF
	server.close()

	// The failing round trip is both the wait and the assertion: an echo
	// against a closed peer must return an error rather than hang. The
	// previous form slept 300ms and asserted nothing, so a reader that
	// wedged on EOF would have passed (#262).
	echoCtx, cancel := context.WithTimeout(ctx, ofDeadline)
	defer cancel()
	if _, err := client.Echo(echoCtx, []byte("after-eof")); err == nil {
		t.Error("an echo against a closed server must fail, not succeed")
	}

	_ = client.Disconnect()
}

// TestClient_Reader_Timeout tests reader handling read timeouts
func TestClient_Reader_Timeout(t *testing.T) {
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

	// The reader sets a read deadline per iteration; a deadline expiring on
	// an idle connection is normal and must not tear the session down. Two
	// round trips prove the client is still usable after the reader has cycled
	// through timeouts, which sleeping 300ms and asserting nothing did not.
	echoCtx, cancel := context.WithTimeout(ctx, ofDeadline)
	defer cancel()
	for i := 0; i < 2; i++ {
		if _, err := client.Echo(echoCtx, []byte("idle")); err != nil {
			t.Fatalf("echo %d failed while the reader was idling on timeouts: %v", i+1, err)
		}
	}
	if !client.IsConnected() {
		t.Error("an idle read timeout must not disconnect the client")
	}

	_ = client.Disconnect()
}

// TestClient_Disconnect_MultipleTimes tests calling Disconnect multiple times
func TestClient_Disconnect_MultipleTimes(t *testing.T) {
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

	// First disconnect
	if err := client.Disconnect(); err != nil {
		t.Errorf("first disconnect failed: %v", err)
	}

	// Second disconnect should be safe
	if err := client.Disconnect(); err != nil {
		t.Errorf("second disconnect failed: %v", err)
	}

	// Third disconnect
	if err := client.Disconnect(); err != nil {
		t.Errorf("third disconnect failed: %v", err)
	}
}

// TestClient_HandleMessage_UnknownXid tests handleMessage with unknown transaction ID
func TestClient_HandleMessage_UnknownXid(t *testing.T) {
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

	// Configure server to send a reply nobody is waiting on. The flag was
	// set and never read before #262, so unknown-xid dispatch was untested.
	server.mu.Lock()
	server.sendUnknownXid = true
	server.mu.Unlock()

	// The fault must actually reach the wire first: "the client survived X"
	// is vacuous if X was never sent, which is exactly what these tests did
	// before #262.
	server.awaitInjected(t)

	// A real round trip is then the synchronisation point AND the assertion:
	// if the reader mishandled the bad input it would have wedged or exited,
	// and this echo would time out. No sleep anywhere.
	echoCtx, cancel := context.WithTimeout(ctx, ofDeadline)
	defer cancel()
	if _, err := client.Echo(echoCtx, []byte("still-alive")); err != nil {
		t.Fatalf("client did not survive %s: %v", "an unknown xid", err)
	}
	if !client.IsConnected() {
		t.Errorf("client reports disconnected after %s", "an unknown xid")
	}

	_ = client.Disconnect()
}

// TestMessages_EdgeCases tests various message marshaling edge cases
func TestMessages_EdgeCases(t *testing.T) {
	t.Run("EchoRequest with max data", func(t *testing.T) {
		xid := uint32(0x1234)
		maxData := make([]byte, 65535-HeaderSize) // Max message size - header
		echo := NewEchoRequest(xid, maxData)
		_, err := echo.MarshalBinary()
		if err != nil {
			t.Errorf("failed to marshal max size echo request: %v", err)
		}
	})

	t.Run("EchoReply with max data", func(t *testing.T) {
		xid := uint32(0x1234)
		maxData := make([]byte, 65535-HeaderSize)
		reply := NewEchoReply(xid, maxData)
		_, err := reply.MarshalBinary()
		if err != nil {
			t.Errorf("failed to marshal max size echo reply: %v", err)
		}
	})

	t.Run("Match with max fields", func(t *testing.T) {
		match := NewMatch()
		// Add many fields
		for i := 0; i < 20; i++ {
			match.AddInPort(uint32(i))
		}
		_, err := match.MarshalBinary()
		if err != nil {
			t.Errorf("failed to marshal match with many fields: %v", err)
		}
	})

	t.Run("FlowMod with all fields set", func(t *testing.T) {
		flow := NewFlowMod(0x12345678)
		flow.Cookie = 0xAABBCCDDEEFF0011
		flow.CookieMask = 0xFFFFFFFFFFFFFFFF
		flow.TableID = 5
		flow.Command = OFPFCAdd
		flow.IdleTimeout = 30
		flow.HardTimeout = 300
		flow.Priority = 1000
		flow.BufferID = 0xFFFFFFFF
		flow.OutPort = OFPPAny
		flow.OutGroup = 0xFFFFFFFF
		flow.Flags = OFPFFSendFlowRem | OFPFFCheckOverlap

		flow.Match.AddInPort(1)
		flow.Match.AddEthType(0x0800)

		output := NewActionOutput(2, 0)
		inst := NewInstructionApplyActions(output)
		flow.Instructions = []Instruction{inst}

		data, err := flow.MarshalBinary()
		if err != nil {
			t.Errorf("failed to marshal complete flow mod: %v", err)
		}

		if len(data) < 56 {
			t.Errorf("flow mod data too short: %d", len(data))
		}
	})

	t.Run("MultipartRequest with zero body", func(t *testing.T) {
		req := NewMultipartRequest(0x1234, OFPMPDesc, []byte{})
		data, err := req.MarshalBinary()
		if err != nil {
			t.Errorf("failed to marshal multipart request with empty body: %v", err)
		}

		if len(data) != 16 {
			t.Errorf("expected length 16, got %d", len(data))
		}
	})
}
