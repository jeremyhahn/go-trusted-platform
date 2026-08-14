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

// makeBatchFlow builds a simple flow mod for batch testing
func makeBatchFlow(priority uint16, inPort, outPort uint32) *FlowMod {
	flow := NewFlowMod(0)
	flow.Priority = priority
	match := NewMatch()
	match.AddInPort(inPort)
	flow.Match = match
	output := NewActionOutput(outPort, 0)
	flow.Instructions = []Instruction{NewInstructionApplyActions(output)}
	return flow
}

// TestClient_SendFlowMods tests batched flow installation
func TestClient_SendFlowMods(t *testing.T) {
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

	flows := []*FlowMod{
		makeBatchFlow(100, 1, 2),
		makeBatchFlow(200, 2, 3),
		makeBatchFlow(300, 3, 4),
	}

	if err := client.SendFlowMods(ctx, flows); err != nil {
		t.Fatalf("failed to send flow mod batch: %v", err)
	}

	flowMods := server.getReceivedFlowMods()
	if len(flowMods) != 3 {
		t.Fatalf("expected 3 flow mods, got %d", len(flowMods))
	}
	for i, fm := range flowMods {
		if fm.Command != OFPFCAdd {
			t.Errorf("flow mod %d: expected add command, got %d", i, fm.Command)
		}
	}

	// The whole batch must be confirmed by exactly one barrier
	if barriers := server.getReceivedBarriers(); barriers != 1 {
		t.Errorf("expected 1 barrier for the batch, got %d", barriers)
	}

	// Each flow mod must carry a distinct xid
	seen := make(map[uint32]struct{}, len(flowMods))
	for _, fm := range flowMods {
		if _, dup := seen[fm.Header.Xid]; dup {
			t.Errorf("duplicate xid %d in batch", fm.Header.Xid)
		}
		seen[fm.Header.Xid] = struct{}{}
	}
}

// TestClient_SendFlowMods_EmptyBatch tests the empty batch fast path
func TestClient_SendFlowMods_EmptyBatch(t *testing.T) {
	client, err := NewClient("test-bridge")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// An empty batch succeeds without a connection
	if err := client.SendFlowMods(context.Background(), nil); err != nil {
		t.Errorf("expected nil for empty batch, got %v", err)
	}
	if err := client.SendFlowMods(context.Background(), []*FlowMod{}); err != nil {
		t.Errorf("expected nil for empty batch, got %v", err)
	}
}

// TestClient_SendFlowMods_NotConnected tests the not-connected error path
func TestClient_SendFlowMods_NotConnected(t *testing.T) {
	client, err := NewClient("test-bridge")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	flows := []*FlowMod{makeBatchFlow(100, 1, 2)}
	if err := client.SendFlowMods(context.Background(), flows); !errors.Is(err, ErrNotConnected) {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}

// TestClient_SendFlowMods_NilFlow tests rejection of nil batch members
func TestClient_SendFlowMods_NilFlow(t *testing.T) {
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

	flows := []*FlowMod{makeBatchFlow(100, 1, 2), nil}
	if err := client.SendFlowMods(ctx, flows); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("expected ErrInvalidMessage, got %v", err)
	}

	// Nothing may have been written before validation failed
	if flowMods := server.getReceivedFlowMods(); len(flowMods) != 0 {
		t.Errorf("expected 0 flow mods, got %d", len(flowMods))
	}
}

// TestClient_SendFlowMods_PartialFailure tests per-flow error collection
func TestClient_SendFlowMods_PartialFailure(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	// Reject the second flow mod (index 1) with a table-full error
	server.failFlowModAt(OFPETFlowModFailed, 1, 1)

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

	flows := []*FlowMod{
		makeBatchFlow(100, 1, 2),
		makeBatchFlow(200, 2, 3),
		makeBatchFlow(300, 3, 4),
	}

	err = client.SendFlowMods(ctx, flows)
	if err == nil {
		t.Fatal("expected batch partial failure, got nil")
	}

	var batchErr *ErrBatchPartialFailure
	if !errors.As(err, &batchErr) {
		t.Fatalf("expected *ErrBatchPartialFailure, got %T: %v", err, err)
	}
	if len(batchErr.Failed) != 1 {
		t.Fatalf("expected 1 failed flow, got %d", len(batchErr.Failed))
	}

	failed := batchErr.Failed[0]
	if failed.Index != 1 {
		t.Errorf("expected failed index 1, got %d", failed.Index)
	}
	if failed.Xid != flows[1].Header.Xid {
		t.Errorf("expected failed xid %d, got %d", flows[1].Header.Xid, failed.Xid)
	}
	if failed.Err == nil {
		t.Fatal("expected OFError detail, got nil")
	}
	if failed.Err.Type != OFPETFlowModFailed || failed.Err.Code != 1 {
		t.Errorf("unexpected OFError: type=%d code=%d", failed.Err.Type, failed.Err.Code)
	}

	// The switch still received all three flow mods and the barrier
	if flowMods := server.getReceivedFlowMods(); len(flowMods) != 3 {
		t.Errorf("expected 3 flow mods, got %d", len(flowMods))
	}
	if barriers := server.getReceivedBarriers(); barriers != 1 {
		t.Errorf("expected 1 barrier, got %d", barriers)
	}
}

// TestClient_SendFlowMods_MultipleFailures tests ordering of collected failures
func TestClient_SendFlowMods_MultipleFailures(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	server.failFlowModAt(OFPETFlowModFailed, 0, 0, 2)

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

	flows := []*FlowMod{
		makeBatchFlow(100, 1, 2),
		makeBatchFlow(200, 2, 3),
		makeBatchFlow(300, 3, 4),
	}

	err = client.SendFlowMods(ctx, flows)

	var batchErr *ErrBatchPartialFailure
	if !errors.As(err, &batchErr) {
		t.Fatalf("expected *ErrBatchPartialFailure, got %T: %v", err, err)
	}
	if len(batchErr.Failed) != 2 {
		t.Fatalf("expected 2 failed flows, got %d", len(batchErr.Failed))
	}
	if batchErr.Failed[0].Index != 0 || batchErr.Failed[1].Index != 2 {
		t.Errorf("expected failed indexes [0 2], got [%d %d]",
			batchErr.Failed[0].Index, batchErr.Failed[1].Index)
	}

	// Unwrap must expose the per-flow errors for errors.As matching
	var flowErr *BatchFlowError
	if !errors.As(err, &flowErr) {
		t.Error("expected errors.As to match *BatchFlowError through Unwrap")
	}
}

// TestClient_SendFlowMods_BarrierTimeout tests barrier failure handling
func TestClient_SendFlowMods_BarrierTimeout(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()

	server.mu.Lock()
	server.sendBarrierReply = false
	server.mu.Unlock()

	socketDir := filepath.Dir(socketPath)
	client, err := NewClient("test-bridge", WithSocketDir(socketDir), WithTimeout(500*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	flows := []*FlowMod{makeBatchFlow(100, 1, 2)}
	if err := client.SendFlowMods(ctx, flows); !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrTimeout, got %v", err)
	}

	// Batch tracking must be cleaned up after the failed barrier
	client.batchMu.Lock()
	remaining := len(client.batches)
	client.batchMu.Unlock()
	if remaining != 0 {
		t.Errorf("expected 0 tracked batch members, got %d", remaining)
	}
}

// TestBatchErrorTypes tests the batch error type formatting and unwrapping
func TestBatchErrorTypes(t *testing.T) {
	flowErr := &BatchFlowError{
		Index: 3,
		Xid:   17,
		Err:   &OFError{Type: OFPETFlowModFailed, Code: 1},
	}
	if flowErr.Error() != "flow mod 3 (xid 17): flow mod failed: table full" {
		t.Errorf("unexpected error string: %q", flowErr.Error())
	}

	var ofErr *OFError
	if !errors.As(flowErr, &ofErr) {
		t.Error("expected errors.As to match *OFError through Unwrap")
	}

	batchErr := &ErrBatchPartialFailure{Failed: []BatchFlowError{*flowErr}}
	if batchErr.Error() != "flow mod batch partially failed: 1 flow(s) rejected" {
		t.Errorf("unexpected error string: %q", batchErr.Error())
	}
	if !errors.As(batchErr, &ofErr) {
		t.Error("expected errors.As to match *OFError through nested Unwrap")
	}
}
