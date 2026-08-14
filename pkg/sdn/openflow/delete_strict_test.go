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
	"path/filepath"
	"testing"
)

// TestClient_DeleteFlowStrict tests strict flow deletion with a cookie
// restriction. The mock server processes messages sequentially on one
// connection, so once the barrier inside DeleteFlowStrict returns, the flow
// mod has been received — no sleeping required.
func TestClient_DeleteFlowStrict(t *testing.T) {
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
	defer func() {
		if err := client.Disconnect(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	flow := NewFlowMod(0)
	flow.TableID = 10
	flow.Priority = 2
	flow.Cookie = 0xF1BE000100000000
	flow.CookieMask = ^uint64(0)

	if err := client.DeleteFlowStrict(ctx, flow); err != nil {
		t.Fatalf("failed to delete flow strict: %v", err)
	}

	flowMods := server.getReceivedFlowMods()
	if len(flowMods) == 0 {
		t.Fatal("no flow mods received by server")
	}
	got := flowMods[0]
	if got.Command != OFPFCDeleteStrict {
		t.Errorf("expected delete-strict command %d, got %d", OFPFCDeleteStrict, got.Command)
	}
	if got.TableID != 10 {
		t.Errorf("expected table 10, got %d", got.TableID)
	}
	if got.Priority != 2 {
		t.Errorf("expected priority 2, got %d", got.Priority)
	}
	if got.Cookie != 0xF1BE000100000000 {
		t.Errorf("expected cookie 0xF1BE000100000000, got 0x%x", got.Cookie)
	}
	if got.CookieMask != ^uint64(0) {
		t.Errorf("expected full cookie mask, got 0x%x", got.CookieMask)
	}
}

// TestClient_DeleteFlowStrict_NotConnected tests the disconnected error path.
func TestClient_DeleteFlowStrict_NotConnected(t *testing.T) {
	client, err := NewClient("test-bridge")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	flow := NewFlowMod(0)
	if err := client.DeleteFlowStrict(context.Background(), flow); err != ErrNotConnected {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}
