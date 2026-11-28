package openflow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A switch that answers a single flow mod with OFPT_ERROR and then the
// barrier reply has refused the flow: AddFlow must return that error rather
// than report the barrier's success (Codex #2021 round 1).
func TestClient_AddFlow_ReturnsTheSwitchRejection(t *testing.T) {
	server, socketPath := newMockOFServer(t)
	defer server.close()
	server.failFlowModAt(OFPETFlowModFailed, 1, 0)

	client, err := NewClient("test-bridge", WithSocketDir(filepath.Dir(socketPath)), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect() }()

	err = client.AddFlow(ctx, makeBatchFlow(100, 1, 2))
	var ofErr *OFError
	if !errors.As(err, &ofErr) {
		t.Fatalf("AddFlow = %v, want the switch's *OFError", err)
	}
	if ofErr.Type != OFPETFlowModFailed || ofErr.Code != 1 {
		t.Errorf("OFError type=%d code=%d, want %d/1", ofErr.Type, ofErr.Code, OFPETFlowModFailed)
	}
	if barriers := server.getReceivedBarriers(); barriers != 1 {
		t.Errorf("barriers = %d, want 1", barriers)
	}
}
