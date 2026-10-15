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

package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

// vmToolNames is the authoritative list of VM lifecycle, snapshot and
// attestation tool names. Registration, routing, and this list must all agree.
var vmToolNames = []string{
	"vm_create",
	"vm_list",
	"vm_get",
	"vm_delete",
	"vm_start",
	"vm_stop",
	"vm_reboot",
	"vm_snapshot_create",
	"vm_snapshot_get",
	"vm_snapshot_list",
	"vm_snapshot_delete",
	"vm_snapshot_restore",
	"vm_attest",
	"vm_attest_verify",
}

// vmStubProvider satisfies VMProvider for tests, capturing the arguments
// each method receives.
type vmStubProvider struct {
	lastCall       string
	lastVMID       string
	lastSnapshotID string
	lastNonce      []byte
	lastPCRs       []int
	lastVerifyReq  *VMAttestVerifyMCPRequest

	snapshotCreateFunc func(ctx context.Context, vmID, name string) (interface{}, error)
	attestFunc         func(ctx context.Context, vmID string, nonce []byte, pcrs []int) (interface{}, error)
	verifyFunc         func(ctx context.Context, vmID string, req *VMAttestVerifyMCPRequest) (interface{}, error)
	snapshotErr        error
}

func (s *vmStubProvider) VMSnapshotCreate(ctx context.Context, vmID, name string) (interface{}, error) {
	s.lastCall = "snapshot_create"
	s.lastVMID = vmID
	s.lastSnapshotID = name
	if s.snapshotCreateFunc != nil {
		return s.snapshotCreateFunc(ctx, vmID, name)
	}
	return map[string]interface{}{"name": name, "vm_id": vmID}, nil
}

func (s *vmStubProvider) VMSnapshotGet(ctx context.Context, vmID, snapshotID string) (interface{}, error) {
	s.lastCall = "snapshot_get"
	s.lastVMID = vmID
	s.lastSnapshotID = snapshotID
	if s.snapshotErr != nil {
		return nil, s.snapshotErr
	}
	return map[string]interface{}{"name": snapshotID, "vm_id": vmID}, nil
}

func (s *vmStubProvider) VMSnapshotList(ctx context.Context, vmID string) (interface{}, error) {
	s.lastCall = "snapshot_list"
	s.lastVMID = vmID
	if s.snapshotErr != nil {
		return nil, s.snapshotErr
	}
	return map[string]interface{}{"vm_id": vmID, "snapshots": []interface{}{}, "count": 0}, nil
}

func (s *vmStubProvider) VMSnapshotDelete(ctx context.Context, vmID, snapshotID string) error {
	s.lastCall = "snapshot_delete"
	s.lastVMID = vmID
	s.lastSnapshotID = snapshotID
	return s.snapshotErr
}

func (s *vmStubProvider) VMSnapshotRestore(ctx context.Context, vmID, snapshotID string) error {
	s.lastCall = "snapshot_restore"
	s.lastVMID = vmID
	s.lastSnapshotID = snapshotID
	return s.snapshotErr
}

func (s *vmStubProvider) VMAttest(ctx context.Context, vmID string, nonce []byte, pcrs []int) (interface{}, error) {
	s.lastCall = "attest"
	s.lastVMID = vmID
	s.lastNonce = nonce
	s.lastPCRs = pcrs
	if s.attestFunc != nil {
		return s.attestFunc(ctx, vmID, nonce, pcrs)
	}
	return map[string]interface{}{"vm_id": vmID, "quote": "cXVvdGU="}, nil
}

func (s *vmStubProvider) VMAttestVerify(ctx context.Context, vmID string, req *VMAttestVerifyMCPRequest) (interface{}, error) {
	s.lastCall = "attest_verify"
	s.lastVMID = vmID
	s.lastVerifyReq = req
	if s.verifyFunc != nil {
		return s.verifyFunc(ctx, vmID, req)
	}
	return map[string]interface{}{"vm_id": vmID, "verified": true}, nil
}

// vmCombinedProvider embeds both mockServiceProvider (satisfies the full
// ServiceProvider interface) and vmStubProvider (satisfies VMProvider) so
// the registry routes vm snapshot/attestation tools through the
// optional-interface path.
type vmCombinedProvider struct {
	*mockServiceProvider
	*vmStubProvider
}

// Compile-time assertions.
var (
	_ ServiceProvider = (*vmCombinedProvider)(nil)
	_ VMProvider      = (*vmCombinedProvider)(nil)
	_ VMProvider      = (*vmStubProvider)(nil)
)

func newVMRegistry() (*ToolRegistry, *vmStubProvider) {
	stub := &vmStubProvider{}
	svc := &vmCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		vmStubProvider:      stub,
	}
	return NewToolRegistry(svc, newTestLogger()), stub
}

// =============================================================================
// Registration <-> routing parity
// =============================================================================

// TestVMToolRegistrationAndRoutingParity guards against the bug class where
// a tool is registered but never routed. It asserts that:
//  1. every expected VM lifecycle/snapshot/attestation tool is registered,
//  2. the dispatch map keys and the expected name list are identical, and
//  3. ExecuteTool actually routes every tool to the VM executor (a provider
//     without the VM interfaces yields ErrVMComputeNotConfigured, never
//     "unknown tool").
func TestVMToolRegistrationAndRoutingParity(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	registered := make(map[string]bool)
	for _, tool := range registry.ListTools() {
		registered[tool.Name] = true
	}
	expected := make(map[string]bool, len(vmToolNames))
	for _, name := range vmToolNames {
		expected[name] = true
		if !registered[name] {
			t.Errorf("expected tool %q is not registered", name)
		}
		if _, ok := vmToolDispatch[name]; !ok {
			t.Errorf("expected tool %q has no executor in vmToolDispatch", name)
		}
	}
	for name := range vmToolDispatch {
		if !expected[name] {
			t.Errorf("dispatch map routes %q but it is not in vmToolNames", name)
		}
	}

	for _, name := range vmToolNames {
		if _, err := registry.ExecuteTool(ctx, name, map[string]interface{}{}); !errors.Is(err, ErrVMComputeNotConfigured) {
			t.Errorf("ExecuteTool(%q) without provider: err = %v, want ErrVMComputeNotConfigured", name, err)
		}
	}
}

// =============================================================================
// Snapshot tools
// =============================================================================

func TestExecuteVMSnapshotCreate(t *testing.T) {
	ctx := context.Background()
	registry, stub := newVMRegistry()

	result, err := registry.ExecuteTool(ctx, "vm_snapshot_create", map[string]interface{}{
		"vm_id": "vm1",
		"name":  "snap1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if stub.lastCall != "snapshot_create" || stub.lastVMID != "vm1" || stub.lastSnapshotID != "snap1" {
		t.Errorf("provider call mismatch: %+v", stub)
	}
}

func TestExecuteVMSnapshotCreate_MissingArgs(t *testing.T) {
	ctx := context.Background()
	registry, _ := newVMRegistry()

	if _, err := registry.ExecuteTool(ctx, "vm_snapshot_create", map[string]interface{}{"name": "snap1"}); !errors.Is(err, ErrVMIDRequired) {
		t.Errorf("missing vm_id: err = %v, want ErrVMIDRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "vm_snapshot_create", map[string]interface{}{"vm_id": "vm1"}); !errors.Is(err, ErrSnapshotNameRequired) {
		t.Errorf("missing name: err = %v, want ErrSnapshotNameRequired", err)
	}
}

func TestExecuteVMSnapshotLifecycle(t *testing.T) {
	ctx := context.Background()
	registry, stub := newVMRegistry()

	args := map[string]interface{}{"vm_id": "vm1", "snapshot_id": "snap1"}

	if _, err := registry.ExecuteTool(ctx, "vm_snapshot_get", args); err != nil {
		t.Fatalf("get: %v", err)
	}
	if stub.lastCall != "snapshot_get" {
		t.Errorf("expected snapshot_get, got %s", stub.lastCall)
	}

	if _, err := registry.ExecuteTool(ctx, "vm_snapshot_list", map[string]interface{}{"vm_id": "vm1"}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if stub.lastCall != "snapshot_list" {
		t.Errorf("expected snapshot_list, got %s", stub.lastCall)
	}

	result, err := registry.ExecuteTool(ctx, "vm_snapshot_delete", args)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if stub.lastCall != "snapshot_delete" {
		t.Errorf("expected snapshot_delete, got %s", stub.lastCall)
	}
	if m, ok := result.(map[string]interface{}); !ok || m["success"] != true {
		t.Errorf("delete result = %v, want success map", result)
	}

	if _, err := registry.ExecuteTool(ctx, "vm_snapshot_restore", args); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if stub.lastCall != "snapshot_restore" {
		t.Errorf("expected snapshot_restore, got %s", stub.lastCall)
	}
}

func TestExecuteVMSnapshotLifecycle_MissingSnapshotID(t *testing.T) {
	ctx := context.Background()
	registry, _ := newVMRegistry()

	for _, tool := range []string{"vm_snapshot_get", "vm_snapshot_delete", "vm_snapshot_restore"} {
		if _, err := registry.ExecuteTool(ctx, tool, map[string]interface{}{"vm_id": "vm1"}); !errors.Is(err, ErrSnapshotIDRequired) {
			t.Errorf("%s missing snapshot_id: err = %v, want ErrSnapshotIDRequired", tool, err)
		}
	}
}

func TestExecuteVMSnapshot_ProviderError(t *testing.T) {
	ctx := context.Background()
	registry, stub := newVMRegistry()

	providerErr := errors.New("snapshot backend failure")
	stub.snapshotErr = providerErr

	if _, err := registry.ExecuteTool(ctx, "vm_snapshot_delete", map[string]interface{}{
		"vm_id":       "vm1",
		"snapshot_id": "snap1",
	}); !errors.Is(err, providerErr) {
		t.Errorf("provider error not propagated: %v", err)
	}
}

// =============================================================================
// Attestation tools
// =============================================================================

func TestExecuteVMAttest(t *testing.T) {
	ctx := context.Background()
	registry, stub := newVMRegistry()

	nonce := []byte("attest-nonce")
	result, err := registry.ExecuteTool(ctx, "vm_attest", map[string]interface{}{
		"vm_id":        "vm1",
		"nonce":        base64.StdEncoding.EncodeToString(nonce),
		"include_pcrs": []interface{}{float64(0), float64(7)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if stub.lastCall != "attest" || stub.lastVMID != "vm1" {
		t.Errorf("provider call mismatch: %+v", stub)
	}
	if string(stub.lastNonce) != string(nonce) {
		t.Errorf("nonce = %q, want %q", stub.lastNonce, nonce)
	}
	if len(stub.lastPCRs) != 2 || stub.lastPCRs[0] != 0 || stub.lastPCRs[1] != 7 {
		t.Errorf("pcrs = %v, want [0 7]", stub.lastPCRs)
	}
}

func TestExecuteVMAttest_InvalidArgs(t *testing.T) {
	ctx := context.Background()
	registry, _ := newVMRegistry()

	if _, err := registry.ExecuteTool(ctx, "vm_attest", map[string]interface{}{}); !errors.Is(err, ErrVMIDRequired) {
		t.Errorf("missing vm_id: err = %v, want ErrVMIDRequired", err)
	}

	_, err := registry.ExecuteTool(ctx, "vm_attest", map[string]interface{}{
		"vm_id": "vm1",
		"nonce": "not-base64!!!",
	})
	var nonceErr ErrVMInvalidNonce
	if !errors.As(err, &nonceErr) {
		t.Errorf("invalid nonce: err = %v, want ErrVMInvalidNonce", err)
	}
}

func TestExecuteVMAttestVerify(t *testing.T) {
	ctx := context.Background()
	registry, stub := newVMRegistry()

	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

	result, err := registry.ExecuteTool(ctx, "vm_attest_verify", map[string]interface{}{
		"vm_id":               "vm1",
		"quote":               b64([]byte("quote")),
		"signature":           b64([]byte("signature")),
		"signature_algorithm": "SHA256-RSAPSS",
		"nonce":               b64([]byte("nonce")),
		"expected_pcrs": map[string]interface{}{
			"0": b64([]byte{0x01}),
			"7": b64([]byte{0x07}),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if stub.lastCall != "attest_verify" {
		t.Errorf("expected attest_verify, got %s", stub.lastCall)
	}
	req := stub.lastVerifyReq
	if req == nil {
		t.Fatal("expected verify request")
	}
	if string(req.Quote) != "quote" || string(req.Signature) != "signature" || string(req.Nonce) != "nonce" {
		t.Errorf("evidence mismatch: %+v", req)
	}
	if req.SignatureAlgorithm != "SHA256-RSAPSS" {
		t.Errorf("expected the declared scheme SHA256-RSAPSS, got %q", req.SignatureAlgorithm)
	}
	if len(req.ExpectedPCRs) != 2 || req.ExpectedPCRs[0][0] != 0x01 || req.ExpectedPCRs[7][0] != 0x07 {
		t.Errorf("expected PCRs mismatch: %v", req.ExpectedPCRs)
	}
}

func TestExecuteVMAttestVerify_InvalidEvidence(t *testing.T) {
	ctx := context.Background()
	registry, _ := newVMRegistry()

	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

	tests := []struct {
		name string
		args map[string]interface{}
	}{
		{"missing quote", map[string]interface{}{
			"vm_id": "vm1", "signature": b64([]byte("s")), "nonce": b64([]byte("n")),
		}},
		{"missing signature", map[string]interface{}{
			"vm_id": "vm1", "quote": b64([]byte("q")), "nonce": b64([]byte("n")),
		}},
		{"missing nonce", map[string]interface{}{
			"vm_id": "vm1", "quote": b64([]byte("q")), "signature": b64([]byte("s")),
		}},
		{"invalid quote encoding", map[string]interface{}{
			"vm_id": "vm1", "quote": "!!!", "signature": b64([]byte("s")), "nonce": b64([]byte("n")),
		}},
		{"invalid expected pcr key", map[string]interface{}{
			"vm_id": "vm1", "quote": b64([]byte("q")), "signature": b64([]byte("s")), "nonce": b64([]byte("n")),
			"expected_pcrs": map[string]interface{}{"abc": b64([]byte{0x01})},
		}},
		{"invalid expected pcr value", map[string]interface{}{
			"vm_id": "vm1", "quote": b64([]byte("q")), "signature": b64([]byte("s")), "nonce": b64([]byte("n")),
			"expected_pcrs": map[string]interface{}{"0": "!!!"},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, "vm_attest_verify", tt.args)
			var evidenceErr ErrVMInvalidEvidence
			if !errors.As(err, &evidenceErr) {
				t.Errorf("err = %v, want ErrVMInvalidEvidence", err)
			}
		})
	}
}
