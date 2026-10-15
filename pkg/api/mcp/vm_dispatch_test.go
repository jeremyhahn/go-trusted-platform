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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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
	"vm_suspend",
	"vm_resume",
	"vm_snapshot_create",
	"vm_snapshot_get",
	"vm_snapshot_list",
	"vm_snapshot_delete",
	"vm_snapshot_restore",
	"vm_attest",
	"vm_attest_verify",
}

// vmStubProvider satisfies VMProvider for tests, capturing the arguments
// and requests each method receives.
type vmStubProvider struct {
	lastCall       string
	lastVMID       string
	lastSnapshotID string
	lastCreateReq  *platformv1.CreateSnapshotRequest
	lastAttestReq  *platformv1.AttestVMRequest
	lastVerifyReq  *platformv1.VerifyVMAttestationRequest
	snapshotErr    error
}

func (s *vmStubProvider) VMSnapshotCreate(_ context.Context, req *platformv1.CreateSnapshotRequest) (interface{}, error) {
	s.lastCall = "snapshot_create"
	s.lastCreateReq = req
	return &platformv1.CreateSnapshotResponse{}, nil
}

func (s *vmStubProvider) VMSnapshotGet(_ context.Context, vmID, snapshotID string) (interface{}, error) {
	return s.recordByID("snapshot_get", vmID, snapshotID)
}

func (s *vmStubProvider) VMSnapshotList(_ context.Context, vmID string) (interface{}, error) {
	return s.recordByID("snapshot_list", vmID, "")
}

func (s *vmStubProvider) VMSnapshotDelete(_ context.Context, vmID, snapshotID string) (interface{}, error) {
	return s.recordByID("snapshot_delete", vmID, snapshotID)
}

func (s *vmStubProvider) VMSnapshotRestore(_ context.Context, vmID, snapshotID string) (interface{}, error) {
	return s.recordByID("snapshot_restore", vmID, snapshotID)
}

// recordByID records a snapshot verb addressed by ids and answers with the
// configured error, or a reply naming the call.
func (s *vmStubProvider) recordByID(call, vmID, snapshotID string) (interface{}, error) {
	s.lastCall = call
	s.lastVMID = vmID
	s.lastSnapshotID = snapshotID
	if s.snapshotErr != nil {
		return nil, s.snapshotErr
	}
	return map[string]interface{}{"call": call}, nil
}

func (s *vmStubProvider) VMAttest(_ context.Context, req *platformv1.AttestVMRequest) (interface{}, error) {
	s.lastCall = "attest"
	s.lastAttestReq = req
	return &platformv1.AttestVMResponse{}, nil
}

func (s *vmStubProvider) VMAttestVerify(_ context.Context, req *platformv1.VerifyVMAttestationRequest) (interface{}, error) {
	s.lastCall = "attest_verify"
	s.lastVerifyReq = req
	return &platformv1.VerifyVMAttestationResponse{}, nil
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
//  2. each expected tool is routed by exactly one of the dispatch map and
//     the gRPC-bound lifecycle map, and neither routes an unlisted tool, and
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
		_, executed := vmToolDispatch[name]
		_, bound := vmLifecycleTools[name]
		if executed == bound {
			t.Errorf("expected tool %q must be routed by exactly one of vmToolDispatch and vmLifecycleTools", name)
		}
	}
	for name := range vmToolDispatch {
		if !expected[name] {
			t.Errorf("dispatch map routes %q but it is not in vmToolNames", name)
		}
	}
	for name := range vmLifecycleTools {
		if !expected[name] {
			t.Errorf("vmLifecycleTools binds %q but it is not in vmToolNames", name)
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
		"vm_id":           "vm1",
		"name":            "snap1",
		"description":     "nightly",
		"memory_snapshot": true,
		"disk_snapshot":   true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	want := &platformv1.CreateSnapshotRequest{
		VmId: "vm1",
		Config: &platformv1.SnapshotConfig{
			Name: "snap1", Description: "nightly", MemorySnapshot: true, DiskSnapshot: true,
		},
	}
	if stub.lastCall != "snapshot_create" || !proto.Equal(stub.lastCreateReq, want) {
		t.Errorf("CreateSnapshot request = %v, want %v", stub.lastCreateReq, want)
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

// TestExecuteVMSnapshotLifecycle: each by-id verb reaches its provider method
// with both ids, and the provider's reply is the tool's reply.
func TestExecuteVMSnapshotLifecycle(t *testing.T) {
	ctx := context.Background()
	registry, stub := newVMRegistry()

	args := map[string]interface{}{"vm_id": "vm1", "snapshot_id": "snap1"}
	for _, tc := range []struct{ tool, call string }{
		{"vm_snapshot_get", "snapshot_get"},
		{"vm_snapshot_delete", "snapshot_delete"},
		{"vm_snapshot_restore", "snapshot_restore"},
	} {
		result, err := registry.ExecuteTool(ctx, tc.tool, args)
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		if stub.lastCall != tc.call || stub.lastVMID != "vm1" || stub.lastSnapshotID != "snap1" {
			t.Errorf("%s: provider saw %s(%q, %q)", tc.tool, stub.lastCall, stub.lastVMID, stub.lastSnapshotID)
		}
		if m, ok := result.(map[string]interface{}); !ok || m["call"] != tc.call {
			t.Errorf("%s: result = %v, want the provider's reply", tc.tool, result)
		}
	}

	if _, err := registry.ExecuteTool(ctx, "vm_snapshot_list", map[string]interface{}{"vm_id": "vm1"}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if stub.lastCall != "snapshot_list" || stub.lastVMID != "vm1" {
		t.Errorf("list: provider saw %s(%q)", stub.lastCall, stub.lastVMID)
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
	want := &platformv1.AttestVMRequest{VmId: "vm1", Nonce: nonce, PcrIndices: []uint32{0, 7}}
	if stub.lastCall != "attest" || !proto.Equal(stub.lastAttestReq, want) {
		t.Errorf("AttestVM request = %v, want %v", stub.lastAttestReq, want)
	}
}

func TestExecuteVMAttest_InvalidArgs(t *testing.T) {
	ctx := context.Background()
	registry, stub := newVMRegistry()

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

	_, err = registry.ExecuteTool(ctx, "vm_attest", map[string]interface{}{
		"vm_id":        "vm1",
		"include_pcrs": []interface{}{float64(-1)},
	})
	var pcrErr ErrVMInvalidPCRIndex
	if !errors.As(err, &pcrErr) || pcrErr.Index != -1 {
		t.Errorf("negative PCR: err = %v, want ErrVMInvalidPCRIndex{-1}", err)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("negative PCR: code = %v, want InvalidArgument", status.Code(err))
	}
	if stub.lastAttestReq != nil {
		t.Errorf("an invalid request reached the provider: %v", stub.lastAttestReq)
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
	want := &platformv1.VerifyVMAttestationRequest{
		VmId:               "vm1",
		Quote:              []byte("quote"),
		Signature:          []byte("signature"),
		SignatureAlgorithm: "SHA256-RSAPSS",
		Nonce:              []byte("nonce"),
		ExpectedPcrs: []*platformv1.PCRValue{
			{Index: 0, Bank: platformv1.PCRBank_PCR_BANK_SHA256, Value: []byte{0x01}},
			{Index: 7, Bank: platformv1.PCRBank_PCR_BANK_SHA256, Value: []byte{0x07}},
		},
	}
	if !proto.Equal(stub.lastVerifyReq, want) {
		t.Errorf("VerifyVMAttestation request = %v, want %v", stub.lastVerifyReq, want)
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
