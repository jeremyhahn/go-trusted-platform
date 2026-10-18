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

//go:build integration

package compute_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// TestComputeMultiProtocol runs all compute VM tests across multiple protocols.
func TestComputeMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []ComputeCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	// The fixture creates, starts and removes the VM the lifecycle-verb case
	// drives, so that case runs on transports that cannot create a VM.
	fixture := NewGRPCAdapter()
	if err := fixture.Setup(ctx); err != nil {
		t.Fatalf("gRPC fixture setup failed: %v", err)
	}
	t.Cleanup(func() {
		if err := fixture.Teardown(ctx); err != nil {
			t.Logf("Warning: fixture teardown failed: %v", err)
		}
	})

	gate := helpers.NewAdapterGate(t, "compute", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown failed: %v", err)
				}
			})

			t.Run("VMLifecycle", func(t *testing.T) { testVMLifecycle(t, ctx, adapter) })
			t.Run("VMGet", func(t *testing.T) { testVMGet(t, ctx, adapter) })
			t.Run("VMList", func(t *testing.T) { testVMList(t, ctx, adapter) })
			t.Run("VMListFiltered", func(t *testing.T) { testVMListFiltered(t, ctx, adapter) })
			t.Run("VMCreateWithLabels", func(t *testing.T) { testVMCreateWithLabels(t, ctx, adapter) })
			t.Run("VMDeleteNotFound", func(t *testing.T) { testVMDeleteNotFound(t, ctx, adapter) })
			t.Run("VMCreateRefusesUnsupportedField", func(t *testing.T) { testVMCreateRefusesUnsupportedField(t, ctx, adapter, fixture) })
			t.Run("VMSuspendResumeReboot", func(t *testing.T) { testVMSuspendResumeReboot(t, ctx, adapter, fixture) })
		})
	}
}

// snapshotAdapter is a transport that carries the VM verbs and the snapshot
// verbs.
type snapshotAdapter interface {
	ComputeCommands
	SnapshotCommands
}

// TestComputeSnapshotsMultiProtocol drives the snapshot verbs on every API
// transport.
func TestComputeSnapshotsMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []snapshotAdapter{
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "compute snapshots", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown failed: %v", err)
				}
			})

			t.Run("VMSnapshots", func(t *testing.T) { testVMSnapshots(t, ctx, adapter) })
		})
	}
}

// testVMSnapshots creates, lists, restores and deletes a snapshot of a
// running VM, then checks a deleted snapshot answers NotFound.
func testVMSnapshots(t *testing.T, ctx context.Context, adapter snapshotAdapter) {
	vmName := generateTestVMName("snap-" + uuid.New().String()[:8])
	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   512,
		DiskSizeGB: 1,
		Firmware:   "bios",
	})
	if err != nil {
		t.Fatalf("CreateVM failed: %v", err)
	}
	vmID := createResult.VMID

	t.Cleanup(func() {
		if _, stopErr := adapter.StopVM(ctx, StopVMOptions{VMID: vmID, Force: true}); stopErr != nil {
			t.Logf("Cleanup: failed to stop VM %s: %v", vmID, stopErr)
		}
		if _, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{VMID: vmID, DeleteDisks: true}); deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	if _, err := adapter.StartVM(ctx, StartVMOptions{VMID: vmID}); err != nil {
		t.Fatalf("StartVM failed: %v", err)
	}

	snapshotName := "snap-" + uuid.New().String()[:8]
	created, err := adapter.CreateSnapshot(ctx, CreateSnapshotOptions{VMID: vmID, Name: snapshotName, Description: "integration"})
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}
	if created.ID != snapshotName || created.VMID != vmID {
		t.Errorf("CreateSnapshot = %+v, want ID %q on VM %q", *created, snapshotName, vmID)
	}

	requireSnapshotListed(t, ctx, adapter, vmID, snapshotName, true)

	snapshot := SnapshotOptions{VMID: vmID, SnapshotID: snapshotName}
	if err := adapter.RestoreSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}
	if err := adapter.DeleteSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("DeleteSnapshot failed: %v", err)
	}

	requireSnapshotListed(t, ctx, adapter, vmID, snapshotName, false)

	err = adapter.DeleteSnapshot(ctx, snapshot)
	if status.Code(err) != codes.NotFound {
		t.Errorf("DeleteSnapshot of a deleted snapshot over %s: got %v, want NotFound", adapter.Name(), err)
	}

	_, err = adapter.ListSnapshots(ctx, "")
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("ListSnapshots without a VM id over %s: got %v, want InvalidArgument", adapter.Name(), err)
	}
}

// requireSnapshotListed fails the test unless the VM's snapshot list does,
// or does not, carry snapshotID.
func requireSnapshotListed(t *testing.T, ctx context.Context, adapter snapshotAdapter, vmID, snapshotID string, want bool) {
	t.Helper()

	snapshots, err := adapter.ListSnapshots(ctx, vmID)
	if err != nil {
		t.Fatalf("ListSnapshots failed: %v", err)
	}
	listed := false
	for _, snapshot := range snapshots {
		if snapshot.ID == snapshotID {
			listed = true
		}
	}
	if listed != want {
		t.Fatalf("ListSnapshots(%s) carries %q = %v, want %v: %+v", vmID, snapshotID, listed, want, snapshots)
	}
}

// attestAdapter is a transport that carries both the VM verbs and the
// attestation verbs.
type attestAdapter interface {
	ComputeCommands
	AttestCommands
}

// TestComputeAttestationMultiProtocol drives the VM attestation verbs
// through every API transport against the real orchestrator.
func TestComputeAttestationMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []attestAdapter{
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "compute attestation", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown failed: %v", err)
				}
			})

			t.Run("VMAttestation", func(t *testing.T) { testVMAttestation(t, ctx, adapter) })
		})
	}
}

// testVMAttestation checks each attestation refusal the orchestrator makes
// before a quote exists reaches the caller with its status code.
func testVMAttestation(t *testing.T, ctx context.Context, adapter attestAdapter) {
	vmName := generateTestVMName("attest-" + uuid.New().String()[:8])
	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   512,
		DiskSizeGB: 1,
		Firmware:   "bios",
		TPM:        true,
	})
	if err != nil {
		t.Fatalf("CreateVM failed: %v", err)
	}
	vmID := createResult.VMID

	t.Cleanup(func() {
		if _, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{VMID: vmID, DeleteDisks: true}); deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	nonce := []byte(uuid.New().String())

	// swtpm runs only while the VM runs, so a stopped VM has no quote.
	_, err = adapter.AttestVM(ctx, AttestVMOptions{VMID: vmID, Nonce: nonce, PCRIndices: []uint32{0, 7}})
	if want := sdkWrongStateCode(adapter.Name()); status.Code(err) != want {
		t.Errorf("AttestVM of a stopped VM over %s: got %v, want %v", adapter.Name(), err, want)
	}

	_, err = adapter.AttestVM(ctx, AttestVMOptions{VMID: "missing-" + uuid.New().String(), Nonce: nonce})
	if status.Code(err) != codes.NotFound {
		t.Errorf("AttestVM of an unknown VM over %s: got %v, want NotFound", adapter.Name(), err)
	}

	_, err = adapter.AttestVM(ctx, AttestVMOptions{Nonce: nonce})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("AttestVM without a VM id over %s: got %v, want InvalidArgument", adapter.Name(), err)
	}

	_, err = adapter.VerifyVMAttestation(ctx, VerifyVMAttestationOptions{
		VMID:    vmID,
		Nonce:   nonce,
		VMQuote: VMQuote{Signature: []byte("signature"), SignatureAlgorithm: "SHA256-RSAPSS"},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("VerifyVMAttestation without a quote over %s: got %v, want InvalidArgument", adapter.Name(), err)
	}
}

// sdkWrongStateCode is the class a VM in the wrong state reaches an SDK
// adapter as. The REST server renders FailedPrecondition as 400, which the
// SDK REST transport reads back as InvalidArgument.
func sdkWrongStateCode(adapter string) codes.Code {
	if adapter == "REST" {
		return codes.InvalidArgument
	}
	return codes.FailedPrecondition
}

// =============================================================================
// Test Suites
// =============================================================================

// testVMLifecycle tests the full VM lifecycle:
// create -> get (verify stopped) -> start -> get (verify running) -> stop ->
// get (verify stopped) -> delete -> get (verify not found).
func testVMLifecycle(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]
	vmName := generateTestVMName("lifecycle-" + testID)

	// Create VM
	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   512,
		DiskSizeGB: 1,
		Firmware:   "uefi",
	})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("CreateVM failed: %v", err)
	}

	if createResult.VMID == "" {
		t.Fatal("CreateVM returned empty VM ID")
	}

	vmID := createResult.VMID

	// Ensure cleanup on test exit
	t.Cleanup(func() {
		_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
			VMID:        vmID,
			DeleteDisks: true,
		})
		if deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	// Get VM - verify stopped
	getResult, err := adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("GetVM after create failed: %v", err)
	}

	if getResult.State != "stopped" {
		t.Errorf("Expected VM state 'stopped' after create, got %q", getResult.State)
	}

	if getResult.Name != vmName {
		t.Errorf("Expected VM name %q, got %q", vmName, getResult.Name)
	}

	// Start VM
	startResult, err := adapter.StartVM(ctx, StartVMOptions{VMID: vmID})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("StartVM failed: %v", err)
	}

	if !startResult.Success {
		t.Errorf("StartVM returned success=false: %s", startResult.Message)
	}

	// Get VM - verify running
	getResult, err = adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		t.Fatalf("GetVM after start failed: %v", err)
	}

	if getResult.State != "running" {
		t.Errorf("Expected VM state 'running' after start, got %q", getResult.State)
	}

	// Stop VM
	stopResult, err := adapter.StopVM(ctx, StopVMOptions{
		VMID:           vmID,
		TimeoutSeconds: 30,
	})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("StopVM failed: %v", err)
	}

	if !stopResult.Success {
		t.Errorf("StopVM returned success=false: %s", stopResult.Message)
	}

	// Get VM - verify stopped
	getResult, err = adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		t.Fatalf("GetVM after stop failed: %v", err)
	}

	if getResult.State != "stopped" {
		t.Errorf("Expected VM state 'stopped' after stop, got %q", getResult.State)
	}

	// Delete VM
	deleteResult, err := adapter.DeleteVM(ctx, DeleteVMOptions{
		VMID:        vmID,
		DeleteDisks: true,
	})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("DeleteVM failed: %v", err)
	}

	if !deleteResult.Success {
		t.Errorf("DeleteVM returned success=false: %s", deleteResult.Message)
	}

	// Get VM - verify not found
	_, err = adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err == nil {
		t.Error("Expected error when getting deleted VM, got nil")
	}
}

// testVMGet tests creating a VM and verifying all returned fields match.
func testVMGet(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]
	vmName := generateTestVMName("get-" + testID)

	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       2,
		MemoryMB:   1024,
		DiskSizeGB: 5,
		Firmware:   "uefi",
	})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("CreateVM failed: %v", err)
	}

	vmID := createResult.VMID
	t.Cleanup(func() {
		_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
			VMID:        vmID,
			DeleteDisks: true,
		})
		if deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	getResult, err := adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("GetVM failed: %v", err)
	}

	if getResult.VMID != vmID {
		t.Errorf("Expected VM ID %q, got %q", vmID, getResult.VMID)
	}

	if getResult.Name != vmName {
		t.Errorf("Expected VM name %q, got %q", vmName, getResult.Name)
	}

	if getResult.CPUs != 2 {
		t.Errorf("Expected 2 CPUs, got %d", getResult.CPUs)
	}

	if getResult.MemoryMB != 1024 {
		t.Errorf("Expected 1024 MB memory, got %d", getResult.MemoryMB)
	}

	if getResult.State != "stopped" {
		t.Errorf("Expected state 'stopped', got %q", getResult.State)
	}
}

// testVMList tests creating multiple VMs and verifying list results.
func testVMList(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]

	vmIDs := make([]string, 0, 2)

	// Create 2 VMs
	for i := range 2 {
		vmName := generateTestVMName("list-" + testID + "-" + string(rune('a'+i)))
		result, err := adapter.CreateVM(ctx, CreateVMOptions{
			Name:       vmName,
			CPUs:       1,
			MemoryMB:   256,
			DiskSizeGB: 1,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateVM[%d] failed: %v", i, err)
		}
		vmIDs = append(vmIDs, result.VMID)
	}

	// Cleanup all created VMs
	t.Cleanup(func() {
		for _, id := range vmIDs {
			_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
				VMID:        id,
				DeleteDisks: true,
			})
			if deleteErr != nil {
				t.Logf("Cleanup: failed to delete VM %s: %v", id, deleteErr)
			}
		}
	})

	// List all VMs
	listResult, err := adapter.ListVMs(ctx, ListVMsOptions{})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("ListVMs failed: %v", err)
	}

	if len(listResult.VMs) < 2 {
		t.Errorf("Expected at least 2 VMs in list, got %d", len(listResult.VMs))
	}

	// Verify our created VMs appear in the list
	foundCount := 0
	for _, vm := range listResult.VMs {
		for _, id := range vmIDs {
			if vm.VMID == id {
				foundCount++
			}
		}
	}

	if foundCount != len(vmIDs) {
		t.Errorf("Expected to find %d test VMs in list, found %d", len(vmIDs), foundCount)
	}
}

// testVMListFiltered tests listing VMs with label-based filtering.
func testVMListFiltered(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]
	filterLabel := "test-filter-" + testID

	// Create a VM with a unique label
	vmName := generateTestVMName("filtered-" + testID)
	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   256,
		DiskSizeGB: 1,
		Labels: map[string]string{
			"env":     filterLabel,
			"purpose": "filter-test",
		},
	})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("CreateVM failed: %v", err)
	}

	vmID := createResult.VMID
	t.Cleanup(func() {
		_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
			VMID:        vmID,
			DeleteDisks: true,
		})
		if deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	// List with matching label
	listResult, err := adapter.ListVMs(ctx, ListVMsOptions{
		Labels: map[string]string{
			"env": filterLabel,
		},
	})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("ListVMs with filter failed: %v", err)
	}

	if len(listResult.VMs) < 1 {
		t.Fatalf("Expected at least 1 VM with label env=%s, got %d", filterLabel, len(listResult.VMs))
	}

	// Verify our VM is in the result
	found := false
	for _, vm := range listResult.VMs {
		if vm.VMID == vmID {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected to find VM %s in filtered list", vmID)
	}
}

// testVMCreateWithLabels tests creating a VM with labels and verifying them.
func testVMCreateWithLabels(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]
	vmName := generateTestVMName("labels-" + testID)

	labels := map[string]string{
		"env":     "test",
		"team":    "platform",
		"purpose": "integration-" + testID,
	}

	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   256,
		DiskSizeGB: 1,
		Labels:     labels,
	})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("CreateVM with labels failed: %v", err)
	}

	vmID := createResult.VMID
	t.Cleanup(func() {
		_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
			VMID:        vmID,
			DeleteDisks: true,
		})
		if deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	// Retrieve VM and verify labels
	getResult, err := adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		surface.RequireImplemented(t, err)
		t.Fatalf("GetVM failed: %v", err)
	}

	for key, expectedVal := range labels {
		actualVal, ok := getResult.Labels[key]
		if !ok {
			t.Errorf("Expected label %q not found on VM", key)
			continue
		}
		if actualVal != expectedVal {
			t.Errorf("Label %q: expected %q, got %q", key, expectedVal, actualVal)
		}
	}
}

// testVMDeleteNotFound tests deleting a non-existent VM and expecting an error.
func testVMDeleteNotFound(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	fakeID := "nonexistent-vm-" + uuid.New().String()[:8]

	_, err := adapter.DeleteVM(ctx, DeleteVMOptions{
		VMID:        fakeID,
		DeleteDisks: true,
	})
	if err == nil {
		t.Error("Expected error when deleting non-existent VM, got nil")
		return
	}

	surface.RequireImplemented(t, err)

	// The operation should have returned an error; we just verify it did
	t.Logf("Delete non-existent VM returned expected error: %v", err)
}

// errorClass reports whether err is the error class a transport answers a
// failed request with.
type errorClass func(err error) bool

// wrongStateClasses maps each adapter to its wrong-state error class. gRPC,
// Unix, QUIC and MCP carry the FailedPrecondition code (the SDK MCP transport
// turns the JSON-RPC code of that class back into it), REST answers 400 and
// the CLI exits non-zero with the gRPC code in its output.
var wrongStateClasses = map[string]errorClass{
	"gRPC": isFailedPrecondition,
	"Unix": isFailedPrecondition,
	"QUIC": isFailedPrecondition,
	"MCP":  isFailedPrecondition,
	"REST": func(err error) bool {
		var restErr ErrRESTRequestFailed
		return errors.As(err, &restErr) && restErr.StatusCode == http.StatusBadRequest
	},
	"CLI": func(err error) bool {
		var cliErr ErrCLIExecution
		return errors.As(err, &cliErr) && strings.Contains(cliErr.Output, "code = "+codes.FailedPrecondition.String())
	},
}

func isFailedPrecondition(err error) bool {
	return status.Code(err) == codes.FailedPrecondition
}

// refusedFieldClasses maps each adapter to the error class CreateVM answers a
// config field the backend cannot honour with. gRPC, Unix, QUIC and MCP carry
// the InvalidArgument code, REST answers 400 and the CLI exits non-zero with
// the gRPC code in its output.
var refusedFieldClasses = map[string]errorClass{
	"gRPC": isInvalidArgument,
	"Unix": isInvalidArgument,
	"QUIC": isInvalidArgument,
	"MCP":  isInvalidArgument,
	"REST": func(err error) bool {
		var restErr ErrRESTRequestFailed
		return errors.As(err, &restErr) && restErr.StatusCode == http.StatusBadRequest
	},
	"CLI": func(err error) bool {
		var cliErr ErrCLIExecution
		return errors.As(err, &cliErr) && strings.Contains(cliErr.Output, "code = "+codes.InvalidArgument.String())
	},
}

func isInvalidArgument(err error) bool {
	return status.Code(err) == codes.InvalidArgument
}

// testVMCreateRefusesUnsupportedField asks for BIOS firmware, which the
// local-qemu backend cannot boot: the request fails with the transport's
// refused-field class and leaves no VM behind.
func testVMCreateRefusesUnsupportedField(t *testing.T, ctx context.Context, adapter ComputeCommands, fixture *GRPCAdapter) {
	isRefused, ok := refusedFieldClasses[adapter.Name()]
	if !ok {
		t.Fatalf("no refused-field error class for adapter %s", adapter.Name())
	}

	vmName := generateTestVMName("refused-" + uuid.New().String()[:8])
	_, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   256,
		DiskSizeGB: 1,
		Firmware:   "bios",
	})
	if err == nil {
		t.Fatalf("CreateVM with BIOS firmware over %s succeeded, want a refusal", adapter.Name())
	}
	if !isRefused(err) {
		t.Errorf("CreateVM with BIOS firmware over %s: got %v, want the transport's refused-field class", adapter.Name(), err)
	}

	listResult, err := fixture.ListVMs(ctx, ListVMsOptions{})
	if err != nil {
		t.Fatalf("fixture ListVMs failed: %v", err)
	}
	for _, vm := range listResult.VMs {
		if vm.Name == vmName {
			t.Errorf("refused CreateVM over %s left VM %s (%s) behind", adapter.Name(), vm.Name, vm.VMID)
		}
	}
}

// testVMSuspendResumeReboot drives suspend, resume and reboot through the
// adapter on a VM the fixture created and started: suspend shows paused,
// resume and reboot show running, and resuming a running VM answers the
// transport's wrong-state error class.
func testVMSuspendResumeReboot(t *testing.T, ctx context.Context, adapter ComputeCommands, fixture *GRPCAdapter) {
	isWrongState, ok := wrongStateClasses[adapter.Name()]
	if !ok {
		t.Fatalf("no wrong-state error class for adapter %s", adapter.Name())
	}

	vmName := generateTestVMName("verbs-" + uuid.New().String()[:8])
	createResult, err := fixture.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   512,
		DiskSizeGB: 1,
		Firmware:   "uefi",
	})
	if err != nil {
		t.Fatalf("fixture CreateVM failed: %v", err)
	}
	vmID := createResult.VMID

	t.Cleanup(func() {
		if _, stopErr := fixture.StopVM(ctx, StopVMOptions{VMID: vmID, Force: true}); stopErr != nil {
			t.Logf("Cleanup: failed to stop VM %s: %v", vmID, stopErr)
		}
		if _, deleteErr := fixture.DeleteVM(ctx, DeleteVMOptions{VMID: vmID, DeleteDisks: true}); deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	if _, err := fixture.StartVM(ctx, StartVMOptions{VMID: vmID}); err != nil {
		t.Fatalf("fixture StartVM failed: %v", err)
	}

	suspendResult, err := adapter.SuspendVM(ctx, SuspendVMOptions{VMID: vmID})
	if err != nil {
		t.Fatalf("SuspendVM failed: %v", err)
	}
	if !suspendResult.Success {
		t.Errorf("SuspendVM returned success=false: %s", suspendResult.Message)
	}
	requireVMState(t, ctx, adapter, vmID, "paused")

	resumeResult, err := adapter.ResumeVM(ctx, ResumeVMOptions{VMID: vmID})
	if err != nil {
		t.Fatalf("ResumeVM failed: %v", err)
	}
	if !resumeResult.Success {
		t.Errorf("ResumeVM returned success=false: %s", resumeResult.Message)
	}
	requireVMState(t, ctx, adapter, vmID, "running")

	rebootResult, err := adapter.RebootVM(ctx, RebootVMOptions{VMID: vmID})
	if err != nil {
		t.Fatalf("RebootVM failed: %v", err)
	}
	if !rebootResult.Success {
		t.Errorf("RebootVM returned success=false: %s", rebootResult.Message)
	}
	requireVMState(t, ctx, adapter, vmID, "running")

	_, err = adapter.ResumeVM(ctx, ResumeVMOptions{VMID: vmID})
	if err == nil {
		t.Fatal("ResumeVM of a running VM succeeded, want a wrong-state error")
	}
	if !isWrongState(err) {
		t.Errorf("ResumeVM of a running VM over %s: got %v, want the transport's wrong-state class", adapter.Name(), err)
	}
}

// requireVMState reads the VM through the adapter and fails unless it is in
// the wanted state.
func requireVMState(t *testing.T, ctx context.Context, adapter ComputeCommands, vmID, want string) {
	t.Helper()

	getResult, err := adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		t.Fatalf("GetVM over %s failed: %v", adapter.Name(), err)
	}
	if getResult.State != want {
		t.Fatalf("VM state over %s: got %q, want %q", adapter.Name(), getResult.State, want)
	}
}
