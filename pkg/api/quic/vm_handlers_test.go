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

//go:build codec_msgpack

package quic

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock VM Orchestrator
// =============================================================================

// mockVMOrchestrator implements VMOrchestrator for testing
type mockVMOrchestrator struct {
	instances          map[string]*compute.Instance
	createError        error
	deleteError        error
	startError         error
	stopError          error
	getError           error
	listError          error
	attachNetworkError error
	detachNetworkError error
	getStateError      error
}

func newMockVMOrchestrator() *mockVMOrchestrator {
	return &mockVMOrchestrator{
		instances: make(map[string]*compute.Instance),
	}
}

func (m *mockVMOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	if m.createError != nil {
		return nil, m.createError
	}

	inst := &compute.Instance{
		ID:        "test-vm-id",
		Name:      profile.Name,
		Type:      compute.ComputeTypeVM,
		State:     compute.StateStopped,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Config: &compute.InstanceConfig{
			Memory:     4096,
			CPUs:       2,
			DiskSize:   "20G",
			TPMEnabled: true,
		},
		Metadata: map[string]string{"env": "test"},
	}

	m.instances[inst.ID] = inst
	return inst, nil
}

func (m *mockVMOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if m.deleteError != nil {
		return m.deleteError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}

	delete(m.instances, instanceID)
	return nil
}

func (m *mockVMOrchestrator) Start(ctx context.Context, instanceID string) error {
	if m.startError != nil {
		return m.startError
	}

	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}

	inst.State = compute.StateRunning
	return nil
}

func (m *mockVMOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if m.stopError != nil {
		return m.stopError
	}

	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}

	inst.State = compute.StateStopped
	return nil
}

func (m *mockVMOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	if m.getError != nil {
		return nil, m.getError
	}

	inst, ok := m.instances[instanceID]
	if !ok {
		return nil, compute.ErrInstanceNotFound
	}

	return inst, nil
}

func (m *mockVMOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	if m.listError != nil {
		return nil, m.listError
	}

	result := make([]*compute.Instance, 0, len(m.instances))
	for _, inst := range m.instances {
		if filter == nil || filter.Matches(inst) {
			result = append(result, inst)
		}
	}

	return result, nil
}

func (m *mockVMOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	if m.getStateError != nil {
		return compute.StateUnknown, m.getStateError
	}

	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.StateUnknown, compute.ErrInstanceNotFound
	}

	return inst.State, nil
}

func (m *mockVMOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	if m.attachNetworkError != nil {
		return m.attachNetworkError
	}

	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}

	inst.NetworkAttachments = append(inst.NetworkAttachments, compute.NetworkAttachment{
		PortName:   portName,
		BridgeName: "br0",
		AttachedAt: time.Now(),
	})
	return nil
}

func (m *mockVMOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	if m.detachNetworkError != nil {
		return m.detachNetworkError
	}

	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}

	// Remove the network attachment
	newAttachments := make([]compute.NetworkAttachment, 0)
	for _, att := range inst.NetworkAttachments {
		if att.PortName != portName {
			newAttachments = append(newAttachments, att)
		}
	}
	inst.NetworkAttachments = newAttachments
	return nil
}

// =============================================================================
// Mock Extended VM Orchestrator
// =============================================================================

// mockExtendedVMOrchestrator implements ExtendedVMOrchestrator for testing
type mockExtendedVMOrchestrator struct {
	*mockVMOrchestrator
	restartError         error
	suspendError         error
	resumeError          error
	attestError          error
	consoleError         error
	createSnapshotError  error
	restoreSnapshotError error
	deleteSnapshotError  error
	listSnapshotsError   error
	attestReport         *VMAttestationReport
	verifyAttestError    error
	verifyResult         *compute.VMVerificationResult
	consoleInfo          *VMConsoleInfo
	snapshots            map[string][]*VMSnapshot
}

func newMockExtendedVMOrchestrator() *mockExtendedVMOrchestrator {
	return &mockExtendedVMOrchestrator{
		mockVMOrchestrator: newMockVMOrchestrator(),
		snapshots:          make(map[string][]*VMSnapshot),
	}
}

func (m *mockExtendedVMOrchestrator) Restart(ctx context.Context, instanceID string) error {
	if m.restartError != nil {
		return m.restartError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}

	return nil
}

func (m *mockExtendedVMOrchestrator) Suspend(ctx context.Context, instanceID string) error {
	if m.suspendError != nil {
		return m.suspendError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}

	return nil
}

func (m *mockExtendedVMOrchestrator) Resume(ctx context.Context, instanceID string) error {
	if m.resumeError != nil {
		return m.resumeError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}

	return nil
}

func (m *mockExtendedVMOrchestrator) GetConsole(ctx context.Context, instanceID string) (*VMConsoleInfo, error) {
	if m.consoleError != nil {
		return nil, m.consoleError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return nil, compute.ErrInstanceNotFound
	}

	if m.consoleInfo != nil {
		return m.consoleInfo, nil
	}

	return &VMConsoleInfo{
		Type:     "vnc",
		Address:  "127.0.0.1",
		Port:     5900,
		Protocol: "rfb",
	}, nil
}

func (m *mockExtendedVMOrchestrator) AttestVM(ctx context.Context, instanceID string, nonce []byte, pcrIndices []int) (*VMAttestationReport, error) {
	if m.attestError != nil {
		return nil, m.attestError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return nil, compute.ErrInstanceNotFound
	}

	if m.attestReport != nil {
		return m.attestReport, nil
	}

	return &VMAttestationReport{
		VMID:      instanceID,
		VMName:    "test-vm",
		Timestamp: time.Now(),
		Verified:  true,
		Nonce:     nonce,
		PCRValues: map[int][]byte{0: []byte("pcr0"), 7: []byte("pcr7")},
		Quote:     []byte("test-quote"),
		Signature: []byte("test-signature"),
		EventLog:  []byte("test-event-log"),
	}, nil
}

func (m *mockExtendedVMOrchestrator) VerifyVMAttestation(ctx context.Context, instanceID string, evidence *compute.VMAttestationEvidence) (*compute.VMVerificationResult, error) {
	if m.verifyAttestError != nil {
		return nil, m.verifyAttestError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return nil, compute.ErrInstanceNotFound
	}

	if m.verifyResult != nil {
		return m.verifyResult, nil
	}

	return &compute.VMVerificationResult{
		Verified:       true,
		SignatureValid: true,
		NonceValid:     true,
		PCRsValid:      true,
		Message:        "attestation verified",
	}, nil
}

func (m *mockExtendedVMOrchestrator) CreateSnapshot(ctx context.Context, instanceID, snapshotName string) (*VMSnapshot, error) {
	if m.createSnapshotError != nil {
		return nil, m.createSnapshotError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return nil, compute.ErrInstanceNotFound
	}

	snapshot := &VMSnapshot{
		Name:        snapshotName,
		VMID:        instanceID,
		CreatedAt:   time.Now(),
		SizeBytes:   1024 * 1024 * 100, // 100MB
		Description: "Test snapshot",
	}

	m.snapshots[instanceID] = append(m.snapshots[instanceID], snapshot)
	return snapshot, nil
}

func (m *mockExtendedVMOrchestrator) RestoreSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if m.restoreSnapshotError != nil {
		return m.restoreSnapshotError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}

	return nil
}

func (m *mockExtendedVMOrchestrator) DeleteSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if m.deleteSnapshotError != nil {
		return m.deleteSnapshotError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}

	return nil
}

func (m *mockExtendedVMOrchestrator) ListSnapshots(ctx context.Context, instanceID string) ([]*VMSnapshot, error) {
	if m.listSnapshotsError != nil {
		return nil, m.listSnapshotsError
	}

	if _, ok := m.instances[instanceID]; !ok {
		return nil, compute.ErrInstanceNotFound
	}

	return m.snapshots[instanceID], nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newVMTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestVMHandler() (*VMHandler, *mockVMOrchestrator) {
	logger := newVMTestLogger()
	orchestrator := newMockVMOrchestrator()
	handler := NewVMHandler(logger, orchestrator)
	return handler, orchestrator
}

func createExtendedTestVMHandler() (*VMHandler, *mockExtendedVMOrchestrator) {
	logger := newVMTestLogger()
	orchestrator := newMockExtendedVMOrchestrator()
	handler := NewVMHandler(logger, orchestrator)
	return handler, orchestrator
}

func createTestVM(orchestrator *mockVMOrchestrator, id, name string) *compute.Instance {
	inst := &compute.Instance{
		ID:        id,
		Name:      name,
		Type:      compute.ComputeTypeVM,
		State:     compute.StateStopped,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Config: &compute.InstanceConfig{
			Memory:     4096,
			CPUs:       2,
			DiskPath:   "/var/lib/vms/" + name + "/disk.qcow2",
			DiskSize:   "20G",
			BootMode:   "bios",
			SecureBoot: false,
			TPMEnabled: true,
		},
		NetworkAttachments: []compute.NetworkAttachment{
			{
				PortName:   "veth-" + name,
				BridgeName: "br0",
				VLAN:       100,
				MACAddress: "52:54:00:12:34:56",
				IPAddress:  "192.168.1.10",
				AttachedAt: time.Now(),
			},
		},
		Metadata: map[string]string{"env": "test"},
	}
	orchestrator.instances[id] = inst
	return inst
}

// =============================================================================
// Test: NewVMHandler
// =============================================================================

func TestNewVMHandler(t *testing.T) {
	t.Run("creates handler with valid inputs", func(t *testing.T) {
		logger := newVMTestLogger()
		orchestrator := newMockVMOrchestrator()
		handler := NewVMHandler(logger, orchestrator)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, orchestrator, handler.orchestrator)
	})

	t.Run("creates handler with nil orchestrator", func(t *testing.T) {
		logger := newVMTestLogger()
		handler := NewVMHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.orchestrator)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestVMHandleRequest(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		resp := handler.HandleRequest(context.Background(), nil)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		req := &Request{
			Opcode: 0x00, // Unknown opcode for VM handler
		}

		resp := handler.HandleRequest(context.Background(), req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown VM operation")
	})
}

// =============================================================================
// Test: CreateVM
// =============================================================================

func TestVMHandleCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("creates VM successfully", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		createReq := &VMCreateRequest{
			Name:        "test-vm",
			ProfileID:   1,
			Memory:      4096,
			CPUs:        2,
			DiskSize:    "20G",
			BootMode:    "uefi",
			EnableKVM:   true,
			SecureBoot:  true,
			TPMEnabled:  true,
			NetworkMode: "bridge",
			Environment: map[string]string{"ENV_VAR": "value"},
			Labels:      map[string]string{"app": "test"},
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var createResp VMCreateResponse
		err = DecodePayload(resp.Payload, &createResp)
		require.NoError(t, err)

		assert.NotNil(t, createResp.VM)
		assert.Equal(t, "test-vm", createResp.VM.Name)
		assert.Equal(t, string(compute.ComputeTypeVM), createResp.VM.Type)
		assert.Greater(t, createResp.Timestamp, int64(0))
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		createReq := &VMCreateRequest{
			Name: "test-vm",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
		assert.Contains(t, string(resp.Payload), "not available")
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		createReq := &VMCreateRequest{
			ProfileID: 1,
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "name")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		req := &Request{
			Opcode:  OpVMCreate,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when create fails", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		orchestrator.createError = compute.ErrInvalidProfile

		createReq := &VMCreateRequest{
			Name: "test-vm",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: DeleteVM
// =============================================================================

func TestVMHandleDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes VM successfully", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		deleteReq := &VMDeleteRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var deleteResp VMDeleteResponse
		err = DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", deleteResp.ID)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		deleteReq := &VMDeleteRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		deleteReq := &VMDeleteRequest{}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "ID")
	})

	t.Run("returns error for VM not found", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		deleteReq := &VMDeleteRequest{
			ID: "nonexistent",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: StartVM
// =============================================================================

func TestVMHandleStart(t *testing.T) {
	ctx := context.Background()

	t.Run("starts VM successfully", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		startReq := &VMStartRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(startReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var startResp VMStartResponse
		err = DecodePayload(resp.Payload, &startResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", startResp.ID)
		assert.True(t, startResp.Success)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		startReq := &VMStartRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(startReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		startReq := &VMStartRequest{}

		payload, err := EncodePayload(startReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for VM not found", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		startReq := &VMStartRequest{
			ID: "nonexistent",
		}

		payload, err := EncodePayload(startReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error when already running", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")
		orchestrator.startError = compute.ErrInstanceAlreadyRunning

		startReq := &VMStartRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(startReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: StopVM
// =============================================================================

func TestVMHandleStop(t *testing.T) {
	ctx := context.Background()

	t.Run("stops VM successfully", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		vm := createTestVM(orchestrator, "vm-1", "test-vm")
		vm.State = compute.StateRunning

		stopReq := &VMStopRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(stopReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var stopResp VMStopResponse
		err = DecodePayload(resp.Payload, &stopResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", stopResp.ID)
		assert.True(t, stopResp.Success)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		stopReq := &VMStopRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(stopReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		stopReq := &VMStopRequest{}

		payload, err := EncodePayload(stopReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for VM not found", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		stopReq := &VMStopRequest{
			ID: "nonexistent",
		}

		payload, err := EncodePayload(stopReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: GetVM
// =============================================================================

func TestVMHandleGet(t *testing.T) {
	ctx := context.Background()

	t.Run("gets VM successfully", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		getReq := &VMGetRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp VMGetResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.VM)
		assert.Equal(t, "vm-1", getResp.VM.ID)
		assert.Equal(t, "test-vm", getResp.VM.Name)
		assert.Equal(t, 4096, getResp.VM.Memory)
		assert.Equal(t, 2, getResp.VM.CPUs)
		assert.True(t, getResp.VM.TPMEnabled)
		assert.NotEmpty(t, getResp.VM.NetworkAttachments)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		getReq := &VMGetRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		getReq := &VMGetRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for VM not found", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		getReq := &VMGetRequest{
			ID: "nonexistent",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListVMs
// =============================================================================

func TestVMHandleList(t *testing.T) {
	ctx := context.Background()

	t.Run("lists VMs successfully", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm-1")
		createTestVM(orchestrator, "vm-2", "test-vm-2")

		listReq := &VMListRequest{
			Limit: 10,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp VMListResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(2), listResp.Count)
		assert.Len(t, listResp.VMs, 2)
	})

	t.Run("filters by state", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		vm1 := createTestVM(orchestrator, "vm-1", "test-vm-1")
		vm1.State = compute.StateRunning
		createTestVM(orchestrator, "vm-2", "test-vm-2")

		listReq := &VMListRequest{
			State: "running",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp VMListResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(1), listResp.Count)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		listReq := &VMListRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		orchestrator.listError = errors.New("list failed")

		listReq := &VMListRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: AttachNetwork
// =============================================================================

func TestVMHandleAttachNetwork(t *testing.T) {
	ctx := context.Background()

	t.Run("attaches network successfully", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		attachReq := &VMAttachNetworkRequest{
			ID:       "vm-1",
			PortName: "veth-test",
		}

		payload, err := EncodePayload(attachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var attachResp VMAttachNetworkResponse
		err = DecodePayload(resp.Payload, &attachResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", attachResp.ID)
		assert.Equal(t, "veth-test", attachResp.PortName)
		assert.True(t, attachResp.Success)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		attachReq := &VMAttachNetworkRequest{
			ID:       "vm-1",
			PortName: "veth-test",
		}

		payload, err := EncodePayload(attachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		attachReq := &VMAttachNetworkRequest{
			PortName: "veth-test",
		}

		payload, err := EncodePayload(attachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing port name", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		attachReq := &VMAttachNetworkRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(attachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for VM not found", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		attachReq := &VMAttachNetworkRequest{
			ID:       "nonexistent",
			PortName: "veth-test",
		}

		payload, err := EncodePayload(attachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: DetachNetwork
// =============================================================================

func TestVMHandleDetachNetwork(t *testing.T) {
	ctx := context.Background()

	t.Run("detaches network successfully", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		detachReq := &VMDetachNetworkRequest{
			ID:       "vm-1",
			PortName: "veth-test-vm",
		}

		payload, err := EncodePayload(detachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDetachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var detachResp VMDetachNetworkResponse
		err = DecodePayload(resp.Payload, &detachResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", detachResp.ID)
		assert.True(t, detachResp.Success)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		detachReq := &VMDetachNetworkRequest{
			ID:       "vm-1",
			PortName: "veth-test",
		}

		payload, err := EncodePayload(detachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDetachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		detachReq := &VMDetachNetworkRequest{
			PortName: "veth-test",
		}

		payload, err := EncodePayload(detachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDetachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing port name", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		detachReq := &VMDetachNetworkRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(detachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDetachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: GetState
// =============================================================================

func TestVMHandleGetState(t *testing.T) {
	ctx := context.Background()

	t.Run("gets state successfully", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		vm := createTestVM(orchestrator, "vm-1", "test-vm")
		vm.State = compute.StateRunning

		stateReq := &VMGetStateRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(stateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var stateResp VMGetStateResponse
		err = DecodePayload(resp.Payload, &stateResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", stateResp.ID)
		assert.Equal(t, "running", stateResp.State)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		stateReq := &VMGetStateRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(stateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		stateReq := &VMGetStateRequest{}

		payload, err := EncodePayload(stateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Extended Operations - Restart
// =============================================================================

func TestVMHandleRestart(t *testing.T) {
	ctx := context.Background()

	t.Run("restarts VM successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		restartReq := &VMRestartRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(restartReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMRestart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var restartResp VMRestartResponse
		err = DecodePayload(resp.Payload, &restartResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", restartResp.ID)
		assert.True(t, restartResp.Success)
	})

	t.Run("returns error when not extended orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		restartReq := &VMRestartRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(restartReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMRestart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotImplemented, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		restartReq := &VMRestartRequest{}

		payload, err := EncodePayload(restartReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMRestart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Extended Operations - Suspend
// =============================================================================

func TestVMHandleSuspend(t *testing.T) {
	ctx := context.Background()

	t.Run("suspends VM successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		suspendReq := &VMSuspendRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(suspendReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSuspend,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var suspendResp VMSuspendResponse
		err = DecodePayload(resp.Payload, &suspendResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", suspendResp.ID)
		assert.True(t, suspendResp.Success)
	})

	t.Run("returns error when not extended orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		suspendReq := &VMSuspendRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(suspendReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSuspend,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotImplemented, resp.Status)
	})
}

// =============================================================================
// Test: Extended Operations - Resume
// =============================================================================

func TestVMHandleResume(t *testing.T) {
	ctx := context.Background()

	t.Run("resumes VM successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		resumeReq := &VMResumeRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(resumeReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMResume,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var resumeResp VMResumeResponse
		err = DecodePayload(resp.Payload, &resumeResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", resumeResp.ID)
		assert.True(t, resumeResp.Success)
	})

	t.Run("returns error when not extended orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		resumeReq := &VMResumeRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(resumeReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMResume,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotImplemented, resp.Status)
	})
}

// =============================================================================
// Test: Extended Operations - Attest
// =============================================================================

func TestVMHandleAttest(t *testing.T) {
	ctx := context.Background()

	t.Run("attests VM successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		attestReq := &VMAttestRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var attestResp VMAttestResponse
		err = DecodePayload(resp.Payload, &attestResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", attestResp.VMID)
		assert.True(t, attestResp.Verified)
		assert.NotEmpty(t, attestResp.Quote)
		assert.NotEmpty(t, attestResp.Signature)
		assert.NotEmpty(t, attestResp.PCRValues)
	})

	t.Run("returns custom attestation report", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.attestReport = &VMAttestationReport{
			VMID:      "vm-1",
			VMName:    "custom-vm",
			Verified:  false,
			Timestamp: time.Now(),
			Quote:     []byte("custom-quote"),
		}

		attestReq := &VMAttestRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var attestResp VMAttestResponse
		err = DecodePayload(resp.Payload, &attestResp)
		require.NoError(t, err)

		assert.Equal(t, "custom-vm", attestResp.VMName)
		assert.False(t, attestResp.Verified)
	})

	t.Run("returns error when not extended orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		attestReq := &VMAttestRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotImplemented, resp.Status)
	})
}

// =============================================================================
// Test: Extended Operations - Console
// =============================================================================

func TestVMHandleGetConsole(t *testing.T) {
	ctx := context.Background()

	t.Run("gets console info successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		consoleReq := &VMConsoleRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(consoleReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMConsole,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var consoleResp VMConsoleResponse
		err = DecodePayload(resp.Payload, &consoleResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", consoleResp.VMID)
		assert.Equal(t, "vnc", consoleResp.Type)
		assert.Equal(t, "127.0.0.1", consoleResp.Address)
		assert.Equal(t, 5900, consoleResp.Port)
	})

	t.Run("returns error when not extended orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		consoleReq := &VMConsoleRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(consoleReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMConsole,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotImplemented, resp.Status)
	})
}

// =============================================================================
// Test: Extended Operations - Snapshots
// =============================================================================

func TestVMHandleCreateSnapshot(t *testing.T) {
	ctx := context.Background()

	t.Run("creates snapshot successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		snapshotReq := &VMSnapshotCreateRequest{
			ID:          "vm-1",
			Name:        "snapshot-1",
			Description: "Test snapshot",
		}

		payload, err := EncodePayload(snapshotReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshot,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var snapshotResp VMSnapshotCreateResponse
		err = DecodePayload(resp.Payload, &snapshotResp)
		require.NoError(t, err)

		assert.NotNil(t, snapshotResp.Snapshot)
		assert.Equal(t, "snapshot-1", snapshotResp.Snapshot.Name)
		assert.Equal(t, "vm-1", snapshotResp.Snapshot.VMID)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		snapshotReq := &VMSnapshotCreateRequest{
			Name: "snapshot-1",
		}

		payload, err := EncodePayload(snapshotReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshot,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing snapshot name", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		snapshotReq := &VMSnapshotCreateRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(snapshotReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshot,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when not extended orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		snapshotReq := &VMSnapshotCreateRequest{
			ID:   "vm-1",
			Name: "snapshot-1",
		}

		payload, err := EncodePayload(snapshotReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshot,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotImplemented, resp.Status)
	})
}

func TestVMHandleRestoreSnapshot(t *testing.T) {
	ctx := context.Background()

	t.Run("restores snapshot successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		restoreReq := &VMSnapshotRestoreRequest{
			ID:   "vm-1",
			Name: "snapshot-1",
		}

		payload, err := EncodePayload(restoreReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotRestore,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var restoreResp VMSnapshotRestoreResponse
		err = DecodePayload(resp.Payload, &restoreResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", restoreResp.ID)
		assert.Equal(t, "snapshot-1", restoreResp.Name)
		assert.True(t, restoreResp.Success)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		restoreReq := &VMSnapshotRestoreRequest{
			Name: "snapshot-1",
		}

		payload, err := EncodePayload(restoreReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotRestore,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing snapshot name", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		restoreReq := &VMSnapshotRestoreRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(restoreReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotRestore,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})
}

func TestVMHandleDeleteSnapshot(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes snapshot successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		deleteReq := &VMSnapshotDeleteRequest{
			ID:   "vm-1",
			Name: "snapshot-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var deleteResp VMSnapshotDeleteResponse
		err = DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", deleteResp.ID)
		assert.Equal(t, "snapshot-1", deleteResp.Name)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		deleteReq := &VMSnapshotDeleteRequest{
			Name: "snapshot-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing snapshot name", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		deleteReq := &VMSnapshotDeleteRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})
}

func TestVMHandleListSnapshots(t *testing.T) {
	ctx := context.Background()

	t.Run("lists snapshots successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.snapshots["vm-1"] = []*VMSnapshot{
			{Name: "snap-1", VMID: "vm-1", CreatedAt: time.Now()},
			{Name: "snap-2", VMID: "vm-1", CreatedAt: time.Now()},
		}

		listReq := &VMSnapshotListRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp VMSnapshotListResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, "vm-1", listResp.VMID)
		assert.Equal(t, int32(2), listResp.Count)
		assert.Len(t, listResp.Snapshots, 2)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		listReq := &VMSnapshotListRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Error Types
// =============================================================================

func TestVMErrorTypes(t *testing.T) {
	t.Run("ErrVMEncodingFailed", func(t *testing.T) {
		cause := errors.New("encoding error")
		err := ErrVMEncodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "encoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrVMDecodingFailed", func(t *testing.T) {
		cause := errors.New("decoding error")
		err := ErrVMDecodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "decoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrVMOperationFailed", func(t *testing.T) {
		cause := errors.New("operation error")
		err := ErrVMOperationFailed{
			Operation: "start",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "start")
		assert.Contains(t, err.Error(), "operation error")
		assert.Equal(t, cause, err.Unwrap())
	})
}

// =============================================================================
// Test: vmErrorResponse - Comprehensive Error Mapping
// =============================================================================

func TestVMErrorResponse(t *testing.T) {
	handler, _ := createTestVMHandler()

	testCases := []struct {
		name           string
		err            error
		expectedStatus byte
	}{
		{"instance not found", compute.ErrInstanceNotFound, StatusNotFound},
		{"instance already exists", compute.ErrInstanceAlreadyExists, StatusAlreadyExists},
		{"instance already running", compute.ErrInstanceAlreadyRunning, StatusInvalidRequest},
		{"instance not running", compute.ErrInstanceNotRunning, StatusInvalidRequest},
		{"invalid instance ID", compute.ErrInvalidInstanceID, StatusInvalidArgument},
		{"invalid profile", compute.ErrInvalidProfile, StatusInvalidArgument},
		{"invalid configuration", compute.ErrInvalidConfiguration, StatusInvalidArgument},
		{"invalid state", compute.ErrInvalidState, StatusInvalidRequest},
		{"resource exhausted", compute.ErrResourceExhausted, StatusResourceExhausted},
		{"orchestrator not initialized", compute.ErrOrchestratorNotInitialized, StatusUnavailable},
		{"timeout", compute.ErrTimeout, StatusTimeout},
		{"unsupported operation", compute.ErrUnsupportedOperation, StatusNotImplemented},
		{"network attachment failed", compute.ErrNetworkAttachmentFailed, StatusInternalError},
		{"network detachment failed", compute.ErrNetworkDetachmentFailed, StatusInternalError},
		{"generic error", errors.New("unknown error"), StatusInternalError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.vmErrorResponse(tc.err)
			assert.Equal(t, tc.expectedStatus, resp.Status)
		})
	}
}

// =============================================================================
// Test: buildProfileFromRequest
// =============================================================================

func TestBuildProfileFromRequest(t *testing.T) {
	handler, _ := createTestVMHandler()

	t.Run("builds profile with all fields", func(t *testing.T) {
		req := &VMCreateRequest{
			Name:        "test-vm",
			ProfileID:   123,
			ProfileName: "test-profile",
			Memory:      4096,
			CPUs:        4,
		}

		profile := handler.buildProfileFromRequest(req)

		assert.Equal(t, "test-vm", profile.Name)
		assert.Equal(t, uint64(123), profile.ID)
	})

	t.Run("builds profile with minimal fields", func(t *testing.T) {
		req := &VMCreateRequest{
			Name: "test-vm",
		}

		profile := handler.buildProfileFromRequest(req)

		assert.Equal(t, "test-vm", profile.Name)
		assert.Equal(t, uint64(0), profile.ID)
	})
}

// =============================================================================
// Test: buildFilterFromRequest
// =============================================================================

func TestBuildFilterFromRequest(t *testing.T) {
	handler, _ := createTestVMHandler()

	t.Run("builds filter with all fields", func(t *testing.T) {
		req := &VMListRequest{
			State:        "running",
			Name:         "test",
			ProfileID:    123,
			CreatedAfter: time.Now().Unix(),
		}

		filter := handler.buildFilterFromRequest(req)

		assert.NotNil(t, filter.Type)
		assert.Equal(t, compute.ComputeTypeVM, *filter.Type)
		assert.NotNil(t, filter.State)
		assert.Equal(t, compute.StateRunning, *filter.State)
		assert.Equal(t, "test", filter.Name)
		assert.NotNil(t, filter.ProfileID)
		assert.Equal(t, uint64(123), *filter.ProfileID)
		assert.NotNil(t, filter.CreatedAfter)
	})

	t.Run("builds filter with minimal fields", func(t *testing.T) {
		req := &VMListRequest{}

		filter := handler.buildFilterFromRequest(req)

		assert.NotNil(t, filter.Type)
		assert.Equal(t, compute.ComputeTypeVM, *filter.Type)
		assert.Nil(t, filter.State)
		assert.Empty(t, filter.Name)
		assert.Nil(t, filter.ProfileID)
	})
}

// =============================================================================
// Test: instanceToVMInfo
// =============================================================================

func TestInstanceToVMInfo(t *testing.T) {
	handler, orchestrator := createTestVMHandler()

	t.Run("converts complete instance", func(t *testing.T) {
		inst := createTestVM(orchestrator, "vm-1", "test-vm")

		info := handler.instanceToVMInfo(inst)

		assert.Equal(t, "vm-1", info.ID)
		assert.Equal(t, "test-vm", info.Name)
		assert.Equal(t, string(compute.StateStopped), info.State)
		assert.Equal(t, string(compute.ComputeTypeVM), info.Type)
		assert.Equal(t, 4096, info.Memory)
		assert.Equal(t, 2, info.CPUs)
		assert.True(t, info.TPMEnabled)
		assert.NotEmpty(t, info.NetworkAttachments)
		assert.Equal(t, "veth-test-vm", info.NetworkAttachments[0].PortName)
	})

	t.Run("handles nil instance", func(t *testing.T) {
		info := handler.instanceToVMInfo(nil)
		assert.Nil(t, info)
	})

	t.Run("handles instance without config", func(t *testing.T) {
		inst := &compute.Instance{
			ID:        "vm-1",
			Name:      "test-vm",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		info := handler.instanceToVMInfo(inst)

		assert.NotNil(t, info)
		assert.Equal(t, 0, info.Memory)
		assert.Equal(t, 0, info.CPUs)
	})

	t.Run("handles instance without network attachments", func(t *testing.T) {
		inst := &compute.Instance{
			ID:        "vm-1",
			Name:      "test-vm",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		info := handler.instanceToVMInfo(inst)

		assert.NotNil(t, info)
		assert.Nil(t, info.NetworkAttachments)
	})
}

// =============================================================================
// Test: snapshotToInfo
// =============================================================================

func TestSnapshotToInfo(t *testing.T) {
	handler, _ := createTestVMHandler()

	t.Run("converts complete snapshot", func(t *testing.T) {
		snapshot := &VMSnapshot{
			Name:        "snap-1",
			VMID:        "vm-1",
			CreatedAt:   time.Now(),
			SizeBytes:   1024 * 1024,
			Description: "Test snapshot",
		}

		info := handler.snapshotToInfo(snapshot)

		assert.Equal(t, "snap-1", info.Name)
		assert.Equal(t, "vm-1", info.VMID)
		assert.Equal(t, int64(1024*1024), info.SizeBytes)
		assert.Equal(t, "Test snapshot", info.Description)
	})

	t.Run("handles nil snapshot", func(t *testing.T) {
		info := handler.snapshotToInfo(nil)
		assert.Nil(t, info)
	})
}

// =============================================================================
// Test: Opcode Constants
// =============================================================================

func TestVMOpcodeConstants(t *testing.T) {
	opcodes := []struct {
		name   string
		opcode byte
	}{
		{"OpVMCreate", OpVMCreate},
		{"OpVMDelete", OpVMDelete},
		{"OpVMStart", OpVMStart},
		{"OpVMStop", OpVMStop},
		{"OpVMGet", OpVMGet},
		{"OpVMList", OpVMList},
		{"OpVMAttachNet", OpVMAttachNet},
		{"OpVMDetachNet", OpVMDetachNet},
		{"OpVMGetState", OpVMGetState},
		{"OpVMRestart", OpVMRestart},
		{"OpVMSuspend", OpVMSuspend},
		{"OpVMResume", OpVMResume},
		{"OpVMAttest", OpVMAttest},
		{"OpVMConsole", OpVMConsole},
		{"OpVMSnapshot", OpVMSnapshot},
		{"OpVMSnapshotRestore", OpVMSnapshotRestore},
		{"OpVMSnapshotDelete", OpVMSnapshotDelete},
		{"OpVMSnapshotList", OpVMSnapshotList},
	}

	seen := make(map[byte]string)
	for _, op := range opcodes {
		if existing, ok := seen[op.opcode]; ok {
			t.Errorf("duplicate opcode 0x%02X: %s and %s", op.opcode, existing, op.name)
		}
		seen[op.opcode] = op.name
	}

	// Verify all opcodes are non-zero (0x00 is typically reserved)
	for _, op := range opcodes {
		assert.NotEqual(t, byte(0x00), op.opcode, "opcode %s should not be zero", op.name)
	}
}

// =============================================================================
// Test: Sentinel Errors
// =============================================================================

func TestVMSentinelErrors(t *testing.T) {
	t.Run("ErrVMOrchestratorNotAvailable", func(t *testing.T) {
		assert.NotEmpty(t, ErrVMOrchestratorNotAvailable.Error())
		assert.Contains(t, ErrVMOrchestratorNotAvailable.Error(), "not available")
	})

	t.Run("ErrVMMissingID", func(t *testing.T) {
		assert.NotEmpty(t, ErrVMMissingID.Error())
		assert.Contains(t, ErrVMMissingID.Error(), "ID")
	})

	t.Run("ErrVMMissingName", func(t *testing.T) {
		assert.NotEmpty(t, ErrVMMissingName.Error())
		assert.Contains(t, ErrVMMissingName.Error(), "name")
	})

	t.Run("ErrVMMissingSnapshotName", func(t *testing.T) {
		assert.NotEmpty(t, ErrVMMissingSnapshotName.Error())
		assert.Contains(t, ErrVMMissingSnapshotName.Error(), "snapshot")
	})

	t.Run("ErrVMOperationNotSupported", func(t *testing.T) {
		assert.NotEmpty(t, ErrVMOperationNotSupported.Error())
		assert.Contains(t, ErrVMOperationNotSupported.Error(), "not supported")
	})

	t.Run("ErrVMMissingPortName", func(t *testing.T) {
		assert.NotEmpty(t, ErrVMMissingPortName.Error())
		assert.Contains(t, ErrVMMissingPortName.Error(), "port")
	})
}

// =============================================================================
// Test: Extended Operations - Error Paths for Coverage
// =============================================================================

func TestVMHandleSuspendErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		suspendReq := &VMSuspendRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(suspendReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSuspend,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		req := &Request{
			Opcode:  OpVMSuspend,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		suspendReq := &VMSuspendRequest{}

		payload, err := EncodePayload(suspendReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSuspend,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when suspend fails", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.suspendError = errors.New("suspend failed")

		suspendReq := &VMSuspendRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(suspendReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSuspend,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

func TestVMHandleResumeErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		resumeReq := &VMResumeRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(resumeReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMResume,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		req := &Request{
			Opcode:  OpVMResume,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		resumeReq := &VMResumeRequest{}

		payload, err := EncodePayload(resumeReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMResume,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when resume fails", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.resumeError = errors.New("resume failed")

		resumeReq := &VMResumeRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(resumeReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMResume,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

func TestVMHandleAttestErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		attestReq := &VMAttestRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		req := &Request{
			Opcode:  OpVMAttest,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		attestReq := &VMAttestRequest{}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when attest fails", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.attestError = errors.New("attest failed")

		attestReq := &VMAttestRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(attestReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

func TestVMHandleGetConsoleErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		consoleReq := &VMConsoleRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(consoleReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMConsole,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		req := &Request{
			Opcode:  OpVMConsole,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		consoleReq := &VMConsoleRequest{}

		payload, err := EncodePayload(consoleReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMConsole,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when console fails", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.consoleError = errors.New("console failed")

		consoleReq := &VMConsoleRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(consoleReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMConsole,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

func TestVMHandleSnapshotErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("create snapshot - orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		snapshotReq := &VMSnapshotCreateRequest{
			ID:   "vm-1",
			Name: "snap-1",
		}

		payload, err := EncodePayload(snapshotReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshot,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("create snapshot - invalid payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		req := &Request{
			Opcode:  OpVMSnapshot,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("create snapshot - fails", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.createSnapshotError = errors.New("snapshot failed")

		snapshotReq := &VMSnapshotCreateRequest{
			ID:   "vm-1",
			Name: "snap-1",
		}

		payload, err := EncodePayload(snapshotReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshot,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})

	t.Run("restore snapshot - orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		restoreReq := &VMSnapshotRestoreRequest{
			ID:   "vm-1",
			Name: "snap-1",
		}

		payload, err := EncodePayload(restoreReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotRestore,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("restore snapshot - not extended orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		restoreReq := &VMSnapshotRestoreRequest{
			ID:   "vm-1",
			Name: "snap-1",
		}

		payload, err := EncodePayload(restoreReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotRestore,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotImplemented, resp.Status)
	})

	t.Run("restore snapshot - invalid payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		req := &Request{
			Opcode:  OpVMSnapshotRestore,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("restore snapshot - fails", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.restoreSnapshotError = errors.New("restore failed")

		restoreReq := &VMSnapshotRestoreRequest{
			ID:   "vm-1",
			Name: "snap-1",
		}

		payload, err := EncodePayload(restoreReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotRestore,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})

	t.Run("delete snapshot - orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		deleteReq := &VMSnapshotDeleteRequest{
			ID:   "vm-1",
			Name: "snap-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("delete snapshot - not extended orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		deleteReq := &VMSnapshotDeleteRequest{
			ID:   "vm-1",
			Name: "snap-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotImplemented, resp.Status)
	})

	t.Run("delete snapshot - invalid payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		req := &Request{
			Opcode:  OpVMSnapshotDelete,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("delete snapshot - fails", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.deleteSnapshotError = errors.New("delete failed")

		deleteReq := &VMSnapshotDeleteRequest{
			ID:   "vm-1",
			Name: "snap-1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})

	t.Run("list snapshots - orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		listReq := &VMSnapshotListRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("list snapshots - not extended orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		listReq := &VMSnapshotListRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotImplemented, resp.Status)
	})

	t.Run("list snapshots - invalid payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		req := &Request{
			Opcode:  OpVMSnapshotList,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("list snapshots - fails", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.listSnapshotsError = errors.New("list failed")

		listReq := &VMSnapshotListRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMSnapshotList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

func TestVMHandleRestartErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewVMHandler(newVMTestLogger(), nil)

		restartReq := &VMRestartRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(restartReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMRestart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		req := &Request{
			Opcode:  OpVMRestart,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when restart fails", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.restartError = errors.New("restart failed")

		restartReq := &VMRestartRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(restartReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMRestart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

func TestVMHandleGetStateErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		req := &Request{
			Opcode:  OpVMGetState,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when get state fails", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")
		orchestrator.getStateError = errors.New("get state failed")

		stateReq := &VMGetStateRequest{
			ID: "vm-1",
		}

		payload, err := EncodePayload(stateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

func TestVMHandleDetachNetworkErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		req := &Request{
			Opcode:  OpVMDetachNet,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when detach fails", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")
		orchestrator.detachNetworkError = errors.New("detach failed")

		detachReq := &VMDetachNetworkRequest{
			ID:       "vm-1",
			PortName: "veth-test",
		}

		payload, err := EncodePayload(detachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDetachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})

	t.Run("returns error for VM not found", func(t *testing.T) {
		handler, _ := createTestVMHandler()

		detachReq := &VMDetachNetworkRequest{
			ID:       "nonexistent",
			PortName: "veth-test",
		}

		payload, err := EncodePayload(detachReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpVMDetachNet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}
