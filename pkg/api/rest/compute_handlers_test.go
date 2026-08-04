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

package rest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock VM Orchestrator
// =============================================================================

type mockVMOrchestrator struct {
	instances      map[string]*compute.Instance
	createErr      error
	startErr       error
	stopErr        error
	deleteErr      error
	listErr        error
	getErr         error
	getStateErr    error
	suspendErr     error
	resumeErr      error
	restartErr     error
	attestErr      error
	consoleErr     error
	createResponse *compute.Instance
	attestReport   *VMAttestationReport
	verifyErr      error
	verifyResult   *compute.VMVerificationResult
	consoleInfo    *VMConsoleInfo
}

func newMockVMOrchestrator() *mockVMOrchestrator {
	return &mockVMOrchestrator{
		instances: make(map[string]*compute.Instance),
	}
}

func (m *mockVMOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	if m.createResponse != nil {
		m.instances[m.createResponse.ID] = m.createResponse
		return m.createResponse, nil
	}
	inst := &compute.Instance{
		ID:        "test-vm-123",
		Name:      profile.Name,
		Type:      compute.ComputeTypeVM,
		State:     compute.StateStopped,
		Profile:   profile,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Config: &compute.InstanceConfig{
			Memory:     4096,
			CPUs:       2,
			DiskPath:   "/var/lib/vms/test-vm-123/disk.qcow2",
			DiskSize:   "20G",
			TPMEnabled: true,
		},
		Metadata: map[string]string{
			"created_by": "test",
		},
	}
	m.instances[inst.ID] = inst
	return inst, nil
}

func (m *mockVMOrchestrator) Start(ctx context.Context, instanceID string) error {
	if m.startErr != nil {
		return m.startErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}
	inst.State = compute.StateRunning
	return nil
}

func (m *mockVMOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}
	inst.State = compute.StateStopped
	return nil
}

func (m *mockVMOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}
	delete(m.instances, instanceID)
	return nil
}

func (m *mockVMOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]*compute.Instance, 0, len(m.instances))
	for _, inst := range m.instances {
		result = append(result, inst)
	}
	return result, nil
}

func (m *mockVMOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return nil, compute.ErrInstanceNotFound
	}
	return inst, nil
}

func (m *mockVMOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	if m.getStateErr != nil {
		return compute.StateUnknown, m.getStateErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.StateUnknown, compute.ErrInstanceNotFound
	}
	return inst.State, nil
}

// Extended VM operations
func (m *mockVMOrchestrator) Suspend(ctx context.Context, instanceID string) error {
	if m.suspendErr != nil {
		return m.suspendErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}
	inst.State = compute.StateStopped
	return nil
}

func (m *mockVMOrchestrator) Resume(ctx context.Context, instanceID string) error {
	if m.resumeErr != nil {
		return m.resumeErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}
	inst.State = compute.StateRunning
	return nil
}

func (m *mockVMOrchestrator) Restart(ctx context.Context, instanceID string) error {
	if m.restartErr != nil {
		return m.restartErr
	}
	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}
	return nil
}

func (m *mockVMOrchestrator) GetConsole(ctx context.Context, instanceID string) (*VMConsoleInfo, error) {
	if m.consoleErr != nil {
		return nil, m.consoleErr
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
		Protocol: "vnc",
	}, nil
}

func (m *mockVMOrchestrator) AttestVM(ctx context.Context, instanceID string, nonce []byte, pcrIndices []int) (*VMAttestationReport, error) {
	if m.attestErr != nil {
		return nil, m.attestErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return nil, compute.ErrInstanceNotFound
	}
	if m.attestReport != nil {
		return m.attestReport, nil
	}
	return &VMAttestationReport{
		VMID:      inst.ID,
		VMName:    inst.Name,
		Timestamp: time.Now(),
		Verified:  true,
		Nonce:     nonce,
		PCRValues: map[int][]byte{
			0: {0x01, 0x02, 0x03},
			7: {0x04, 0x05, 0x06},
		},
		Quote:     []byte("test-quote"),
		Signature: []byte("test-signature"),
		EventLog:  []byte("test-event-log"),
	}, nil
}

func (m *mockVMOrchestrator) VerifyVMAttestation(ctx context.Context, instanceID string, evidence *compute.VMAttestationEvidence) (*compute.VMVerificationResult, error) {
	if m.verifyErr != nil {
		return nil, m.verifyErr
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

func (m *mockVMOrchestrator) addTestVM(id, name string, state compute.InstanceState) *compute.Instance {
	inst := &compute.Instance{
		ID:        id,
		Name:      name,
		Type:      compute.ComputeTypeVM,
		State:     state,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Config: &compute.InstanceConfig{
			Memory:     4096,
			CPUs:       2,
			TPMEnabled: true,
		},
	}
	m.instances[id] = inst
	return inst
}

// =============================================================================
// Mock Container Orchestrator
// =============================================================================

type mockComputeContainerOrchestrator struct {
	containers     map[string]*container.Container
	createErr      error
	startErr       error
	stopErr        error
	removeErr      error
	getErr         error
	listErr        error
	logsErr        error
	attestErr      error
	execErr        error
	createResponse *container.Container
	attestReport   *container.AttestationReport
	execResult     *ExecResult
	logsReader     io.ReadCloser
}

func newMockComputeContainerOrchestrator() *mockComputeContainerOrchestrator {
	return &mockComputeContainerOrchestrator{
		containers: make(map[string]*container.Container),
	}
}

func (m *mockComputeContainerOrchestrator) Create(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.Container, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	if m.createResponse != nil {
		m.containers[m.createResponse.ID] = m.createResponse
		return m.createResponse, nil
	}
	c := &container.Container{
		ID:        "test-container-123",
		Name:      spec.Name,
		Image:     spec.Image,
		State:     container.StateCreated,
		CreatedAt: time.Now(),
		Labels:    spec.Labels,
	}
	m.containers[c.ID] = c
	return c, nil
}

func (m *mockComputeContainerOrchestrator) Start(ctx context.Context, id string) error {
	if m.startErr != nil {
		return m.startErr
	}
	c, ok := m.containers[id]
	if !ok {
		return container.ErrContainerNotFound
	}
	c.State = container.StateRunning
	c.StartedAt = time.Now()
	return nil
}

func (m *mockComputeContainerOrchestrator) Stop(ctx context.Context, id string, timeout time.Duration) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	c, ok := m.containers[id]
	if !ok {
		return container.ErrContainerNotFound
	}
	c.State = container.StateStopped
	c.FinishedAt = time.Now()
	return nil
}

func (m *mockComputeContainerOrchestrator) Remove(ctx context.Context, id string, force bool) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	if _, ok := m.containers[id]; !ok {
		return container.ErrContainerNotFound
	}
	delete(m.containers, id)
	return nil
}

func (m *mockComputeContainerOrchestrator) Get(ctx context.Context, id string) (*container.Container, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	c, ok := m.containers[id]
	if !ok {
		return nil, container.ErrContainerNotFound
	}
	return c, nil
}

func (m *mockComputeContainerOrchestrator) List(ctx context.Context, opts container.ListOptions) ([]*container.Container, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]*container.Container, 0, len(m.containers))
	for _, c := range m.containers {
		result = append(result, c)
	}
	return result, nil
}

func (m *mockComputeContainerOrchestrator) Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
	if m.logsErr != nil {
		return nil, m.logsErr
	}
	if _, ok := m.containers[id]; !ok {
		return nil, container.ErrContainerNotFound
	}
	if m.logsReader != nil {
		return m.logsReader, nil
	}
	return io.NopCloser(strings.NewReader("test log line 1\ntest log line 2\n")), nil
}

func (m *mockComputeContainerOrchestrator) Attest(ctx context.Context, id string) (*container.AttestationReport, error) {
	if m.attestErr != nil {
		return nil, m.attestErr
	}
	c, ok := m.containers[id]
	if !ok {
		return nil, container.ErrContainerNotFound
	}
	if m.attestReport != nil {
		return m.attestReport, nil
	}
	return &container.AttestationReport{
		ContainerID:   c.ID,
		ContainerName: c.Name,
		Timestamp:     time.Now(),
		Verified:      true,
		ImageDigest:   []byte("image-digest"),
		ConfigDigest:  []byte("config-digest"),
		Quote:         []byte("quote"),
		Signature:     []byte("signature"),
		PCRValues: map[int][]byte{
			0: {0x01, 0x02},
		},
	}, nil
}

func (m *mockComputeContainerOrchestrator) Exec(ctx context.Context, id string, cmd []string, opts ExecOptions) (*ExecResult, error) {
	if m.execErr != nil {
		return nil, m.execErr
	}
	if _, ok := m.containers[id]; !ok {
		return nil, container.ErrContainerNotFound
	}
	if m.execResult != nil {
		return m.execResult, nil
	}
	return &ExecResult{
		ExitCode: 0,
		Output:   []byte("command output"),
	}, nil
}

func (m *mockComputeContainerOrchestrator) addTestContainer(id, name string, state container.ContainerState) *container.Container {
	c := &container.Container{
		ID:        id,
		Name:      name,
		Image:     "alpine:latest",
		State:     state,
		CreatedAt: time.Now(),
	}
	m.containers[id] = c
	return c
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func setupComputeHandlers(t *testing.T, vmOrch VMOrchestrator, containerOrch ComputeContainerOrchestrator) (*ComputeHandlers, *mux.Router) {
	t.Helper()
	logger := slog.Default()
	handlers := NewComputeHandlers(vmOrch, containerOrch, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func createTestRequest(method, path string, body interface{}) *http.Request {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// =============================================================================
// VM Handler Tests
// =============================================================================

func TestComputeHandlers_CreateVM_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms", CreateVMRequest{
		Name:       "test-vm",
		Memory:     4096,
		CPUs:       2,
		DiskSize:   "20G",
		TPMEnabled: true,
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	var resp VMResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, "test-vm", resp.Name)
}

func TestComputeHandlers_CreateVM_MissingName(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms", CreateVMRequest{
		Memory: 4096,
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComputeHandlers_CreateVM_InvalidBody(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComputeHandlers_CreateVM_OrchestratorError(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.createErr = errors.New("orchestrator error")
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms", CreateVMRequest{
		Name: "test-vm",
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestComputeHandlers_CreateVM_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms", CreateVMRequest{
		Name: "test-vm",
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_ListVMs_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm-1", compute.StateRunning)
	vmOrch.addTestVM("vm-2", "test-vm-2", compute.StateStopped)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMListResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Count)
}

func TestComputeHandlers_ListVMs_Empty(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMListResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Count)
}

func TestComputeHandlers_ListVMs_WithFilter(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm-1", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms?state=running&name=test", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestComputeHandlers_ListVMs_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_GetVM_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms/vm-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "vm-1", resp.ID)
}

func TestComputeHandlers_GetVM_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms/nonexistent", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_GetVM_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms/vm-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_DeleteVM_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateStopped)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/compute/vms/vm-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMActionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "delete", resp.Action)
}

func TestComputeHandlers_DeleteVM_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/compute/vms/nonexistent", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_DeleteVM_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/compute/vms/vm-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_StartVM_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateStopped)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/start", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMActionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "start", resp.Action)
}

func TestComputeHandlers_StartVM_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/nonexistent/start", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_StartVM_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/start", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_StopVM_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/stop", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMActionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "stop", resp.Action)
}

func TestComputeHandlers_StopVM_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/nonexistent/stop", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_StopVM_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/stop", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_RestartVM_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/restart", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMActionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "restart", resp.Action)
}

func TestComputeHandlers_RestartVM_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/nonexistent/restart", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_RestartVM_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/restart", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_SuspendVM_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/suspend", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMActionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "suspend", resp.Action)
}

func TestComputeHandlers_SuspendVM_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/nonexistent/suspend", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_SuspendVM_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/suspend", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_ResumeVM_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateStopped)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/resume", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMActionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "resume", resp.Action)
}

func TestComputeHandlers_ResumeVM_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/nonexistent/resume", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_ResumeVM_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/resume", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_AttestVM_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/attest", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp AttestVMResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Verified)
}

func TestComputeHandlers_AttestVM_WithBody(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/attest", AttestVMRequest{
		Nonce:           base64.StdEncoding.EncodeToString([]byte("test-nonce")),
		IncludePCRs:     []int{0, 7},
		IncludeEventLog: true,
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestComputeHandlers_AttestVM_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/nonexistent/attest", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_AttestVM_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/attest", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_GetVMConsole_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms/vm-1/console", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp VMConsoleResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "vnc", resp.Type)
	assert.Equal(t, 5900, resp.Port)
}

func TestComputeHandlers_GetVMConsole_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms/nonexistent/console", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_GetVMConsole_NilOrchestrator(t *testing.T) {
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, nil, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms/vm-1/console", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// =============================================================================
// Container Handler Tests
// =============================================================================

func TestComputeHandlers_CreateContainer_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers", CreateComputeContainerRequest{
		Name:  "test-container",
		Image: "alpine:latest",
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	var resp ComputeContainerResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, "test-container", resp.Name)
}

func TestComputeHandlers_CreateContainer_WithStart(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers", CreateComputeContainerRequest{
		Name:  "test-container",
		Image: "alpine:latest",
		Start: true,
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestComputeHandlers_CreateContainer_MissingName(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers", CreateComputeContainerRequest{
		Image: "alpine:latest",
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComputeHandlers_CreateContainer_MissingImage(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers", CreateComputeContainerRequest{
		Name: "test-container",
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComputeHandlers_CreateContainer_InvalidBody(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComputeHandlers_CreateContainer_NilOrchestrator(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, nil)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers", CreateComputeContainerRequest{
		Name:  "test-container",
		Image: "alpine:latest",
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_ListContainers_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "container-1", container.StateRunning)
	containerOrch.addTestContainer("c-2", "container-2", container.StateStopped)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ComputeContainerListResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Count)
}

func TestComputeHandlers_ListContainers_WithFilters(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "container-1", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers?all=true&limit=10&state=running&name=test&image=alpine", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestComputeHandlers_ListContainers_NilOrchestrator(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_GetContainer_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers/c-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ComputeContainerResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "c-1", resp.ID)
}

func TestComputeHandlers_GetContainer_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers/nonexistent", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_GetContainer_NilOrchestrator(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers/c-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_DeleteContainer_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateStopped)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/compute/containers/c-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ContainerActionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestComputeHandlers_DeleteContainer_Force(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/compute/containers/c-1?force=true", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestComputeHandlers_DeleteContainer_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/compute/containers/nonexistent", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_DeleteContainer_NilOrchestrator(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/compute/containers/c-1", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_StartContainer_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateStopped)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/c-1/start", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ContainerActionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestComputeHandlers_StartContainer_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/nonexistent/start", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_StartContainer_NilOrchestrator(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/c-1/start", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_StopContainer_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/c-1/stop", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ContainerActionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestComputeHandlers_StopContainer_WithTimeout(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers/c-1/stop", StopContainerRequest{
		Timeout: 60,
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestComputeHandlers_StopContainer_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/nonexistent/stop", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_StopContainer_NilOrchestrator(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/c-1/stop", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_GetContainerLogs_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers/c-1/logs", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ContainerLogsResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Logs, "test log line")
}

func TestComputeHandlers_GetContainerLogs_WithOptions(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers/c-1/logs?stdout=true&stderr=false&tail=100&timestamps=true&since=2024-01-01T00:00:00Z&until=2024-12-31T23:59:59Z", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestComputeHandlers_GetContainerLogs_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers/nonexistent/logs", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_GetContainerLogs_NilOrchestrator(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers/c-1/logs", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_ExecContainer_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers/c-1/exec", ContainerExecRequest{
		Command: []string{"ls", "-la"},
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ContainerExecResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.ExitCode)
}

func TestComputeHandlers_ExecContainer_WithOptions(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers/c-1/exec", ContainerExecRequest{
		Command:     []string{"/bin/sh", "-c", "echo hello"},
		Environment: []string{"FOO=bar"},
		WorkingDir:  "/tmp",
		User:        "nobody",
		Tty:         true,
		Stdin:       false,
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestComputeHandlers_ExecContainer_MissingCommand(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers/c-1/exec", ContainerExecRequest{
		Command: []string{},
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComputeHandlers_ExecContainer_InvalidBody(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/c-1/exec", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComputeHandlers_ExecContainer_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers/nonexistent/exec", ContainerExecRequest{
		Command: []string{"ls"},
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_ExecContainer_NilOrchestrator(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, nil)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers/c-1/exec", ContainerExecRequest{
		Command: []string{"ls"},
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestComputeHandlers_AttestContainer_Success(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/c-1/attest", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp AttestContainerResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Verified)
}

func TestComputeHandlers_AttestContainer_WithBody(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers/c-1/attest", AttestContainerRequest{
		Nonce:       "test-nonce",
		IncludePCRs: []int{0, 7},
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestComputeHandlers_AttestContainer_NotFound(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/nonexistent/attest", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestComputeHandlers_AttestContainer_NilOrchestrator(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/c-1/attest", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// =============================================================================
// Basic VM Orchestrator (without extended operations)
// =============================================================================

type basicVMOrchestrator struct {
	instances map[string]*compute.Instance
}

func newBasicVMOrchestrator() *basicVMOrchestrator {
	return &basicVMOrchestrator{
		instances: make(map[string]*compute.Instance),
	}
}

func (m *basicVMOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	inst := &compute.Instance{
		ID:        "basic-vm-123",
		Name:      profile.Name,
		Type:      compute.ComputeTypeVM,
		State:     compute.StateStopped,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.instances[inst.ID] = inst
	return inst, nil
}

func (m *basicVMOrchestrator) Start(ctx context.Context, instanceID string) error {
	return nil
}

func (m *basicVMOrchestrator) Stop(ctx context.Context, instanceID string) error {
	return nil
}

func (m *basicVMOrchestrator) Delete(ctx context.Context, instanceID string) error {
	return nil
}

func (m *basicVMOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	result := make([]*compute.Instance, 0, len(m.instances))
	for _, inst := range m.instances {
		result = append(result, inst)
	}
	return result, nil
}

func (m *basicVMOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	inst, ok := m.instances[instanceID]
	if !ok {
		return nil, compute.ErrInstanceNotFound
	}
	return inst, nil
}

func (m *basicVMOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.StateUnknown, compute.ErrInstanceNotFound
	}
	return inst.State, nil
}

func (m *basicVMOrchestrator) addTestVM(id, name string, state compute.InstanceState) *compute.Instance {
	inst := &compute.Instance{
		ID:        id,
		Name:      name,
		Type:      compute.ComputeTypeVM,
		State:     state,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.instances[id] = inst
	return inst
}

// =============================================================================
// Extended Operation Tests (testing interface type assertion)
// =============================================================================

func TestComputeHandlers_RestartVM_NotExtended(t *testing.T) {
	vmOrch := newBasicVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/restart", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestComputeHandlers_SuspendVM_NotExtended(t *testing.T) {
	vmOrch := newBasicVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/suspend", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestComputeHandlers_ResumeVM_NotExtended(t *testing.T) {
	vmOrch := newBasicVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateStopped)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/resume", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestComputeHandlers_AttestVM_NotExtended(t *testing.T) {
	vmOrch := newBasicVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/attest", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestComputeHandlers_GetVMConsole_NotExtended(t *testing.T) {
	vmOrch := newBasicVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms/vm-1/console", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestComputeHandlers_ParseVMListFilter(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	handlers, _ := setupComputeHandlers(t, vmOrch, containerOrch)

	tests := []struct {
		name        string
		queryString string
	}{
		{"empty", ""},
		{"with_state", "?state=running"},
		{"with_name", "?name=test"},
		{"with_both", "?state=running&name=test"},
		{"with_invalid_state", "?state=invalid"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms"+tc.queryString, nil)
			filter := handlers.parseVMListFilter(req)
			assert.NotNil(t, filter)
		})
	}
}

func TestComputeHandlers_BuildVMProfileFromRequest(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	handlers, _ := setupComputeHandlers(t, vmOrch, containerOrch)

	req := &CreateVMRequest{
		Name:      "test-vm",
		ProfileID: 123,
		Memory:    4096,
		CPUs:      2,
	}

	profile := handlers.buildVMProfileFromRequest(req)

	assert.Equal(t, "test-vm", profile.Name)
	assert.Equal(t, uint64(123), profile.ID)
}

func TestComputeHandlers_BuildContainerSpecFromRequest(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	handlers, _ := setupComputeHandlers(t, vmOrch, containerOrch)

	req := &CreateComputeContainerRequest{
		Name:        "test-container",
		Image:       "alpine:latest",
		Command:     []string{"/bin/sh"},
		Args:        []string{"-c", "echo hello"},
		Environment: map[string]string{"FOO": "bar"},
		Labels:      map[string]string{"app": "test"},
		WorkingDir:  "/tmp",
		User:        "nobody",
		Privileged:  true,
		NetworkMode: "bridge",
		Mounts: []MountRequest{
			{Source: "/host/path", Target: "/container/path", Type: "bind", ReadOnly: true},
		},
		Ports: []PortRequest{
			{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		},
		RestartPolicy: "always",
		CPULimit:      "1.0",
		MemoryLimit:   "512m",
		CapAdd:        []string{"NET_ADMIN"},
		CapDrop:       []string{"ALL"},
	}

	spec := handlers.buildContainerSpecFromRequest(req)

	assert.Equal(t, "test-container", spec.Name)
	assert.Equal(t, "alpine:latest", spec.Image)
	assert.True(t, spec.Privileged)
	assert.Len(t, spec.Mounts, 1)
	assert.Len(t, spec.Ports, 1)
}

func TestComputeHandlers_InstanceToVMResponse_WithNetworkAttachments(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	handlers, _ := setupComputeHandlers(t, vmOrch, containerOrch)

	inst := &compute.Instance{
		ID:        "vm-1",
		Name:      "test-vm",
		Type:      compute.ComputeTypeVM,
		State:     compute.StateRunning,
		PID:       12345,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Config: &compute.InstanceConfig{
			Memory:     4096,
			CPUs:       2,
			DiskPath:   "/var/lib/vms/disk.qcow2",
			DiskSize:   "20G",
			BootMode:   "uefi",
			SecureBoot: true,
			TPMEnabled: true,
		},
		Metadata: map[string]string{"key": "value"},
		NetworkAttachments: []compute.NetworkAttachment{
			{
				PortName:   "eth0",
				BridgeName: "br0",
				VLAN:       100,
				MACAddress: "00:11:22:33:44:55",
				IPAddress:  "192.168.1.100",
				AttachedAt: time.Now(),
			},
		},
	}

	resp := handlers.instanceToVMResponse(inst)

	assert.Equal(t, "vm-1", resp.ID)
	assert.Equal(t, 4096, resp.Memory)
	assert.True(t, resp.TPMEnabled)
	assert.Len(t, resp.NetworkAttachments, 1)
	assert.Equal(t, "eth0", resp.NetworkAttachments[0].PortName)
}

func TestComputeHandlers_ContainerToComputeResponse(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	handlers, _ := setupComputeHandlers(t, vmOrch, containerOrch)

	c := &container.Container{
		ID:         "c-1",
		Name:       "test-container",
		Image:      "alpine:latest",
		ImageID:    "sha256:abc123",
		State:      container.StateRunning,
		Pid:        12345,
		ExitCode:   0,
		CreatedAt:  time.Now(),
		StartedAt:  time.Now(),
		FinishedAt: time.Time{},
		Labels:     map[string]string{"app": "test"},
		Platform:   "linux/amd64",
	}

	resp := handlers.containerToComputeResponse(c)

	assert.Equal(t, "c-1", resp.ID)
	assert.Equal(t, "test-container", resp.Name)
	assert.Equal(t, "container", resp.Type)
	assert.Equal(t, "alpine:latest", resp.Image)
}

func TestComputeHandlers_AttestationReportToVMResponse(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	handlers, _ := setupComputeHandlers(t, vmOrch, containerOrch)

	report := &VMAttestationReport{
		VMID:      "vm-1",
		VMName:    "test-vm",
		Timestamp: time.Now(),
		Verified:  true,
		PCRValues: map[int][]byte{
			0: {0x01, 0x02, 0x03},
			7: {0x04, 0x05, 0x06},
		},
		Quote:     []byte("quote-data"),
		Signature: []byte("sig-data"),
		EventLog:  []byte("event-log"),
	}

	resp := handlers.attestationReportToVMResponse(report)

	assert.Equal(t, "vm-1", resp.VMID)
	assert.True(t, resp.Verified)
	assert.NotEmpty(t, resp.Quote)
	assert.NotEmpty(t, resp.PCRValues)
}

func TestComputeHandlers_AttestationReportToContainerResponse(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	handlers, _ := setupComputeHandlers(t, vmOrch, containerOrch)

	report := &container.AttestationReport{
		ContainerID:   "c-1",
		ContainerName: "test-container",
		Timestamp:     time.Now(),
		Verified:      true,
		ImageDigest:   []byte("image-digest"),
		ConfigDigest:  []byte("config-digest"),
		Quote:         []byte("quote"),
		Signature:     []byte("signature"),
		PCRValues: map[int][]byte{
			0: {0x01, 0x02},
		},
	}

	resp := handlers.attestationReportToContainerResponse(report)

	assert.Equal(t, "c-1", resp.ContainerID)
	assert.True(t, resp.Verified)
	assert.NotEmpty(t, resp.ImageDigest)
}

func TestComputeHandlers_RegisterRoutes(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	// Add test VM for routes that need existing resources
	vmOrch.addTestVM("test", "test-vm", compute.StateRunning)

	containerOrch := newMockComputeContainerOrchestrator()
	// Add test container for routes that need existing resources
	containerOrch.addTestContainer("test", "test-container", container.StateRunning)

	logger := slog.Default()
	handlers := NewComputeHandlers(vmOrch, containerOrch, logger)
	router := mux.NewRouter()

	handlers.RegisterRoutes(router)

	// Verify that routes are registered by checking Content-Type header
	// Our handlers always set Content-Type to application/json
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/compute/vms"},
		{http.MethodGet, "/api/v1/compute/vms"},
		{http.MethodGet, "/api/v1/compute/vms/test"},
		{http.MethodDelete, "/api/v1/compute/vms/test"},
		{http.MethodPost, "/api/v1/compute/vms/test/start"},
		{http.MethodPost, "/api/v1/compute/vms/test/stop"},
		{http.MethodPost, "/api/v1/compute/vms/test/restart"},
		{http.MethodPost, "/api/v1/compute/vms/test/suspend"},
		{http.MethodPost, "/api/v1/compute/vms/test/resume"},
		{http.MethodPost, "/api/v1/compute/vms/test/attest"},
		{http.MethodGet, "/api/v1/compute/vms/test/console"},
		{http.MethodPost, "/api/v1/compute/containers"},
		{http.MethodGet, "/api/v1/compute/containers"},
		{http.MethodGet, "/api/v1/compute/containers/test"},
		{http.MethodDelete, "/api/v1/compute/containers/test"},
		{http.MethodPost, "/api/v1/compute/containers/test/start"},
		{http.MethodPost, "/api/v1/compute/containers/test/stop"},
		{http.MethodGet, "/api/v1/compute/containers/test/logs"},
		{http.MethodPost, "/api/v1/compute/containers/test/exec"},
		{http.MethodPost, "/api/v1/compute/containers/test/attest"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			// Route is registered if Content-Type is application/json (set by our handlers)
			// If route is not found, mux returns plain text "404 page not found"
			contentType := rec.Header().Get("Content-Type")
			assert.Contains(t, contentType, "application/json", "Route should be registered: %s %s", route.method, route.path)
		})
	}
}

// =============================================================================
// NewComputeHandlers Tests
// =============================================================================

func TestNewComputeHandlers_WithNilLogger(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()

	handlers := NewComputeHandlers(vmOrch, containerOrch, nil)

	assert.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestComputeHandlers_ErrorTypes(t *testing.T) {
	t.Run("ErrVMOrchestratorNotAvailable", func(t *testing.T) {
		err := ErrVMOrchestratorNotAvailable{}
		assert.Equal(t, "VM orchestrator not available", err.Error())
	})

	t.Run("ErrVMOperationFailed", func(t *testing.T) {
		cause := errors.New("test error")
		err := ErrVMOperationFailed{Operation: "start", Cause: cause}
		assert.Contains(t, err.Error(), "VM operation start failed")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrComputeOperationNotSupported", func(t *testing.T) {
		err := ErrComputeOperationNotSupported{Operation: "migrate"}
		assert.Equal(t, "compute operation migrate not supported", err.Error())
	})

	t.Run("ErrInvalidComputeVMID_Empty", func(t *testing.T) {
		err := ErrInvalidComputeVMID{}
		assert.Equal(t, "VM ID is required", err.Error())
	})

	t.Run("ErrInvalidComputeVMID_WithID", func(t *testing.T) {
		err := ErrInvalidComputeVMID{ID: "bad-id"}
		assert.Equal(t, "invalid VM ID: bad-id", err.Error())
	})
}

// =============================================================================
// VM Error Mapping Tests
// =============================================================================

func TestComputeHandlers_WriteVMError_AllCases(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	handlers, _ := setupComputeHandlers(t, vmOrch, containerOrch)

	errorCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"ErrInstanceNotFound", compute.ErrInstanceNotFound, http.StatusNotFound},
		{"ErrInstanceAlreadyExists", compute.ErrInstanceAlreadyExists, http.StatusConflict},
		{"ErrInstanceAlreadyRunning", compute.ErrInstanceAlreadyRunning, http.StatusConflict},
		{"ErrInstanceNotRunning", compute.ErrInstanceNotRunning, http.StatusConflict},
		{"ErrInvalidInstanceID", compute.ErrInvalidInstanceID, http.StatusBadRequest},
		{"ErrInvalidProfile", compute.ErrInvalidProfile, http.StatusBadRequest},
		{"ErrInvalidState", compute.ErrInvalidState, http.StatusConflict},
		{"ErrResourceExhausted", compute.ErrResourceExhausted, http.StatusServiceUnavailable},
		{"ErrOrchestratorNotInitialized", compute.ErrOrchestratorNotInitialized, http.StatusServiceUnavailable},
		{"ErrTimeout", compute.ErrTimeout, http.StatusGatewayTimeout},
		{"ErrUnsupportedOperation", compute.ErrUnsupportedOperation, http.StatusNotImplemented},
		{"UnknownError", errors.New("unknown error"), http.StatusInternalServerError},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handlers.writeVMError(rec, "test", tc.err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

// =============================================================================
// Container Error Mapping Tests
// =============================================================================

func TestComputeHandlers_WriteContainerComputeError_AllCases(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	handlers, _ := setupComputeHandlers(t, vmOrch, containerOrch)

	errorCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"ErrContainerNotFound", container.ErrContainerNotFound, http.StatusNotFound},
		{"ErrContainerExists", container.ErrContainerExists, http.StatusConflict},
		{"ErrContainerRunning", container.ErrContainerRunning, http.StatusConflict},
		{"ErrContainerStopped", container.ErrContainerStopped, http.StatusConflict},
		{"ErrInvalidSpec", container.ErrInvalidSpec, http.StatusBadRequest},
		{"ErrInvalidName", container.ErrInvalidName, http.StatusBadRequest},
		{"ErrInvalidImage", container.ErrInvalidImage, http.StatusBadRequest},
		{"ErrAttestationFailed", container.ErrAttestationFailed, http.StatusInternalServerError},
		{"ErrPolicyDenied", container.ErrPolicyDenied, http.StatusForbidden},
		{"ErrOperationTimeout", container.ErrOperationTimeout, http.StatusGatewayTimeout},
		{"ErrImageNotFound", container.ErrImageNotFound, http.StatusNotFound},
		{"ErrImageVerificationFailed", container.ErrImageVerificationFailed, http.StatusForbidden},
		{"ErrOrchestratorNotInitialized", container.ErrOrchestratorNotInitialized, http.StatusServiceUnavailable},
		{"UnknownError", errors.New("unknown error"), http.StatusInternalServerError},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handlers.writeContainerComputeError(rec, "test", tc.err)
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

// =============================================================================
// Additional Error Scenario Tests
// =============================================================================

func TestComputeHandlers_ListVMs_OrchestratorError(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.listErr = errors.New("list error")
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestComputeHandlers_ListContainers_OrchestratorError(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.listErr = errors.New("list error")
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/containers", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestComputeHandlers_CreateContainer_OrchestratorError(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.createErr = errors.New("create error")
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := createTestRequest(http.MethodPost, "/api/v1/compute/containers", CreateComputeContainerRequest{
		Name:  "test-container",
		Image: "alpine:latest",
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestComputeHandlers_AttestVM_InvalidBody(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	vmOrch.addTestVM("vm-1", "test-vm", compute.StateRunning)
	containerOrch := newMockComputeContainerOrchestrator()
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/vms/vm-1/attest", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = 12
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestComputeHandlers_AttestContainer_InvalidBody(t *testing.T) {
	vmOrch := newMockVMOrchestrator()
	containerOrch := newMockComputeContainerOrchestrator()
	containerOrch.addTestContainer("c-1", "test-container", container.StateRunning)
	_, router := setupComputeHandlers(t, vmOrch, containerOrch)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compute/containers/c-1/attest", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = 12
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
