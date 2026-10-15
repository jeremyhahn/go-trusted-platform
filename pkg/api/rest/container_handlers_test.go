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
// Mock Orchestrator
// =============================================================================

type mockOrchestrator struct {
	instances      map[string]*compute.Instance
	createErr      error
	startErr       error
	stopErr        error
	deleteErr      error
	listErr        error
	getErr         error
	getStateErr    error
	logsErr        error
	attestErr      error
	logsContent    string
	attestReport   *container.AttestationReport
	createResponse *compute.Instance
}

func newMockOrchestrator() *mockOrchestrator {
	return &mockOrchestrator{
		instances: make(map[string]*compute.Instance),
	}
}

func (m *mockOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	if m.createResponse != nil {
		m.instances[m.createResponse.ID] = m.createResponse
		return m.createResponse, nil
	}
	inst := &compute.Instance{
		ID:        "test-container-123",
		Name:      profile.Name,
		Type:      compute.ComputeTypeContainer,
		State:     compute.StateStopped,
		Profile:   profile,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata: map[string]string{
			"image": "docker.io/library/alpine:latest",
		},
	}
	m.instances[inst.ID] = inst
	return inst, nil
}

func (m *mockOrchestrator) Start(ctx context.Context, instanceID string) error {
	if m.startErr != nil {
		return m.startErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}
	inst.State = compute.StateRunning
	inst.UpdatedAt = time.Now()
	return nil
}

func (m *mockOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.ErrInstanceNotFound
	}
	inst.State = compute.StateStopped
	inst.UpdatedAt = time.Now()
	return nil
}

func (m *mockOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}
	delete(m.instances, instanceID)
	return nil
}

func (m *mockOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]*compute.Instance, 0, len(m.instances))
	for _, inst := range m.instances {
		if filter != nil && !filter.Matches(inst) {
			continue
		}
		result = append(result, inst)
	}
	return result, nil
}

func (m *mockOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return nil, compute.ErrInstanceNotFound
	}
	return inst, nil
}

func (m *mockOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	if m.getStateErr != nil {
		return compute.StateUnknown, m.getStateErr
	}
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.StateUnknown, compute.ErrInstanceNotFound
	}
	return inst.State, nil
}

// Implement ExtendedContainerOrchestrator interface
func (m *mockOrchestrator) Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
	if m.logsErr != nil {
		return nil, m.logsErr
	}
	if _, ok := m.instances[id]; !ok {
		return nil, compute.ErrInstanceNotFound
	}
	content := m.logsContent
	if content == "" {
		content = "test log line 1\ntest log line 2\n"
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

func (m *mockOrchestrator) Attest(ctx context.Context, id string) (*container.AttestationReport, error) {
	if m.attestErr != nil {
		return nil, m.attestErr
	}
	if _, ok := m.instances[id]; !ok {
		return nil, compute.ErrInstanceNotFound
	}
	if m.attestReport != nil {
		return m.attestReport, nil
	}
	return &container.AttestationReport{
		ContainerID:   id,
		ContainerName: "test-container",
		Timestamp:     time.Now(),
		Verified:      true,
		ImageDigest:   testCanonicalImageDigest,
		ConfigDigest:  testCanonicalConfigDigest,
		Quote:         []byte{0x07, 0x08, 0x09},
		Signature:     []byte{0x0a, 0x0b, 0x0c},
		PCRValues: map[int][]byte{
			14: {0x0d, 0x0e, 0x0f},
		},
	}, nil
}

// addTestInstance adds a test instance to the mock orchestrator.
func (m *mockOrchestrator) addTestInstance(id, name string, state compute.InstanceState) {
	m.instances[id] = &compute.Instance{
		ID:        id,
		Name:      name,
		Type:      compute.ComputeTypeContainer,
		State:     state,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata: map[string]string{
			"image": "docker.io/library/alpine:latest",
		},
	}
}

// =============================================================================
// Mock Orchestrator with Streaming Support
// =============================================================================

// streamingMockOrchestrator provides streaming log support for testing SSE
type streamingMockOrchestrator struct {
	mockOrchestrator
	logsReader io.ReadCloser
}

func newStreamingMockOrchestrator() *streamingMockOrchestrator {
	return &streamingMockOrchestrator{
		mockOrchestrator: mockOrchestrator{
			instances: make(map[string]*compute.Instance),
		},
	}
}

func (m *streamingMockOrchestrator) Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
	if m.logsErr != nil {
		return nil, m.logsErr
	}
	if _, ok := m.instances[id]; !ok {
		return nil, compute.ErrInstanceNotFound
	}
	if m.logsReader != nil {
		return m.logsReader, nil
	}
	content := m.logsContent
	if content == "" {
		content = "test log line 1\ntest log line 2\n"
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupTestHandler(orch *mockOrchestrator) (*ContainerHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewContainerHandlers(orch, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func decodeResponse(t *testing.T, body io.Reader, v interface{}) {
	t.Helper()
	err := json.NewDecoder(body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestContainerHandlerErrors(t *testing.T) {
	t.Run("ErrContainerOrchestratorNotAvailable", func(t *testing.T) {
		err := ErrContainerOrchestratorNotAvailable{}
		assert.Equal(t, "container orchestrator not available", err.Error())
	})

	t.Run("ErrInvalidContainerID with empty ID", func(t *testing.T) {
		err := ErrInvalidContainerID{}
		assert.Equal(t, "container ID is required", err.Error())
	})

	t.Run("ErrInvalidContainerID with ID", func(t *testing.T) {
		err := ErrInvalidContainerID{ID: "bad-id"}
		assert.Equal(t, "invalid container ID: bad-id", err.Error())
	})

	t.Run("ErrInvalidRequestBody", func(t *testing.T) {
		err := ErrInvalidRequestBody{Reason: "invalid JSON"}
		assert.Equal(t, "invalid request body: invalid JSON", err.Error())
	})

	t.Run("ErrMissingRequiredField", func(t *testing.T) {
		err := ErrMissingRequiredField{Field: "name"}
		assert.Equal(t, "missing required field: name", err.Error())
	})

	t.Run("ErrContainerOperationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrContainerOperationFailed{Operation: "start", Cause: cause}
		assert.Equal(t, "container operation start failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewContainerHandlers(t *testing.T) {
	t.Run("creates handlers with orchestrator and logger", func(t *testing.T) {
		orch := newMockOrchestrator()
		logger := slog.Default()
		handlers := NewContainerHandlers(orch, logger)
		require.NotNil(t, handlers)
		assert.Equal(t, orch, handlers.orchestrator)
		assert.Equal(t, logger, handlers.logger)
	})

	t.Run("creates handlers with nil logger uses default", func(t *testing.T) {
		orch := newMockOrchestrator()
		handlers := NewContainerHandlers(orch, nil)
		require.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
	})
}

func TestRegisterRoutes(t *testing.T) {
	t.Run("registers all container routes", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		// Verify routes are registered
		routes := []struct {
			method string
			path   string
		}{
			{http.MethodPost, "/api/v1/containers"},
			{http.MethodGet, "/api/v1/containers"},
			{http.MethodGet, "/api/v1/containers/test-id"},
			{http.MethodDelete, "/api/v1/containers/test-id"},
			{http.MethodPost, "/api/v1/containers/test-id/start"},
			{http.MethodPost, "/api/v1/containers/test-id/stop"},
			{http.MethodGet, "/api/v1/containers/test-id/logs"},
			{http.MethodPost, "/api/v1/containers/test-id/attest"},
		}

		for _, route := range routes {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			matched := router.Match(req, match)
			assert.True(t, matched, "Route %s %s should be registered", route.method, route.path)
		}
	})
}

// =============================================================================
// Create Container Tests
// =============================================================================

func TestHandleCreateContainer(t *testing.T) {
	t.Run("creates container successfully", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		reqBody := CreateContainerRequest{
			Name:  "test-container",
			Image: "alpine:latest",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var containerResp ContainerResponse
		decodeResponse(t, resp.Body, &containerResp)
		assert.Equal(t, "test-container", containerResp.Name)
		assert.Equal(t, "stopped", containerResp.State)
	})

	t.Run("creates container with profile ID", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		reqBody := CreateContainerRequest{
			Name:      "test-container",
			ProfileID: 123,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("returns error when orchestrator not available", func(t *testing.T) {
		handlers := NewContainerHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := CreateContainerRequest{Name: "test"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON body", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers", strings.NewReader("invalid json"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when name is missing", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		reqBody := CreateContainerRequest{Image: "alpine:latest"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp ErrorResponse
		decodeResponse(t, resp.Body, &errResp)
		assert.Contains(t, errResp.Error, "name")
	})

	t.Run("returns error when creation fails", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.createErr = compute.ErrResourceExhausted
		_, router := setupTestHandler(orch)

		reqBody := CreateContainerRequest{Name: "test"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// List Containers Tests
// =============================================================================

func TestHandleListContainers(t *testing.T) {
	t.Run("returns empty list when no containers", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp ContainerListResponse
		decodeResponse(t, resp.Body, &listResp)
		assert.Equal(t, 0, listResp.Count)
		assert.NotNil(t, listResp.Containers)
	})

	t.Run("returns list of containers", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("id1", "container1", compute.StateRunning)
		orch.addTestInstance("id2", "container2", compute.StateStopped)
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp ContainerListResponse
		decodeResponse(t, resp.Body, &listResp)
		assert.Equal(t, 2, listResp.Count)
	})

	t.Run("filters by state", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("id1", "container1", compute.StateRunning)
		orch.addTestInstance("id2", "container2", compute.StateStopped)
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers?state=running", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp ContainerListResponse
		decodeResponse(t, resp.Body, &listResp)
		assert.Equal(t, 1, listResp.Count)
		assert.Equal(t, "running", listResp.Containers[0].State)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.listErr = errors.New("list failed")
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when orchestrator not available", func(t *testing.T) {
		handlers := NewContainerHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Get Container Tests
// =============================================================================

func TestHandleGetContainer(t *testing.T) {
	t.Run("returns container by ID", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var containerResp ContainerResponse
		decodeResponse(t, resp.Body, &containerResp)
		assert.Equal(t, "test-id", containerResp.ID)
		assert.Equal(t, "test-container", containerResp.Name)
		assert.Equal(t, "running", containerResp.State)
	})

	t.Run("returns 404 for non-existent container", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when orchestrator not available", func(t *testing.T) {
		handlers := NewContainerHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Start Container Tests
// =============================================================================

func TestHandleStartContainer(t *testing.T) {
	t.Run("starts container successfully", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateStopped)
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp ContainerActionResponse
		decodeResponse(t, resp.Body, &actionResp)
		assert.Equal(t, "test-id", actionResp.ContainerID)
		assert.Equal(t, "start", actionResp.Action)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns error for non-existent container", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/nonexistent/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when start fails", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateStopped)
		orch.startErr = compute.ErrInstanceAlreadyRunning
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("returns error when orchestrator not available", func(t *testing.T) {
		handlers := NewContainerHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Stop Container Tests
// =============================================================================

func TestHandleStopContainer(t *testing.T) {
	t.Run("stops container successfully", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp ContainerActionResponse
		decodeResponse(t, resp.Body, &actionResp)
		assert.Equal(t, "test-id", actionResp.ContainerID)
		assert.Equal(t, "stop", actionResp.Action)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns error for non-existent container", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/nonexistent/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when stop fails", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		orch.stopErr = compute.ErrInstanceNotRunning
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("returns error when orchestrator not available", func(t *testing.T) {
		handlers := NewContainerHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Remove Container Tests
// =============================================================================

func TestHandleRemoveContainer(t *testing.T) {
	t.Run("removes container successfully", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateStopped)
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/containers/test-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp ContainerActionResponse
		decodeResponse(t, resp.Body, &actionResp)
		assert.Equal(t, "test-id", actionResp.ContainerID)
		assert.Equal(t, "remove", actionResp.Action)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns error for non-existent container", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/containers/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when delete fails", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateStopped)
		orch.deleteErr = compute.ErrInvalidState
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/containers/test-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("returns error when orchestrator not available", func(t *testing.T) {
		handlers := NewContainerHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/containers/test-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Container Logs Tests
// =============================================================================

func TestHandleGetContainerLogs(t *testing.T) {
	t.Run("returns container logs", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		orch.logsContent = "log line 1\nlog line 2\n"
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id/logs", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var logsResp ContainerLogsResponse
		decodeResponse(t, resp.Body, &logsResp)
		assert.Equal(t, "test-id", logsResp.ContainerID)
		assert.Contains(t, logsResp.Logs, "log line 1")
		assert.Contains(t, logsResp.Logs, "log line 2")
	})

	t.Run("returns error for non-existent container", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/nonexistent/logs", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when logs fetch fails", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		orch.logsErr = errors.New("logs unavailable")
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id/logs", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("respects query parameters", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id/logs?tail=100&timestamps=true&stdout=true&stderr=false", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error when orchestrator not available", func(t *testing.T) {
		handlers := NewContainerHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id/logs", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Container Logs Streaming Tests
// =============================================================================

// errorReader returns an error when Read is called after the first read
type errorReader struct {
	firstRead bool
	content   string
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	if !r.firstRead {
		r.firstRead = true
		copy(p, r.content)
		return len(r.content), nil
	}
	return 0, io.EOF
}

func (r *errorReader) Close() error {
	return nil
}

func TestStreamContainerLogs(t *testing.T) {
	t.Run("streams logs with follow parameter", func(t *testing.T) {
		orch := newStreamingMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		orch.logsReader = &errorReader{content: "streaming log\n"}

		handlers := NewContainerHandlers(orch, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id/logs?follow=true", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
		assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))
		assert.Equal(t, "keep-alive", resp.Header.Get("Connection"))
	})

	t.Run("streams logs error on initial fetch", func(t *testing.T) {
		orch := newStreamingMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		orch.logsErr = errors.New("stream error")

		handlers := NewContainerHandlers(orch, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id/logs?follow=true", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("streaming logs with context cancellation", func(t *testing.T) {
		orch := newStreamingMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)

		// Create a reader that blocks until context is canceled
		pr, pw := io.Pipe()
		orch.logsReader = pr

		handlers := NewContainerHandlers(orch, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id/logs?follow=true", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		streamed := make(chan error, 2)
		go func() {
			// A pipe write returns only once the handler has read it, so
			// the stream loop is live when the context is cancelled.
			_, err := pw.Write([]byte("line 1\n"))
			streamed <- err
			cancel()
			// A handler blocked in Read takes this line and then sees the
			// cancelled context; one that already returned closed the
			// reader, which fails the write with io.ErrClosedPipe.
			_, err = pw.Write([]byte("line 2\n"))
			streamed <- err
		}()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.NoError(t, <-streamed)
		if err := <-streamed; err != nil {
			assert.ErrorIs(t, err, io.ErrClosedPipe)
		}

		// Response should be OK because we set up SSE headers before
		// streaming, and the stream ends on the context, not on EOF.
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NotContains(t, w.Body.String(), "event: end")
	})
}

// =============================================================================
// Container Attestation Tests
// =============================================================================

func TestHandleAttestContainer(t *testing.T) {
	t.Run("attests container successfully", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/attest", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var attestResp AttestContainerResponse
		decodeResponse(t, resp.Body, &attestResp)
		assert.Equal(t, "test-id", attestResp.ContainerID)
		assert.True(t, attestResp.Verified)
		assert.NotEmpty(t, attestResp.ImageDigest)
		assert.NotEmpty(t, attestResp.Quote)
		assert.NotEmpty(t, attestResp.Signature)
	})

	t.Run("attests with request body", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		_, router := setupTestHandler(orch)

		reqBody := AttestContainerRequest{
			Nonce:           "test-nonce",
			IncludePCRs:     []int{14, 15},
			IncludeEventLog: true,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/attest", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error for non-existent container", func(t *testing.T) {
		orch := newMockOrchestrator()
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/nonexistent/attest", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when attestation fails", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		orch.attestErr = container.ErrAttestationFailed
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/attest", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error for invalid request body", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/attest", strings.NewReader("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = 12
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when orchestrator not available", func(t *testing.T) {
		handlers := NewContainerHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/attest", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestWriteContainerError(t *testing.T) {
	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"instance not found", compute.ErrInstanceNotFound, http.StatusNotFound},
		{"instance already exists", compute.ErrInstanceAlreadyExists, http.StatusConflict},
		{"instance already running", compute.ErrInstanceAlreadyRunning, http.StatusConflict},
		{"instance not running", compute.ErrInstanceNotRunning, http.StatusConflict},
		{"invalid instance ID", compute.ErrInvalidInstanceID, http.StatusBadRequest},
		{"invalid profile", compute.ErrInvalidProfile, http.StatusBadRequest},
		{"invalid state", compute.ErrInvalidState, http.StatusConflict},
		{"resource exhausted", compute.ErrResourceExhausted, http.StatusServiceUnavailable},
		{"orchestrator not initialized", compute.ErrOrchestratorNotInitialized, http.StatusServiceUnavailable},
		{"container not found", container.ErrContainerNotFound, http.StatusNotFound},
		{"container exists", container.ErrContainerExists, http.StatusConflict},
		{"container running", container.ErrContainerRunning, http.StatusConflict},
		{"container stopped", container.ErrContainerStopped, http.StatusConflict},
		{"attestation failed", container.ErrAttestationFailed, http.StatusInternalServerError},
		{"policy denied", container.ErrPolicyDenied, http.StatusForbidden},
		{"unknown error", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			orch := newMockOrchestrator()
			handlers := NewContainerHandlers(orch, slog.Default())

			w := httptest.NewRecorder()
			handlers.writeContainerError(w, "test", tc.err)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestParseListFilter(t *testing.T) {
	handlers := NewContainerHandlers(nil, nil)

	t.Run("parses state filter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers?state=running", nil)
		filter := handlers.parseListFilter(req)

		require.NotNil(t, filter.State)
		assert.Equal(t, compute.StateRunning, *filter.State)
	})

	t.Run("parses name filter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers?name=test", nil)
		filter := handlers.parseListFilter(req)

		assert.Equal(t, "test", filter.Name)
	})

	t.Run("sets container type filter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers", nil)
		filter := handlers.parseListFilter(req)

		require.NotNil(t, filter.Type)
		assert.Equal(t, compute.ComputeTypeContainer, *filter.Type)
	})

	t.Run("ignores invalid state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers?state=invalid", nil)
		filter := handlers.parseListFilter(req)

		assert.Nil(t, filter.State)
	})
}

func TestParseLogOptions(t *testing.T) {
	handlers := NewContainerHandlers(nil, nil)

	t.Run("default options", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test/logs", nil)
		opts := handlers.parseLogOptions(req)

		assert.True(t, opts.Stdout)
		assert.True(t, opts.Stderr)
	})

	t.Run("parses stdout false", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test/logs?stdout=false", nil)
		opts := handlers.parseLogOptions(req)

		assert.False(t, opts.Stdout)
		assert.True(t, opts.Stderr)
	})

	t.Run("parses stderr false", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test/logs?stderr=false", nil)
		opts := handlers.parseLogOptions(req)

		assert.True(t, opts.Stdout)
		assert.False(t, opts.Stderr)
	})

	t.Run("parses tail", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test/logs?tail=100", nil)
		opts := handlers.parseLogOptions(req)

		assert.Equal(t, "100", opts.Tail)
	})

	t.Run("parses timestamps", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test/logs?timestamps=true", nil)
		opts := handlers.parseLogOptions(req)

		assert.True(t, opts.Timestamps)
	})

	t.Run("parses since and until", func(t *testing.T) {
		since := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
		until := time.Now().Format(time.RFC3339)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test/logs?since="+since+"&until="+until, nil)
		opts := handlers.parseLogOptions(req)

		assert.False(t, opts.Since.IsZero())
		assert.False(t, opts.Until.IsZero())
	})

	t.Run("ignores invalid since", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test/logs?since=invalid", nil)
		opts := handlers.parseLogOptions(req)

		assert.True(t, opts.Since.IsZero())
	})

	t.Run("ignores invalid until", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test/logs?until=invalid", nil)
		opts := handlers.parseLogOptions(req)

		assert.True(t, opts.Until.IsZero())
	})
}

func TestParseBoolParam(t *testing.T) {
	t.Run("returns default for empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		assert.True(t, ParseBoolParam(req, "param", true))
		assert.False(t, ParseBoolParam(req, "param", false))
	})

	t.Run("returns parsed value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?param=true", nil)
		assert.True(t, ParseBoolParam(req, "param", false))

		req = httptest.NewRequest(http.MethodGet, "/test?param=false", nil)
		assert.False(t, ParseBoolParam(req, "param", true))
	})

	t.Run("returns default for invalid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?param=invalid", nil)
		assert.True(t, ParseBoolParam(req, "param", true))
	})
}

func TestParseIntParam(t *testing.T) {
	t.Run("returns default for empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		assert.Equal(t, 42, ParseIntParam(req, "param", 42))
	})

	t.Run("returns parsed value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?param=100", nil)
		assert.Equal(t, 100, ParseIntParam(req, "param", 42))
	})

	t.Run("returns default for invalid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?param=invalid", nil)
		assert.Equal(t, 42, ParseIntParam(req, "param", 42))
	})
}

func TestInstanceToResponse(t *testing.T) {
	handlers := NewContainerHandlers(nil, nil)

	t.Run("converts instance to response", func(t *testing.T) {
		inst := &compute.Instance{
			ID:        "test-id",
			Name:      "test-name",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			PID:       12345,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Metadata: map[string]string{
				"image": "alpine:latest",
			},
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

		resp := handlers.instanceToResponse(inst)

		assert.Equal(t, "test-id", resp.ID)
		assert.Equal(t, "test-name", resp.Name)
		assert.Equal(t, "container", resp.Type)
		assert.Equal(t, "running", resp.State)
		assert.Equal(t, 12345, resp.PID)
		assert.Equal(t, "alpine:latest", resp.Image)
		require.Len(t, resp.NetworkAttachments, 1)
		assert.Equal(t, "eth0", resp.NetworkAttachments[0].PortName)
		assert.Equal(t, "br0", resp.NetworkAttachments[0].BridgeName)
		assert.Equal(t, uint16(100), resp.NetworkAttachments[0].VLAN)
	})

	t.Run("handles instance without metadata", func(t *testing.T) {
		inst := &compute.Instance{
			ID:        "test-id",
			Name:      "test-name",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		resp := handlers.instanceToResponse(inst)

		assert.Equal(t, "test-id", resp.ID)
		assert.Empty(t, resp.Image)
	})

	t.Run("handles instance with nil network attachments", func(t *testing.T) {
		inst := &compute.Instance{
			ID:                 "test-id",
			Name:               "test-name",
			Type:               compute.ComputeTypeContainer,
			State:              compute.StateRunning,
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
			NetworkAttachments: nil,
		}

		resp := handlers.instanceToResponse(inst)

		assert.Nil(t, resp.NetworkAttachments)
	})
}

// Canonical OCI content digests, the form the container attestation report
// now carries end to end.
const (
	testCanonicalImageDigest = "sha256:" +
		"1111111111111111111111111111111111111111111111111111111111111111"
	testCanonicalConfigDigest = "sha256:" +
		"2222222222222222222222222222222222222222222222222222222222222222"
)

func TestAttestationReportToResponse(t *testing.T) {
	handlers := NewContainerHandlers(nil, nil)

	t.Run("converts report to response", func(t *testing.T) {
		report := &container.AttestationReport{
			ContainerID:   "test-id",
			ContainerName: "test-name",
			Verified:      true,
			Timestamp:     time.Now(),
			ImageDigest:   testCanonicalImageDigest,
			ConfigDigest:  testCanonicalConfigDigest,
			Quote:         []byte{0x07, 0x08, 0x09},
			Signature:     []byte{0x0a, 0x0b, 0x0c},
			PCRValues: map[int][]byte{
				14: {0x0d, 0x0e, 0x0f},
			},
		}

		resp := handlers.attestationReportToResponse(report)

		assert.Equal(t, "test-id", resp.ContainerID)
		assert.Equal(t, "test-name", resp.ContainerName)
		assert.True(t, resp.Verified)
		// Digests are already canonical OCI strings and are emitted
		// verbatim rather than hex-encoded a second time.
		assert.Equal(t, testCanonicalImageDigest, resp.ImageDigest)
		assert.Equal(t, testCanonicalConfigDigest, resp.ConfigDigest)
		assert.Equal(t, "070809", resp.Quote)
		assert.Equal(t, "0a0b0c", resp.Signature)
		require.Contains(t, resp.PCRValues, 14)
		assert.Equal(t, "0d0e0f", resp.PCRValues[14])
	})

	t.Run("handles report with empty fields", func(t *testing.T) {
		report := &container.AttestationReport{
			ContainerID:   "test-id",
			ContainerName: "test-name",
			Verified:      false,
			Timestamp:     time.Now(),
		}

		resp := handlers.attestationReportToResponse(report)

		assert.Equal(t, "test-id", resp.ContainerID)
		assert.False(t, resp.Verified)
		assert.Empty(t, resp.ImageDigest)
		assert.Empty(t, resp.ConfigDigest)
		assert.Empty(t, resp.Quote)
		assert.Empty(t, resp.Signature)
		assert.Nil(t, resp.PCRValues)
	})
}

// =============================================================================
// Basic orchestrator without logs/attest support
// =============================================================================

type basicMockOrchestrator struct {
	instances map[string]*compute.Instance
}

func newBasicMockOrchestrator() *basicMockOrchestrator {
	return &basicMockOrchestrator{
		instances: make(map[string]*compute.Instance),
	}
}

func (m *basicMockOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	inst := &compute.Instance{
		ID:        "test-container-123",
		Name:      profile.Name,
		Type:      compute.ComputeTypeContainer,
		State:     compute.StateStopped,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.instances[inst.ID] = inst
	return inst, nil
}

func (m *basicMockOrchestrator) Start(ctx context.Context, instanceID string) error {
	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}
	return nil
}

func (m *basicMockOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}
	return nil
}

func (m *basicMockOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if _, ok := m.instances[instanceID]; !ok {
		return compute.ErrInstanceNotFound
	}
	delete(m.instances, instanceID)
	return nil
}

func (m *basicMockOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	result := make([]*compute.Instance, 0, len(m.instances))
	for _, inst := range m.instances {
		result = append(result, inst)
	}
	return result, nil
}

func (m *basicMockOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	inst, ok := m.instances[instanceID]
	if !ok {
		return nil, compute.ErrInstanceNotFound
	}
	return inst, nil
}

func (m *basicMockOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	inst, ok := m.instances[instanceID]
	if !ok {
		return compute.StateUnknown, compute.ErrInstanceNotFound
	}
	return inst.State, nil
}

func (m *basicMockOrchestrator) addTestInstance(id, name string, state compute.InstanceState) {
	m.instances[id] = &compute.Instance{
		ID:        id,
		Name:      name,
		Type:      compute.ComputeTypeContainer,
		State:     state,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestLogsNotImplemented(t *testing.T) {
	t.Run("returns not implemented for basic orchestrator", func(t *testing.T) {
		orch := newBasicMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		handlers := NewContainerHandlers(orch, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id/logs", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})
}

func TestAttestNotImplemented(t *testing.T) {
	t.Run("returns not implemented for basic orchestrator", func(t *testing.T) {
		orch := newBasicMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		handlers := NewContainerHandlers(orch, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/test-id/attest", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})
}

// =============================================================================
// JSON Response Tests
// =============================================================================

func TestWriteJSON(t *testing.T) {
	handlers := NewContainerHandlers(nil, slog.Default())

	t.Run("writes JSON response with correct headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		data := map[string]string{"key": "value"}

		handlers.writeJSON(w, http.StatusOK, data)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

		var result map[string]string
		err := json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, "value", result["key"])
	})
}

func TestWriteError(t *testing.T) {
	handlers := NewContainerHandlers(nil, slog.Default())

	t.Run("writes error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := errors.New("test error")

		handlers.writeError(w, http.StatusBadRequest, err)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp ErrorResponse
		decErr := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, decErr)
		assert.Equal(t, "test error", errResp.Error)
		assert.Equal(t, http.StatusBadRequest, errResp.Code)
		assert.False(t, errResp.Timestamp.IsZero())
	})
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestEmptyContainerID(t *testing.T) {
	// This tests what happens when the router doesn't match but
	// we still reach the handler (edge case)
	handlers := NewContainerHandlers(newMockOrchestrator(), slog.Default())

	t.Run("get with empty ID handled by router", func(t *testing.T) {
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		// The router won't match this path, so we get 404 from router
		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		// Router returns 404 because the route doesn't match
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestNetworkAttachmentsInResponse(t *testing.T) {
	t.Run("handles instance with network attachments", func(t *testing.T) {
		orch := newMockOrchestrator()
		orch.instances["test-id"] = &compute.Instance{
			ID:        "test-id",
			Name:      "test-container",
			Type:      compute.ComputeTypeContainer,
			State:     compute.StateRunning,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			NetworkAttachments: []compute.NetworkAttachment{
				{
					PortName:   "eth0",
					BridgeName: "br0",
					VLAN:       100,
					MACAddress: "00:11:22:33:44:55",
					IPAddress:  "192.168.1.100",
					AttachedAt: time.Now(),
				},
				{
					PortName:   "eth1",
					BridgeName: "br1",
					VLAN:       200,
					MACAddress: "00:11:22:33:44:66",
					IPAddress:  "10.0.0.100",
					AttachedAt: time.Now(),
				},
			},
		}
		_, router := setupTestHandler(orch)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var containerResp ContainerResponse
		decodeResponse(t, resp.Body, &containerResp)
		require.Len(t, containerResp.NetworkAttachments, 2)
		assert.Equal(t, "eth0", containerResp.NetworkAttachments[0].PortName)
		assert.Equal(t, "eth1", containerResp.NetworkAttachments[1].PortName)
	})
}

func TestBuildProfileFromRequest(t *testing.T) {
	handlers := NewContainerHandlers(nil, nil)

	t.Run("builds profile with name only", func(t *testing.T) {
		req := &CreateContainerRequest{
			Name: "test-container",
		}

		profile := handlers.buildProfileFromRequest(req)

		assert.Equal(t, "test-container", profile.Name)
		assert.Equal(t, uint64(0), profile.ID)
	})

	t.Run("builds profile with profile ID", func(t *testing.T) {
		req := &CreateContainerRequest{
			Name:      "test-container",
			ProfileID: 123,
		}

		profile := handlers.buildProfileFromRequest(req)

		assert.Equal(t, "test-container", profile.Name)
		assert.Equal(t, uint64(123), profile.ID)
	})
}

// =============================================================================
// Read Error Handling Tests
// =============================================================================

// failingReader returns an error when Read is called
type failingReader struct{}

func (r *failingReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func (r *failingReader) Close() error {
	return nil
}

func TestLogsReadError(t *testing.T) {
	t.Run("handles read error from logs reader", func(t *testing.T) {
		orch := newStreamingMockOrchestrator()
		orch.addTestInstance("test-id", "test-container", compute.StateRunning)
		orch.logsReader = &failingReader{}

		handlers := NewContainerHandlers(orch, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/containers/test-id/logs", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		// Should return error because ReadAll fails
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}
