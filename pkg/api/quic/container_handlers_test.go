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
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = quicwire.SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock Container Orchestrator
// =============================================================================

// mockContainerOrchestrator implements container.ContainerOrchestrator for testing
type mockContainerOrchestrator struct {
	containers   map[string]*container.Container
	createError  error
	startError   error
	stopError    error
	removeError  error
	getError     error
	listError    error
	logsError    error
	attestError  error
	attestReport *container.AttestationReport
	logsContent  string
	closed       bool
}

func newMockContainerOrchestrator() *mockContainerOrchestrator {
	return &mockContainerOrchestrator{
		containers: make(map[string]*container.Container),
	}
}

func (m *mockContainerOrchestrator) Create(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.Container, error) {
	if m.createError != nil {
		return nil, m.createError
	}

	c := &container.Container{
		ID:        "test-container-id",
		Name:      spec.Name,
		Image:     spec.Image,
		ImageID:   "sha256:abc123",
		State:     container.StateCreated,
		CreatedAt: time.Now(),
		Labels:    spec.Labels,
		Platform:  "linux/amd64",
	}

	m.containers[c.ID] = c
	return c, nil
}

func (m *mockContainerOrchestrator) Start(ctx context.Context, id string) error {
	if m.startError != nil {
		return m.startError
	}

	c, ok := m.containers[id]
	if !ok {
		return container.ErrContainerNotFound
	}

	c.State = container.StateRunning
	c.StartedAt = time.Now()
	return nil
}

func (m *mockContainerOrchestrator) Stop(ctx context.Context, id string, timeout time.Duration) error {
	if m.stopError != nil {
		return m.stopError
	}

	c, ok := m.containers[id]
	if !ok {
		return container.ErrContainerNotFound
	}

	c.State = container.StateStopped
	c.FinishedAt = time.Now()
	return nil
}

func (m *mockContainerOrchestrator) Remove(ctx context.Context, id string, force bool) error {
	if m.removeError != nil {
		return m.removeError
	}

	if _, ok := m.containers[id]; !ok {
		return container.ErrContainerNotFound
	}

	delete(m.containers, id)
	return nil
}

func (m *mockContainerOrchestrator) Get(ctx context.Context, id string) (*container.Container, error) {
	if m.getError != nil {
		return nil, m.getError
	}

	c, ok := m.containers[id]
	if !ok {
		return nil, container.ErrContainerNotFound
	}

	return c, nil
}

func (m *mockContainerOrchestrator) List(ctx context.Context, opts container.ListOptions) ([]*container.Container, error) {
	if m.listError != nil {
		return nil, m.listError
	}

	result := make([]*container.Container, 0, len(m.containers))
	for _, c := range m.containers {
		result = append(result, c)
	}

	return result, nil
}

func (m *mockContainerOrchestrator) Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
	if m.logsError != nil {
		return nil, m.logsError
	}

	if _, ok := m.containers[id]; !ok {
		return nil, container.ErrContainerNotFound
	}

	content := m.logsContent
	if content == "" {
		content = "test log output\n"
	}

	return io.NopCloser(strings.NewReader(content)), nil
}

func (m *mockContainerOrchestrator) Attest(ctx context.Context, id string) (*container.AttestationReport, error) {
	if m.attestError != nil {
		return nil, m.attestError
	}

	if _, ok := m.containers[id]; !ok {
		return nil, container.ErrContainerNotFound
	}

	if m.attestReport != nil {
		return m.attestReport, nil
	}

	return &container.AttestationReport{
		ContainerID:   id,
		ContainerName: "test-container",
		Verified:      true,
		Timestamp:     time.Now(),
		Quote:         []byte("test-quote"),
		Signature:     []byte("test-signature"),
		ImageDigest:   "test-image-digest",
		ConfigDigest:  "test-config-digest",
		PCRValues:     map[int][]byte{14: []byte("test-pcr-value")},
	}, nil
}

func (m *mockContainerOrchestrator) VerifyAttestation(ctx context.Context, id string, evidence []byte) error {
	return nil
}

func (m *mockContainerOrchestrator) EvaluatePolicy(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.PolicyDecision, error) {
	return &container.PolicyDecision{
		Allowed:   true,
		Timestamp: time.Now(),
	}, nil
}

func (m *mockContainerOrchestrator) PullImage(ctx context.Context, ref string, opts container.PullOptions) error {
	return nil
}

func (m *mockContainerOrchestrator) VerifyImage(ctx context.Context, ref string) (*container.ImageVerification, error) {
	return &container.ImageVerification{
		ImageRef:  ref,
		Verified:  true,
		Timestamp: time.Now(),
	}, nil
}

func (m *mockContainerOrchestrator) Close() error {
	m.closed = true
	return nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestContainerHandler() (*ContainerHandler, *mockContainerOrchestrator) {
	logger := newTestLogger()
	orchestrator := newMockContainerOrchestrator()
	handler := NewContainerHandler(logger, orchestrator)
	return handler, orchestrator
}

func createTestContainer(orchestrator *mockContainerOrchestrator, id, name string) *container.Container {
	c := &container.Container{
		ID:        id,
		Name:      name,
		Image:     "test-image:latest",
		ImageID:   "sha256:abc123",
		State:     container.StateCreated,
		CreatedAt: time.Now(),
		Labels:    map[string]string{"env": "test"},
		Platform:  "linux/amd64",
		NetworkSettings: &container.NetworkSettings{
			IPAddress:  "172.17.0.2",
			Gateway:    "172.17.0.1",
			MACAddress: "02:42:ac:11:00:02",
			Ports: map[string][]container.PortBinding{
				"8080/tcp": {{HostIP: "0.0.0.0", HostPort: "80"}},
			},
			Networks: map[string]*container.NetworkInfo{
				"bridge": {
					NetworkID:  "bridge-id",
					IPAddress:  "172.17.0.2",
					Gateway:    "172.17.0.1",
					MACAddress: "02:42:ac:11:00:02",
				},
			},
		},
	}
	orchestrator.containers[id] = c
	return c
}

// =============================================================================
// Test: NewContainerHandler
// =============================================================================

func TestNewContainerHandler(t *testing.T) {
	t.Run("creates handler with valid inputs", func(t *testing.T) {
		logger := newTestLogger()
		orchestrator := newMockContainerOrchestrator()
		handler := NewContainerHandler(logger, orchestrator)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, orchestrator, handler.orchestrator)
	})

	t.Run("creates handler with nil orchestrator", func(t *testing.T) {
		logger := newTestLogger()
		handler := NewContainerHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.orchestrator)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestHandleRequest(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		resp := handler.HandleRequest(context.Background(), nil)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		req := &quicwire.Request{
			Opcode: 0x00, // Unknown opcode for container handler
		}

		resp := handler.HandleRequest(context.Background(), req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown container operation")
	})
}

// =============================================================================
// Test: CreateContainer
// =============================================================================

func TestHandleCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("creates container successfully", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		createReq := &ContainerCreateRequest{
			Name:        "test-container",
			Image:       "nginx:latest",
			Command:     []string{"nginx", "-g", "daemon off;"},
			Env:         map[string]string{"ENV_VAR": "value"},
			Labels:      map[string]string{"app": "test"},
			NetworkMode: "bridge",
			Mounts: []ContainerMount{
				{Source: "/host/path", Target: "/container/path", Type: "bind", ReadOnly: true},
			},
			Ports: []ContainerPort{
				{HostIP: "0.0.0.0", HostPort: 80, ContainerPort: 8080, Protocol: "tcp"},
			},
			CapAdd:        []string{"NET_ADMIN"},
			CapDrop:       []string{"SETUID"},
			CPULimit:      "2",
			MemoryLimit:   "512M",
			RestartPolicy: "always",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var createResp ContainerCreateResponse
		err = quicwire.DecodePayload(resp.Payload, &createResp)
		require.NoError(t, err)

		assert.NotNil(t, createResp.Container)
		assert.Equal(t, "test-container", createResp.Container.Name)
		assert.Equal(t, "nginx:latest", createResp.Container.Image)
		assert.Equal(t, string(container.StateCreated), createResp.Container.State)
		assert.Greater(t, createResp.Timestamp, int64(0))
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewContainerHandler(newTestLogger(), nil)

		createReq := &ContainerCreateRequest{
			Name:  "test-container",
			Image: "nginx:latest",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
		assert.Contains(t, string(resp.Payload), "not available")
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		createReq := &ContainerCreateRequest{
			Image: "nginx:latest",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "name")
	})

	t.Run("returns error for missing image", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		createReq := &ContainerCreateRequest{
			Name: "test-container",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "image")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerCreate,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when create fails", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		orchestrator.createError = container.ErrInvalidSpec

		createReq := &ContainerCreateRequest{
			Name:  "test-container",
			Image: "nginx:latest",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: StartContainer
// =============================================================================

func TestHandleStart(t *testing.T) {
	ctx := context.Background()

	t.Run("starts container successfully", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")

		startReq := &ContainerStartRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var startResp ContainerStartResponse
		err = quicwire.DecodePayload(resp.Payload, &startResp)
		require.NoError(t, err)

		assert.Equal(t, "container-1", startResp.ID)
		assert.True(t, startResp.Success)
		assert.Greater(t, startResp.Timestamp, int64(0))
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewContainerHandler(newTestLogger(), nil)

		startReq := &ContainerStartRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		startReq := &ContainerStartRequest{}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "ID")
	})

	t.Run("returns error for container not found", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		startReq := &ContainerStartRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error when start fails", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")
		orchestrator.startError = container.ErrContainerRunning

		startReq := &ContainerStartRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: StopContainer
// =============================================================================

func TestHandleStop(t *testing.T) {
	ctx := context.Background()

	t.Run("stops container successfully", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")

		stopReq := &ContainerStopRequest{
			ID:      "container-1",
			Timeout: 30,
		}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var stopResp ContainerStopResponse
		err = quicwire.DecodePayload(resp.Payload, &stopResp)
		require.NoError(t, err)

		assert.Equal(t, "container-1", stopResp.ID)
		assert.True(t, stopResp.Success)
	})

	t.Run("uses default timeout when not specified", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")

		stopReq := &ContainerStopRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewContainerHandler(newTestLogger(), nil)

		stopReq := &ContainerStopRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		stopReq := &ContainerStopRequest{}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for container not found", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		stopReq := &ContainerStopRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error when stop times out", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")
		orchestrator.stopError = container.ErrOperationTimeout

		stopReq := &ContainerStopRequest{
			ID:      "container-1",
			Timeout: 1,
		}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusTimeout, resp.Status)
	})
}

// =============================================================================
// Test: RemoveContainer
// =============================================================================

func TestHandleRemove(t *testing.T) {
	ctx := context.Background()

	t.Run("removes container successfully", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")

		removeReq := &ContainerRemoveRequest{
			ID:    "container-1",
			Force: false,
		}

		payload, err := quicwire.EncodePayload(removeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerRemove,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var removeResp ContainerRemoveResponse
		err = quicwire.DecodePayload(resp.Payload, &removeResp)
		require.NoError(t, err)

		assert.Equal(t, "container-1", removeResp.ID)
		assert.True(t, removeResp.Success)
	})

	t.Run("force removes running container", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		c := createTestContainer(orchestrator, "container-1", "test-container")
		c.State = container.StateRunning

		removeReq := &ContainerRemoveRequest{
			ID:    "container-1",
			Force: true,
		}

		payload, err := quicwire.EncodePayload(removeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerRemove,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewContainerHandler(newTestLogger(), nil)

		removeReq := &ContainerRemoveRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(removeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerRemove,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		removeReq := &ContainerRemoveRequest{}

		payload, err := quicwire.EncodePayload(removeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerRemove,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for container not found", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		removeReq := &ContainerRemoveRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(removeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerRemove,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: GetContainer
// =============================================================================

func TestHandleGet(t *testing.T) {
	ctx := context.Background()

	t.Run("gets container successfully", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")

		getReq := &ContainerGetRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var getResp ContainerGetResponse
		err = quicwire.DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Container)
		assert.Equal(t, "container-1", getResp.Container.ID)
		assert.Equal(t, "test-container", getResp.Container.Name)
		assert.NotNil(t, getResp.Container.NetworkSettings)
		assert.Equal(t, "172.17.0.2", getResp.Container.NetworkSettings.IPAddress)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewContainerHandler(newTestLogger(), nil)

		getReq := &ContainerGetRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		getReq := &ContainerGetRequest{}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for container not found", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		getReq := &ContainerGetRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListContainers
// =============================================================================

func TestHandleList(t *testing.T) {
	ctx := context.Background()

	t.Run("lists containers successfully", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container-1")
		createTestContainer(orchestrator, "container-2", "test-container-2")

		listReq := &ContainerListRequest{
			All:   true,
			Limit: 10,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp ContainerListResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(2), listResp.Count)
		assert.Len(t, listResp.Containers, 2)
	})

	t.Run("uses default limit when not specified", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		listReq := &ContainerListRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("caps limit at max", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		listReq := &ContainerListRequest{
			Limit: 5000, // exceeds max
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("applies filters", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container-1")

		listReq := &ContainerListRequest{
			Filters: map[string]string{
				"name": "test",
			},
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewContainerHandler(newTestLogger(), nil)

		listReq := &ContainerListRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		orchestrator.listError = errors.New("list failed")

		listReq := &ContainerListRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: GetContainerLogs
// =============================================================================

func TestHandleLogs(t *testing.T) {
	ctx := context.Background()

	t.Run("gets container logs successfully", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")
		orchestrator.logsContent = "log line 1\nlog line 2\n"

		logsReq := &ContainerLogsRequest{
			ID:     "container-1",
			Stdout: true,
			Stderr: true,
		}

		payload, err := quicwire.EncodePayload(logsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerLogs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var logsResp ContainerLogsResponse
		err = quicwire.DecodePayload(resp.Payload, &logsResp)
		require.NoError(t, err)

		assert.Equal(t, "container-1", logsResp.ID)
		assert.Equal(t, "log line 1\nlog line 2\n", string(logsResp.Logs))
	})

	t.Run("defaults to stdout and stderr", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")

		logsReq := &ContainerLogsRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(logsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerLogs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("respects since and until parameters", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")

		logsReq := &ContainerLogsRequest{
			ID:    "container-1",
			Since: time.Now().Add(-1 * time.Hour).Unix(),
			Until: time.Now().Unix(),
		}

		payload, err := quicwire.EncodePayload(logsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerLogs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewContainerHandler(newTestLogger(), nil)

		logsReq := &ContainerLogsRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(logsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerLogs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		logsReq := &ContainerLogsRequest{}

		payload, err := quicwire.EncodePayload(logsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerLogs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for container not found", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		logsReq := &ContainerLogsRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(logsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerLogs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: AttestContainer
// =============================================================================

func TestHandleAttest(t *testing.T) {
	ctx := context.Background()

	t.Run("attests container successfully", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")

		attestReq := &ContainerAttestRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var attestResp ContainerAttestResponse
		err = quicwire.DecodePayload(resp.Payload, &attestResp)
		require.NoError(t, err)

		assert.Equal(t, "container-1", attestResp.ContainerID)
		assert.True(t, attestResp.Verified)
		assert.NotEmpty(t, attestResp.Quote)
		assert.NotEmpty(t, attestResp.Signature)
		assert.NotEmpty(t, attestResp.ImageDigest)
		assert.NotEmpty(t, attestResp.PCRValues)
	})

	t.Run("returns custom attestation report", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")
		orchestrator.attestReport = &container.AttestationReport{
			ContainerID:   "container-1",
			ContainerName: "custom-container",
			Verified:      false,
			Timestamp:     time.Now(),
			Quote:         []byte("custom-quote"),
			Signature:     []byte("custom-signature"),
		}

		attestReq := &ContainerAttestRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var attestResp ContainerAttestResponse
		err = quicwire.DecodePayload(resp.Payload, &attestResp)
		require.NoError(t, err)

		assert.Equal(t, "custom-container", attestResp.ContainerName)
		assert.False(t, attestResp.Verified)
		assert.Equal(t, []byte("custom-quote"), attestResp.Quote)
	})

	t.Run("returns error when orchestrator unavailable", func(t *testing.T) {
		handler := NewContainerHandler(newTestLogger(), nil)

		attestReq := &ContainerAttestRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		attestReq := &ContainerAttestRequest{}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for container not found", func(t *testing.T) {
		handler, _ := createTestContainerHandler()

		attestReq := &ContainerAttestRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error when attestation fails", func(t *testing.T) {
		handler, orchestrator := createTestContainerHandler()
		createTestContainer(orchestrator, "container-1", "test-container")
		orchestrator.attestError = container.ErrAttestationFailed

		attestReq := &ContainerAttestRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: Error Types
// =============================================================================

func TestContainerErrorTypes(t *testing.T) {
	t.Run("ErrContainerEncodingFailed", func(t *testing.T) {
		cause := errors.New("encoding error")
		err := ErrContainerEncodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "encoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrContainerDecodingFailed", func(t *testing.T) {
		cause := errors.New("decoding error")
		err := ErrContainerDecodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "decoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrContainerOperationFailed", func(t *testing.T) {
		cause := errors.New("operation error")
		err := ErrContainerOperationFailed{
			Operation: "start",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "start")
		assert.Contains(t, err.Error(), "operation error")
		assert.Equal(t, cause, err.Unwrap())
	})
}

// =============================================================================
// Test: containerErrorResponse - Comprehensive Error Mapping
// =============================================================================

func TestContainerErrorResponse(t *testing.T) {
	handler, _ := createTestContainerHandler()

	testCases := []struct {
		name           string
		err            error
		expectedStatus byte
	}{
		{"container not found", container.ErrContainerNotFound, quicwire.StatusNotFound},
		{"container exists", container.ErrContainerExists, quicwire.StatusAlreadyExists},
		{"container running", container.ErrContainerRunning, quicwire.StatusInvalidRequest},
		{"container stopped", container.ErrContainerStopped, quicwire.StatusInvalidRequest},
		{"invalid spec", container.ErrInvalidSpec, quicwire.StatusInvalidArgument},
		{"invalid name", container.ErrInvalidName, quicwire.StatusInvalidArgument},
		{"invalid image", container.ErrInvalidImage, quicwire.StatusInvalidArgument},
		{"invalid container ID", container.ErrInvalidContainerID, quicwire.StatusInvalidArgument},
		{"attestation failed", container.ErrAttestationFailed, quicwire.StatusInternalError},
		{"policy denied", container.ErrPolicyDenied, quicwire.StatusPermissionDenied},
		{"orchestrator not initialized", container.ErrOrchestratorNotInitialized, quicwire.StatusUnavailable},
		{"orchestrator closed", container.ErrOrchestratorClosed, quicwire.StatusUnavailable},
		{"operation timeout", container.ErrOperationTimeout, quicwire.StatusTimeout},
		{"image not found", container.ErrImageNotFound, quicwire.StatusNotFound},
		{"image verification failed", container.ErrImageVerificationFailed, quicwire.StatusPermissionDenied},
		{"image pull failed", container.ErrImagePullFailed, quicwire.StatusInternalError},
		{"generic error", errors.New("unknown error"), quicwire.StatusInternalError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.containerErrorResponse(tc.err)
			assert.Equal(t, tc.expectedStatus, resp.Status)
		})
	}
}

// =============================================================================
// Test: buildSpecFromRequest
// =============================================================================

func TestBuildSpecFromRequest(t *testing.T) {
	handler, _ := createTestContainerHandler()

	t.Run("builds complete spec", func(t *testing.T) {
		req := &ContainerCreateRequest{
			Name:        "test-container",
			Image:       "nginx:latest",
			Command:     []string{"nginx"},
			Args:        []string{"-g", "daemon off;"},
			Env:         map[string]string{"ENV": "value"},
			Labels:      map[string]string{"app": "test"},
			User:        "nginx",
			WorkingDir:  "/app",
			Privileged:  true,
			NetworkMode: "host",
			Mounts: []ContainerMount{
				{Source: "/host", Target: "/container", Type: "bind", ReadOnly: true},
			},
			Ports: []ContainerPort{
				{HostPort: 80, ContainerPort: 8080, Protocol: "tcp"},
			},
			CapAdd:        []string{"NET_ADMIN"},
			CapDrop:       []string{"SETUID"},
			CPULimit:      "2",
			MemoryLimit:   "512M",
			RestartPolicy: "always",
		}

		spec := handler.buildSpecFromRequest(req)

		assert.Equal(t, "test-container", spec.Name)
		assert.Equal(t, "nginx:latest", spec.Image)
		assert.Equal(t, []string{"nginx"}, spec.Command)
		assert.Equal(t, []string{"-g", "daemon off;"}, spec.Args)
		assert.Equal(t, "value", spec.Env["ENV"])
		assert.Equal(t, "test", spec.Labels["app"])
		assert.Equal(t, "nginx", spec.User)
		assert.Equal(t, "/app", spec.WorkingDir)
		assert.True(t, spec.Privileged)
		assert.Equal(t, container.NetworkModeHost, spec.Network.Mode)
		assert.Len(t, spec.Mounts, 1)
		assert.Equal(t, "/host", spec.Mounts[0].Source)
		assert.Len(t, spec.Ports, 1)
		assert.Equal(t, uint16(8080), spec.Ports[0].ContainerPort)
		assert.Equal(t, []string{"NET_ADMIN"}, spec.Capabilities.Add)
		assert.Equal(t, []string{"SETUID"}, spec.Capabilities.Drop)
		assert.Equal(t, "2", spec.Resources.CPULimit)
		assert.Equal(t, "512M", spec.Resources.MemoryLimit)
		assert.Equal(t, container.RestartAlways, spec.RestartPolicy)
	})

	t.Run("builds minimal spec", func(t *testing.T) {
		req := &ContainerCreateRequest{
			Name:  "test-container",
			Image: "nginx:latest",
		}

		spec := handler.buildSpecFromRequest(req)

		assert.Equal(t, "test-container", spec.Name)
		assert.Equal(t, "nginx:latest", spec.Image)
		assert.Empty(t, spec.Command)
		assert.Empty(t, spec.Mounts)
		assert.Empty(t, spec.Ports)
	})
}

// =============================================================================
// Test: containerToInfo
// =============================================================================

func TestContainerToInfo(t *testing.T) {
	handler, orchestrator := createTestContainerHandler()

	t.Run("converts complete container", func(t *testing.T) {
		c := createTestContainer(orchestrator, "container-1", "test-container")
		c.StartedAt = time.Now().Add(-1 * time.Hour)
		c.FinishedAt = time.Now()
		c.ExitCode = 0
		c.Pid = 12345

		info := handler.containerToInfo(c)

		assert.Equal(t, "container-1", info.ID)
		assert.Equal(t, "test-container", info.Name)
		assert.Equal(t, "test-image:latest", info.Image)
		assert.Equal(t, "sha256:abc123", info.ImageID)
		assert.Equal(t, string(container.StateCreated), info.State)
		assert.Greater(t, info.CreatedAt, int64(0))
		assert.Greater(t, info.StartedAt, int64(0))
		assert.Greater(t, info.FinishedAt, int64(0))
		assert.Equal(t, 0, info.ExitCode)
		assert.Equal(t, 12345, info.Pid)
		assert.Equal(t, "linux/amd64", info.Platform)
		assert.NotNil(t, info.NetworkSettings)
		assert.Equal(t, "172.17.0.2", info.NetworkSettings.IPAddress)
		assert.NotNil(t, info.NetworkSettings.Ports)
		assert.NotNil(t, info.NetworkSettings.Networks)
	})

	t.Run("handles nil container", func(t *testing.T) {
		info := handler.containerToInfo(nil)
		assert.Nil(t, info)
	})

	t.Run("handles container without network settings", func(t *testing.T) {
		c := &container.Container{
			ID:        "container-1",
			Name:      "test-container",
			CreatedAt: time.Now(),
		}

		info := handler.containerToInfo(c)

		assert.NotNil(t, info)
		assert.Nil(t, info.NetworkSettings)
	})

	t.Run("handles zero timestamps", func(t *testing.T) {
		c := &container.Container{
			ID:        "container-1",
			Name:      "test-container",
			CreatedAt: time.Now(),
			// StartedAt and FinishedAt are zero
		}

		info := handler.containerToInfo(c)

		assert.Equal(t, int64(0), info.StartedAt)
		assert.Equal(t, int64(0), info.FinishedAt)
	})
}

// =============================================================================
// Test: Opcode Constants
// =============================================================================

func TestOpcodeConstants(t *testing.T) {
	// Verify opcodes are unique and in expected ranges
	opcodes := []struct {
		name   string
		opcode byte
	}{
		{"OpContainerCreate", quicwire.OpContainerCreate},
		{"OpContainerStart", quicwire.OpContainerStart},
		{"OpContainerStop", quicwire.OpContainerStop},
		{"OpContainerRemove", quicwire.OpContainerRemove},
		{"OpContainerGet", quicwire.OpContainerGet},
		{"OpContainerList", quicwire.OpContainerList},
		{"OpContainerLogs", quicwire.OpContainerLogs},
		{"OpContainerAttest", quicwire.OpContainerAttest},
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
// Test: Pagination Constants
// =============================================================================

func TestPaginationConstants(t *testing.T) {
	assert.Equal(t, int32(50), containerDefaultLimit)
	assert.Equal(t, int32(1000), containerMaxLimit)
	assert.Less(t, containerDefaultLimit, containerMaxLimit)
}

// =============================================================================
// Test: Additional Error Paths for Coverage
// =============================================================================

func TestContainerHandlerStartErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when start fails", func(t *testing.T) {
		handler, orch := createTestContainerHandler()
		createTestContainer(orch, "container-1", "test-container")
		orch.startError = errors.New("start failed")

		startReq := &ContainerStartRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestContainerHandlerStopErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when stop fails", func(t *testing.T) {
		handler, orch := createTestContainerHandler()
		createTestContainer(orch, "container-1", "test-container")
		orch.stopError = errors.New("stop failed")

		stopReq := &ContainerStopRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestContainerHandlerRemoveErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when remove fails", func(t *testing.T) {
		handler, orch := createTestContainerHandler()
		createTestContainer(orch, "container-1", "test-container")
		orch.removeError = errors.New("remove failed")

		removeReq := &ContainerRemoveRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(removeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerRemove,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestContainerHandlerGetErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when get fails", func(t *testing.T) {
		handler, orch := createTestContainerHandler()
		createTestContainer(orch, "container-1", "test-container")
		orch.getError = errors.New("get failed")

		getReq := &ContainerGetRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestContainerHandlerLogsErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when logs fails", func(t *testing.T) {
		handler, orch := createTestContainerHandler()
		createTestContainer(orch, "container-1", "test-container")
		orch.logsError = errors.New("logs failed")

		logsReq := &ContainerLogsRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(logsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerLogs,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestContainerHandlerAttestErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when attest fails", func(t *testing.T) {
		handler, orch := createTestContainerHandler()
		createTestContainer(orch, "container-1", "test-container")
		orch.attestError = errors.New("attest failed")

		attestReq := &ContainerAttestRequest{
			ID: "container-1",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpContainerAttest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}
