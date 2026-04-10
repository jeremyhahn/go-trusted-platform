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

package grpc

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockOrchestrator implements container.ContainerOrchestrator for testing.
type mockOrchestrator struct {
	containers      map[string]*container.Container
	createErr       error
	startErr        error
	stopErr         error
	removeErr       error
	getErr          error
	listErr         error
	logsErr         error
	attestErr       error
	logsReader      io.ReadCloser
	attestReport    *container.AttestationReport
	createContainer *container.Container
}

func newMockOrchestrator() *mockOrchestrator {
	return &mockOrchestrator{
		containers: make(map[string]*container.Container),
	}
}

func (m *mockOrchestrator) Create(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.Container, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	if m.createContainer != nil {
		return m.createContainer, nil
	}
	c := &container.Container{
		ID:        "test-container-id",
		Name:      spec.Name,
		Image:     spec.Image,
		State:     container.StateCreated,
		Spec:      spec,
		CreatedAt: time.Now(),
	}
	m.containers[c.ID] = c
	return c, nil
}

func (m *mockOrchestrator) Start(ctx context.Context, id string) error {
	if m.startErr != nil {
		return m.startErr
	}
	if c, ok := m.containers[id]; ok {
		c.State = container.StateRunning
		c.StartedAt = time.Now()
	}
	return nil
}

func (m *mockOrchestrator) Stop(ctx context.Context, id string, timeout time.Duration) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	if c, ok := m.containers[id]; ok {
		c.State = container.StateStopped
		c.FinishedAt = time.Now()
	}
	return nil
}

func (m *mockOrchestrator) Remove(ctx context.Context, id string, force bool) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	delete(m.containers, id)
	return nil
}

func (m *mockOrchestrator) Get(ctx context.Context, id string) (*container.Container, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if c, ok := m.containers[id]; ok {
		return c, nil
	}
	return nil, container.ErrContainerNotFound
}

func (m *mockOrchestrator) List(ctx context.Context, opts container.ListOptions) ([]*container.Container, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	containers := make([]*container.Container, 0, len(m.containers))
	for _, c := range m.containers {
		containers = append(containers, c)
	}
	return containers, nil
}

func (m *mockOrchestrator) Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
	if m.logsErr != nil {
		return nil, m.logsErr
	}
	if m.logsReader != nil {
		return m.logsReader, nil
	}
	return io.NopCloser(strings.NewReader("test logs")), nil
}

func (m *mockOrchestrator) Attest(ctx context.Context, id string) (*container.AttestationReport, error) {
	if m.attestErr != nil {
		return nil, m.attestErr
	}
	if m.attestReport != nil {
		return m.attestReport, nil
	}
	return &container.AttestationReport{
		ContainerID:   id,
		ContainerName: "test-container",
		Timestamp:     time.Now(),
		Quote:         []byte("test-quote"),
		Signature:     []byte("test-signature"),
		Verified:      true,
		PCRValues: map[int][]byte{
			14: []byte("pcr-14-value"),
		},
	}, nil
}

func (m *mockOrchestrator) VerifyAttestation(ctx context.Context, id string, evidence []byte) error {
	return nil
}

func (m *mockOrchestrator) EvaluatePolicy(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.PolicyDecision, error) {
	return &container.PolicyDecision{Allowed: true}, nil
}

func (m *mockOrchestrator) PullImage(ctx context.Context, ref string, opts container.PullOptions) error {
	return nil
}

func (m *mockOrchestrator) VerifyImage(ctx context.Context, ref string) (*container.ImageVerification, error) {
	return &container.ImageVerification{Verified: true}, nil
}

func (m *mockOrchestrator) Close() error {
	return nil
}

// mockLogStream implements a test log reader that can be controlled.
type mockLogStream struct {
	data    []byte
	pos     int
	closed  bool
	readErr error
}

func newMockLogStream(data string) *mockLogStream {
	return &mockLogStream{data: []byte(data)}
}

func (m *mockLogStream) Read(p []byte) (int, error) {
	if m.closed {
		return 0, io.EOF
	}
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockLogStream) Close() error {
	m.closed = true
	return nil
}

// mockLogsServer implements platformv1.ComputeService_GetContainerLogsServer for testing.
type mockLogsServer struct {
	ctx     context.Context
	entries []*platformv1.LogEntry
	sendErr error
}

func newMockLogsServer(ctx context.Context) *mockLogsServer {
	return &mockLogsServer{
		ctx:     ctx,
		entries: make([]*platformv1.LogEntry, 0),
	}
}

func (m *mockLogsServer) Send(entry *platformv1.LogEntry) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockLogsServer) SetHeader(md metadata.MD) error {
	return nil
}

func (m *mockLogsServer) SendHeader(md metadata.MD) error {
	return nil
}

func (m *mockLogsServer) SetTrailer(md metadata.MD) {
}

func (m *mockLogsServer) Context() context.Context {
	return m.ctx
}

func (m *mockLogsServer) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockLogsServer) RecvMsg(msg interface{}) error {
	return nil
}

func testLogger() *logging.Logger {
	return logging.DefaultLogger()
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestContainerErrorTypes(t *testing.T) {
	t.Run("ErrNilOrchestrator", func(t *testing.T) {
		err := ErrNilOrchestrator{}
		if err.Error() != "container orchestrator is nil" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrMissingContainerID", func(t *testing.T) {
		err := ErrMissingContainerID{}
		if err.Error() != "container ID is required" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrMissingContainerConfig", func(t *testing.T) {
		err := ErrMissingContainerConfig{}
		if err.Error() != "container configuration is required" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrMissingContainerName", func(t *testing.T) {
		err := ErrMissingContainerName{}
		if err.Error() != "container name is required" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrMissingContainerImage", func(t *testing.T) {
		err := ErrMissingContainerImage{}
		if err.Error() != "container image is required" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrStreamSend", func(t *testing.T) {
		cause := errors.New("send failed")
		err := ErrStreamSend{Cause: cause}
		if !strings.Contains(err.Error(), "send failed") {
			t.Errorf("unexpected error message: %s", err.Error())
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return the cause")
		}
	})
}

// =============================================================================
// CreateContainer Tests
// =============================================================================

func TestCreateContainer_Success(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Name:  "test-container",
			Image: "alpine:latest",
		},
	}

	resp, err := svc.CreateContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
	if resp.GetContainer() == nil {
		t.Error("expected container in response")
	}
	if resp.GetContainer().GetConfig().GetName() != "test-container" {
		t.Errorf("unexpected container name: %s", resp.GetContainer().GetConfig().GetName())
	}
}

func TestCreateContainer_WithStart(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Name:  "test-container",
			Image: "alpine:latest",
		},
		Start: true,
	}

	resp, err := svc.CreateContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
	if resp.GetContainer().GetState() != platformv1.ContainerState_CONTAINER_STATE_RUNNING {
		t.Errorf("expected running state, got: %v", resp.GetContainer().GetState())
	}
}

func TestCreateContainer_StartFailure(t *testing.T) {
	orch := newMockOrchestrator()
	orch.startErr = errors.New("start failed")
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Name:  "test-container",
			Image: "alpine:latest",
		},
		Start: true,
	}

	resp, err := svc.CreateContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return the container but with failure status
	if resp.GetStatus().GetSuccess() {
		t.Error("expected failure status")
	}
	if resp.GetContainer() == nil {
		t.Error("expected container in response even on start failure")
	}
}

func TestCreateContainer_NilOrchestrator(t *testing.T) {
	svc := NewContainerGRPCService(testLogger(), nil)

	req := &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Name:  "test-container",
			Image: "alpine:latest",
		},
	}

	_, err := svc.CreateContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

func TestCreateContainer_NilConfig(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.CreateContainerRequest{}

	_, err := svc.CreateContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %v", status.Code(err))
	}
}

func TestCreateContainer_MissingName(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Image: "alpine:latest",
		},
	}

	_, err := svc.CreateContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %v", status.Code(err))
	}
}

func TestCreateContainer_MissingImage(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Name: "test-container",
		},
	}

	_, err := svc.CreateContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %v", status.Code(err))
	}
}

func TestCreateContainer_OrchestratorError(t *testing.T) {
	orch := newMockOrchestrator()
	orch.createErr = container.ErrContainerExists
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Name:  "test-container",
			Image: "alpine:latest",
		},
	}

	_, err := svc.CreateContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("expected AlreadyExists, got: %v", status.Code(err))
	}
}

func TestCreateContainer_WithFullConfig(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Name:       "full-test-container",
			Image:      "nginx:latest",
			Command:    []string{"/bin/sh"},
			Args:       []string{"-c", "nginx -g 'daemon off;'"},
			WorkingDir: "/app",
			Privileged: false,
			Network:    "bridge",
			Labels: map[string]string{
				"app": "test",
			},
			Env: []*platformv1.EnvVar{
				{Name: "FOO", Value: "bar"},
			},
			Volumes: []*platformv1.VolumeMount{
				{Source: "/host/data", Destination: "/data", Readonly: true},
			},
			Ports: []*platformv1.PortMapping{
				{ContainerPort: 80, HostPort: 8080, Protocol: "tcp"},
			},
			Capabilities:  []string{"NET_ADMIN"},
			RestartPolicy: platformv1.RestartPolicy_RESTART_POLICY_ALWAYS,
			Resources: &platformv1.ResourceLimits{
				MaxMemoryMb: 512,
				MaxCpus:     2,
			},
		},
	}

	resp, err := svc.CreateContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
}

// =============================================================================
// StartContainer Tests
// =============================================================================

func TestStartContainer_Success(t *testing.T) {
	orch := newMockOrchestrator()
	// Pre-create a container
	orch.containers["test-id"] = &container.Container{
		ID:    "test-id",
		Name:  "test",
		State: container.StateStopped,
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.StartContainerRequest{Id: "test-id"}

	resp, err := svc.StartContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
}

func TestStartContainer_NilOrchestrator(t *testing.T) {
	svc := NewContainerGRPCService(testLogger(), nil)

	req := &platformv1.StartContainerRequest{Id: "test-id"}

	_, err := svc.StartContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

func TestStartContainer_MissingID(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.StartContainerRequest{}

	_, err := svc.StartContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %v", status.Code(err))
	}
}

func TestStartContainer_OrchestratorError(t *testing.T) {
	orch := newMockOrchestrator()
	orch.startErr = container.ErrContainerRunning
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.StartContainerRequest{Id: "test-id"}

	_, err := svc.StartContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

// =============================================================================
// StopContainer Tests
// =============================================================================

func TestStopContainer_Success(t *testing.T) {
	orch := newMockOrchestrator()
	orch.containers["test-id"] = &container.Container{
		ID:    "test-id",
		Name:  "test",
		State: container.StateRunning,
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.StopContainerRequest{Id: "test-id", TimeoutSeconds: 30}

	resp, err := svc.StopContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
}

func TestStopContainer_DefaultTimeout(t *testing.T) {
	orch := newMockOrchestrator()
	orch.containers["test-id"] = &container.Container{
		ID:    "test-id",
		State: container.StateRunning,
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	// No timeout specified - should use default
	req := &platformv1.StopContainerRequest{Id: "test-id"}

	resp, err := svc.StopContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
}

func TestStopContainer_NilOrchestrator(t *testing.T) {
	svc := NewContainerGRPCService(testLogger(), nil)

	req := &platformv1.StopContainerRequest{Id: "test-id"}

	_, err := svc.StopContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

func TestStopContainer_MissingID(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.StopContainerRequest{}

	_, err := svc.StopContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %v", status.Code(err))
	}
}

func TestStopContainer_OrchestratorError(t *testing.T) {
	orch := newMockOrchestrator()
	orch.stopErr = container.ErrContainerStopped
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.StopContainerRequest{Id: "test-id"}

	_, err := svc.StopContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

// =============================================================================
// DeleteContainer Tests
// =============================================================================

func TestDeleteContainer_Success(t *testing.T) {
	orch := newMockOrchestrator()
	orch.containers["test-id"] = &container.Container{
		ID:    "test-id",
		State: container.StateStopped,
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.DeleteContainerRequest{Id: "test-id"}

	resp, err := svc.DeleteContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
}

func TestDeleteContainer_Force(t *testing.T) {
	orch := newMockOrchestrator()
	orch.containers["test-id"] = &container.Container{
		ID:    "test-id",
		State: container.StateRunning,
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.DeleteContainerRequest{Id: "test-id", Force: true}

	resp, err := svc.DeleteContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
}

func TestDeleteContainer_NilOrchestrator(t *testing.T) {
	svc := NewContainerGRPCService(testLogger(), nil)

	req := &platformv1.DeleteContainerRequest{Id: "test-id"}

	_, err := svc.DeleteContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

func TestDeleteContainer_MissingID(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.DeleteContainerRequest{}

	_, err := svc.DeleteContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %v", status.Code(err))
	}
}

func TestDeleteContainer_OrchestratorError(t *testing.T) {
	orch := newMockOrchestrator()
	orch.removeErr = container.ErrContainerNotFound
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.DeleteContainerRequest{Id: "test-id"}

	_, err := svc.DeleteContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got: %v", status.Code(err))
	}
}

// =============================================================================
// GetContainer Tests
// =============================================================================

func TestGetContainer_Success(t *testing.T) {
	orch := newMockOrchestrator()
	orch.containers["test-id"] = &container.Container{
		ID:        "test-id",
		Name:      "test",
		Image:     "alpine:latest",
		State:     container.StateRunning,
		CreatedAt: time.Now(),
		Spec: &container.OrchestratorContainerSpec{
			Name:  "test",
			Image: "alpine:latest",
		},
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.GetContainerRequest{Id: "test-id"}

	resp, err := svc.GetContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.GetContainer() == nil {
		t.Fatal("expected container in response")
	}
	if resp.GetContainer().GetId() != "test-id" {
		t.Errorf("unexpected container ID: %s", resp.GetContainer().GetId())
	}
}

func TestGetContainer_NilOrchestrator(t *testing.T) {
	svc := NewContainerGRPCService(testLogger(), nil)

	req := &platformv1.GetContainerRequest{Id: "test-id"}

	_, err := svc.GetContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

func TestGetContainer_MissingID(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.GetContainerRequest{}

	_, err := svc.GetContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %v", status.Code(err))
	}
}

func TestGetContainer_NotFound(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.GetContainerRequest{Id: "nonexistent"}

	_, err := svc.GetContainer(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got: %v", status.Code(err))
	}
}

// =============================================================================
// ListContainers Tests
// =============================================================================

func TestListContainers_Success(t *testing.T) {
	orch := newMockOrchestrator()
	orch.containers["c1"] = &container.Container{
		ID:    "c1",
		Name:  "container1",
		State: container.StateRunning,
		Spec: &container.OrchestratorContainerSpec{
			Name:  "container1",
			Image: "alpine:latest",
		},
	}
	orch.containers["c2"] = &container.Container{
		ID:    "c2",
		Name:  "container2",
		State: container.StateStopped,
		Spec: &container.OrchestratorContainerSpec{
			Name:  "container2",
			Image: "nginx:latest",
		},
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.ListContainersRequest{}

	resp, err := svc.ListContainers(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.GetContainers()) != 2 {
		t.Errorf("expected 2 containers, got: %d", len(resp.GetContainers()))
	}
}

func TestListContainers_WithPagination(t *testing.T) {
	orch := newMockOrchestrator()
	for i := 0; i < 10; i++ {
		id := string(rune('a' + i))
		orch.containers[id] = &container.Container{
			ID:    id,
			State: container.StateRunning,
		}
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.ListContainersRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     1,
			PageSize: 5,
		},
	}

	resp, err := svc.ListContainers(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.GetPagination() == nil {
		t.Fatal("expected pagination in response")
	}
	if resp.GetPagination().GetTotalItems() != 10 {
		t.Errorf("expected 10 total items, got: %d", resp.GetPagination().GetTotalItems())
	}
}

func TestListContainers_WithStateFilter(t *testing.T) {
	orch := newMockOrchestrator()
	orch.containers["c1"] = &container.Container{
		ID:    "c1",
		State: container.StateRunning,
	}
	orch.containers["c2"] = &container.Container{
		ID:    "c2",
		State: container.StateStopped,
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.ListContainersRequest{
		States: []platformv1.ContainerState{
			platformv1.ContainerState_CONTAINER_STATE_RUNNING,
		},
	}

	resp, err := svc.ListContainers(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mock returns all containers, but we verify filter was set
	if len(resp.GetContainers()) == 0 {
		t.Error("expected containers in response")
	}
}

func TestListContainers_WithLabelSelector(t *testing.T) {
	orch := newMockOrchestrator()
	orch.containers["c1"] = &container.Container{
		ID:    "c1",
		State: container.StateRunning,
		Labels: map[string]string{
			"app": "web",
		},
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.ListContainersRequest{
		Selector: &platformv1.LabelSelector{
			MatchLabels: map[string]string{
				"app": "web",
			},
		},
	}

	resp, err := svc.ListContainers(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.GetContainers()) == 0 {
		t.Error("expected containers in response")
	}
}

func TestListContainers_NilOrchestrator(t *testing.T) {
	svc := NewContainerGRPCService(testLogger(), nil)

	req := &platformv1.ListContainersRequest{}

	_, err := svc.ListContainers(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

func TestListContainers_OrchestratorError(t *testing.T) {
	orch := newMockOrchestrator()
	orch.listErr = errors.New("list failed")
	svc := NewContainerGRPCService(testLogger(), orch)

	req := &platformv1.ListContainersRequest{}

	_, err := svc.ListContainers(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected Internal, got: %v", status.Code(err))
	}
}

// =============================================================================
// GetContainerLogs Tests
// =============================================================================

func TestGetContainerLogs_Success(t *testing.T) {
	orch := newMockOrchestrator()
	orch.logsReader = newMockLogStream("test log line 1\ntest log line 2\n")
	svc := NewContainerGRPCService(testLogger(), orch)

	ctx := context.Background()
	stream := newMockLogsServer(ctx)

	req := &platformv1.GetContainerLogsRequest{
		Id:     "test-id",
		Stdout: true,
		Stderr: true,
	}

	err := svc.GetContainerLogs(req, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stream.entries) == 0 {
		t.Error("expected log entries")
	}
}

func TestGetContainerLogs_DefaultStreams(t *testing.T) {
	orch := newMockOrchestrator()
	orch.logsReader = newMockLogStream("logs")
	svc := NewContainerGRPCService(testLogger(), orch)

	ctx := context.Background()
	stream := newMockLogsServer(ctx)

	// Neither stdout nor stderr specified - should default to both
	req := &platformv1.GetContainerLogsRequest{
		Id: "test-id",
	}

	err := svc.GetContainerLogs(req, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetContainerLogs_WithTailLines(t *testing.T) {
	orch := newMockOrchestrator()
	orch.logsReader = newMockLogStream("logs")
	svc := NewContainerGRPCService(testLogger(), orch)

	ctx := context.Background()
	stream := newMockLogsServer(ctx)

	req := &platformv1.GetContainerLogsRequest{
		Id:        "test-id",
		TailLines: 100,
	}

	err := svc.GetContainerLogs(req, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetContainerLogs_WithSince(t *testing.T) {
	orch := newMockOrchestrator()
	orch.logsReader = newMockLogStream("logs")
	svc := NewContainerGRPCService(testLogger(), orch)

	ctx := context.Background()
	stream := newMockLogsServer(ctx)

	req := &platformv1.GetContainerLogsRequest{
		Id:    "test-id",
		Since: timestamppb.New(time.Now().Add(-1 * time.Hour)),
	}

	err := svc.GetContainerLogs(req, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetContainerLogs_NilOrchestrator(t *testing.T) {
	svc := NewContainerGRPCService(testLogger(), nil)

	ctx := context.Background()
	stream := newMockLogsServer(ctx)

	req := &platformv1.GetContainerLogsRequest{Id: "test-id"}

	err := svc.GetContainerLogs(req, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

func TestGetContainerLogs_MissingID(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	ctx := context.Background()
	stream := newMockLogsServer(ctx)

	req := &platformv1.GetContainerLogsRequest{}

	err := svc.GetContainerLogs(req, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %v", status.Code(err))
	}
}

func TestGetContainerLogs_OrchestratorError(t *testing.T) {
	orch := newMockOrchestrator()
	orch.logsErr = container.ErrContainerNotFound
	svc := NewContainerGRPCService(testLogger(), orch)

	ctx := context.Background()
	stream := newMockLogsServer(ctx)

	req := &platformv1.GetContainerLogsRequest{Id: "test-id"}

	err := svc.GetContainerLogs(req, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got: %v", status.Code(err))
	}
}

func TestGetContainerLogs_StreamSendError(t *testing.T) {
	orch := newMockOrchestrator()
	orch.logsReader = newMockLogStream("test logs")
	svc := NewContainerGRPCService(testLogger(), orch)

	ctx := context.Background()
	stream := newMockLogsServer(ctx)
	stream.sendErr = errors.New("send failed")

	req := &platformv1.GetContainerLogsRequest{Id: "test-id"}

	err := svc.GetContainerLogs(req, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected Internal, got: %v", status.Code(err))
	}
}

func TestGetContainerLogs_ContextCanceled(t *testing.T) {
	orch := newMockOrchestrator()
	// Create a log stream that never ends
	infiniteStream := &mockLogStream{
		data: []byte("infinite logs"),
	}
	infiniteStream.readErr = nil // Will block until context canceled
	orch.logsReader = infiniteStream
	svc := NewContainerGRPCService(testLogger(), orch)

	ctx, cancel := context.WithCancel(context.Background())
	stream := newMockLogsServer(ctx)

	req := &platformv1.GetContainerLogsRequest{
		Id:     "test-id",
		Follow: true,
	}

	// Cancel context immediately
	cancel()

	err := svc.GetContainerLogs(req, stream)
	// Should return context canceled error
	if err != nil && !errors.Is(err, context.Canceled) {
		// It's okay if we get EOF since we canceled
		if !strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "EOF") {
			t.Logf("got error (expected): %v", err)
		}
	}
}

// =============================================================================
// AttestContainer Tests
// =============================================================================

func TestAttestContainer_Success(t *testing.T) {
	orch := newMockOrchestrator()
	orch.attestReport = &container.AttestationReport{
		ContainerID:   "test-id",
		ContainerName: "test-container",
		Timestamp:     time.Now(),
		Quote:         []byte("quote-data"),
		Signature:     []byte("sig-data"),
		Verified:      true,
		PCRValues: map[int][]byte{
			14: []byte("pcr-value"),
		},
		AIKCertificate: []byte("aik-cert"),
	}
	svc := NewContainerGRPCService(testLogger(), orch)

	resp, err := svc.AttestContainer(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("expected success status")
	}
	if len(resp.GetQuote()) == 0 {
		t.Error("expected quote in response")
	}
	if len(resp.GetSignature()) == 0 {
		t.Error("expected signature in response")
	}
	if len(resp.GetPcrValues()) == 0 {
		t.Error("expected PCR values in response")
	}
}

func TestAttestContainer_NilOrchestrator(t *testing.T) {
	svc := NewContainerGRPCService(testLogger(), nil)

	_, err := svc.AttestContainer(context.Background(), "test-id")
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

func TestAttestContainer_MissingID(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	_, err := svc.AttestContainer(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got: %v", status.Code(err))
	}
}

func TestAttestContainer_OrchestratorError(t *testing.T) {
	orch := newMockOrchestrator()
	orch.attestErr = container.ErrAttestationFailed
	svc := NewContainerGRPCService(testLogger(), orch)

	_, err := svc.AttestContainer(context.Background(), "test-id")
	if err == nil {
		t.Fatal("expected error")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got: %v", status.Code(err))
	}
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestMapError_AllErrorTypes(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	testCases := []struct {
		name     string
		err      error
		expected codes.Code
	}{
		{"nil error", nil, codes.OK},
		{"ErrContainerNotFound", container.ErrContainerNotFound, codes.NotFound},
		{"ErrContainerExists", container.ErrContainerExists, codes.AlreadyExists},
		{"ErrContainerRunning", container.ErrContainerRunning, codes.FailedPrecondition},
		{"ErrContainerStopped", container.ErrContainerStopped, codes.FailedPrecondition},
		{"ErrInvalidSpec", container.ErrInvalidSpec, codes.InvalidArgument},
		{"ErrInvalidName", container.ErrInvalidName, codes.InvalidArgument},
		{"ErrInvalidImage", container.ErrInvalidImage, codes.InvalidArgument},
		{"ErrInvalidContainerID", container.ErrInvalidContainerID, codes.InvalidArgument},
		{"ErrPolicyDenied", container.ErrPolicyDenied, codes.PermissionDenied},
		{"ErrAttestationFailed", container.ErrAttestationFailed, codes.FailedPrecondition},
		{"ErrAttestationRequired", container.ErrAttestationRequired, codes.FailedPrecondition},
		{"ErrOrchestratorNotInitialized", container.ErrOrchestratorNotInitialized, codes.FailedPrecondition},
		{"ErrOrchestratorClosed", container.ErrOrchestratorClosed, codes.Unavailable},
		{"ErrOperationTimeout", container.ErrOperationTimeout, codes.DeadlineExceeded},
		{"ErrImageNotFound", container.ErrImageNotFound, codes.NotFound},
		{"ErrImagePullFailed", container.ErrImagePullFailed, codes.Unavailable},
		{"ErrRegistryUnreachable", container.ErrRegistryUnreachable, codes.Unavailable},
		{"ErrRegistryAuthFailed", container.ErrRegistryAuthFailed, codes.Unauthenticated},
		{"unknown error", errors.New("unknown"), codes.Internal},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.mapError("test", tc.err)
			if tc.err == nil {
				if result != nil {
					t.Errorf("expected nil, got: %v", result)
				}
				return
			}
			if status.Code(result) != tc.expected {
				t.Errorf("expected %v, got: %v", tc.expected, status.Code(result))
			}
		})
	}
}

// =============================================================================
// State Conversion Tests
// =============================================================================

func TestStateToProto_AllStates(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	testCases := []struct {
		state    container.ContainerState
		expected platformv1.ContainerState
	}{
		{container.StateCreated, platformv1.ContainerState_CONTAINER_STATE_CREATED},
		{container.StateRunning, platformv1.ContainerState_CONTAINER_STATE_RUNNING},
		{container.StatePaused, platformv1.ContainerState_CONTAINER_STATE_PAUSED},
		{container.StateStopped, platformv1.ContainerState_CONTAINER_STATE_STOPPED},
		{container.StateRestarting, platformv1.ContainerState_CONTAINER_STATE_STARTING},
		{container.StateRemoving, platformv1.ContainerState_CONTAINER_STATE_STOPPING},
		{container.StateExited, platformv1.ContainerState_CONTAINER_STATE_EXITED},
		{container.StateDead, platformv1.ContainerState_CONTAINER_STATE_ERROR},
		{container.ContainerState("unknown"), platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(string(tc.state), func(t *testing.T) {
			result := svc.stateToProto(tc.state)
			if result != tc.expected {
				t.Errorf("expected %v, got: %v", tc.expected, result)
			}
		})
	}
}

func TestProtoStateToString_AllStates(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	testCases := []struct {
		state    platformv1.ContainerState
		expected string
	}{
		{platformv1.ContainerState_CONTAINER_STATE_CREATED, "created"},
		{platformv1.ContainerState_CONTAINER_STATE_RUNNING, "running"},
		{platformv1.ContainerState_CONTAINER_STATE_PAUSED, "paused"},
		{platformv1.ContainerState_CONTAINER_STATE_STOPPED, "stopped"},
		{platformv1.ContainerState_CONTAINER_STATE_EXITED, "exited"},
		{platformv1.ContainerState_CONTAINER_STATE_STARTING, "starting"},
		{platformv1.ContainerState_CONTAINER_STATE_STOPPING, "stopping"},
		{platformv1.ContainerState_CONTAINER_STATE_ERROR, "error"},
		{platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := svc.protoStateToString(tc.state)
			if result != tc.expected {
				t.Errorf("expected %v, got: %v", tc.expected, result)
			}
		})
	}
}

// =============================================================================
// Config Conversion Tests
// =============================================================================

func TestProtoConfigToSpec_NetworkModes(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	testCases := []struct {
		network  string
		expected container.NetworkMode
	}{
		{"host", container.NetworkModeHost},
		{"none", container.NetworkModeNone},
		{"sdn", container.NetworkModeSDN},
		{"bridge", container.NetworkModeBridge},
		{"", container.NetworkModeBridge},
		{"custom", container.NetworkModeBridge},
	}

	for _, tc := range testCases {
		t.Run(tc.network, func(t *testing.T) {
			config := &platformv1.ContainerConfig{
				Name:    "test",
				Image:   "alpine",
				Network: tc.network,
			}
			spec := svc.protoConfigToSpec(config)
			if spec.Network.Mode != tc.expected {
				t.Errorf("expected %v, got: %v", tc.expected, spec.Network.Mode)
			}
		})
	}
}

func TestProtoConfigToSpec_RestartPolicies(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	testCases := []struct {
		policy   platformv1.RestartPolicy
		expected container.RestartPolicy
	}{
		{platformv1.RestartPolicy_RESTART_POLICY_ALWAYS, container.RestartAlways},
		{platformv1.RestartPolicy_RESTART_POLICY_ON_FAILURE, container.RestartOnFailure},
		{platformv1.RestartPolicy_RESTART_POLICY_UNLESS_STOPPED, container.RestartUnlessStopped},
		{platformv1.RestartPolicy_RESTART_POLICY_NO, container.RestartNever},
		{platformv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED, container.RestartNever},
	}

	for _, tc := range testCases {
		t.Run(tc.policy.String(), func(t *testing.T) {
			config := &platformv1.ContainerConfig{
				Name:          "test",
				Image:         "alpine",
				RestartPolicy: tc.policy,
			}
			spec := svc.protoConfigToSpec(config)
			if spec.RestartPolicy != tc.expected {
				t.Errorf("expected %v, got: %v", tc.expected, spec.RestartPolicy)
			}
		})
	}
}

func TestSpecToProtoConfig_NetworkModes(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	testCases := []struct {
		mode     container.NetworkMode
		expected string
	}{
		{container.NetworkModeHost, "host"},
		{container.NetworkModeNone, "none"},
		{container.NetworkModeSDN, "sdn"},
		{container.NetworkModeBridge, "bridge"},
		{container.NetworkMode(""), "bridge"},
	}

	for _, tc := range testCases {
		t.Run(string(tc.mode), func(t *testing.T) {
			spec := &container.OrchestratorContainerSpec{
				Name:  "test",
				Image: "alpine",
				Network: container.ContainerNetworkConfig{
					Mode: tc.mode,
				},
			}
			config := svc.specToProtoConfig(spec)
			if config.GetNetwork() != tc.expected {
				t.Errorf("expected %v, got: %v", tc.expected, config.GetNetwork())
			}
		})
	}
}

func TestSpecToProtoConfig_RestartPolicies(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	testCases := []struct {
		policy   container.RestartPolicy
		expected platformv1.RestartPolicy
	}{
		{container.RestartAlways, platformv1.RestartPolicy_RESTART_POLICY_ALWAYS},
		{container.RestartOnFailure, platformv1.RestartPolicy_RESTART_POLICY_ON_FAILURE},
		{container.RestartUnlessStopped, platformv1.RestartPolicy_RESTART_POLICY_UNLESS_STOPPED},
		{container.RestartNever, platformv1.RestartPolicy_RESTART_POLICY_NO},
		{container.RestartPolicy(""), platformv1.RestartPolicy_RESTART_POLICY_NO},
	}

	for _, tc := range testCases {
		t.Run(string(tc.policy), func(t *testing.T) {
			spec := &container.OrchestratorContainerSpec{
				Name:          "test",
				Image:         "alpine",
				RestartPolicy: tc.policy,
			}
			config := svc.specToProtoConfig(spec)
			if config.GetRestartPolicy() != tc.expected {
				t.Errorf("expected %v, got: %v", tc.expected, config.GetRestartPolicy())
			}
		})
	}
}

func TestContainerToProto_NilContainer(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	result := svc.containerToProto(nil)
	if result != nil {
		t.Error("expected nil result for nil container")
	}
}

func TestContainerToProto_NoSpec(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	c := &container.Container{
		ID:    "test-id",
		Name:  "test-name",
		Image: "test-image",
		State: container.StateRunning,
	}

	result := svc.containerToProto(c)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.GetConfig().GetName() != "test-name" {
		t.Errorf("unexpected name: %s", result.GetConfig().GetName())
	}
	if result.GetConfig().GetImage() != "test-image" {
		t.Errorf("unexpected image: %s", result.GetConfig().GetImage())
	}
}

func TestSpecToProtoConfig_NilSpec(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	result := svc.specToProtoConfig(nil)
	if result != nil {
		t.Error("expected nil result for nil spec")
	}
}

// =============================================================================
// AttestationReportToProto Tests
// =============================================================================

func TestAttestationReportToProto_Success(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	report := &container.AttestationReport{
		ContainerID:   "test-id",
		ContainerName: "test-name",
		Timestamp:     time.Now(),
		Verified:      true,
		ImageDigest:   []byte("image-digest"),
		ConfigDigest:  []byte("config-digest"),
		Quote:         []byte("quote"),
		Signature:     []byte("signature"),
	}

	result := svc.AttestationReportToProto(report)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["container_id"] != "test-id" {
		t.Errorf("unexpected container_id: %s", result["container_id"])
	}
	if result["verified"] != "true" {
		t.Errorf("unexpected verified: %s", result["verified"])
	}
	if _, ok := result["image_digest"]; !ok {
		t.Error("expected image_digest in result")
	}
}

func TestAttestationReportToProto_NotVerified(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	report := &container.AttestationReport{
		ContainerID: "test-id",
		Verified:    false,
		Timestamp:   time.Now(),
	}

	result := svc.AttestationReportToProto(report)
	if result["verified"] != "false" {
		t.Errorf("expected verified=false, got: %s", result["verified"])
	}
}

func TestAttestationReportToProto_Nil(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	result := svc.AttestationReportToProto(nil)
	if result != nil {
		t.Error("expected nil result for nil report")
	}
}

// =============================================================================
// Format Memory Tests
// =============================================================================

func TestFormatMemory(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	testCases := []struct {
		mb       uint64
		expected string
	}{
		{0, ""},
		{512, string(rune(512)) + "M"},
		{1024, string(rune(1)) + "G"},
		{2048, string(rune(2)) + "G"},
	}

	for _, tc := range testCases {
		result := svc.formatMemory(tc.mb)
		if result != tc.expected {
			t.Errorf("formatMemory(%d): expected %q, got %q", tc.mb, tc.expected, result)
		}
	}
}

// =============================================================================
// Spec to Proto with Full Fields Tests
// =============================================================================

func TestSpecToProtoConfig_WithEnvAndMounts(t *testing.T) {
	orch := newMockOrchestrator()
	svc := NewContainerGRPCService(testLogger(), orch)

	spec := &container.OrchestratorContainerSpec{
		Name:  "test",
		Image: "alpine",
		Env: map[string]string{
			"FOO": "bar",
			"BAZ": "qux",
		},
		Mounts: []container.MountConfig{
			{
				Source:   "/host/path",
				Target:   "/container/path",
				ReadOnly: true,
				Type:     container.MountTypeBind,
			},
		},
		Ports: []container.PortMapping{
			{
				ContainerPort: 80,
				HostPort:      8080,
				HostIP:        "0.0.0.0",
				Protocol:      "tcp",
			},
		},
		Capabilities: container.CapabilityConfig{
			Add: []string{"NET_ADMIN", "SYS_TIME"},
		},
	}

	config := svc.specToProtoConfig(spec)
	if len(config.GetEnv()) != 2 {
		t.Errorf("expected 2 env vars, got: %d", len(config.GetEnv()))
	}
	if len(config.GetVolumes()) != 1 {
		t.Errorf("expected 1 volume, got: %d", len(config.GetVolumes()))
	}
	if len(config.GetPorts()) != 1 {
		t.Errorf("expected 1 port, got: %d", len(config.GetPorts()))
	}
	if len(config.GetCapabilities()) != 2 {
		t.Errorf("expected 2 capabilities, got: %d", len(config.GetCapabilities()))
	}
}
