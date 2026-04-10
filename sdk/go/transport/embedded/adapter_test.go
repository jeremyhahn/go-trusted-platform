package embedded

import (
	"context"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// testDaemonServer implements PlatformDaemonServer for testing.
type testDaemonServer struct {
	platformv1.UnimplementedPlatformDaemonServer
}

func (s *testDaemonServer) GetVersion(ctx context.Context, req *platformv1.GetVersionRequest) (*platformv1.GetVersionResponse, error) {
	return &platformv1.GetVersionResponse{
		Version: "1.0.0-test",
	}, nil
}

func (s *testDaemonServer) GetStatus(ctx context.Context, req *platformv1.GetStatusRequest) (*platformv1.GetStatusResponse, error) {
	return &platformv1.GetStatusResponse{}, nil
}

func (s *testDaemonServer) GetHealth(ctx context.Context, req *platformv1.GetHealthRequest) (*platformv1.GetHealthResponse, error) {
	return &platformv1.GetHealthResponse{
		Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
	}, nil
}

// testRegistry returns a ServiceRegistry with only a Daemon service set.
func testRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		Daemon: &testDaemonServer{},
	}
}

func TestAdapter_ImplementsInterface(t *testing.T) {
	var _ transport.Adapter = (*Adapter)(nil)
}

func TestNew_WithValidRegistry(t *testing.T) {
	registry := testRegistry()

	adapter, err := New(registry)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	if !adapter.IsConnected() {
		t.Error("expected IsConnected() to return true after New()")
	}

	if adapter.Connection() == nil {
		t.Error("expected Connection() to return non-nil value")
	}

	if adapter.Target() != "embedded://in-process" {
		t.Errorf("expected Target() = %q, got %q", "embedded://in-process", adapter.Target())
	}
}

func TestNew_WithNilRegistry(t *testing.T) {
	adapter, err := New(nil)
	if adapter != nil {
		t.Error("expected nil adapter when registry is nil")
	}

	var nilRegistryErr ErrNilRegistry
	if !errors.As(err, &nilRegistryErr) {
		t.Errorf("expected ErrNilRegistry, got %T: %v", err, err)
	}
}

func TestNew_WithEmptyRegistry(t *testing.T) {
	registry := &ServiceRegistry{}

	adapter, err := New(registry)
	if err != nil {
		t.Fatalf("New() with empty registry returned unexpected error: %v", err)
	}

	if !adapter.IsConnected() {
		t.Error("expected IsConnected() to return true for empty registry")
	}

	if adapter.Connection() == nil {
		t.Error("expected Connection() to return non-nil for empty registry")
	}

	conn, ok := adapter.Connection().(*embeddedClientConn)
	if !ok {
		t.Fatal("expected Connection() to return *embeddedClientConn")
	}

	if conn.MethodCount() != 0 {
		t.Errorf("expected 0 methods for empty registry, got %d", conn.MethodCount())
	}
}

func TestConnect_WithValidOptions(t *testing.T) {
	registry := testRegistry()
	opts := &platform.Options{
		EmbeddedServices: registry,
	}

	adapter, err := Connect(context.Background(), opts)
	if err != nil {
		t.Fatalf("Connect() returned unexpected error: %v", err)
	}

	if !adapter.IsConnected() {
		t.Error("expected IsConnected() to return true after Connect()")
	}

	if adapter.Connection() == nil {
		t.Error("expected Connection() to return non-nil value")
	}

	if adapter.Target() != "embedded://in-process" {
		t.Errorf("expected Target() = %q, got %q", "embedded://in-process", adapter.Target())
	}
}

func TestConnect_WithNilOptions(t *testing.T) {
	adapter, err := Connect(context.Background(), nil)
	if adapter != nil {
		t.Error("expected nil adapter when options are nil")
	}

	var nilRegistryErr ErrNilRegistry
	if !errors.As(err, &nilRegistryErr) {
		t.Errorf("expected ErrNilRegistry, got %T: %v", err, err)
	}
}

func TestConnect_WithNilServices(t *testing.T) {
	opts := &platform.Options{
		EmbeddedServices: nil,
	}

	adapter, err := Connect(context.Background(), opts)
	if adapter != nil {
		t.Error("expected nil adapter when EmbeddedServices is nil")
	}

	var nilRegistryErr ErrNilRegistry
	if !errors.As(err, &nilRegistryErr) {
		t.Errorf("expected ErrNilRegistry, got %T: %v", err, err)
	}
}

func TestConnect_WithWrongType(t *testing.T) {
	opts := &platform.Options{
		EmbeddedServices: "not-a-registry",
	}

	adapter, err := Connect(context.Background(), opts)
	if adapter != nil {
		t.Error("expected nil adapter when EmbeddedServices is wrong type")
	}

	var nilRegistryErr ErrNilRegistry
	if !errors.As(err, &nilRegistryErr) {
		t.Errorf("expected ErrNilRegistry, got %T: %v", err, err)
	}
}

func TestAdapter_Close(t *testing.T) {
	registry := testRegistry()

	adapter, err := New(registry)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	if !adapter.IsConnected() {
		t.Error("expected IsConnected() to return true before Close()")
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	if adapter.IsConnected() {
		t.Error("expected IsConnected() to return false after Close()")
	}
}

func TestAdapter_Close_Idempotent(t *testing.T) {
	registry := testRegistry()

	adapter, err := New(registry)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("first Close() returned unexpected error: %v", err)
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("second Close() returned unexpected error: %v", err)
	}

	if adapter.IsConnected() {
		t.Error("expected IsConnected() to return false after double Close()")
	}
}

func TestAdapter_Target(t *testing.T) {
	registry := testRegistry()

	adapter, err := New(registry)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	expected := "embedded://in-process"
	if got := adapter.Target(); got != expected {
		t.Errorf("expected Target() = %q, got %q", expected, got)
	}
}
