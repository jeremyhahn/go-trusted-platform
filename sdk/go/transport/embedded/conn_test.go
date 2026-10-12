package embedded

import (
	"context"
	"errors"
	"strings"
	"testing"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInvoke_RegisteredMethod(t *testing.T) {
	registry := testRegistry()
	conn := newEmbeddedClientConn(registry)

	req := &platformv1.GetVersionRequest{}
	reply := &platformv1.GetVersionResponse{}

	err := conn.Invoke(context.Background(), platformv1.PlatformDaemon_GetVersion_FullMethodName, req, reply)
	if err != nil {
		t.Fatalf("Invoke() returned unexpected error: %v", err)
	}

	if reply.Version != "1.0.0-test" {
		t.Errorf("expected Version = %q, got %q", "1.0.0-test", reply.Version)
	}
}

func TestInvoke_UnregisteredMethod(t *testing.T) {
	registry := testRegistry()
	conn := newEmbeddedClientConn(registry)

	req := &platformv1.GetVersionRequest{}
	reply := &platformv1.GetVersionResponse{}

	err := conn.Invoke(context.Background(), "/platform.v1.Nonexistent/FakeMethod", req, reply)
	if err == nil {
		t.Fatal("expected error for unregistered method, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}

	if st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented code, got %v", st.Code())
	}

	if !strings.Contains(st.Message(), "not registered") {
		t.Errorf("expected error message to contain 'not registered', got %q", st.Message())
	}
}

// An in-process call has no connection, so a call bound to its channel is
// refused with the typed error before dispatch and its proof callback never
// runs.
func TestInvoke_RefusesChannelBinding(t *testing.T) {
	conn := newEmbeddedClientConn(testRegistry())
	called := false
	bind := transport.WithChannelBinding(func(context.Context, []byte) error {
		called = true
		return nil
	})

	err := conn.Invoke(context.Background(), platformv1.PlatformDaemon_GetVersion_FullMethodName,
		&platformv1.GetVersionRequest{}, &platformv1.GetVersionResponse{}, bind)

	var unavailable *transport.ErrChannelBindingUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want ErrChannelBindingUnavailable", err)
	}
	if unavailable.Transport != platform.ProtocolEmbedded.String() {
		t.Errorf("transport = %q, want %q", unavailable.Transport, platform.ProtocolEmbedded.String())
	}
	if called {
		t.Error("the proof callback ran on a transport with no connection to bind to")
	}
}

func TestInvoke_NilResponse(t *testing.T) {
	// Create a daemon server that returns nil for GetStatus.
	nilServer := &nilResponseDaemonServer{}
	registry := &ServiceRegistry{
		Daemon: nilServer,
	}
	conn := newEmbeddedClientConn(registry)

	req := &platformv1.GetStatusRequest{}
	reply := &platformv1.GetStatusResponse{}

	err := conn.Invoke(context.Background(), platformv1.PlatformDaemon_GetStatus_FullMethodName, req, reply)
	if err != nil {
		t.Fatalf("Invoke() with nil response returned unexpected error: %v", err)
	}
}

// nilResponseDaemonServer returns nil responses for testing.
type nilResponseDaemonServer struct {
	platformv1.UnimplementedPlatformDaemonServer
}

func (s *nilResponseDaemonServer) GetStatus(ctx context.Context, req *platformv1.GetStatusRequest) (*platformv1.GetStatusResponse, error) {
	return nil, nil
}

func TestInvoke_HandlerError(t *testing.T) {
	errServer := &errorDaemonServer{}
	registry := &ServiceRegistry{
		Daemon: errServer,
	}
	conn := newEmbeddedClientConn(registry)

	req := &platformv1.GetStatusRequest{}
	reply := &platformv1.GetStatusResponse{}

	err := conn.Invoke(context.Background(), platformv1.PlatformDaemon_GetStatus_FullMethodName, req, reply)
	if err == nil {
		t.Fatal("expected error from handler, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

// errorDaemonServer returns errors for testing.
type errorDaemonServer struct {
	platformv1.UnimplementedPlatformDaemonServer
}

func (s *errorDaemonServer) GetStatus(ctx context.Context, req *platformv1.GetStatusRequest) (*platformv1.GetStatusResponse, error) {
	return nil, status.Error(codes.Internal, "test error from handler")
}

// callerKey marks the context a CallerContext hook returns.
type callerKey struct{}

// callerDaemonServer reports, as its version, the caller identity the
// context reached it with.
type callerDaemonServer struct {
	platformv1.UnimplementedPlatformDaemonServer
}

func (s *callerDaemonServer) GetVersion(ctx context.Context, req *platformv1.GetVersionRequest) (*platformv1.GetVersionResponse, error) {
	caller, ok := ctx.Value(callerKey{}).(string)
	if !ok {
		caller = "none"
	}
	return &platformv1.GetVersionResponse{Version: caller}, nil
}

// The embedder states who is calling, as a network transport's interceptors
// do; the hook's context is the one the service sees.
func TestInvoke_CallerContextReachesTheHandler(t *testing.T) {
	conn := newEmbeddedClientConn(&ServiceRegistry{
		Daemon: &callerDaemonServer{},
		CallerContext: func(ctx context.Context) context.Context {
			return context.WithValue(ctx, callerKey{}, "the embedder")
		},
	})

	reply := &platformv1.GetVersionResponse{}
	if err := conn.Invoke(context.Background(), platformv1.PlatformDaemon_GetVersion_FullMethodName, &platformv1.GetVersionRequest{}, reply); err != nil {
		t.Fatalf("Invoke() error: %v", err)
	}
	if reply.GetVersion() != "the embedder" {
		t.Fatalf("caller = %q, want the embedder", reply.GetVersion())
	}
}

// Without a hook the call carries no identity, and a service that checks
// one refuses it.
func TestInvoke_NoCallerContextAddsNoIdentity(t *testing.T) {
	conn := newEmbeddedClientConn(&ServiceRegistry{Daemon: &callerDaemonServer{}})

	reply := &platformv1.GetVersionResponse{}
	if err := conn.Invoke(context.Background(), platformv1.PlatformDaemon_GetVersion_FullMethodName, &platformv1.GetVersionRequest{}, reply); err != nil {
		t.Fatalf("Invoke() error: %v", err)
	}
	if reply.GetVersion() != "none" {
		t.Fatalf("caller = %q, want none", reply.GetVersion())
	}
}

func TestNewStream_ReturnsUnimplemented(t *testing.T) {
	registry := testRegistry()
	conn := newEmbeddedClientConn(registry)

	stream, err := conn.NewStream(context.Background(), nil, "/platform.v1.PlatformDaemon/StreamEvents")
	if stream != nil {
		t.Error("expected nil stream")
	}

	if err == nil {
		t.Fatal("expected error from NewStream, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}

	if st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented code, got %v", st.Code())
	}

	if !strings.Contains(st.Message(), "streaming not supported") {
		t.Errorf("expected error message to contain 'streaming not supported', got %q", st.Message())
	}
}

func TestMethodCount(t *testing.T) {
	registry := testRegistry()
	conn := newEmbeddedClientConn(registry)

	count := conn.MethodCount()
	if count == 0 {
		t.Error("expected MethodCount() > 0 for registry with Daemon service")
	}

	// The daemon service registers 14 unary methods (excluding streaming).
	if count != 13 {
		t.Errorf("expected 13 daemon methods, got %d", count)
	}
}

func TestMethodCount_EmptyRegistry(t *testing.T) {
	registry := &ServiceRegistry{}
	conn := newEmbeddedClientConn(registry)

	if conn.MethodCount() != 0 {
		t.Errorf("expected 0 methods for empty registry, got %d", conn.MethodCount())
	}
}

func TestHasMethod_Existing(t *testing.T) {
	registry := testRegistry()
	conn := newEmbeddedClientConn(registry)

	if !conn.HasMethod(platformv1.PlatformDaemon_GetVersion_FullMethodName) {
		t.Errorf("expected HasMethod(%q) to return true", platformv1.PlatformDaemon_GetVersion_FullMethodName)
	}

	if !conn.HasMethod(platformv1.PlatformDaemon_GetHealth_FullMethodName) {
		t.Errorf("expected HasMethod(%q) to return true", platformv1.PlatformDaemon_GetHealth_FullMethodName)
	}

	if !conn.HasMethod(platformv1.PlatformDaemon_GetStatus_FullMethodName) {
		t.Errorf("expected HasMethod(%q) to return true", platformv1.PlatformDaemon_GetStatus_FullMethodName)
	}
}

func TestHasMethod_Missing(t *testing.T) {
	registry := testRegistry()
	conn := newEmbeddedClientConn(registry)

	if conn.HasMethod("/platform.v1.Nonexistent/FakeMethod") {
		t.Error("expected HasMethod() to return false for unregistered method")
	}

	if conn.HasMethod("") {
		t.Error("expected HasMethod() to return false for empty string")
	}
}

func TestCopyProtoMessage_Valid(t *testing.T) {
	src := &platformv1.GetVersionResponse{
		Version:   "2.0.0",
		BuildTime: "2026-01-01",
		GitCommit: "abc123",
		GoVersion: "go1.26",
	}
	dst := &platformv1.GetVersionResponse{}

	err := copyProtoMessage(src, dst)
	if err != nil {
		t.Fatalf("copyProtoMessage() returned unexpected error: %v", err)
	}

	if dst.Version != src.Version {
		t.Errorf("expected Version = %q, got %q", src.Version, dst.Version)
	}

	if dst.BuildTime != src.BuildTime {
		t.Errorf("expected BuildTime = %q, got %q", src.BuildTime, dst.BuildTime)
	}

	if dst.GitCommit != src.GitCommit {
		t.Errorf("expected GitCommit = %q, got %q", src.GitCommit, dst.GitCommit)
	}

	if dst.GoVersion != src.GoVersion {
		t.Errorf("expected GoVersion = %q, got %q", src.GoVersion, dst.GoVersion)
	}
}

func TestCopyProtoMessage_NonProtoSource(t *testing.T) {
	src := "not-a-proto-message"
	dst := &platformv1.GetVersionResponse{}

	err := copyProtoMessage(src, dst)
	if err == nil {
		t.Fatal("expected error for non-proto source, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}

	if !strings.Contains(st.Message(), "not a proto.Message") {
		t.Errorf("expected error about proto.Message, got %q", st.Message())
	}
}

func TestCopyProtoMessage_NonProtoDest(t *testing.T) {
	src := &platformv1.GetVersionResponse{Version: "1.0.0"}
	var dst string

	err := copyProtoMessage(src, dst)
	if err == nil {
		t.Fatal("expected error for non-proto destination, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

func TestString(t *testing.T) {
	registry := testRegistry()
	conn := newEmbeddedClientConn(registry)

	str := conn.String()
	if !strings.Contains(str, "embeddedClientConn") {
		t.Errorf("expected String() to contain 'embeddedClientConn', got %q", str)
	}

	if !strings.Contains(str, "methods:") {
		t.Errorf("expected String() to contain 'methods:', got %q", str)
	}
}
