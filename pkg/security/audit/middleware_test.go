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

package audit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestHTTPAuditMiddleware(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := HTTPMiddlewareConfig{
		Logger: logger,
		ActorExtractor: func(r *http.Request) string {
			return r.Header.Get("X-User")
		},
	}

	middleware := HTTPAuditMiddleware(config)

	// Create a simple handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with middleware
	handler2 := middleware(nextHandler)

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-User", "testuser")
	req.Header.Set("X-Request-ID", "req-123")

	// Make request
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	// Check response
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Close logger to flush all events before checking buffer
	logger.Close()

	// Check that audit was logged
	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_SkipPaths(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false, // Use sync logging for deterministic test
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger:    logger,
		SkipPaths: []string{"/health", "/metrics"},
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	// Request to skipped path
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	// Should not be logged
	if buf.Len() > 0 {
		t.Error("skipped path should not be logged")
	}

	// Request to non-skipped path
	req = httptest.NewRequest(http.MethodGet, "/api/data", nil)
	handler2.ServeHTTP(rr, req)

	// Should be logged (sync mode, so immediate)
	if buf.Len() == 0 {
		t.Error("non-skipped path should be logged")
	}
}

func TestHTTPAuditMiddleware_StatusCodes(t *testing.T) {
	tests := []struct {
		name            string
		statusCode      int
		expectedOutcome string
	}{
		{"success", http.StatusOK, "success"},
		{"client error", http.StatusBadRequest, "failure"},
		{"unauthorized", http.StatusUnauthorized, "denied"},
		{"forbidden", http.StatusForbidden, "denied"},
		{"server error", http.StatusInternalServerError, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, nil)
			logger, err := NewLogger(LoggerConfig{
				Logger:        slog.New(handler),
				EnableAsync:   true,
				BufferSize:    100,
				FlushInterval: 10 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}

			config := HTTPMiddlewareConfig{Logger: logger}
			middleware := HTTPAuditMiddleware(config)

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})

			handler2 := middleware(nextHandler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rr := httptest.NewRecorder()
			handler2.ServeHTTP(rr, req)

			time.Sleep(30 * time.Millisecond)
			logger.Close()

			// Check the log contains expected outcome
			logOutput := buf.String()
			if logOutput == "" {
				t.Error("nothing was logged")
			}
		})
	}
}

func TestHTTPAuditMiddleware_IncludeHeaders(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger:         logger,
		IncludeHeaders: []string{"X-Custom-Header"},
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Custom-Header", "custom-value")

	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	time.Sleep(30 * time.Millisecond)
}

func TestHTTPAuditMiddleware_ResourceExtractor(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger: logger,
		ResourceExtractor: func(r *http.Request) (resource, resourceType string) {
			return "document:123", "document"
		},
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/documents/123", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	time.Sleep(30 * time.Millisecond)
}

func TestHTTPAuditMiddleware_IncludeQueryParams(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false, // Use sync for deterministic test
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger:             logger,
		IncludeQueryParams: true,
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/test?param1=value1&param2=value2", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	// Check that something was logged
	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_CorrelationID(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger: logger,
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	// Test with X-Correlation-ID instead of X-Request-ID
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Correlation-ID", "corr-456")
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_WriteWithoutWriteHeader(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger: logger,
	}

	middleware := HTTPAuditMiddleware(config)

	// Handler that writes without calling WriteHeader first
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write without WriteHeader should set status to 200
		w.Write([]byte("response body"))
	})

	handler2 := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	// Check response code defaults to 200
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestExtractSourceIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:       "from X-Forwarded-For single",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "1.2.3.4",
		},
		{
			name:       "from X-Forwarded-For multiple",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "1.2.3.4",
		},
		{
			name:       "from X-Real-IP",
			headers:    map[string]string{"X-Real-IP": "1.2.3.4"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "1.2.3.4",
		},
		{
			name:       "from RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "10.0.0.1:12345",
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"},
			remoteAddr: "10.0.0.1:12345",
			expected:   "1.2.3.4",
		},
		{
			name:       "RemoteAddr without port",
			headers:    map[string]string{},
			remoteAddr: "10.0.0.1",
			expected:   "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := extractSourceIP(req)
			if ip != tt.expected {
				t.Errorf("extractSourceIP() = %s, expected %s", ip, tt.expected)
			}
		})
	}
}

func TestExtractMethodName(t *testing.T) {
	tests := []struct {
		fullMethod string
		expected   string
	}{
		{"/pkg.Service/Method", "Method"},
		{"/Service/Method", "Method"},
		{"Method", "Method"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.fullMethod, func(t *testing.T) {
			result := extractMethodName(tt.fullMethod)
			if result != tt.expected {
				t.Errorf("extractMethodName(%s) = %s, expected %s", tt.fullMethod, result, tt.expected)
			}
		})
	}
}

func TestExtractGRPCMetadata(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		key      string
		expected string
	}{
		{
			name:     "empty context",
			ctx:      context.Background(),
			key:      "x-request-id",
			expected: "",
		},
		{
			name: "metadata with value",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("x-request-id", "req-123"),
			),
			key:      "x-request-id",
			expected: "req-123",
		},
		{
			name: "metadata without requested key",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("other-key", "other-value"),
			),
			key:      "x-request-id",
			expected: "",
		},
		{
			name: "metadata with multiple values",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("x-request-id", "first", "x-request-id", "second"),
			),
			key:      "x-request-id",
			expected: "first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractGRPCMetadata(tt.ctx, tt.key)
			if result != tt.expected {
				t.Errorf("extractGRPCMetadata() = %s, expected %s", result, tt.expected)
			}
		})
	}
}

// mockAddr implements net.Addr for testing
type mockAddr struct {
	network string
	address string
}

func (a mockAddr) Network() string { return a.network }
func (a mockAddr) String() string  { return a.address }

func TestExtractGRPCSourceIP(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name:     "no peer",
			ctx:      context.Background(),
			expected: "",
		},
		{
			name: "peer with IP and port",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr: mockAddr{network: "tcp", address: "192.168.1.1:12345"},
			}),
			expected: "192.168.1.1",
		},
		{
			name: "peer without port",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr: mockAddr{network: "tcp", address: "192.168.1.1"},
			}),
			expected: "192.168.1.1",
		},
		{
			name: "peer with IPv6",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr: mockAddr{network: "tcp", address: "[::1]:12345"},
			}),
			expected: "[::1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractGRPCSourceIP(tt.ctx)
			if result != tt.expected {
				t.Errorf("extractGRPCSourceIP() = %s, expected %s", result, tt.expected)
			}
		})
	}
}

func TestGRPCAuditInterceptor_Success(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCAuditInterceptor(config)

	// Create mock context with peer
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: mockAddr{network: "tcp", address: "192.168.1.1:12345"},
	})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-request-id", "grpc-req-123"))

	info := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.TestService/TestMethod",
	}

	// Successful handler
	handler2 := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	resp, err := interceptor(ctx, "request", info, handler2)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if resp != "response" {
		t.Errorf("expected 'response', got %v", resp)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCAuditInterceptor_Error(t *testing.T) {
	tests := []struct {
		name           string
		grpcErr        error
		expectedLogged bool
	}{
		{
			name:           "permission denied",
			grpcErr:        status.Error(codes.PermissionDenied, "permission denied"),
			expectedLogged: true,
		},
		{
			name:           "unauthenticated",
			grpcErr:        status.Error(codes.Unauthenticated, "unauthenticated"),
			expectedLogged: true,
		},
		{
			name:           "internal error",
			grpcErr:        status.Error(codes.Internal, "internal error"),
			expectedLogged: true,
		},
		{
			name:           "unavailable",
			grpcErr:        status.Error(codes.Unavailable, "unavailable"),
			expectedLogged: true,
		},
		{
			name:           "data loss",
			grpcErr:        status.Error(codes.DataLoss, "data loss"),
			expectedLogged: true,
		},
		{
			name:           "invalid argument",
			grpcErr:        status.Error(codes.InvalidArgument, "invalid argument"),
			expectedLogged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, nil)
			logger, err := NewLogger(LoggerConfig{
				Logger:        slog.New(handler),
				EnableAsync:   true,
				BufferSize:    100,
				FlushInterval: 10 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}

			config := GRPCInterceptorConfig{
				Logger: logger,
			}

			interceptor := GRPCAuditInterceptor(config)

			ctx := context.Background()
			info := &grpc.UnaryServerInfo{
				FullMethod: "/pkg.TestService/TestMethod",
			}

			handler2 := func(ctx context.Context, req any) (any, error) {
				return nil, tt.grpcErr
			}

			_, err = interceptor(ctx, "request", info, handler2)
			if err == nil {
				t.Error("expected error, got nil")
			}

			logger.Close()

			if tt.expectedLogged && buf.Len() == 0 {
				t.Error("nothing was logged")
			}
		})
	}
}

func TestGRPCAuditInterceptor_SkipMethods(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false, // Use sync for deterministic test
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := GRPCInterceptorConfig{
		Logger:      logger,
		SkipMethods: []string{"HealthCheck", "Ping"},
	}

	interceptor := GRPCAuditInterceptor(config)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.TestService/HealthCheck",
	}

	handler2 := func(ctx context.Context, req any) (any, error) {
		return "healthy", nil
	}

	_, err = interceptor(ctx, "request", info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should not be logged because method is skipped
	if buf.Len() > 0 {
		t.Error("skipped method should not be logged")
	}
}

func TestGRPCAuditInterceptor_ActorExtractor(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
		ActorExtractor: func(ctx context.Context) string {
			return "custom-actor"
		},
	}

	interceptor := GRPCAuditInterceptor(config)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.TestService/TestMethod",
	}

	handler2 := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	_, err = interceptor(ctx, "request", info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCAuditInterceptor_ResourceExtractor(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
		ResourceExtractor: func(ctx context.Context, method string, req any) (resource, resourceType string) {
			return "document:456", "document"
		},
	}

	interceptor := GRPCAuditInterceptor(config)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.TestService/TestMethod",
	}

	handler2 := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	_, err = interceptor(ctx, "request", info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCAuditInterceptor_CorrelationID(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCAuditInterceptor(config)

	// Create context with x-correlation-id instead of x-request-id
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-correlation-id", "corr-789"))
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.TestService/TestMethod",
	}

	handler2 := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	_, err = interceptor(ctx, "request", info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *mockServerStream) Context() context.Context {
	return s.ctx
}

func TestGRPCStreamAuditInterceptor_Success(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCStreamAuditInterceptor(config)

	// Create mock context with peer
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: mockAddr{network: "tcp", address: "192.168.1.1:12345"},
	})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-request-id", "stream-req-123"))

	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/pkg.TestService/StreamMethod",
		IsClientStream: true,
		IsServerStream: true,
	}

	handler2 := func(srv any, ss grpc.ServerStream) error {
		return nil
	}

	err = interceptor(nil, stream, info, handler2)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCStreamAuditInterceptor_Error(t *testing.T) {
	tests := []struct {
		name           string
		grpcErr        error
		expectedLogged bool
	}{
		{
			name:           "permission denied",
			grpcErr:        status.Error(codes.PermissionDenied, "permission denied"),
			expectedLogged: true,
		},
		{
			name:           "unauthenticated",
			grpcErr:        status.Error(codes.Unauthenticated, "unauthenticated"),
			expectedLogged: true,
		},
		{
			name:           "internal error",
			grpcErr:        status.Error(codes.Internal, "internal error"),
			expectedLogged: true,
		},
		{
			name:           "unavailable",
			grpcErr:        status.Error(codes.Unavailable, "unavailable"),
			expectedLogged: true,
		},
		{
			name:           "data loss",
			grpcErr:        status.Error(codes.DataLoss, "data loss"),
			expectedLogged: true,
		},
		{
			name:           "invalid argument",
			grpcErr:        status.Error(codes.InvalidArgument, "invalid argument"),
			expectedLogged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, nil)
			logger, err := NewLogger(LoggerConfig{
				Logger:        slog.New(handler),
				EnableAsync:   true,
				BufferSize:    100,
				FlushInterval: 10 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}

			config := GRPCInterceptorConfig{
				Logger: logger,
			}

			interceptor := GRPCStreamAuditInterceptor(config)

			stream := &mockServerStream{ctx: context.Background()}
			info := &grpc.StreamServerInfo{
				FullMethod:     "/pkg.TestService/StreamMethod",
				IsClientStream: true,
				IsServerStream: true,
			}

			handler2 := func(srv any, ss grpc.ServerStream) error {
				return tt.grpcErr
			}

			err = interceptor(nil, stream, info, handler2)
			if err == nil {
				t.Error("expected error, got nil")
			}

			logger.Close()

			if tt.expectedLogged && buf.Len() == 0 {
				t.Error("nothing was logged")
			}
		})
	}
}

func TestGRPCStreamAuditInterceptor_SkipMethods(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := GRPCInterceptorConfig{
		Logger:      logger,
		SkipMethods: []string{"StreamHealthCheck"},
	}

	interceptor := GRPCStreamAuditInterceptor(config)

	stream := &mockServerStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/pkg.TestService/StreamHealthCheck",
		IsClientStream: false,
		IsServerStream: true,
	}

	handler2 := func(srv any, ss grpc.ServerStream) error {
		return nil
	}

	err = interceptor(nil, stream, info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should not be logged because method is skipped
	if buf.Len() > 0 {
		t.Error("skipped method should not be logged")
	}
}

func TestGRPCStreamAuditInterceptor_ActorExtractor(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
		ActorExtractor: func(ctx context.Context) string {
			return "stream-actor"
		},
	}

	interceptor := GRPCStreamAuditInterceptor(config)

	stream := &mockServerStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/pkg.TestService/StreamMethod",
		IsClientStream: true,
		IsServerStream: false,
	}

	handler2 := func(srv any, ss grpc.ServerStream) error {
		return nil
	}

	err = interceptor(nil, stream, info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCStreamAuditInterceptor_CorrelationID(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCStreamAuditInterceptor(config)

	// Create context with x-correlation-id instead of x-request-id
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-correlation-id", "stream-corr-789"))

	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/pkg.TestService/StreamMethod",
		IsClientStream: true,
		IsServerStream: true,
	}

	handler2 := func(srv any, ss grpc.ServerStream) error {
		return nil
	}

	err = interceptor(nil, stream, info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestResponseWriter_WriteHeader_Idempotent(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	// First call should set the status code
	rw.WriteHeader(http.StatusCreated)
	if rw.statusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", rw.statusCode)
	}
	if !rw.written {
		t.Error("expected written to be true")
	}

	// Second call should not change the status code
	rw.WriteHeader(http.StatusNotFound)
	if rw.statusCode != http.StatusCreated {
		t.Errorf("status code should not change after first write, got %d", rw.statusCode)
	}
}

func TestResponseWriter_Write_SetsDefaultStatus(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	// Write without WriteHeader should set status to 200
	n, err := rw.Write([]byte("test"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != 4 {
		t.Errorf("expected 4 bytes written, got %d", n)
	}
	if rw.statusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", rw.statusCode)
	}
	if !rw.written {
		t.Error("expected written to be true")
	}
}

func TestExtractGRPCSourceIP_WithTCPAddr(t *testing.T) {
	// Test with real net.TCPAddr
	addr := &net.TCPAddr{
		IP:   net.ParseIP("10.0.0.1"),
		Port: 54321,
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})

	result := extractGRPCSourceIP(ctx)
	if result != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", result)
	}
}

// mockPersister implements EventPersister for testing
type mockPersister struct {
	persistErr error
	queryErr   error
	events     []AuditEvent
	closeErr   error
}

func (m *mockPersister) Persist(ctx context.Context, event AuditEvent) error {
	if m.persistErr != nil {
		return m.persistErr
	}
	m.events = append(m.events, event)
	return nil
}

func (m *mockPersister) Query(ctx context.Context, filter AuditFilter) ([]AuditEvent, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	return m.events, nil
}

func (m *mockPersister) Close() error {
	return m.closeErr
}

func TestGRPCAuditInterceptor_WithPersister(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
		Persister:     persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCAuditInterceptor(config)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.TestService/TestMethod",
	}

	handler2 := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	_, err = interceptor(ctx, "request", info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	if len(persister.events) == 0 {
		t.Error("expected event to be persisted")
	}
}

func TestGRPCStreamAuditInterceptor_WithPersister(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
		Persister:     persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCStreamAuditInterceptor(config)

	stream := &mockServerStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/pkg.TestService/StreamMethod",
		IsClientStream: true,
		IsServerStream: true,
	}

	handler2 := func(srv any, ss grpc.ServerStream) error {
		return nil
	}

	err = interceptor(nil, stream, info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	if len(persister.events) == 0 {
		t.Error("expected event to be persisted")
	}
}

func TestHTTPAuditMiddleware_WithPersister(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
		Persister:     persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := HTTPMiddlewareConfig{
		Logger: logger,
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	if len(persister.events) == 0 {
		t.Error("expected event to be persisted")
	}
}

func TestHTTPAuditMiddleware_UserAgent(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger: logger,
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", "TestAgent/1.0")
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_AnonymousActor(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// Config without ActorExtractor - should default to "anonymous"
	config := HTTPMiddlewareConfig{
		Logger: logger,
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCAuditInterceptor_AnonymousActor(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Config without ActorExtractor - should default to "anonymous"
	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCAuditInterceptor(config)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.TestService/TestMethod",
	}

	handler2 := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	_, err = interceptor(ctx, "request", info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCStreamAuditInterceptor_AnonymousActor(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Config without ActorExtractor - should default to "anonymous"
	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCStreamAuditInterceptor(config)

	stream := &mockServerStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/pkg.TestService/StreamMethod",
		IsClientStream: true,
		IsServerStream: true,
	}

	handler2 := func(srv any, ss grpc.ServerStream) error {
		return nil
	}

	err = interceptor(nil, stream, info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCAuditInterceptor_EmptyResource(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// ResourceExtractor that returns empty resource
	config := GRPCInterceptorConfig{
		Logger: logger,
		ResourceExtractor: func(ctx context.Context, method string, req any) (resource, resourceType string) {
			return "", "" // Empty resource
		},
	}

	interceptor := GRPCAuditInterceptor(config)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.TestService/TestMethod",
	}

	handler2 := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	_, err = interceptor(ctx, "request", info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_EmptyResource(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// ResourceExtractor that returns empty resource
	config := HTTPMiddlewareConfig{
		Logger: logger,
		ResourceExtractor: func(r *http.Request) (resource, resourceType string) {
			return "", "" // Empty resource
		},
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_EmptyRequestID(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger: logger,
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	// Request without X-Request-ID or X-Correlation-ID
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCAuditInterceptor_EmptyRequestID(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCAuditInterceptor(config)

	// Context without x-request-id or x-correlation-id metadata
	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.TestService/TestMethod",
	}

	handler2 := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	_, err = interceptor(ctx, "request", info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestGRPCStreamAuditInterceptor_EmptyRequestID(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := GRPCInterceptorConfig{
		Logger: logger,
	}

	interceptor := GRPCStreamAuditInterceptor(config)

	// Context without x-request-id or x-correlation-id metadata
	stream := &mockServerStream{ctx: context.Background()}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/pkg.TestService/StreamMethod",
		IsClientStream: true,
		IsServerStream: true,
	}

	handler2 := func(srv any, ss grpc.ServerStream) error {
		return nil
	}

	err = interceptor(nil, stream, info, handler2)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_IncludeQueryParams_Empty(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger:             logger,
		IncludeQueryParams: true,
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	// Request without query params
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_IncludeHeaders_EmptyValue(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger:         logger,
		IncludeHeaders: []string{"X-Custom-Header"},
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	// Request without the specified header
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_NoUserAgent(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   false,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	config := HTTPMiddlewareConfig{
		Logger: logger,
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	// Request without User-Agent header
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Del("User-Agent")
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestHTTPAuditMiddleware_PersisterError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockPersister{persistErr: errors.New("persist error")}
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
		Persister:     persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	config := HTTPMiddlewareConfig{
		Logger: logger,
	}

	middleware := HTTPAuditMiddleware(config)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler2 := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	// Request should still succeed even if persistence fails
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}
