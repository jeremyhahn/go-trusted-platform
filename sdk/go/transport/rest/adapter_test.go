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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

func TestConnect_NilOptions(t *testing.T) {
	ctx := context.Background()

	_, err := Connect(ctx, nil)
	if !errors.Is(err, platform.ErrNilOptions) {
		t.Errorf("Connect(nil) error = %v, want %v", err, platform.ErrNilOptions)
	}
}

func TestConnect_EmptyAddress(t *testing.T) {
	ctx := context.Background()
	opts := platform.NewOptions()
	opts.RESTAddr = ""

	_, err := Connect(ctx, opts)
	if !errors.Is(err, platform.ErrEmptyAddress) {
		t.Errorf("Connect() error = %v, want %v", err, platform.ErrEmptyAddress)
	}
}

func TestConnect_WithHealthyServer(t *testing.T) {
	// Create a test server with health endpoint
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	if !adapter.IsConnected() {
		t.Error("adapter should report connected")
	}

	if adapter.Target() != server.URL {
		t.Errorf("Target() = %q, want %q", adapter.Target(), server.URL)
	}

	if adapter.Connection() == nil {
		t.Error("Connection() should not return nil")
	}
}

// trustServer returns the option that makes the adapter trust the
// in-process TLS test server's self-signed certificate.
func trustServer(server *httptest.Server) platform.Option {
	return platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
}

// assertConnectionFailed fails the test unless err is a REST
// ErrConnectionFailed for target.
func assertConnectionFailed(t *testing.T, err error, target string) {
	t.Helper()
	var connErr platform.ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("Connect() error = %T: %v, want platform.ErrConnectionFailed", err, err)
	}
	if connErr.Protocol != platform.ProtocolREST {
		t.Errorf("Protocol = %v, want %v", connErr.Protocol, platform.ProtocolREST)
	}
	if connErr.Target != target {
		t.Errorf("Target = %q, want %q", connErr.Target, target)
	}
}

func TestConnect_HealthProbeNotOK(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	adapter, err := Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	))
	if adapter != nil {
		t.Error("Connect() must not return an adapter when the health probe fails")
	}
	assertConnectionFailed(t, err, server.URL)

	var statusErr ErrHTTPStatus
	if !errors.As(err, &statusErr) {
		t.Fatalf("Connect() error should wrap ErrHTTPStatus, got %v", err)
	}
	if statusErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d, want %d", statusErr.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestConnect_HealthProbeUnreachable(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	target := server.URL
	opt := trustServer(server)
	server.Close()

	adapter, err := Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(target),
		opt,
	))
	if adapter != nil {
		t.Error("Connect() must not return an adapter when the server is unreachable")
	}
	assertConnectionFailed(t, err, target)
}

func TestConnect_UntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// No trustServer option: the system roots do not hold the test CA.
	_, err := Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL),
	))
	assertConnectionFailed(t, err, server.URL)
}

func TestConnect_RefusesPlaintextHTTP(t *testing.T) {
	tests := []struct {
		name string
		opts []platform.Option
	}{
		{name: "without a token"},
		{name: "with a token", opts: []platform.Option{platform.WithBearerToken("secret")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			opts := platform.NewOptions(append(tt.opts, platform.WithRESTAddr(server.URL))...)
			adapter, err := Connect(context.Background(), opts)
			if adapter != nil {
				t.Error("Connect() must not return an adapter for an http:// address")
			}

			var insecureErr platform.ErrInsecureTransport
			if !errors.As(err, &insecureErr) {
				t.Fatalf("Connect() error = %T: %v, want platform.ErrInsecureTransport", err, err)
			}
			if insecureErr.Protocol != platform.ProtocolREST {
				t.Errorf("Protocol = %v, want %v", insecureErr.Protocol, platform.ProtocolREST)
			}
			if requests.Load() != 0 {
				t.Errorf("server received %d plaintext requests, want 0", requests.Load())
			}
		})
	}
}

func TestConnect_AddsHTTPSPrefix(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addrWithoutScheme := strings.TrimPrefix(server.URL, "https://")

	adapter, err := Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(addrWithoutScheme),
		trustServer(server),
	))
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	if adapter.Target() != server.URL {
		t.Errorf("Target() = %q, want %q", adapter.Target(), server.URL)
	}
}

func TestConnect_SendsBearerTokenOverTLS(t *testing.T) {
	var authHeader atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			authHeader.Store(r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	adapter, err := Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
		platform.WithBearerToken("secret"),
	))
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	if err := adapter.(*Adapter).DoRequest(context.Background(), http.MethodGet, "/api/test", nil, nil); err != nil {
		t.Fatalf("DoRequest() returned error: %v", err)
	}
	if got := authHeader.Load(); got != "Bearer secret" {
		t.Errorf("Authorization = %v, want %q", got, "Bearer secret")
	}
}

func TestConnect_HonoursTLSServerName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// The httptest certificate is valid for example.com and 127.0.0.1.
	t.Run("matching name connects", func(t *testing.T) {
		adapter, err := Connect(context.Background(), platform.NewOptions(
			platform.WithRESTAddr(server.URL),
			trustServer(server),
			platform.WithTLSServerName("example.com"),
		))
		if err != nil {
			t.Fatalf("Connect() returned error: %v", err)
		}
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	t.Run("mismatched name is rejected", func(t *testing.T) {
		_, err := Connect(context.Background(), platform.NewOptions(
			platform.WithRESTAddr(server.URL),
			trustServer(server),
			platform.WithTLSServerName("wrong.example"),
		))
		assertConnectionFailed(t, err, server.URL)
	})
}

func TestAdapter_IsConnected(t *testing.T) {
	a := &Adapter{}

	// Initially not connected
	if a.IsConnected() {
		t.Error("IsConnected() should return false initially")
	}

	// After storing true
	a.connected.Store(true)
	if !a.IsConnected() {
		t.Error("IsConnected() should return true after storing true")
	}

	// After storing closed
	a.closed.Store(true)
	if a.IsConnected() {
		t.Error("IsConnected() should return false when closed")
	}
}

func TestAdapter_Close(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}

	// Close should succeed
	err = adapter.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Should be disconnected after close
	if adapter.IsConnected() {
		t.Error("IsConnected() should return false after Close()")
	}

	// Close again should be safe (idempotent)
	err = adapter.Close()
	if err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}

func TestAdapter_SetToken(t *testing.T) {
	a := &Adapter{}

	// Initially empty
	if got := a.GetToken(); got != "" {
		t.Errorf("GetToken() = %q, want empty", got)
	}

	// After setting token
	a.SetToken("test-token-123")
	if got := a.GetToken(); got != "test-token-123" {
		t.Errorf("GetToken() = %q, want %q", got, "test-token-123")
	}

	// Update token
	a.SetToken("new-token-456")
	if got := a.GetToken(); got != "new-token-456" {
		t.Errorf("GetToken() = %q, want %q", got, "new-token-456")
	}
}

func TestAdapter_DoRequest_Success(t *testing.T) {
	expectedResponse := map[string]string{"status": "ok"}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(expectedResponse); err != nil {
			return
		}
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	restAdapter := adapter.(*Adapter)

	var result map[string]string
	err = restAdapter.DoRequest(ctx, http.MethodPost, "/api/test", nil, &result)
	if err != nil {
		t.Fatalf("DoRequest() returned error: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("result[status] = %q, want %q", result["status"], "ok")
	}
}

func TestAdapter_DoRequest_WithBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body["name"] != "test" {
			t.Errorf("Expected body[name] = 'test', got %s", body["name"])
		}
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	restAdapter := adapter.(*Adapter)

	reqBody := map[string]string{"name": "test"}
	err = restAdapter.DoRequest(ctx, http.MethodPost, "/api/test", reqBody, nil)
	if err != nil {
		t.Fatalf("DoRequest() returned error: %v", err)
	}
}

func TestAdapter_DoRequest_WithToken(t *testing.T) {
	var authHeaderReceived string

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		authHeaderReceived = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	restAdapter := adapter.(*Adapter)
	restAdapter.SetToken("test-token")

	err = restAdapter.DoRequest(ctx, http.MethodGet, "/api/test", nil, nil)
	if err != nil {
		t.Fatalf("DoRequest() returned error: %v", err)
	}

	if authHeaderReceived != "Bearer test-token" {
		t.Errorf("Expected Authorization header 'Bearer test-token', got %s", authHeaderReceived)
	}
}

func TestAdapter_DoRequest_HTTPError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("resource not found"))
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	restAdapter := adapter.(*Adapter)

	err = restAdapter.DoRequest(ctx, http.MethodGet, "/api/missing", nil, nil)
	if err == nil {
		t.Fatal("DoRequest() should return error for 404")
	}

	var httpErr ErrHTTPStatus
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected ErrHTTPStatus, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want %d", httpErr.StatusCode, http.StatusNotFound)
	}
}

func TestAdapter_DoRequest_ClientClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}

	restAdapter := adapter.(*Adapter)
	adapter.Close()

	err = restAdapter.DoRequest(ctx, http.MethodGet, "/api/test", nil, nil)
	if err == nil {
		t.Fatal("DoRequest() should return error when client is closed")
	}

	var closedErr ErrClientClosed
	if !errors.As(err, &closedErr) {
		t.Fatalf("expected ErrClientClosed, got %T: %v", err, err)
	}
}

func TestRestClientConn_Invoke(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"version": "1.0.0"}); err != nil {
			return
		}
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	conn := adapter.Connection()

	var reply map[string]string
	err = conn.Invoke(ctx, "/platform.v1.PlatformDaemon/GetVersion", nil, &reply)
	if err != nil {
		t.Fatalf("Invoke() returned error: %v", err)
	}

	if reply["version"] != "1.0.0" {
		t.Errorf("reply[version] = %q, want %q", reply["version"], "1.0.0")
	}
}

func TestRestClientConn_Invoke_Closed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}

	conn := adapter.Connection()
	adapter.Close()

	err = conn.Invoke(ctx, "/platformv1.PlatformDaemon/GetVersion", nil, nil)
	if err == nil {
		t.Fatal("Invoke() should return error when closed")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unavailable)
	}
}

func TestRestClientConn_NewStream(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(true)
	conn := &restClientConn{adapter: a}

	_, err := conn.NewStream(context.Background(), nil, "/test/method")
	if err == nil {
		t.Fatal("NewStream() should return error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unimplemented {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unimplemented)
	}
}

func TestMapGRPCMethodToREST_KnownMethods(t *testing.T) {
	tests := []struct {
		grpcMethod     string
		expectedPath   string
		expectedMethod string
	}{
		{"/platform.v1.PlatformDaemon/GetVersion", "/api/v1/version", http.MethodGet},
		{"/platform.v1.CAService/IssueCertificate", "/api/v1/ca/certificates", http.MethodPost},
		{"/platform.v1.CAService/SignCSR", "/api/v1/ca/sign-csr", http.MethodPost},
		{"/platform.v1.KeyManagementService/Encrypt", "/api/v1/kms/encrypt", http.MethodPost},
		{"/platform.v1.VTPMService/Create", "/api/v1/vtpm/instances", http.MethodPost},
	}

	for _, tt := range tests {
		t.Run(tt.grpcMethod, func(t *testing.T) {
			path, method := mapGRPCMethodToREST(tt.grpcMethod)
			if path != tt.expectedPath {
				t.Errorf("path = %q, want %q", path, tt.expectedPath)
			}
			if method != tt.expectedMethod {
				t.Errorf("method = %q, want %q", method, tt.expectedMethod)
			}
		})
	}
}

func TestMapGRPCMethodToREST_UnknownMethod(t *testing.T) {
	// Test fallback path derivation for unknown methods
	path, method := mapGRPCMethodToREST("/platform.v1.UnknownService/UnknownMethod")

	// Should derive from method name - service name without "Service" suffix
	expectedPath := "/api/v1/unknown/unknownmethod"
	if path != expectedPath {
		t.Errorf("path = %q, want %q", path, expectedPath)
	}
	if method != http.MethodPost {
		t.Errorf("method = %q, want %q", method, http.MethodPost)
	}
}

func TestTranslateErrorToGRPC(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{
			name:         "HTTP 400",
			err:          ErrHTTPStatus{StatusCode: http.StatusBadRequest, Status: "Bad Request"},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "HTTP 401",
			err:          ErrHTTPStatus{StatusCode: http.StatusUnauthorized, Status: "Unauthorized"},
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "HTTP 403",
			err:          ErrHTTPStatus{StatusCode: http.StatusForbidden, Status: "Forbidden"},
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "HTTP 404",
			err:          ErrHTTPStatus{StatusCode: http.StatusNotFound, Status: "Not Found"},
			expectedCode: codes.NotFound,
		},
		{
			name:         "HTTP 409",
			err:          ErrHTTPStatus{StatusCode: http.StatusConflict, Status: "Conflict"},
			expectedCode: codes.AlreadyExists,
		},
		{
			name:         "HTTP 500",
			err:          ErrHTTPStatus{StatusCode: http.StatusInternalServerError, Status: "Internal Server Error"},
			expectedCode: codes.Internal,
		},
		{
			name:         "HTTP 503",
			err:          ErrHTTPStatus{StatusCode: http.StatusServiceUnavailable, Status: "Service Unavailable"},
			expectedCode: codes.Unavailable,
		},
		{
			name:         "Client Closed",
			err:          ErrClientClosed{},
			expectedCode: codes.Unavailable,
		},
		{
			name:         "Request Failed",
			err:          ErrRequestFailed{Method: "GET", Path: "/test", Err: errors.New("network error")},
			expectedCode: codes.Unavailable,
		},
		{
			name:         "Marshal Failed",
			err:          ErrMarshalFailed{Err: errors.New("invalid json")},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "Unmarshal Failed",
			err:          ErrUnmarshalFailed{Err: errors.New("invalid response")},
			expectedCode: codes.Internal,
		},
		{
			name:         "Unknown Error",
			err:          errors.New("unknown error"),
			expectedCode: codes.Unknown,
		},
		{
			name:         "Nil Error",
			err:          nil,
			expectedCode: codes.OK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := translateErrorToGRPC(tt.err)
			if tt.err == nil {
				if grpcErr != nil {
					t.Errorf("translateErrorToGRPC(nil) = %v, want nil", grpcErr)
				}
				return
			}

			st, ok := status.FromError(grpcErr)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T: %v", grpcErr, grpcErr)
			}
			if st.Code() != tt.expectedCode {
				t.Errorf("code = %v, want %v", st.Code(), tt.expectedCode)
			}
		})
	}
}

// TestTranslateErrorToGRPC_Message pins the status message: the bare "error"
// string of a platformd {"error":"..."} body, the same message QUIC and MCP
// return, and the body unchanged when it has no such string.
func TestTranslateErrorToGRPC_Message(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "error envelope", body: `{"error":"luks: device path is required"}`, want: "luks: device path is required"},
		{name: "error beside other keys", body: `{"code":400,"error":"bad slot","success":false}`, want: "bad slot"},
		{name: "plain text", body: "upstream unavailable", want: "upstream unavailable"},
		{name: "empty error string", body: `{"error":""}`, want: `{"error":""}`},
		{name: "error is an object", body: `{"error":{"code":7}}`, want: `{"error":{"code":7}}`},
		{name: "empty body", body: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, ok := status.FromError(translateErrorToGRPC(ErrHTTPStatus{StatusCode: http.StatusBadRequest, Body: tt.body}))
			if !ok {
				t.Fatal("expected a gRPC status error")
			}
			if st.Code() != codes.InvalidArgument {
				t.Errorf("code = %v, want %v", st.Code(), codes.InvalidArgument)
			}
			if st.Message() != tt.want {
				t.Errorf("message = %q, want %q", st.Message(), tt.want)
			}
		})
	}
}

func TestErrHTTPStatus_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrHTTPStatus
		expected string
	}{
		{
			name:     "with body",
			err:      ErrHTTPStatus{StatusCode: 404, Status: "Not Found", Body: "resource not found"},
			expected: "HTTP 404 Not Found: resource not found",
		},
		{
			name:     "without body",
			err:      ErrHTTPStatus{StatusCode: 500, Status: "Internal Server Error"},
			expected: "HTTP 500 Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrRequestFailed_Unwrap(t *testing.T) {
	innerErr := errors.New("connection refused")
	err := ErrRequestFailed{Method: "GET", Path: "/test", Err: innerErr}

	if !errors.Is(err, innerErr) {
		t.Error("Unwrap() should return the inner error")
	}
}

func TestErrMarshalFailed_Unwrap(t *testing.T) {
	innerErr := errors.New("invalid type")
	err := ErrMarshalFailed{Err: innerErr}

	if !errors.Is(err, innerErr) {
		t.Error("Unwrap() should return the inner error")
	}
}

func TestErrUnmarshalFailed_Unwrap(t *testing.T) {
	innerErr := errors.New("invalid json")
	err := ErrUnmarshalFailed{Err: innerErr}

	if !errors.Is(err, innerErr) {
		t.Error("Unwrap() should return the inner error")
	}
}

func TestConnect_StripsTrailingSlash(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL+"/"),
		trustServer(server),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Should have stripped trailing slash
	if adapter.Target() != server.URL {
		t.Errorf("Target() = %q, want %q", adapter.Target(), server.URL)
	}
}

func TestErrClientClosed_Error(t *testing.T) {
	err := ErrClientClosed{}
	expected := "REST client is closed"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrNotImplemented_Error(t *testing.T) {
	err := ErrNotImplemented{Method: "streaming"}
	expected := "method not implemented for REST transport: streaming"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}
