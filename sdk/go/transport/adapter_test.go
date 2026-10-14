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

package transport_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"

	// Register the connectors that auto-detection walks through.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// TestConnect_FallsBackWhenRESTProbeFails proves that auto-detection moves on
// to the next protocol when the REST health probe fails, instead of handing
// back a REST client for a daemon that is not serving.
func TestConnect_FallsBackWhenRESTProbeFails(t *testing.T) {
	var healthProbes atomic.Int32
	restServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			healthProbes.Add(1)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer restServer.Close()

	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mcpwire.JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(mcpwire.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{"protocolVersion": "2024-11-05"},
		})
	}))
	defer mcpServer.Close()

	// Both httptest TLS servers share one certificate, so one config
	// trusts both.
	opts := platform.NewOptions(
		platform.WithRESTAddr(restServer.URL),
		platform.WithMCPAddr(mcpServer.URL),
		platform.WithTLSConfig(restServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()),
	)
	opts.UnixSocket = ""

	client, err := platform.Connect(context.Background(), opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer client.Close()

	if got := client.Protocol(); got != platform.ProtocolMCP {
		t.Errorf("Protocol() = %v, want %v", got, platform.ProtocolMCP)
	}
	if n := healthProbes.Load(); n != 1 {
		t.Errorf("REST health probes = %d, want 1", n)
	}
}

// timeoutNetError is a net.Error whose Timeout result the test chooses.
type timeoutNetError struct{ timeout bool }

func (e timeoutNetError) Error() string   { return "net error" }
func (e timeoutNetError) Timeout() bool   { return e.timeout }
func (e timeoutNetError) Temporary() bool { return false }

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"context deadline", context.DeadlineExceeded, true},
		{"wrapped context deadline", &url.Error{Op: "Get", URL: "https://x/health", Err: context.DeadlineExceeded}, true},
		{"network timeout", &net.OpError{Op: "dial", Err: timeoutNetError{timeout: true}}, true},
		{"network error that is not a timeout", timeoutNetError{timeout: false}, false},
		{"cancelled context", context.Canceled, false},
		{"plain error", errors.New("refused"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := transport.IsTimeout(tt.err); got != tt.want {
				t.Errorf("IsTimeout(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// newStalledTLSServer returns a TLS server that accepts every request and
// never answers it; the handlers return when the test ends.
func newStalledTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	// Cleanups run last-in first-out: release the handlers, then close.
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	return server
}

// requireConnectTimeout asserts err is an ErrConnectionFailed for proto that
// carries ErrTimeout and still unwraps to context.DeadlineExceeded.
func requireConnectTimeout(t *testing.T, err error, proto platform.Protocol) {
	t.Helper()
	var connErr platform.ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("err = %v, want ErrConnectionFailed", err)
	}
	if connErr.Protocol != proto {
		t.Errorf("Protocol = %v, want %v", connErr.Protocol, proto)
	}
	var timeout platform.ErrTimeout
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v, want it to carry ErrTimeout", err)
	}
	if timeout.Elapsed <= 0 {
		t.Errorf("Elapsed = %v, want > 0", timeout.Elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want it to unwrap to context.DeadlineExceeded", err)
	}
}

// TestConnect_RESTProbeTimeoutIsErrTimeout pins that a REST endpoint that
// never answers GET /health is reported as ErrTimeout, not a bare error.
func TestConnect_RESTProbeTimeoutIsErrTimeout(t *testing.T) {
	server := newStalledTLSServer(t)

	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		platform.WithOnlyProtocol(platform.ProtocolREST),
		platform.WithTimeout(50*time.Millisecond),
		platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()),
	)

	_, err := platform.Connect(context.Background(), opts)
	requireConnectTimeout(t, err, platform.ProtocolREST)
}

// TestConnect_MCPInitializeTimeoutIsErrTimeout pins the same for an MCP
// endpoint that never answers initialize.
func TestConnect_MCPInitializeTimeoutIsErrTimeout(t *testing.T) {
	server := newStalledTLSServer(t)

	opts := platform.NewOptions(
		platform.WithMCPAddr(server.URL),
		platform.WithOnlyProtocol(platform.ProtocolMCP),
		platform.WithTimeout(50*time.Millisecond),
		platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()),
	)

	_, err := platform.Connect(context.Background(), opts)
	requireConnectTimeout(t, err, platform.ProtocolMCP)
}

// TestConnect_RefusedIsNotErrTimeout pins that a failure that is not a
// timeout keeps its own cause.
func TestConnect_RefusedIsNotErrTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		platform.WithOnlyProtocol(platform.ProtocolREST),
		platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()),
	)

	_, err := platform.Connect(context.Background(), opts)
	var connErr platform.ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("err = %v, want ErrConnectionFailed", err)
	}
	var timeout platform.ErrTimeout
	if errors.As(err, &timeout) {
		t.Errorf("err = %v, a 503 must not be reported as ErrTimeout", err)
	}
}

// TestConnect_AllProtocolsFail proves that a probe failure on every
// configured protocol surfaces as ErrDaemonUnavailable.
func TestConnect_AllProtocolsFail(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	opts := platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()),
	)
	opts.UnixSocket = ""

	_, err := platform.Connect(context.Background(), opts)
	var unavailable platform.ErrDaemonUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("Connect() error = %v, want ErrDaemonUnavailable", err)
	}
	if len(unavailable.Attempted) != 1 || unavailable.Attempted[0] != platform.ProtocolREST {
		t.Errorf("Attempted = %v, want [REST]", unavailable.Attempted)
	}
}
