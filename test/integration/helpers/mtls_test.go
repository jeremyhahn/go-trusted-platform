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

//go:build integration

package helpers

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// startPeercredUDSServer serves gRPC health on a Unix socket with the same
// transport credentials platformd's UDS listener uses (plaintext, SO_PEERCRED),
// and returns the socket path and a channel carrying each caller's AuthInfo.
func startPeercredUDSServer(t *testing.T) (string, <-chan credentials.AuthInfo) {
	t.Helper()

	// t.TempDir paths can exceed the 108-byte sun_path limit.
	dir, err := os.MkdirTemp("", "uds")
	if err != nil {
		t.Fatalf("create socket dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove socket dir: %v", err)
		}
	})
	socketPath := filepath.Join(dir, "platformd.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on %s: %v", socketPath, err)
	}

	callers := make(chan credentials.AuthInfo, 1)
	recordCaller := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if p, ok := peer.FromContext(ctx); ok {
			select {
			case callers <- p.AuthInfo:
			default:
			}
		}
		return handler(ctx, req)
	}

	server := grpc.NewServer(
		grpc.Creds(peercred.NewUnixTransportCredentials()),
		grpc.UnaryInterceptor(recordCaller),
	)
	healthpb.RegisterHealthServer(server, health.NewServer())

	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		// Stop can win the race with Serve's start; Serve then returns ErrServerStopped, its other clean-shutdown result.
		if err := <-served; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve: %v", err)
		}
	})
	return socketPath, callers
}

func checkHealth(socketPath string, creds grpc.DialOption) error {
	conn, err := grpc.NewClient("unix://"+socketPath, creds)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestGRPCUnixCredentialsReachesThePeercredSocket(t *testing.T) {
	socketPath, callers := startPeercredUDSServer(t)

	if err := checkHealth(socketPath, GRPCUnixCredentials()); err != nil {
		t.Fatalf("the UDS helper must reach a handler on platformd's plaintext socket, got %v", err)
	}

	info := <-callers
	type peercredInfo interface {
		Credentials() peercred.UnixCredentials
	}
	caller, ok := info.(peercredInfo)
	if !ok {
		t.Fatalf("the server must authenticate the caller by SO_PEERCRED, got AuthInfo %T", info)
	}
	if got, want := caller.Credentials().UID, uint32(os.Getuid()); got != want {
		t.Errorf("SO_PEERCRED uid = %d, want this process's uid %d", got, want)
	}
}

// TestTLSCredentialsCannotReachThePeercredSocket pins the #532 failure: an
// adapter that dials the UDS with the mTLS credentials fails its handshake and
// never reaches a handler, which blanked the device suite's Unix column.
func TestTLSCredentialsCannotReachThePeercredSocket(t *testing.T) {
	socketPath, _ := startPeercredUDSServer(t)

	tlsCreds := grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13}))
	if err := checkHealth(socketPath, tlsCreds); err == nil {
		t.Fatal("a TLS dial must not reach a handler on the plaintext UDS")
	}
}

// The MCP endpoint reaches the suites in two shapes: the suites' own defaults
// are a bare host:port, while the devcontainer harness exports a URL with its
// scheme. The sdn MCP adapter prepended http:// to both and dialled
// "http://https://localhost:9445/mcp" (#537).
func TestMCPEndpointURLAddsHTTPSToABareHostPort(t *testing.T) {
	if got, want := MCPEndpointURL("127.0.0.1:9445"), "https://127.0.0.1:9445/mcp"; got != want {
		t.Errorf("MCPEndpointURL(host:port) = %q, want %q", got, want)
	}
}

func TestMCPEndpointURLKeepsAnExplicitScheme(t *testing.T) {
	for _, endpoint := range []string{"https://localhost:9445", "http://localhost:9445"} {
		if got, want := MCPEndpointURL(endpoint), endpoint+"/mcp"; got != want {
			t.Errorf("MCPEndpointURL(%q) = %q, want %q (scheme kept, never doubled)", endpoint, got, want)
		}
	}
}

// TestRESTBaseURLKeepsAnExplicitScheme pins the run-55577 KMS and secrets
// failure: the adapters prefixed http:// onto https://localhost:8443 and
// dialled host "https".
func TestRESTBaseURLKeepsAnExplicitScheme(t *testing.T) {
	cases := map[string]string{
		"https://localhost:8443":  "https://localhost:8443",
		"https://localhost:8443/": "https://localhost:8443",
		"http://localhost:8080":   "http://localhost:8080",
	}
	for endpoint, want := range cases {
		if got := RESTBaseURL(endpoint); got != want {
			t.Errorf("RESTBaseURL(%q) = %q, want %q (scheme kept, never doubled)", endpoint, got, want)
		}
	}
}

func TestRESTBaseURLAddsHTTPSToABareHostPort(t *testing.T) {
	if got, want := RESTBaseURL("localhost:8443"), "https://localhost:8443"; got != want {
		t.Errorf("RESTBaseURL(host:port) = %q, want %q", got, want)
	}
}
