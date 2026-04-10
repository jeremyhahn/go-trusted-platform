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
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// SkipIfNotIntegration skips the test if INTEGRATION_TEST is not set.
// This provides a safety mechanism for tests that should only run in
// the devcontainer environment.
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test: INTEGRATION_TEST not set")
	}
}

// SkipIfNotDevContainer skips the test if not running inside the devcontainer
func SkipIfNotDevContainer(t *testing.T) {
	t.Helper()
	if os.Getenv("DEVCONTAINER") == "" && os.Getenv("REMOTE_CONTAINERS") == "" {
		t.Skip("Skipping test: not running in devcontainer")
	}
}

// SkipIfNoTPM skips the test if no TPM device is available
func SkipIfNoTPM(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/dev/tpm0"); os.IsNotExist(err) {
		if _, err := os.Stat("/dev/tpmrm0"); os.IsNotExist(err) {
			t.Skip("Skipping test: no TPM device available")
		}
	}
}

// SkipIfNoSwtpm skips the test if swtpm is not available
func SkipIfNoSwtpm(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/swtpm"); os.IsNotExist(err) {
		t.Skip("Skipping test: swtpm not available")
	}
}

// SkipIfNoOVS skips the test if Open vSwitch is not available
func SkipIfNoOVS(t *testing.T) {
	t.Helper()
	socketPath := os.Getenv("OVS_DB_SOCKET")
	if socketPath == "" {
		socketPath = "/var/run/openvswitch/db.sock"
	}
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Skip("Skipping test: OVS not available")
	}
}

// SkipIfProtocolUnavailable checks if a protocol endpoint is reachable
// and skips the test if not
func SkipIfProtocolUnavailable(t *testing.T, protocol string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch strings.ToLower(protocol) {
	case "rest", "https":
		skipIfRESTUnavailable(t, ctx, GetRESTEndpoint())
	case "grpc":
		skipIfGRPCUnavailable(t, ctx, GetGRPCEndpoint())
	case "quic":
		skipIfQUICUnavailable(t, GetQUICEndpoint())
	case "mcp":
		skipIfMCPUnavailable(t, ctx, GetMCPEndpoint())
	case "socket", "unix":
		skipIfSocketUnavailable(t, GetSocketPath())
	default:
		t.Fatalf("Unknown protocol: %s", protocol)
	}
}

// skipIfRESTUnavailable checks REST endpoint availability
func skipIfRESTUnavailable(t *testing.T, ctx context.Context, endpoint string) {
	t.Helper()

	client := NewHTTPClient(5 * time.Second)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/health", nil)
	if err != nil {
		t.Skipf("Skipping REST test: failed to create request: %v", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("Skipping REST test: endpoint %s unreachable: %v", endpoint, err)
		return
	}
	defer resp.Body.Close()
}

// skipIfGRPCUnavailable checks gRPC endpoint availability
func skipIfGRPCUnavailable(t *testing.T, ctx context.Context, endpoint string) {
	t.Helper()

	conn, err := grpc.DialContext(ctx,
		endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Skipf("Skipping gRPC test: could not connect to %s: %v", endpoint, err)
		return
	}
	defer conn.Close()
}

// skipIfQUICUnavailable checks QUIC endpoint availability
func skipIfQUICUnavailable(t *testing.T, endpoint string) {
	t.Helper()

	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		t.Skipf("Skipping QUIC test: invalid endpoint %s: %v", endpoint, err)
		return
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Skipf("Skipping QUIC test: could not dial %s: %v", endpoint, err)
		return
	}
	conn.Close()
}

// skipIfMCPUnavailable checks MCP endpoint availability
func skipIfMCPUnavailable(t *testing.T, ctx context.Context, endpoint string) {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/health", nil)
	if err != nil {
		t.Skipf("Skipping MCP test: failed to create request: %v", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("Skipping MCP test: endpoint %s unreachable: %v", endpoint, err)
		return
	}
	defer resp.Body.Close()
}

// skipIfSocketUnavailable checks Unix socket availability
func skipIfSocketUnavailable(t *testing.T, socketPath string) {
	t.Helper()

	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		t.Skipf("Skipping Socket test: could not connect to %s: %v", socketPath, err)
		return
	}
	conn.Close()
}

// SkipIfServiceUnavailable checks if a specific service is available
// via gRPC and skips if not
func SkipIfServiceUnavailable(t *testing.T, ctx context.Context, conn *grpc.ClientConn, serviceName string) {
	t.Helper()

	// Try to call a simple health-check or list method
	// The actual implementation depends on the service
	switch serviceName {
	case "vtpm":
		// Would call vTPM health check
		t.Log("Checking vTPM service availability...")
	case "dns":
		// Would call DNS health check
		t.Log("Checking DNS service availability...")
	case "device":
		// Would call Device service health check
		t.Log("Checking Device service availability...")
	case "sdn":
		// Would call SDN service health check
		t.Log("Checking SDN service availability...")
	default:
		t.Fatalf("Unknown service: %s", serviceName)
	}
}

// RequirePlatformd ensures the platform daemon is running
func RequirePlatformd(t *testing.T) {
	t.Helper()

	socketPath := GetSocketPath()
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Fatalf("Platform daemon not running: socket %s not found", socketPath)
	}

	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		t.Fatalf("Platform daemon not responding: %v", err)
	}
	conn.Close()
}

// RequirePrerequisite checks for a required prerequisite
func RequirePrerequisite(t *testing.T, name string, check func() error) {
	t.Helper()

	if err := check(); err != nil {
		t.Fatalf("Missing prerequisite %s: %v", name, err)
	}
}

// CheckFileExists returns a check function for RequirePrerequisite
func CheckFileExists(path string) func() error {
	return func() error {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", path)
		}
		return nil
	}
}

// CheckCommandExists returns a check function for RequirePrerequisite
func CheckCommandExists(cmd string) func() error {
	return func() error {
		paths := []string{
			"/usr/bin/" + cmd,
			"/usr/local/bin/" + cmd,
			"/bin/" + cmd,
			"/sbin/" + cmd,
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				return nil
			}
		}
		return fmt.Errorf("command not found: %s", cmd)
	}
}
