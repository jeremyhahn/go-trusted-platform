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

package piv

import (
	"os"

	daemonpkg "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	mcpapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// Environment variable names for service endpoints, identical to the CA
// adapter so run-integration-tests.sh exports one set.
const (
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformCTL          = "PLATFORMCTL_PATH"
)

// ServiceEndpoints collects per-transport endpoint strings.
type ServiceEndpoints struct {
	PlatformGRPC string
	PlatformREST string
	PlatformQUIC string
	PlatformMCP  string
	PlatformUnix string
	PlatformCTL  string
}

// GetServiceEndpoints returns the default endpoints matching the devcontainer
// run-integration-tests.sh script.
func GetServiceEndpoints() *ServiceEndpoints {
	return &ServiceEndpoints{
		PlatformGRPC: "localhost:10443",
		PlatformREST: "http://localhost:8443",
		PlatformQUIC: "localhost:9444",
		PlatformMCP:  "localhost:9445",
		PlatformUnix: "/run/platformd.sock",
		PlatformCTL:  "platformctl",
	}
}

// isBackendUnavailable reports whether err is a declared gap: a typed
// not-implemented declaration or the daemon's PIV not-configured sentinel,
// which every transport carries as the sentinel's text. Any other error
// fails the test (#487).
func isBackendUnavailable(err error) bool {
	return surface.IsNotImplemented(err) || surface.IsDeclaredRefusal(err,
		daemonpkg.ErrPIVNotConfigured,
		pivsdk.ErrNotYetWired,
		mcpapi.ErrPhase35NotConfigured,
	)
}

// SkipIfNotIntegration skips the test when INTEGRATION_TEST is not set.
func SkipIfNotIntegration(t interface {
	Skip(args ...any)
}) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test: INTEGRATION_TEST not set")
	}
}
