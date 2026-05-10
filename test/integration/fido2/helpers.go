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

package fido2

import (
	"errors"
	"os"
	"strings"

	daemonpkg "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
)

// Environment variable names for service endpoints.
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

// GetServiceEndpoints returns the default devcontainer endpoints.
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

// isBackendUnavailable returns true when the supplied error indicates the
// FIDO2 backend is not configured or no authenticator is attached.
func isBackendUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, daemonpkg.ErrFIDO2NotConfigured) {
		return true
	}
	if errors.Is(err, fido2sdk.ErrNotYetWired) {
		return true
	}
	msg := strings.ToLower(err.Error())
	needles := []string{
		"backend not configured",
		"not yet wired",
		"unavailable",
		"not implemented",
		"501",
		"503",
		"phase35: service provider not configured",
		"fido2: ",
		"no device",
		"no such device",
		"permission denied",
	}
	for _, n := range needles {
		if strings.Contains(msg, n) {
			return true
		}
	}
	return false
}

// SkipIfNotIntegration skips when INTEGRATION_TEST is not set.
func SkipIfNotIntegration(t interface {
	Skip(args ...any)
}) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test: INTEGRATION_TEST not set")
	}
}
