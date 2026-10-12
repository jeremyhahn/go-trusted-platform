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

package cold_start

import (
	"fmt"
	"os"
	"testing"
)

// Environment variables consumed by the cold-start harness and adapters.
// Kept in a single block so the runner script and adapters share names.
const (
	// EnvIntegration is the standard "integration tests are running"
	// gate, matching the pattern in test/integration/helpers/skip.go.
	EnvIntegration = "INTEGRATION_TEST"

	// EnvColdStartBinary points to the platformd binary used to launch
	// the dedicated cold-start instance (NOT the shared daemon).
	EnvColdStartBinary = "PLATFORM_COLD_START_BIN"

	// EnvColdStartDataDir is the data directory the harness manages.
	EnvColdStartDataDir = "PLATFORM_COLD_START_DIR"

	// EnvPlatformCTLPath points to the platformctl binary used by CLI
	// adapters and the harness IssueAdminBundle helper.
	EnvPlatformCTLPath = "PLATFORMCTL_PATH"
)

// SkipIfNotIntegration skips the test when the integration gate is not
// set. The cold-start suite requires the devcontainer runner to seed the
// PLATFORM_COLD_START_* env vars; the suite cannot run on a host shell.
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvIntegration) == "" {
		t.Skip("Skipping cold-start integration test: INTEGRATION_TEST not set")
	}
}

// ServiceEndpoints returns the host:port pairs for every transport the
// cold-start harness binds. The values mirror DefaultHarnessConfig and
// are exposed so adapters can construct their dial targets without a
// reference to the harness type.
type ServiceEndpoints struct {
	REST string
	GRPC string
	QUIC string
	MCP  string
	Unix string
}

// GetServiceEndpoints returns the cold-start endpoints anchored to the
// harness ports.
func GetServiceEndpoints(cfg HarnessConfig) ServiceEndpoints {
	return ServiceEndpoints{
		REST: fmt.Sprintf("https://127.0.0.1:%d", cfg.RESTPort),
		GRPC: fmt.Sprintf("127.0.0.1:%d", cfg.GRPCPort),
		QUIC: fmt.Sprintf("127.0.0.1:%d", cfg.QUICPort),
		MCP:  fmt.Sprintf("https://127.0.0.1:%d", cfg.MCPPort),
		Unix: cfg.SocketPath,
	}
}
