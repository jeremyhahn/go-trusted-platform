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

import "fmt"

// Environment variables consumed by the cold-start harness and adapters.
// Kept in a single block so the runner script and adapters share names.
const (
	// EnvColdStartBinary points to the platformd binary used to launch
	// the dedicated cold-start instance (NOT the shared daemon).
	EnvColdStartBinary = "PLATFORM_COLD_START_BIN"

	// EnvColdStartDataDir is the data directory the harness manages.
	EnvColdStartDataDir = "PLATFORM_COLD_START_DIR"

	// EnvPlatformCTLPath points to the platformctl binary used by CLI
	// adapters and the harness IssueAdminBundle helper.
	EnvPlatformCTLPath = "PLATFORMCTL_PATH"
)

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
