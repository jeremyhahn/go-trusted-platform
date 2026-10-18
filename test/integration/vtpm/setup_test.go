//go:build integration

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

// Package vtpm provides multi-protocol integration tests for vTPM services.
// The suite expects a real platformd instance started externally by the
// integration test shell script, with endpoints provided via environment
// variables. The integration build tag selects it; there is no env gate.
package vtpm

// =============================================================================
// Environment Variable Constants
// =============================================================================

const (
	// EnvPlatformdSocket is the Unix socket path for platformd.
	EnvPlatformdSocket = "PLATFORMD_SOCKET"

	// EnvPlatformAPIEndpoint is the REST endpoint environment variable.
	EnvPlatformAPIEndpoint = "PLATFORM_API_ENDPOINT"

	// EnvPlatformGRPCEndpoint is the gRPC endpoint environment variable.
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"

	// EnvPlatformQUICEndpoint is the QUIC endpoint environment variable.
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"

	// EnvPlatformMCPEndpoint is the MCP endpoint environment variable.
	EnvPlatformMCPEndpoint = "PLATFORM_MCP_ENDPOINT"

	// EnvPlatformctlBinary is the path to the platformctl binary.
	EnvPlatformctlBinary = "PLATFORMCTL_BINARY"
)
