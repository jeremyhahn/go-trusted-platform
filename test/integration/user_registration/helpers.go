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

// Package user_registration provides integration tests for user registration services.
// This file provides helper functions for the adapters.
package user_registration

import (
	"os"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// GetRESTEndpoint returns the REST API endpoint
func GetRESTEndpoint() string {
	if endpoint := os.Getenv("AUTH_REST_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetRESTEndpoint()
}

// GetGRPCEndpoint returns the gRPC API endpoint
func GetGRPCEndpoint() string {
	if endpoint := os.Getenv("AUTH_GRPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetGRPCEndpoint()
}

// GetQUICEndpoint returns the QUIC API endpoint
func GetQUICEndpoint() string {
	if endpoint := os.Getenv("AUTH_QUIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetQUICEndpoint()
}

// GetMCPEndpoint returns the MCP API endpoint
func GetMCPEndpoint() string {
	if endpoint := os.Getenv("AUTH_MCP_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetMCPEndpoint()
}

// GetSocketPath returns the Unix socket path
func GetSocketPath() string {
	if path := os.Getenv("AUTH_SOCKET_PATH"); path != "" {
		return path
	}
	return helpers.GetSocketPath()
}

// GetCLIPath returns the path to the platformctl CLI
func GetCLIPath() string {
	if path := os.Getenv("PLATFORMCTL_PATH"); path != "" {
		return path
	}
	return "platformctl"
}
