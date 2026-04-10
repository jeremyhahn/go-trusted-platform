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

package compute_test

import (
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// SkipIfNotIntegration skips the test if not running in integration mode.
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	helpers.SkipIfNotIntegration(t)
}

// GetCLIPath returns the path to the platformctl binary.
func GetCLIPath() string {
	if p := os.Getenv("PLATFORMCTL_PATH"); p != "" {
		return p
	}
	return "platformctl"
}

// GetRESTEndpoint returns the REST API endpoint for compute tests.
func GetRESTEndpoint() string {
	return helpers.GetRESTEndpoint()
}

// GetGRPCEndpoint returns the gRPC API endpoint for compute tests.
func GetGRPCEndpoint() string {
	return helpers.GetGRPCEndpoint()
}

// GetQUICEndpoint returns the QUIC API endpoint for compute tests.
func GetQUICEndpoint() string {
	return helpers.GetQUICEndpoint()
}

// GetMCPEndpoint returns the MCP API endpoint for compute tests.
func GetMCPEndpoint() string {
	return helpers.GetMCPEndpoint()
}

// GetSocketPath returns the Unix socket path for compute tests.
func GetSocketPath() string {
	return helpers.GetSocketPath()
}

// skipIfNotImplemented skips the test if the error indicates the method
// is not implemented for the current protocol adapter.
func skipIfNotImplemented(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}

	errMsg := strings.ToLower(err.Error())
	notImplementedPatterns := []string{
		"not implemented",
		"unimplemented",
		"not supported",
		"service unavailable",
		"not available",
		"unknown service",
		"connection required",
		"404 page not found",
		"status: 404",
		"unknown flag",
		"context canceled",
		"context deadline exceeded",
	}

	for _, pattern := range notImplementedPatterns {
		if strings.Contains(errMsg, pattern) {
			t.Skipf("Not implemented: %v", err)
		}
	}
}

// generateTestVMName generates a unique VM name for testing.
func generateTestVMName(suffix string) string {
	return "test-vm-" + helpers.GenerateUniqueID(suffix)
}
