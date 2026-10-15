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

// Package sdn provides multi-protocol integration tests for SDN services.
// The platformd daemon is started externally by the integration test shell
// script; endpoint addresses are provided via environment variables.
package sdn

import (
	"fmt"
	"os"
	"testing"
)

// TestMain is the entry point for the SDN integration test suite. It verifies
// that the INTEGRATION_TEST environment variable is set (indicating the test
// is running inside the devcontainer with a real platformd instance) and then
// delegates to the standard test runner.
func TestMain(m *testing.M) {
	// A suite that exits 0 without running proves nothing: an unset
	// INTEGRATION_TEST means the harness did not prepare the environment,
	// which is a failure, never a skip.
	if os.Getenv(EnvIntegrationTest) == "" {
		fmt.Println("SDN integration tests: INTEGRATION_TEST is not set; run them through `make integration-test-sdn` or `make integration-test-nat64`")
		os.Exit(1)
	}

	os.Exit(m.Run())
}
