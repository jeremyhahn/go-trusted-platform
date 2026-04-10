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

// Package ca provides multi-protocol integration tests for Certificate Authority services.
// The daemon is started externally by the integration test shell script and endpoints
// are provided via environment variables.
package ca

import (
	"fmt"
	"os"
	"testing"
)

// TestMain checks that the integration test environment is configured and runs tests.
// The platformd daemon is started externally by run-integration-tests.sh; this function
// only verifies the environment variable is set before proceeding.
func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		fmt.Println("INTEGRATION_TEST not set, skipping CA integration tests")
		os.Exit(0)
	}
	os.Exit(m.Run())
}
