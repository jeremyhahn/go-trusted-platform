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
	if os.Getenv("INTEGRATION_TEST") == "" {
		fmt.Println("skipping SDN integration tests: INTEGRATION_TEST env var not set")
		os.Exit(0)
	}

	os.Exit(m.Run())
}
