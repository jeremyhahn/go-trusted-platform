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

// Package daemon provides multi-protocol integration tests for the platformd daemon.
// The daemon is started externally by the integration test shell script and endpoints
// are provided via environment variables.
package daemon

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		fmt.Println("Skipping daemon integration tests: INTEGRATION_TEST not set")
		os.Exit(0)
	}
	os.Exit(m.Run())
}
