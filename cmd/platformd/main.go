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

package main

import (
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/daemon/commands"
)

func main() {
	// Every failure, startup or usage, exits 1; a clean shutdown returns and
	// exits 0. The contract is docs/daemon/cli.md §7.1 and main_test.go
	// asserts it against the running process (#352).
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
