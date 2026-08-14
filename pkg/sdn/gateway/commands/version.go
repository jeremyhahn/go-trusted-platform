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

package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Build metadata injected via -ldflags (see the Makefile LDFLAGS block).
// gatewayd carries its own version variables instead of linking pkg/app:
// pkg/app is the platformd composition root and pulls the entire daemon
// dependency graph into any binary that imports it (enforced by
// pkg/arch/gatewayguard_test.go).
var (
	// Name is the product name.
	Name = "trusted-platform"
	// Version is the semantic build version.
	Version = "dev"
	// Repository is the source repository URL.
	Repository = ""
	// Package is the Go module path.
	Package = "github.com/jeremyhahn/go-trusted-platform"
	// GitBranch is the branch the binary was built from.
	GitBranch = ""
	// GitTag is the tag the binary was built from.
	GitTag = ""
	// GitHash is the commit hash the binary was built from.
	GitHash = ""
	// BuildUser is the user that produced the binary.
	BuildUser = ""
	// BuildDate is the build timestamp.
	BuildDate = ""
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the daemon version",
	Long:  `Displays gatewayd build and version details.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Name:\t\t\t%s (gatewayd)\n", Name)
		fmt.Printf("Version:\t\t%s\n", Version)
		fmt.Printf("Repository:\t\t%s\n", Repository)
		fmt.Printf("Package:\t\t%s\n", Package)
		fmt.Printf("Git Branch:\t\t%s\n", GitBranch)
		fmt.Printf("Git Tag:\t\t%s\n", GitTag)
		fmt.Printf("Git Hash:\t\t%s\n", GitHash)
		fmt.Printf("Build User:\t\t%s\n", BuildUser)
		fmt.Printf("Build Date:\t\t%s\n", BuildDate)
	},
}
