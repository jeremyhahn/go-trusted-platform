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

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the daemon version",
	Long:  `Displays gatewayd build and version details.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Name:\t\t\t%s (gatewayd)\n", app.Name)
		fmt.Printf("Version:\t\t%s\n", app.Version)
		fmt.Printf("Repository:\t\t%s\n", app.Repository)
		fmt.Printf("Package:\t\t%s\n", app.Package)
		fmt.Printf("Git Branch:\t\t%s\n", app.GitBranch)
		fmt.Printf("Git Tag:\t\t%s\n", app.GitTag)
		fmt.Printf("Git Hash:\t\t%s\n", app.GitHash)
		fmt.Printf("Build User:\t\t%s\n", app.BuildUser)
		fmt.Printf("Build Date:\t\t%s\n", app.BuildDate)
	},
}
