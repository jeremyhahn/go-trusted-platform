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

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	daemonsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
)

// NewVersionCommand creates the version command
func NewVersionCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var clientOnly bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  "Display version information for platformctl and the platform server",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runVersion(flags, clientOnly)
		},
	}

	cmd.Flags().BoolVarP(&clientOnly, "client", "", false, "show client version only")

	return cmd
}

func runVersion(flags *cli.CommonFlags, clientOnly bool) error {
	// Always show client version
	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	if clientOnly {
		// Just print client version
		if flags.OutputFormat == cli.OutputFormatTable {
			printer.PrintKeyValue("Client Version", getClientVersion())
			return nil
		}
		return printer.Print(map[string]string{
			"client_version": getClientVersion(),
		})
	}

	// Get server version
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	version, err := daemonClient.GetVersionDomain(ctx)
	if err != nil {
		return err
	}

	// Format output based on output format
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		versionData := map[string]interface{}{
			"client": map[string]string{
				"version": getClientVersion(),
			},
			"server": version,
		}
		return printer.Print(versionData)

	case cli.OutputFormatTable:
		return printVersionTable(printer, version)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printVersionTable(printer *cli.Printer, version *daemonsvc.VersionInfo) error {
	printer.PrintInfo("Client Version:")
	fmt.Println()
	printer.PrintKeyValue("  Version", getClientVersion())
	fmt.Println()

	printer.PrintInfo("Server Version:")
	fmt.Println()
	printer.PrintKeyValue("  Version", version.Version)
	printer.PrintKeyValue("  Build Time", version.BuildTime)
	printer.PrintKeyValue("  Git Commit", version.GitCommit)
	printer.PrintKeyValue("  Go Version", version.GoVersion)

	if len(version.Components) > 0 {
		fmt.Println()
		printer.PrintInfo("Component Versions:")
		fmt.Println()
		for name, ver := range version.Components {
			printer.PrintKeyValue(fmt.Sprintf("  %s", name), ver)
		}
	}

	return nil
}

func getClientVersion() string {
	if app.Version != "" {
		return app.Version
	}
	return "dev"
}
