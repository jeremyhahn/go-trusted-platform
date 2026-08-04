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
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	daemonsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
)

// NewConfigCommand creates the config management command
func NewConfigCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage platform configuration",
		Long:  "Get, set, and reload platform configuration",
	}

	cmd.AddCommand(newConfigGetCommand(getFlags))
	cmd.AddCommand(newConfigSetCommand(getFlags))
	cmd.AddCommand(newConfigReloadCommand(getFlags))

	return cmd
}

// newConfigGetCommand creates the config get subcommand
func newConfigGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var section string

	cmd := &cobra.Command{
		Use:   "get [section]",
		Short: "Get configuration",
		Long:  "Get platform configuration for all sections or a specific section",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			if len(args) > 0 {
				section = args[0]
			}
			return runConfigGet(flags, section)
		},
	}

	return cmd
}

// newConfigSetCommand creates the config set subcommand
func newConfigSetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var persist bool

	cmd := &cobra.Command{
		Use:   "set <section> <key=value> [key=value...]",
		Short: "Set configuration values",
		Long:  "Set configuration values for a specific section",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			section := args[0]
			values := args[1:]
			return runConfigSet(flags, section, values, persist)
		},
	}

	cmd.Flags().BoolVarP(&persist, "persist", "p", false, "persist changes to disk")

	return cmd
}

// newConfigReloadCommand creates the config reload subcommand
func newConfigReloadCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Reload configuration",
		Long:  "Reload platform configuration from disk",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runConfigReload(flags)
		},
	}
}

func runConfigGet(flags *cli.CommonFlags, section string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	sections, err := daemonClient.GetConfigDomain(ctx, section)
	if err != nil {
		return err
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(sections)

	case cli.OutputFormatTable:
		for _, sec := range sections {
			printer.PrintInfo(fmt.Sprintf("Section: %s", sec.Section))
			fmt.Println()
			for key, value := range sec.Values {
				printer.PrintKeyValue(fmt.Sprintf("  %s", key), value)
			}
			fmt.Println()
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runConfigSet(flags *cli.CommonFlags, section string, values []string, persist bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Parse key=value pairs
	configValues := make(map[string]string)
	for _, v := range values {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			return &MessageError{Msg: fmt.Sprintf("invalid key=value pair: %s", v)}
		}
		configValues[parts[0]] = parts[1]
	}

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	_, err = daemonClient.UpdateConfigDomain(ctx, section, configValues, persist)
	if err != nil {
		return err
	}

	printer := base.Printer()
	printer.PrintSuccess("Configuration updated successfully")
	if persist {
		printer.PrintInfo("Changes persisted to disk")
	} else {
		printer.PrintWarning("Changes not persisted (use --persist to save)")
	}
	return nil
}

func runConfigReload(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	reloadedSections, err := daemonClient.ReloadConfigDomain(ctx)
	if err != nil {
		return err
	}

	printer := base.Printer()
	printer.PrintSuccess("Configuration reloaded successfully")
	if len(reloadedSections) > 0 {
		printer.PrintInfo(fmt.Sprintf("Reloaded sections: %s",
			strings.Join(reloadedSections, ", ")))
	}
	return nil
}
