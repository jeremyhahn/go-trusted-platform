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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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

	ctx := base.Context()
	resp, err := base.Client().Daemon().GetConfig(ctx, &platformv1.GetConfigRequest{
		Section: section,
	})
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		for _, sec := range resp.Sections {
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
			return fmt.Errorf("invalid key=value pair: %s", v)
		}
		configValues[parts[0]] = parts[1]
	}

	ctx := base.Context()
	resp, err := base.Client().Daemon().UpdateConfig(ctx, &platformv1.UpdateConfigRequest{
		Section: &platformv1.ConfigSection{
			Section: section,
			Values:  configValues,
		},
		Persist: persist,
	})
	if err != nil {
		return fmt.Errorf("failed to set config: %w", err)
	}

	printer := base.Printer()

	if resp.Status != nil && resp.Status.Success {
		printer.PrintSuccess("Configuration updated successfully")
		if persist {
			printer.PrintInfo("Changes persisted to disk")
		} else {
			printer.PrintWarning("Changes not persisted (use --persist to save)")
		}
		return nil
	}

	if resp.Status != nil && resp.Status.Error != nil {
		return fmt.Errorf("failed to update config: %s", resp.Status.Error.Message)
	}

	return fmt.Errorf("failed to update config: unknown error")
}

func runConfigReload(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().Daemon().ReloadConfig(ctx, &platformv1.ReloadConfigRequest{})
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	printer := base.Printer()

	if resp.Status != nil && resp.Status.Success {
		printer.PrintSuccess("Configuration reloaded successfully")
		if len(resp.ReloadedSections) > 0 {
			printer.PrintInfo(fmt.Sprintf("Reloaded sections: %s",
				strings.Join(resp.ReloadedSections, ", ")))
		}
		return nil
	}

	if resp.Status != nil && resp.Status.Error != nil {
		return fmt.Errorf("failed to reload config: %s", resp.Status.Error.Message)
	}

	return fmt.Errorf("failed to reload config: unknown error")
}
