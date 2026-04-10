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

package iso

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// profileFlags holds common flags for profile subcommands
type profileFlags struct {
	noColor bool
}

// generateProfileFlags holds flags for the profile generate command
type generateProfileFlags struct {
	profileName    string
	outputFile     string
	overrideDevice string
	interactive    bool
}

// newProfileCommand creates the profile subcommand group for installation profile management
func newProfileCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &profileFlags{}

	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage installation profiles",
		Long: `Manage installation configuration profiles for ISO building.

Profiles provide pre-configured installation settings for different use cases:
- dev: Development workstation with debug enabled and relaxed security
- production: Production server with balanced security and integrity lockdown
- fips: FIPS 140-3 compliant with FIPS mode and integrity lockdown
- production-hs: High-security production with FIPS and confidentiality lockdown`,
	}

	// Global flags for profile subcommand
	cmd.PersistentFlags().BoolVar(&flags.noColor, "no-color", false, "Disable colored output")

	// Add subcommands
	cmd.AddCommand(newProfileListCommand(getFlags, flags))
	cmd.AddCommand(newProfileShowCommand(getFlags, flags))
	cmd.AddCommand(newProfileValidateCommand(getFlags, flags))
	cmd.AddCommand(newProfileGenerateCommand(getFlags, flags))

	return cmd
}

// newProfileListCommand creates the list subcommand for listing profiles
func newProfileListCommand(getFlags func() *cli.CommonFlags, pFlags *profileFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available installation profiles",
		Long: `Lists all built-in installation profiles with descriptions.

Each profile provides a different security and feature configuration:
- dev: Development environment with debug enabled
- production: Secure production setup with TPM and integrity lockdown
- fips: FIPS 140-3 compliant configuration
- production-hs: Maximum security with confidentiality lockdown`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileList(getFlags(), pFlags)
		},
	}

	return cmd
}

// newProfileShowCommand creates the show subcommand for displaying profile details
func newProfileShowCommand(getFlags func() *cli.CommonFlags, pFlags *profileFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <profile-name>",
		Short: "Show installation profile configuration",
		Long: `Displays the complete configuration for a specific installation profile.

The output shows all settings including disk layout, encryption, packages,
and security features in YAML format.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileShow(getFlags(), pFlags, args[0])
		},
	}

	return cmd
}

// newProfileValidateCommand creates the validate subcommand for validating configs
func newProfileValidateCommand(getFlags func() *cli.CommonFlags, pFlags *profileFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <config-file>",
		Short: "Validate installation configuration",
		Long: `Validates an installation configuration file for correctness.

The validator checks:
- Required fields are present
- Values are within valid ranges
- Configuration is internally consistent`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileValidate(getFlags(), pFlags, args[0])
		},
	}

	return cmd
}

// newProfileGenerateCommand creates the generate subcommand for generating configs
func newProfileGenerateCommand(getFlags func() *cli.CommonFlags, pFlags *profileFlags) *cobra.Command {
	flags := &generateProfileFlags{}

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate installation configuration",
		Long: `Generates a new installation configuration file based on a profile.

The generated configuration can be customized with command-line overrides
or edited manually before use.

Examples:
  # Generate from dev profile
  platformctl iso profile generate --profile dev --output dev.yaml

  # Generate with custom device
  platformctl iso profile generate --profile production --device /dev/nvme0n1 --output prod.yaml

  # Generate to stdout
  platformctl iso profile generate --profile dev`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileGenerate(getFlags(), pFlags, flags)
		},
	}

	// Generate flags
	cmd.Flags().StringVarP(&flags.profileName, "profile", "p", "", "Profile name to use as base (required)")
	cmd.Flags().StringVarP(&flags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&flags.overrideDevice, "device", "", "Override disk device (e.g., /dev/sda, /dev/nvme0n1)")
	cmd.Flags().BoolVarP(&flags.interactive, "interactive", "i", false, "Interactive configuration wizard (future)")

	// Mark required flags
	_ = cmd.MarkFlagRequired("profile")

	return cmd
}

// runProfileList executes the profile list command
func runProfileList(commonFlags *cli.CommonFlags, pFlags *profileFlags) error {
	// Profile list requires App initialization which needs daemon connection
	// Dual-mode will be added later to support local-only operations
	return ErrDaemonConnectionRequired{Command: "iso profile list"}
}

// runProfileShow executes the profile show command
func runProfileShow(commonFlags *cli.CommonFlags, pFlags *profileFlags, profileName string) error {
	// Profile show requires App initialization which needs daemon connection
	// Dual-mode will be added later to support local-only operations
	return ErrDaemonConnectionRequired{Command: "iso profile show"}
}

// runProfileValidate executes the profile validate command
func runProfileValidate(commonFlags *cli.CommonFlags, pFlags *profileFlags, configPath string) error {
	// Profile validate requires App initialization which needs daemon connection
	// Dual-mode will be added later to support local-only operations
	return ErrDaemonConnectionRequired{Command: "iso profile validate"}
}

// runProfileGenerate executes the profile generate command
func runProfileGenerate(commonFlags *cli.CommonFlags, pFlags *profileFlags, flags *generateProfileFlags) error {
	// Profile generate requires App initialization which needs daemon connection
	// Dual-mode will be added later to support local-only operations
	return ErrDaemonConnectionRequired{Command: "iso profile generate"}
}
