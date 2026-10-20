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
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// generateProfileFlags holds flags for the profile generate command
type generateProfileFlags struct {
	profileName    string
	outputFile     string
	overrideDevice string
}

// profileSummary is the security posture of one built-in profile, as
// `iso profile list` and `iso profile show` print it (docs/installer/cli.md §4).
type profileSummary struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	SecureBoot  bool   `json:"secure_boot" yaml:"secure_boot"`
	TPMUnseal   bool   `json:"tpm_unseal" yaml:"tpm_unseal"`
	LUKS        bool   `json:"luks" yaml:"luks"`
	FIPS        bool   `json:"fips" yaml:"fips"`
	Lockdown    string `json:"lockdown" yaml:"lockdown"`
}

// profileListResult is what `iso profile list` prints.
type profileListResult struct {
	Success  bool             `json:"success" yaml:"success"`
	Profiles []profileSummary `json:"profiles" yaml:"profiles"`
	Message  string           `json:"message" yaml:"message"`
}

// profileShowResult is what `iso profile show` prints. YAML is the profile
// rendered as an install configuration, the same document `generate` writes.
type profileShowResult struct {
	Success bool           `json:"success" yaml:"success"`
	Profile profileSummary `json:"profile" yaml:"profile"`
	YAML    string         `json:"yaml" yaml:"yaml"`
	Message string         `json:"message" yaml:"message"`
}

// profileValidateResult is what `iso profile validate` prints.
type profileValidateResult struct {
	Success bool     `json:"success" yaml:"success"`
	Valid   bool     `json:"valid" yaml:"valid"`
	Errors  []string `json:"errors" yaml:"errors"`
	Message string   `json:"message" yaml:"message"`
}

// profileGenerateResult is what `iso profile generate` prints.
type profileGenerateResult struct {
	Success    bool   `json:"success" yaml:"success"`
	OutputFile string `json:"output_file" yaml:"output_file"`
	YAML       string `json:"yaml" yaml:"yaml"`
	Message    string `json:"message" yaml:"message"`
}

// newProfileCommand creates the profile subcommand group for installation profile management
func newProfileCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
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

	cmd.AddCommand(newProfileListCommand(getFlags))
	cmd.AddCommand(newProfileShowCommand(getFlags))
	cmd.AddCommand(newProfileValidateCommand(getFlags))
	cmd.AddCommand(newProfileGenerateCommand(getFlags))

	return cmd
}

// newProfileListCommand creates the list subcommand for listing profiles
func newProfileListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
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
			return runProfileList(getFlags(), cmd.OutOrStdout())
		},
	}

	return cmd
}

// newProfileShowCommand creates the show subcommand for displaying profile details
func newProfileShowCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <profile-name>",
		Short: "Show installation profile configuration",
		Long: `Displays the complete configuration for a specific installation profile.

The output carries the profile's security posture and the profile rendered
as an install configuration in YAML: disk layout, encryption, packages and
security features.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileShow(getFlags(), args[0], cmd.OutOrStdout())
		},
	}

	return cmd
}

// newProfileValidateCommand creates the validate subcommand for validating configs
func newProfileValidateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <config-file>",
		Short: "Validate installation configuration",
		Long: `Validates an installation configuration file for correctness.

The file is loaded exactly as the installer loads it: environment variables
are expanded, the version is checked, and the configuration is validated
(disk device, LUKS mapping name, architecture, install target, boot
firmware, network and Secure Boot). An invalid file prints valid: false with
the reason and exits non-zero.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileValidate(getFlags(), args[0], cmd.OutOrStdout())
		},
	}

	return cmd
}

// newProfileGenerateCommand creates the generate subcommand for generating configs
func newProfileGenerateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &generateProfileFlags{}

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate installation configuration",
		Long: `Generates a new installation configuration file based on a profile.

The generated configuration can be customized with command-line overrides
or edited manually before use. --output names the file to write (mode 0600);
it shadows the global -o, so the result prints as YAML.

Examples:
  # Generate from dev profile
  platformctl iso profile generate --profile dev --output dev.yaml

  # Generate with custom device
  platformctl iso profile generate --profile production --device /dev/nvme0n1 --output prod.yaml

  # Generate to stdout
  platformctl iso profile generate --profile dev`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProfileGenerate(getFlags(), flags, cmd.OutOrStdout())
		},
	}

	// Generate flags
	cmd.Flags().StringVarP(&flags.profileName, "profile", "p", "", "Profile name to use as base (required)")
	cmd.Flags().StringVarP(&flags.outputFile, "output", "o", "", "Output file path (default: the YAML is printed only)")
	cmd.Flags().StringVar(&flags.overrideDevice, "device", "", "Override disk device (e.g., /dev/sda, /dev/nvme0n1)")

	// Mark required flags
	cli.MarkFlagsRequired(cmd, "profile")

	return cmd
}

// runProfileList prints every built-in profile's security posture.
func runProfileList(commonFlags *cli.CommonFlags, out io.Writer) error {
	infos := installer.ListProfilesWithDescriptions()
	summaries := make([]profileSummary, 0, len(infos))
	for _, info := range infos {
		summary, _, err := loadProfile(info.Name)
		if err != nil {
			return err
		}
		summaries = append(summaries, summary)
	}

	return printResult(out, commonFlags, profileListResult{
		Success:  true,
		Profiles: summaries,
		Message:  "built-in installation profiles",
	})
}

// runProfileShow prints one profile's posture and its install configuration.
func runProfileShow(commonFlags *cli.CommonFlags, profileName string, out io.Writer) error {
	summary, config, err := loadProfile(profileName)
	if err != nil {
		return err
	}

	data, err := installer.GenerateInstallConfig(config)
	if err != nil {
		return &WrappedError{Msg: "failed to render profile " + profileName, Err: err}
	}

	return printResult(out, commonFlags, profileShowResult{
		Success: true,
		Profile: summary,
		YAML:    string(data),
		Message: "profile " + summary.Name,
	})
}

// runProfileValidate loads configPath the way the installer does and reports
// whether it is valid. An invalid file prints its result and then returns
// ErrConfigValidationFailed so the command exits non-zero.
func runProfileValidate(commonFlags *cli.CommonFlags, configPath string, out io.Writer) error {
	if _, err := os.Stat(configPath); err != nil {
		return ErrConfigParseError{Path: configPath, Reason: err.Error()}
	}

	if _, err := installer.LoadInstallConfig(configPath); err != nil {
		if printErr := printResult(out, commonFlags, profileValidateResult{
			Success: true,
			Valid:   false,
			Errors:  []string{err.Error()},
			Message: configPath + " is not a valid install configuration",
		}); printErr != nil {
			return printErr
		}
		return ErrConfigValidationFailed{Reason: err.Error()}
	}

	return printResult(out, commonFlags, profileValidateResult{
		Success: true,
		Valid:   true,
		Errors:  []string{},
		Message: configPath + " is a valid install configuration",
	})
}

// runProfileGenerate renders a profile, with its overrides, as an install
// configuration and writes it to --output when one is given.
func runProfileGenerate(commonFlags *cli.CommonFlags, flags *generateProfileFlags, out io.Writer) error {
	if _, _, err := loadProfile(flags.profileName); err != nil {
		return err
	}

	overrides := map[string]string{}
	if flags.overrideDevice != "" {
		overrides["device"] = flags.overrideDevice
	}
	config, err := installer.GenerateConfigFromProfile(flags.profileName, overrides)
	if err != nil {
		return &WrappedError{Msg: "failed to generate configuration from profile " + flags.profileName, Err: err}
	}

	data, err := installer.GenerateInstallConfig(config)
	if err != nil {
		return ErrConfigValidationFailed{Reason: err.Error()}
	}

	message := "configuration generated from profile " + flags.profileName
	if flags.outputFile != "" {
		if err := os.WriteFile(flags.outputFile, data, 0o600); err != nil {
			return &WrappedError{Msg: "failed to write " + flags.outputFile, Err: err}
		}
		message += " and written to " + flags.outputFile
	}

	return printResult(out, commonFlags, profileGenerateResult{
		Success:    true,
		OutputFile: flags.outputFile,
		YAML:       string(data),
		Message:    message,
	})
}

// loadProfile resolves a built-in profile by name and summarises its
// security posture. An unknown name is ErrProfileNotFound.
func loadProfile(name string) (profileSummary, *installer.Config, error) {
	if err := installer.ValidateProfileName(name); err != nil {
		return profileSummary{}, nil, ErrProfileNotFound{ProfileName: name}
	}

	profile, err := installer.GetProfileWithDescription(name)
	if err != nil {
		return profileSummary{}, nil, &WrappedError{Msg: "failed to load profile " + name, Err: err}
	}

	return summarizeProfile(string(profile.Name), profile.Description, profile.Config), profile.Config, nil
}

// summarizeProfile derives the posture fields from an installer configuration.
func summarizeProfile(name, description string, config *installer.Config) profileSummary {
	summary := profileSummary{
		Name:        name,
		Description: description,
		SecureBoot:  config.SecureBoot != nil && config.SecureBoot.Enabled,
		TPMUnseal:   config.EnableTPMSealing,
		Lockdown:    "none",
	}
	if config.Disk != nil {
		summary.LUKS = config.Disk.Encryption != nil
	}
	if config.OS != nil {
		summary.FIPS = config.OS.FIPS
		if config.OS.Lockdown {
			summary.Lockdown = config.OS.LockdownMode
		}
	}
	return summary
}
