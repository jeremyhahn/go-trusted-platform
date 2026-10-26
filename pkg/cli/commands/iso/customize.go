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
	"context"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

// customizeFlags holds flags for the customize command
type customizeFlags struct {
	isoDir                string
	overlay               string
	keysDir               string
	platformdPath         string
	platformctlPath       string
	platformctlStaticPath string
	platformConfig        string
	configFile            string
	workDir               string
	preFetch              bool
	debug                 bool
}

// customizeResult is what `iso customize` prints (docs/installer/cli.md §4).
type customizeResult struct {
	Success bool   `json:"success" yaml:"success"`
	ISODir  string `json:"iso_dir" yaml:"iso_dir"`
	Message string `json:"message" yaml:"message"`
}

// newCustomizeCommand creates the customize subcommand for customizing ISO contents
func newCustomizeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &customizeFlags{}

	cmd := &cobra.Command{
		Use:   "customize",
		Short: "Customize ISO with overlays and initramfs",
		Long: `Customize an extracted ISO with platform-specific components.

This command:
- Stages platformd, the platform configuration and the install configuration
- Applies overlay files
- Copies Secure Boot keys
- Integrates platformd into the initramfs and writes the autoinstall script
- Pre-fetches the packages the install needs into the ISO's offline
  repository (apks-prefetch/<arch>), unless --pre-fetch=false

A platform configuration is required unless the --config file names a
config server (dynamic configuration).

Example:
  platformctl iso customize --iso-dir work/iso --platformd-binary ./platformd-static \
    --platform-config configs/platform/templates/single-node/default.yaml \
    --keys-dir secure-boot-keys`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCustomize(cmd.Context(), getFlags(), flags, cmd.OutOrStdout())
		},
	}

	// Customize flags
	cmd.Flags().StringVar(&flags.isoDir, "iso-dir", "", "Directory containing extracted ISO contents (required)")
	cmd.Flags().StringVar(&flags.overlay, "overlay", "", "Overlay directory to merge into ISO")
	cmd.Flags().StringVar(&flags.keysDir, "keys-dir", "", "Secure Boot keys directory")
	cmd.Flags().StringVar(&flags.platformdPath, "platformd-binary", "", "Path to platformd binary (default: platformd beside platformctl)")
	cmd.Flags().StringVar(&flags.platformctlPath, "platformctl-binary", "", "platformctl binary the media installs with (default: this platformctl)")
	cmd.Flags().StringVar(&flags.platformctlStaticPath, "platformctl-static-binary", "", "Static platformctl for Alpine/musl (default: not installed)")
	cmd.Flags().StringVar(&flags.platformConfig, "platform-config", "", "Platform configuration baked into the ISO")

	// Common flags
	cmd.Flags().StringVar(&flags.configFile, "config", "", "Path to ISO build configuration file")
	cmd.Flags().StringVar(&flags.workDir, "work-dir", "work", "Working directory for ISO operations")
	// The autoinstall script installs from the offline repository when it
	// boots from the ISO: the stock Alpine repository lacks lvm2, parted and
	// the rest, so the default matches iso create's.
	cmd.Flags().BoolVar(&flags.preFetch, "pre-fetch", true,
		"Pre-download all packages into the ISO for offline installation. "+
			"Pass --pre-fetch=false only when the install network reaches an Alpine mirror")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")

	// Mark required flags
	cli.MarkFlagsRequired(cmd, "iso-dir")

	return cmd
}

// runCustomize executes the customize command
func runCustomize(ctx context.Context, commonFlags *cli.CommonFlags, flags *customizeFlags, out io.Writer) error {
	info, err := os.Stat(flags.isoDir)
	if err != nil || !info.IsDir() {
		return ErrDirectoryNotFound{Path: flags.isoDir}
	}

	buildConfig, err := customizeBuildConfig(flags)
	if err != nil {
		return err
	}
	workDir, err := buildConfig.ResolveWorkDir()
	if err != nil {
		return ErrCustomizationFailed{Reason: err.Error()}
	}

	platformConfig := pkgiso.NewPlatformISOConfig(buildConfig, workDir)
	platformConfig.Directories.ISO = flags.isoDir
	if flags.overlay != "" {
		platformConfig.Directories.Overlay = flags.overlay
	}

	customizer := pkgiso.NewCustomizer(platformConfig, newVerbLogger(flags.debug))
	if err := customizer.CustomizeAll(ctx); err != nil {
		return ErrCustomizationFailed{Reason: err.Error()}
	}

	return printResult(out, commonFlags, customizeResult{
		Success: true,
		ISODir:  flags.isoDir,
		Message: "ISO tree customized",
	})
}

// customizeBuildConfig loads the --config file, or the defaults, and applies
// the verb's flags over it.
func customizeBuildConfig(flags *customizeFlags) (*pkgiso.ISOBuildConfig, error) {
	buildConfig := pkgiso.DefaultISOBuildConfig()
	if flags.configFile != "" {
		loaded, err := pkgiso.LoadISOBuildConfig(flags.configFile)
		if err != nil {
			return nil, ErrConfigParseError{Path: flags.configFile, Reason: err.Error()}
		}
		buildConfig = loaded
	}

	if flags.workDir != "" {
		buildConfig.WorkDir = flags.workDir
	}
	if flags.keysDir != "" {
		buildConfig.KeysDir = flags.keysDir
	}
	if flags.platformdPath != "" {
		buildConfig.PlatformdBinary = flags.platformdPath
	}
	if buildConfig.PlatformdBinary == "" {
		platformdPath, err := siblingPlatformdBinary()
		if err != nil {
			return nil, err
		}
		buildConfig.PlatformdBinary = platformdPath
	}
	if err := namePlatformctlBinaries(buildConfig, flags.platformctlPath, flags.platformctlStaticPath); err != nil {
		return nil, err
	}
	if flags.platformConfig != "" {
		buildConfig.PlatformConfigFile = flags.platformConfig
	}
	if buildConfig.PlatformVersion == "" {
		buildConfig.PlatformVersion = pkgiso.ReadVersionFile()
	}
	buildConfig.PreFetch = flags.preFetch
	buildConfig.Debug = buildConfig.Debug || flags.debug

	if err := buildConfig.Validate(); err != nil {
		return nil, ErrConfigValidationFailed{Reason: err.Error()}
	}
	if err := buildConfig.ResolveBinaries(); err != nil {
		return nil, ErrConfigValidationFailed{Reason: err.Error()}
	}
	return buildConfig, nil
}
