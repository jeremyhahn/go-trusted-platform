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

// downloadFlags holds flags for the download command
type downloadFlags struct {
	url          string
	version      string
	mirror       string
	arch         string
	force        bool
	verify       bool
	resumeEnable bool
	configFile   string
	workDir      string
	debug        bool
	verbose      bool
}

// newDownloadCommand creates the download subcommand for downloading Alpine ISO
func newDownloadCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &downloadFlags{}

	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download Alpine Linux base ISO",
		Long: `Downloads Alpine Linux ISO image with SHA256 checksum verification
and support for resuming interrupted downloads.

The download is verified against the SHA256 checksum published by Alpine Linux
to ensure integrity. If the ISO already exists and is verified, the download
is skipped unless --force is specified.

Examples:
  # Download default Alpine version (3.22.2)
  platformctl iso download

  # Download specific version
  platformctl iso download --version 3.21.0

  # Download from specific mirror
  platformctl iso download --mirror http://dl-cdn.alpinelinux.org/alpine

  # Force re-download
  platformctl iso download --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDownload(getFlags(), flags)
		},
	}

	// Download flags
	cmd.Flags().StringVar(&flags.url, "url", "", "Direct URL to Alpine ISO (overrides auto-detection)")
	cmd.Flags().StringVar(&flags.version, "version", "3.22.2", "Alpine Linux version to download")
	cmd.Flags().StringVar(&flags.mirror, "mirror", "http://mirror.cs.odu.edu/alpine", "Alpine Linux mirror URL")
	cmd.Flags().StringVar(&flags.arch, "arch", "x86_64", "Architecture (x86_64 or aarch64)")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Force re-download even if ISO exists")
	cmd.Flags().BoolVar(&flags.verify, "verify", true, "Verify SHA256 checksum after download")
	cmd.Flags().BoolVar(&flags.resumeEnable, "resume", true, "Enable resuming partial downloads")

	// Common flags
	cmd.Flags().StringVar(&flags.configFile, "config", "", "Path to ISO build configuration file")
	cmd.Flags().StringVar(&flags.workDir, "work-dir", "work", "Working directory for ISO operations")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")

	return cmd
}

// runDownload executes the download command
func runDownload(commonFlags *cli.CommonFlags, flags *downloadFlags) error {
	// ISO download requires App initialization which needs daemon connection
	// Dual-mode will be added later to support local-only operations
	return ErrDaemonConnectionRequired{Command: "iso download"}
}
