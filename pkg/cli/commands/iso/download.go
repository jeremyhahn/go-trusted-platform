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
	"net/url"
	"path"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
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
	workDir      string
	debug        bool
}

// downloadResult is what `iso download` prints (docs/installer/cli.md §4).
type downloadResult struct {
	Success   bool   `json:"success" yaml:"success"`
	ISOPath   string `json:"iso_path" yaml:"iso_path"`
	SHA256    string `json:"sha256" yaml:"sha256"`
	SizeBytes int64  `json:"size_bytes" yaml:"size_bytes"`
	Verified  bool   `json:"verified" yaml:"verified"`
	Message   string `json:"message" yaml:"message"`
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
			return runDownload(cmd.Context(), getFlags(), flags, cmd.OutOrStdout())
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
	cmd.Flags().StringVar(&flags.workDir, "work-dir", "work", "Directory the ISO is downloaded into")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")

	return cmd
}

// runDownload executes the download command
func runDownload(ctx context.Context, commonFlags *cli.CommonFlags, flags *downloadFlags, out io.Writer) error {
	isoConfig := pkgiso.DefaultISOConfig()
	isoConfig.Version = flags.version
	isoConfig.MirrorURL = flags.mirror
	isoConfig.Architecture = flags.arch
	isoConfig.WorkDir = flags.workDir
	isoConfig.VerifyChecksum = flags.verify
	isoConfig.ResumeDownload = flags.resumeEnable
	isoConfig.Debug = flags.debug

	if flags.url != "" {
		parsed, err := url.Parse(flags.url)
		if err != nil || parsed.Scheme == "" || path.Base(parsed.Path) == "/" || path.Base(parsed.Path) == "." {
			return ErrConfigValidationFailed{Reason: "--url must be an absolute URL naming an ISO file: " + flags.url}
		}
		isoConfig.URL = flags.url
		isoConfig.ISO = path.Base(parsed.Path)
	}

	if err := isoConfig.Validate(); err != nil {
		return ErrConfigValidationFailed{Reason: err.Error()}
	}

	if flags.force {
		removeExistingISOFiles(isoConfig)
	}

	if err := pkgiso.DownloadISO(ctx, isoConfig); err != nil {
		return &WrappedError{Msg: "failed to download ISO", Err: err}
	}

	sum, size, err := fileDigest(isoConfig.ISOPath())
	if err != nil {
		return err
	}

	return printResult(out, commonFlags, downloadResult{
		Success:   true,
		ISOPath:   isoConfig.ISOPath(),
		SHA256:    sum,
		SizeBytes: size,
		Verified:  flags.verify,
		Message:   "ISO ready, source " + isoConfig.URL,
	})
}
