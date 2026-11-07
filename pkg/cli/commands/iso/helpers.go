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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/fatih/color"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Output formatting functions for consistent CLI experience

// progressOut receives every progress line the iso verbs print. It is
// stderr: stdout carries only a verb's result object, so `-o json` output
// stays parseable (docs/installer/cli.md §4).
var progressOut io.Writer = color.Error

// printHeader prints a section header
func printHeader(message string) {
	fmt.Fprintln(progressOut)
	color.New(color.FgCyan, color.Bold).Fprintln(progressOut, "========================================")
	color.New(color.FgCyan, color.Bold).Fprintln(progressOut, message)
	color.New(color.FgCyan, color.Bold).Fprintln(progressOut, "========================================")
	fmt.Fprintln(progressOut)
}

// printInfo prints an informational message
func printInfo(message string) {
	color.New(color.FgBlue).Fprintf(progressOut, "  %s\n", message)
}

// printSuccess prints a success message
func printSuccess(message string) {
	color.New(color.FgGreen).Fprintf(progressOut, "✓ %s\n", message)
}

// printWarn prints a warning message
func printWarn(message string) {
	color.New(color.FgYellow).Fprintf(progressOut, "⚠ %s\n", message)
}

// printError prints an error message
func printError(message string) {
	color.New(color.FgRed).Fprintf(progressOut, "✗ %s\n", message)
}

// printResult writes a verb's result in the global --output format. The
// table format falls back to YAML for a struct (pkg/cli/output.go).
func printResult(out io.Writer, flags *cli.CommonFlags, result any) error {
	return cli.NewPrinterWithWriter(flags.OutputFormat, flags.NoColor, out).Print(result)
}

// newVerbLogger returns the stderr logger the pkg/iso steps report through,
// so stdout carries only the verb's result.
func newVerbLogger(debug bool) *logging.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return logging.NewLogger(level, nil)
}

// fileDigest returns a file's SHA-256 and size.
func fileDigest(path string) (string, int64, error) {
	sum, err := calculateFileSHA256(path)
	if err != nil {
		return "", 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, &WrappedError{Msg: "failed to stat file", Err: err}
	}
	return sum, info.Size(), nil
}

// removeFileIfExists removes a file if it exists, ignoring not-exist errors
func removeFileIfExists(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return &WrappedError{Msg: fmt.Sprintf("failed to remove %s", path), Err: err}
	}
	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirExists checks if a directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// siblingPlatformdBinary returns the platformd binary installed beside the
// running platformctl. platformd and platformctl are separate binaries built
// from separate cmd/ directories and shipped together.
func siblingPlatformdBinary() (string, error) {
	selfPath, err := selfBinary()
	if err != nil {
		return "", err
	}
	platformdPath := filepath.Join(filepath.Dir(selfPath), "platformd")
	if _, err := os.Stat(platformdPath); err != nil {
		return "", &MessageError{Msg: fmt.Sprintf("platformd binary not found at %s (build with 'make build')", platformdPath)}
	}
	return platformdPath, nil
}

// selfBinary is the resolved path of the running platformctl.
func selfBinary() (string, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return "", &WrappedError{Msg: "failed to get executable path", Err: err}
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return "", &WrappedError{Msg: "failed to resolve executable path", Err: err}
	}
	return selfPath, nil
}

// namePlatformctlBinaries names the platformctl binaries the media carries
// (#351). platformctl, the installer's entry point, defaults to this running
// platformctl; platformctl-static is installed only when named. pkg/iso never
// infers either from platformd's path.
func namePlatformctlBinaries(config *pkgiso.ISOBuildConfig, platformctl, platformctlStatic string) error {
	if platformctl != "" {
		config.PlatformctlBinary = platformctl
	}
	if platformctlStatic != "" {
		config.PlatformctlStaticBinary = platformctlStatic
	}
	if config.PlatformctlBinary != "" {
		return nil
	}
	self, err := selfBinary()
	if err != nil {
		return err
	}
	config.PlatformctlBinary = self
	return nil
}
