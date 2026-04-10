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
	"os"

	"github.com/fatih/color"
)

// Output formatting functions for consistent CLI experience

// printHeader prints a section header
func printHeader(message string) {
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("========================================")
	color.New(color.FgCyan, color.Bold).Println(message)
	color.New(color.FgCyan, color.Bold).Println("========================================")
	fmt.Println()
}

// printInfo prints an informational message
func printInfo(message string) {
	color.New(color.FgBlue).Printf("  %s\n", message)
}

// printSuccess prints a success message
func printSuccess(message string) {
	color.New(color.FgGreen).Printf("✓ %s\n", message)
}

// printWarn prints a warning message
func printWarn(message string) {
	color.New(color.FgYellow).Printf("⚠ %s\n", message)
}

// printError prints an error message
func printError(message string) {
	color.New(color.FgRed).Printf("✗ %s\n", message)
}

// removeFileIfExists removes a file if it exists, ignoring not-exist errors
func removeFileIfExists(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", path, err)
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
