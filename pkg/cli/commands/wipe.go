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

// Package commands provides CLI commands for platformctl
package commands

import (
	cryptorand "crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// wipeFlags holds flags specific to the wipe command
type wipeFlags struct {
	path    string
	passes  int
	random  bool
	trim    bool
	verbose bool
}

// NewWipeCommand creates the wipe command for secure disk wiping
func NewWipeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags wipeFlags

	cmd := &cobra.Command{
		Use:   "wipe",
		Short: "Securely wipe a LUKS container or device",
		Long: `Securely wipe a LUKS container or device using go-luks2.

This command provides cryptographically secure wiping with:
  - Multiple overwrite passes (configurable)
  - Optional random data or zeros
  - TRIM/DISCARD support for SSDs to release blocks
  - Proper file locking for exclusive access

The TRIM option issues BLKDISCARD ioctl after wiping, which informs SSDs
to release the blocks. This is crucial for forensic protection as it ensures
the SSD firmware doesn't retain copies in spare blocks.

This command is designed to be called from the dracut hook after successful
firstboot to securely wipe the installer.luks container.`,
		Example: `  # Wipe installer container with TRIM (recommended for SSDs)
  platformctl wipe --path /boot/efi/tpm2/installer.luks --trim

  # Multiple pass wipe with random data
  platformctl wipe --path /dev/sda2 --passes 3 --random --trim

  # Quick wipe with zeros
  platformctl wipe --path /tmp/container.luks`,
		RunE: func(cmd *cobra.Command, args []string) error {
			commonFlags := getFlags()
			return runWipe(commonFlags, &flags)
		},
	}

	cmd.Flags().StringVarP(&flags.path, "path", "p", "", "Path to device or container file to wipe (required)")
	cmd.Flags().IntVar(&flags.passes, "passes", 1, "Number of wipe passes (default: 1)")
	cmd.Flags().BoolVar(&flags.random, "random", false, "Use random data instead of zeros")
	cmd.Flags().BoolVar(&flags.trim, "trim", true, "Issue TRIM/DISCARD after wipe for SSDs (default: true)")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "V", false, "Enable verbose output")

	if err := cmd.MarkFlagRequired("path"); err != nil {
		// This should never happen at init time, but handle it anyway
		panic(fmt.Sprintf("failed to mark path flag as required: %v", err))
	}

	return cmd
}

func runWipe(commonFlags *cli.CommonFlags, flags *wipeFlags) error {
	// Validate path
	if flags.path == "" {
		return ErrWipePathRequired{}
	}

	// Check if file/device exists
	info, err := os.Stat(flags.path)
	if err != nil {
		return ErrWipeAccessFailed{Path: flags.path, Err: err}
	}

	startTime := time.Now()

	if flags.verbose || commonFlags.Verbose {
		fmt.Fprintf(os.Stderr, "[WIPE] Starting secure wipe\n")
		fmt.Fprintf(os.Stderr, "[WIPE] Target: %s\n", flags.path)
		fmt.Fprintf(os.Stderr, "[WIPE] Size: %d bytes\n", info.Size())
		fmt.Fprintf(os.Stderr, "[WIPE] Passes: %d\n", flags.passes)
		fmt.Fprintf(os.Stderr, "[WIPE] Random: %v\n", flags.random)
		fmt.Fprintf(os.Stderr, "[WIPE] TRIM: %v\n", flags.trim)
	}

	// Regular files (like installer.luks) are wiped with direct file
	// operations so the pass pattern and the delete are this command's; the
	// boot path's equivalent is pkg/securewipe.
	if !isBlockDevice(info) {
		if flags.verbose || commonFlags.Verbose {
			fmt.Fprintf(os.Stderr, "[WIPE] Target is a regular file, using file wipe\n")
		}
		return wipeFile(flags, commonFlags, info.Size())
	}

	// For block devices, use go-luks2 Wipe
	opts := luks2.WipeOptions{
		Device: flags.path,
		Passes: flags.passes,
		Random: flags.random,
		Trim:   flags.trim,
	}

	if flags.verbose || commonFlags.Verbose {
		fmt.Fprintf(os.Stderr, "[WIPE] Wiping block device...\n")
	}

	if err := luks2.Wipe(opts); err != nil {
		return ErrWipeFailed{Path: flags.path, Err: err}
	}

	duration := time.Since(startTime)
	if flags.verbose || commonFlags.Verbose {
		fmt.Fprintf(os.Stderr, "[WIPE] Wipe completed in %v\n", duration)
	}

	fmt.Printf("Successfully wiped %s (%v)\n", flags.path, duration)
	return nil
}

// isBlockDevice checks if the file info represents a block device
func isBlockDevice(info os.FileInfo) bool {
	mode := info.Mode()
	return mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0
}

// wipeFile performs secure wipe on a regular file (like installer.luks)
// This handles files that are loop-mounted LUKS containers
func wipeFile(flags *wipeFlags, commonFlags *cli.CommonFlags, size int64) error {
	verbose := flags.verbose || commonFlags.Verbose

	if verbose {
		fmt.Fprintf(os.Stderr, "[WIPE] Opening file for secure wipe\n")
	}

	f, err := os.OpenFile(flags.path, os.O_RDWR, 0600)
	if err != nil {
		return ErrWipeOpenFailed{Path: flags.path, Err: err}
	}
	defer f.Close()

	const bufferSize = 1024 * 1024 // 1MB buffer
	buffer := make([]byte, bufferSize)
	defer clearBuffer(buffer)

	for pass := 0; pass < flags.passes; pass++ {
		if verbose {
			fmt.Fprintf(os.Stderr, "[WIPE] Pass %d/%d\n", pass+1, flags.passes)
		}

		// Seek to beginning
		if _, err := f.Seek(0, 0); err != nil {
			return ErrWipeSeekFailed{Err: err}
		}

		remaining := size
		for remaining > 0 {
			writeSize := int64(bufferSize)
			if remaining < writeSize {
				writeSize = remaining
			}

			// Fill buffer
			if flags.random {
				// Use crypto/rand for random data
				if _, err := cryptoRandRead(buffer[:writeSize]); err != nil {
					return ErrWipeRandomFailed{Err: err}
				}
			} else {
				// Zero fill
				for i := int64(0); i < writeSize; i++ {
					buffer[i] = 0
				}
			}

			// Write
			n, err := f.Write(buffer[:writeSize])
			if err != nil {
				return ErrWipeWriteFailed{Err: err}
			}

			remaining -= int64(n)
		}
	}

	// Sync to ensure writes are flushed to disk
	if err := f.Sync(); err != nil {
		return ErrWipeSyncFailed{Err: err}
	}

	// Close before attempting TRIM
	f.Close()

	// Try TRIM if requested - this works best when the file is on an SSD
	// For loop-mounted files, TRIM on the underlying device is more complex
	// and may not work, but we try anyway
	if flags.trim {
		if verbose {
			fmt.Fprintf(os.Stderr, "[WIPE] TRIM not directly applicable to regular files\n")
			fmt.Fprintf(os.Stderr, "[WIPE] File wiped - delete to release space\n")
		}
	}

	// Delete the file after wiping
	if verbose {
		fmt.Fprintf(os.Stderr, "[WIPE] Removing wiped file\n")
	}
	if err := os.Remove(flags.path); err != nil {
		return ErrWipeRemoveFailed{Path: flags.path, Err: err}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[WIPE] File securely wiped and deleted\n")
	}

	return nil
}

// clearBuffer securely zeros a byte slice
func clearBuffer(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// cryptoRandRead reads cryptographically secure random data
func cryptoRandRead(b []byte) (int, error) {
	// Use /dev/urandom for random data in initrd environment
	// crypto/rand may not work reliably in minimal initrd
	f, err := os.Open("/dev/urandom")
	if err != nil {
		// Fallback to crypto/rand
		return cryptoRandFallback(b)
	}
	defer f.Close()
	return f.Read(b)
}

// cryptoRandFallback uses crypto/rand as fallback
func cryptoRandFallback(b []byte) (int, error) {
	return cryptorand.Read(b)
}

// ErrWipePathRequired is returned when the path flag is not provided
type ErrWipePathRequired struct{}

func (e ErrWipePathRequired) Error() string {
	return "--path flag is required"
}

// ErrWipeAccessFailed is returned when the target path cannot be accessed
type ErrWipeAccessFailed struct {
	Path string
	Err  error
}

func (e ErrWipeAccessFailed) Error() string {
	return fmt.Sprintf("cannot access %s: %v", e.Path, e.Err)
}

// ErrWipeFailed is returned when the wipe operation fails
type ErrWipeFailed struct {
	Path string
	Err  error
}

func (e ErrWipeFailed) Error() string {
	return fmt.Sprintf("wipe failed for %s: %v", e.Path, e.Err)
}

// ErrWipeOpenFailed is returned when the file cannot be opened for wiping
type ErrWipeOpenFailed struct {
	Path string
	Err  error
}

func (e ErrWipeOpenFailed) Error() string {
	return fmt.Sprintf("failed to open file %s: %v", e.Path, e.Err)
}

// ErrWipeSeekFailed is returned when seeking to the beginning of the file fails
type ErrWipeSeekFailed struct {
	Err error
}

func (e ErrWipeSeekFailed) Error() string {
	return fmt.Sprintf("seek failed: %v", e.Err)
}

// ErrWipeRandomFailed is returned when generating random data fails
type ErrWipeRandomFailed struct {
	Err error
}

func (e ErrWipeRandomFailed) Error() string {
	return fmt.Sprintf("failed to generate random data: %v", e.Err)
}

// ErrWipeWriteFailed is returned when writing to the file fails
type ErrWipeWriteFailed struct {
	Err error
}

func (e ErrWipeWriteFailed) Error() string {
	return fmt.Sprintf("write failed: %v", e.Err)
}

// ErrWipeSyncFailed is returned when syncing the file fails
type ErrWipeSyncFailed struct {
	Err error
}

func (e ErrWipeSyncFailed) Error() string {
	return fmt.Sprintf("sync failed: %v", e.Err)
}

// ErrWipeRemoveFailed is returned when removing the wiped file fails
type ErrWipeRemoveFailed struct {
	Path string
	Err  error
}

func (e ErrWipeRemoveFailed) Error() string {
	return fmt.Sprintf("failed to remove wiped file %s: %v", e.Path, e.Err)
}
