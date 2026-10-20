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
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// ExtractISO extracts ISO contents to the configured ISODir directory
// using 7z or similar extraction tool. This replaces the extract-iso.sh script.
func ExtractISO(ctx context.Context, config *ISOConfig) error {
	logger := slog.Default()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return &WrappedError{Msg: "invalid configuration", Err: err}
	}

	isoPath := config.ISOPath()
	isoDir := config.ISODir

	// Check if ISO exists
	if _, err := os.Stat(isoPath); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("ISO file not found: %s", isoPath)}
	}

	logger.Info("Extracting Alpine ISO",
		"iso", isoPath,
		"destination", isoDir)

	// Remove existing directory if it exists
	if err := os.RemoveAll(isoDir); err != nil {
		return &WrappedError{Msg: "failed to remove existing ISO directory", Err: err}
	}

	// Create ISO directory
	if err := os.MkdirAll(isoDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create ISO directory", Err: err}
	}

	// Try different extraction methods in order of preference
	extractors := []func(context.Context, string, string) error{
		extract7z,
		extractBsdtar,
		extractOsirrox,
	}

	var lastErr error
	for _, extractor := range extractors {
		if err := extractor(ctx, isoPath, isoDir); err != nil {
			lastErr = err
			continue
		}

		// Extraction succeeded
		logger.Info("ISO extraction successful", "method", "7z")

		// Make all files writable (equivalent to chmod -R u+w)
		if err := makeWritable(isoDir); err != nil {
			return &WrappedError{Msg: "failed to make files writable", Err: err}
		}

		logger.Info("ISO extracted successfully",
			"destination", isoDir)

		return nil
	}

	// All extraction methods failed
	if lastErr != nil {
		return &WrappedError{Msg: "failed to extract ISO (tried 7z, bsdtar, osirrox)", Err: lastErr}
	}

	return &MessageError{Msg: "no ISO extraction tools available"}
}

// extract7z extracts an ISO using 7z command
func extract7z(ctx context.Context, isoPath, destDir string) error {
	logger := slog.Default()

	// Check if 7z is available
	if _, err := exec.LookPath("7z"); err != nil {
		return &WrappedError{Msg: "7z not found", Err: err}
	}

	logger.Info("Extracting ISO using 7z")

	// Execute: 7z x <iso> -o<destdir>
	cmd := exec.CommandContext(ctx, "7z", "x", isoPath, "-o"+destDir)
	cmd.Stdout = os.Stderr // tool chatter is diagnostics; stdout carries the verb's result
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return &WrappedError{Msg: "7z extraction failed", Err: err}
	}

	return nil
}

// extractBsdtar extracts an ISO using bsdtar command
func extractBsdtar(ctx context.Context, isoPath, destDir string) error {
	logger := slog.Default()

	// Check if bsdtar is available
	if _, err := exec.LookPath("bsdtar"); err != nil {
		return &WrappedError{Msg: "bsdtar not found", Err: err}
	}

	logger.Info("Extracting ISO using bsdtar")

	// Execute: bsdtar -xf <iso> -C <destdir>
	cmd := exec.CommandContext(ctx, "bsdtar", "-xf", isoPath, "-C", destDir)
	cmd.Stdout = os.Stderr // tool chatter is diagnostics; stdout carries the verb's result
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return &WrappedError{Msg: "bsdtar extraction failed", Err: err}
	}

	return nil
}

// extractOsirrox extracts an ISO using xorriso's osirrox feature
func extractOsirrox(ctx context.Context, isoPath, destDir string) error {
	logger := slog.Default()

	// Check if xorriso is available
	if _, err := exec.LookPath("xorriso"); err != nil {
		return &WrappedError{Msg: "xorriso not found", Err: err}
	}

	logger.Info("Extracting ISO using xorriso osirrox")

	// Execute: xorriso -osirrox on -indev <iso> -extract / <destdir>
	cmd := exec.CommandContext(ctx, "xorriso",
		"-osirrox", "on",
		"-indev", isoPath,
		"-extract", "/", destDir)
	cmd.Stdout = os.Stderr // tool chatter is diagnostics; stdout carries the verb's result
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return &WrappedError{Msg: "xorriso extraction failed", Err: err}
	}

	return nil
}

// makeWritable makes all files in the directory tree writable by the user
// This is equivalent to: chmod -R u+w <dir>
func makeWritable(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Get current file info
		info, err := os.Lstat(path)
		if err != nil {
			return &WrappedError{Msg: fmt.Sprintf("failed to stat %s", path), Err: err}
		}

		// Get current mode
		mode := info.Mode()

		// Add user write permission
		newMode := mode | 0200 // Add user write bit

		// Only change if needed
		if newMode != mode {
			if err := os.Chmod(path, newMode); err != nil {
				return &WrappedError{Msg: fmt.Sprintf("failed to chmod %s", path), Err: err}
			}
		}

		return nil
	})
}

// ExtractWithProgress extracts ISO with progress reporting
func ExtractWithProgress(ctx context.Context, config *ISOConfig, progress func(string, float64)) error {
	logger := slog.Default()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return &WrappedError{Msg: "invalid configuration", Err: err}
	}

	isoPath := config.ISOPath()
	isoDir := config.ISODir

	// Check if ISO exists
	isoInfo, err := os.Stat(isoPath)
	if os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("ISO file not found: %s", isoPath)}
	}
	isoSize := isoInfo.Size()

	logger.Info("Extracting Alpine ISO with progress tracking",
		"iso", isoPath,
		"destination", isoDir,
		"size_mb", isoSize/(1024*1024))

	// Remove existing directory if it exists
	if err := os.RemoveAll(isoDir); err != nil {
		return &WrappedError{Msg: "failed to remove existing ISO directory", Err: err}
	}

	// Create ISO directory
	if err := os.MkdirAll(isoDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create ISO directory", Err: err}
	}

	// Report initial progress immediately so the callback is always
	// invoked at least once, even if extraction completes quickly.
	if progress != nil {
		progress("starting", 0)
	}

	// Start progress monitor
	done := make(chan bool)
	if progress != nil {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					// Calculate extracted size
					var extractedSize int64
					filepath.WalkDir(isoDir, func(path string, d fs.DirEntry, err error) error {
						if err == nil && !d.IsDir() {
							if info, err := d.Info(); err == nil {
								extractedSize += info.Size()
							}
						}
						return nil
					})

					percent := float64(extractedSize) / float64(isoSize) * 100
					if percent > 100 {
						percent = 100
					}
					progress("extracting", percent)
				}
			}
		}()
	}

	// Perform extraction
	err = ExtractISO(ctx, config)

	// Stop progress monitor
	close(done)

	if err != nil {
		return err
	}

	if progress != nil {
		progress("complete", 100)
	}

	return nil
}

// CopyISO creates a copy of the ISO file
func CopyISO(ctx context.Context, src, dst string) error {
	logger := slog.Default()

	logger.Info("Copying ISO", "source", src, "destination", dst)

	// Open source file
	srcFile, err := os.Open(src)
	if err != nil {
		return &WrappedError{Msg: "failed to open source ISO", Err: err}
	}
	defer srcFile.Close()

	// Get source file info
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return &WrappedError{Msg: "failed to stat source ISO", Err: err}
	}

	// Create destination file
	dstFile, err := os.Create(dst)
	if err != nil {
		return &WrappedError{Msg: "failed to create destination ISO", Err: err}
	}
	defer dstFile.Close()

	// Copy with context support
	written, err := copyWithContext(ctx, dstFile, srcFile)
	if err != nil {
		os.Remove(dst)
		return &WrappedError{Msg: "failed to copy ISO", Err: err}
	}

	// Verify size
	if written != srcInfo.Size() {
		os.Remove(dst)
		return &MessageError{Msg: fmt.Sprintf("incomplete copy: expected %d bytes, got %d", srcInfo.Size(), written)}
	}

	// Preserve permissions
	if err := os.Chmod(dst, srcInfo.Mode()); err != nil {
		return &WrappedError{Msg: "failed to set permissions", Err: err}
	}

	logger.Info("ISO copied successfully",
		"size_mb", written/(1024*1024))

	return nil
}

// VerifyExtraction verifies that the ISO was extracted successfully
func VerifyExtraction(isoDir string) error {
	// Check if directory exists
	info, err := os.Stat(isoDir)
	if err != nil {
		return &WrappedError{Msg: "extraction directory does not exist", Err: err}
	}

	if !info.IsDir() {
		return &MessageError{Msg: fmt.Sprintf("%s is not a directory", isoDir)}
	}

	// Check for common ISO files that should exist
	requiredFiles := []string{
		"boot",
		".disk",
	}

	for _, file := range requiredFiles {
		path := filepath.Join(isoDir, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Warning only, as ISO structure may vary
			slog.Warn("Expected file not found in extracted ISO", "file", file)
		}
	}

	// Count extracted files
	var fileCount int
	err = filepath.WalkDir(isoDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			fileCount++
		}
		return nil
	})

	if err != nil {
		return &WrappedError{Msg: "failed to verify extraction", Err: err}
	}

	if fileCount == 0 {
		return &MessageError{Msg: "no files found in extraction directory"}
	}

	slog.Info("Extraction verified",
		"directory", isoDir,
		"file_count", fileCount)

	return nil
}

// GetDiskUsage returns the disk usage of a directory in bytes
func GetDiskUsage(path string) (int64, error) {
	var size int64

	err := filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			size += info.Size()
		}
		return nil
	})

	return size, err
}

// GetAvailableSpace returns the available disk space in bytes for the given path
func GetAvailableSpace(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, &WrappedError{Msg: "failed to get filesystem stats", Err: err}
	}

	// Available blocks * block size
	return stat.Bavail * uint64(stat.Bsize), nil
}

// CheckDiskSpace verifies sufficient disk space is available for extraction
func CheckDiskSpace(isoPath, destDir string) error {
	// Get ISO size
	isoInfo, err := os.Stat(isoPath)
	if err != nil {
		return &WrappedError{Msg: "failed to stat ISO", Err: err}
	}

	isoSize := uint64(isoInfo.Size())

	// Get available space
	available, err := GetAvailableSpace(destDir)
	if err != nil {
		return err
	}

	// Require 2x the ISO size (extraction can temporarily use more space)
	required := isoSize * 2

	if available < required {
		return &MessageError{Msg: fmt.Sprintf("insufficient disk space: need %d MB, have %d MB", required/(1024*1024), available/(1024*1024))}
	}

	slog.Info("Disk space check passed",
		"iso_size_mb", isoSize/(1024*1024),
		"available_mb", available/(1024*1024),
		"required_mb", required/(1024*1024))

	return nil
}
