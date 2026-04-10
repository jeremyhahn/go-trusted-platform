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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// DownloadISO downloads an Alpine Linux ISO with checksum verification
// and support for resuming interrupted downloads.
func DownloadISO(ctx context.Context, config *ISOConfig) error {
	logger := slog.Default()

	// Validate and populate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Create work directory
	if err := os.MkdirAll(config.WorkDir, 0755); err != nil {
		return fmt.Errorf("failed to create work directory: %w", err)
	}

	// Check if ISO already exists and is verified
	if isVerified(config) {
		logger.Info("ISO already exists and is verified, skipping download",
			"iso", config.ISO,
			"path", config.ISOPath())
		return nil
	}

	// Download the ISO
	logger.Info("Downloading Alpine ISO",
		"iso", config.ISO,
		"url", config.URL)

	if err := downloadFile(ctx, config); err != nil {
		return fmt.Errorf("failed to download ISO: %w", err)
	}

	// Download and verify checksum if enabled
	if config.VerifyChecksum {
		logger.Info("Downloading SHA256 checksum",
			"url", config.ChecksumURL())

		if err := downloadChecksum(ctx, config); err != nil {
			return fmt.Errorf("failed to download checksum: %w", err)
		}

		logger.Info("Verifying SHA256 checksum")

		if err := verifyChecksum(config); err != nil {
			// Clean up the downloaded file on checksum failure
			os.Remove(config.ISOPath())
			return fmt.Errorf("checksum verification failed: %w", err)
		}

		logger.Info("Checksum verification passed")

		// Create verification marker
		if err := markAsVerified(config); err != nil {
			return fmt.Errorf("failed to create verification marker: %w", err)
		}
	}

	logger.Info("Alpine ISO downloaded and verified successfully",
		"path", config.ISOPath())

	return nil
}

// isVerified checks if the ISO exists and has been verified
func isVerified(config *ISOConfig) bool {
	if _, err := os.Stat(config.ISOPath()); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(config.VerifiedMarkerPath()); os.IsNotExist(err) {
		return false
	}
	return true
}

// downloadFile downloads the ISO file with support for resuming
func downloadFile(ctx context.Context, config *ISOConfig) error {
	var startByte int64
	targetPath := config.ISOPath()

	// Check if we should resume
	if config.ResumeDownload {
		if info, err := os.Stat(config.TempPath()); err == nil {
			startByte = info.Size()
		}
	}

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", config.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add range header for resume support
	if startByte > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", startByte))
		slog.Info("Resuming download", "from_byte", startByte)
	}

	// Execute the request
	client := &http.Client{
		Timeout: 30 * time.Minute,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Open or create the temporary file
	var out *os.File
	if startByte > 0 && resp.StatusCode == http.StatusPartialContent {
		// Resume: append to existing file
		out, err = os.OpenFile(config.TempPath(), os.O_APPEND|os.O_WRONLY, 0644)
	} else {
		// Fresh download: create new file
		out, err = os.Create(config.TempPath())
		startByte = 0
	}
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()

	// Get total size
	totalSize := resp.ContentLength + startByte
	if totalSize <= 0 {
		totalSize = resp.ContentLength
	}

	// Create a progress writer if callback is provided
	writer := io.Writer(out)
	if config.ProgressCallback != nil {
		writer = &progressWriter{
			writer:    out,
			total:     totalSize,
			written:   startByte,
			callback:  config.ProgressCallback,
			lastLog:   time.Now(),
			startTime: time.Now(),
		}
	}

	// Copy data with context cancellation support
	_, err = copyWithContext(ctx, writer, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Rename temp file to final name on success
	if err := os.Rename(config.TempPath(), targetPath); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// downloadChecksum downloads the checksum file
func downloadChecksum(ctx context.Context, config *ISOConfig) error {
	req, err := http.NewRequestWithContext(ctx, "GET", config.ChecksumURL(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download checksum: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create the checksum file
	out, err := os.Create(config.ChecksumPath())
	if err != nil {
		return fmt.Errorf("failed to create checksum file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write checksum file: %w", err)
	}

	return nil
}

// verifyChecksum verifies the ISO against the downloaded checksum
func verifyChecksum(config *ISOConfig) error {
	// Read expected checksum
	checksumData, err := os.ReadFile(config.ChecksumPath())
	if err != nil {
		return fmt.Errorf("failed to read checksum file: %w", err)
	}

	// Parse checksum (format: "hash  filename" or just "hash")
	expectedSum := strings.Fields(string(checksumData))[0]
	expectedSum = strings.TrimSpace(expectedSum)

	// Calculate actual checksum
	actualSum, err := calculateSHA256(config.ISOPath())
	if err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	// Compare checksums
	if !strings.EqualFold(expectedSum, actualSum) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSum, actualSum)
	}

	slog.Info("Checksum verified",
		"expected", expectedSum,
		"actual", actualSum)

	return nil
}

// calculateSHA256 calculates the SHA256 hash of a file
func calculateSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// markAsVerified creates the verification marker file
func markAsVerified(config *ISOConfig) error {
	file, err := os.Create(config.VerifiedMarkerPath())
	if err != nil {
		return err
	}
	defer file.Close()

	// Write timestamp to marker file
	_, err = file.WriteString(time.Now().Format(time.RFC3339) + "\n")
	return err
}

// copyWithContext copies data from src to dst with context cancellation support
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024) // 32KB buffer
	var written int64

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		// Read from source
		nr, err := src.Read(buf)
		if nr > 0 {
			// Write to destination
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return written, nil
			}
			return written, err
		}
	}
}

// progressWriter wraps an io.Writer to report progress
type progressWriter struct {
	writer    io.Writer
	total     int64
	written   int64
	callback  func(int64, int64, float64)
	lastLog   time.Time
	startTime time.Time
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	pw.written += int64(n)

	// Report progress at most once per second
	now := time.Now()
	if now.Sub(pw.lastLog) >= time.Second || pw.written >= pw.total {
		percent := float64(pw.written) / float64(pw.total) * 100
		if pw.callback != nil {
			pw.callback(pw.written, pw.total, percent)
		}
		pw.lastLog = now

		// Log progress
		elapsed := now.Sub(pw.startTime)
		speed := float64(pw.written) / elapsed.Seconds() / 1024 / 1024 // MB/s
		slog.Info("Download progress",
			"downloaded_mb", pw.written/1024/1024,
			"total_mb", pw.total/1024/1024,
			"percent", fmt.Sprintf("%.1f%%", percent),
			"speed_mbps", fmt.Sprintf("%.2f", speed))
	}

	return n, err
}
