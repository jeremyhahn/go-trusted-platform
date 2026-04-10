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

package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// PostInstallExecutor handles post-install script execution
type PostInstallExecutor struct {
	logger *logging.Logger
	config *OSConfig
}

// NewPostInstallExecutor creates a new post-install script executor
func NewPostInstallExecutor(logger *logging.Logger, config *OSConfig) *PostInstallExecutor {
	return &PostInstallExecutor{
		logger: logger,
		config: config,
	}
}

// Execute runs the post-install scripts defined in the configuration
func (pe *PostInstallExecutor) Execute(ctx context.Context, rootPath string) error {
	// Execute inline script if provided
	if pe.config.PostInstall != "" {
		if err := pe.executeInlineScript(ctx, rootPath, pe.config.PostInstall); err != nil {
			return fmt.Errorf("inline post-install script failed: %w", err)
		}
	}

	// Execute script from file/HTTP if provided
	if pe.config.PostInstallScript != "" {
		if err := pe.executeScriptFile(ctx, rootPath, pe.config.PostInstallScript); err != nil {
			return fmt.Errorf("post-install script file failed: %w", err)
		}
	}

	return nil
}

// executeInlineScript executes an inline script embedded in the YAML
// config. The script is written INSIDE the chroot's /tmp/ directory so
// that the subsequent `chroot rootPath /bin/sh ...` invocation can
// actually see it — writing to the host's /tmp/ was a bug witnessed in
// the 2026-04-08 lab-node-2 install where the install log recorded
// `sh: can't open '/tmp/post-install-inline.sh': No such file or
// directory` and the installer silently swallowed the failure.
func (pe *PostInstallExecutor) executeInlineScript(ctx context.Context, rootPath, script string) error {
	pe.logger.Info("[POST-INSTALL] Executing inline post-install script")

	// Write the script inside the chroot at /tmp/post-install-inline.sh
	// so the chroot invocation can read it with the same path.
	hostTmpDir := filepath.Join(rootPath, "tmp")
	if err := os.MkdirAll(hostTmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create chroot /tmp directory: %w", err)
	}
	hostScriptPath := filepath.Join(hostTmpDir, "post-install-inline.sh")
	if err := os.WriteFile(hostScriptPath, []byte(script), 0700); err != nil {
		return fmt.Errorf("failed to write inline script to chroot: %w", err)
	}
	defer os.Remove(hostScriptPath)

	// Inside the chroot the script path is relative to the chroot root.
	chrootScriptPath := "/tmp/post-install-inline.sh"

	// Execute in chroot environment. Use -e so a failing command
	// surfaces as a non-zero exit status instead of silently
	// continuing past the error.
	cmd := exec.CommandContext(ctx, "chroot", rootPath, "/bin/sh", "-e", chrootScriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("inline script execution failed: %w", err)
	}

	pe.logger.Info("[POST-INSTALL] Inline script executed successfully")
	return nil
}

// executeScriptFile executes a script from a local file or HTTP URL
func (pe *PostInstallExecutor) executeScriptFile(ctx context.Context, rootPath, scriptPath string) error {
	var localPath string
	var err error

	// Check if it's an HTTP URL
	if strings.HasPrefix(scriptPath, "http://") || strings.HasPrefix(scriptPath, "https://") {
		pe.logger.Info("[POST-INSTALL] Downloading post-install script from HTTP", "url", scriptPath)
		localPath, err = pe.downloadAndValidateHTTPScript(ctx, scriptPath)
		if err != nil {
			return fmt.Errorf("failed to download HTTP script: %w", err)
		}
		defer os.Remove(localPath)
	} else {
		// Local file path
		pe.logger.Info("[POST-INSTALL] Using local post-install script", "path", scriptPath)
		if _, err := os.Stat(scriptPath); err != nil {
			return fmt.Errorf("local script file not found: %w", err)
		}
		localPath = scriptPath
	}

	// Copy script to target system
	scriptData, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read script file: %w", err)
	}

	targetScript := filepath.Join(rootPath, "tmp", "post-install.sh")
	if err := os.WriteFile(targetScript, scriptData, 0700); err != nil {
		return fmt.Errorf("failed to write script to target system: %w", err)
	}
	defer os.Remove(targetScript)

	// Execute in chroot environment
	pe.logger.Info("[POST-INSTALL] Executing post-install script in chroot")
	cmd := exec.CommandContext(ctx, "chroot", rootPath, "/bin/sh", "/tmp/post-install.sh")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("script execution failed: %w", err)
	}

	pe.logger.Info("[POST-INSTALL] Post-install script executed successfully")
	return nil
}

// downloadAndValidateHTTPScript downloads a script from HTTP and validates its SHA256 checksum
func (pe *PostInstallExecutor) downloadAndValidateHTTPScript(ctx context.Context, url string) (string, error) {
	// Download the .sha256 checksum file first
	checksumURL := url + ".sha256"
	pe.logger.Info("[POST-INSTALL] Downloading SHA256 checksum", "url", checksumURL)

	checksumReq, err := http.NewRequestWithContext(ctx, "GET", checksumURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create checksum request: %w", err)
	}

	checksumResp, err := http.DefaultClient.Do(checksumReq)
	if err != nil {
		return "", fmt.Errorf("failed to download checksum file: %w", err)
	}
	defer func() {
		if closeErr := checksumResp.Body.Close(); closeErr != nil {
			pe.logger.Warn("[POST-INSTALL] Failed to close checksum response body", "error", closeErr)
		}
	}()

	if checksumResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum file not found (HTTP %d): refusing to download script without checksum validation", checksumResp.StatusCode)
	}

	// Read expected checksum
	checksumBytes, err := io.ReadAll(checksumResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read checksum: %w", err)
	}

	expectedChecksum := strings.TrimSpace(string(checksumBytes))
	// Handle format: "checksum  filename" or just "checksum"
	if parts := strings.Fields(expectedChecksum); len(parts) > 0 {
		expectedChecksum = parts[0]
	}

	pe.logger.Info("[POST-INSTALL] Expected SHA256 checksum", "checksum", expectedChecksum)

	// Download the script
	pe.logger.Info("[POST-INSTALL] Downloading script", "url", url)
	scriptReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create script request: %w", err)
	}

	scriptResp, err := http.DefaultClient.Do(scriptReq)
	if err != nil {
		return "", fmt.Errorf("failed to download script: %w", err)
	}
	defer func() {
		if closeErr := scriptResp.Body.Close(); closeErr != nil {
			pe.logger.Warn("[POST-INSTALL] Failed to close script response body", "error", closeErr)
		}
	}()

	if scriptResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download script: HTTP %d", scriptResp.StatusCode)
	}

	// Create temporary file and calculate checksum while writing
	tmpFile, err := os.CreateTemp("/tmp", "post-install-*.sh")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := tmpFile.Name()

	hash := sha256.New()
	writer := io.MultiWriter(tmpFile, hash)

	if _, err := io.Copy(writer, scriptResp.Body); err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			pe.logger.Warn("[POST-INSTALL] Failed to close temp file", "error", closeErr)
		}
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to download script: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Verify checksum
	actualChecksum := hex.EncodeToString(hash.Sum(nil))
	pe.logger.Info("[POST-INSTALL] Calculated SHA256 checksum", "checksum", actualChecksum)

	if actualChecksum != expectedChecksum {
		os.Remove(tmpPath)
		return "", fmt.Errorf("checksum mismatch: expected %s, got %s (refusing to execute script)", expectedChecksum, actualChecksum)
	}

	pe.logger.Info("[POST-INSTALL] Checksum validation successful")

	// Make script executable
	if err := os.Chmod(tmpPath, 0700); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to make script executable: %w", err)
	}

	return tmpPath, nil
}
