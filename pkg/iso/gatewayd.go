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
	"os"
	"path/filepath"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// gatewaydBinaryName is the edge daemon shipped beside platformd under the
// ISO's platformd-bin/ directory; the installer places it on gateway-role
// nodes (#66).
const gatewaydBinaryName = "gatewayd"

// gatewaydBinaryPath derives gatewayd's build location from platformd's:
// the two are built into the same directory (`make build` produces both).
func gatewaydBinaryPath(platformdBinary string) string {
	if platformdBinary == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(platformdBinary), gatewaydBinaryName)
}

// isoTargetsGatewayRole reports whether the platform configuration bundled
// into this ISO enables the gateway role. It is the one signal that decides
// whether gatewayd is a boot-critical input of the artifact.
func isoTargetsGatewayRole(configFile string) (bool, error) {
	if configFile == "" {
		return false, nil
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false, &WrappedError{Msg: "failed to read the bundled platform config for the gateway role decision", Err: err}
	}
	enabled, err := tpconfig.GatewayRoleEnabled(data)
	if err != nil {
		return false, &WrappedError{Msg: "bundled platform config is unreadable for the gateway role decision", Err: err}
	}
	return enabled, nil
}

// CopyGatewaydBinary stages gatewayd under platformd-bin/ on the ISO.
//
// required follows the bundled platform configuration's role: an ISO whose
// config enables the gateway role cannot produce a working node without
// gatewayd, so its absence fails the build (the #48 rule for boot-critical
// inputs). An ISO for any other role copies gatewayd when it is present and
// skips it otherwise.
func (c *Customizer) CopyGatewaydBinary(ctx context.Context, binaryPath string, required bool) error {
	if binaryPath == "" {
		if required {
			return ErrBootCriticalBinaryMissing(gatewaydBinaryName, "(no platformd binary configured, so no build directory to look in)",
				"set platform.platformd_binary so gatewayd can be found beside it")
		}
		c.logger.Debug("No gatewayd binary path derivable, skipping")
		return nil
	}

	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		if required {
			return ErrBootCriticalBinaryMissing(gatewaydBinaryName, binaryPath,
				"this ISO's platform config enables the gateway role; build gatewayd with `make build` beside platformd")
		}
		c.logger.Info("gatewayd binary not present and this ISO does not target the gateway role; skipping", "path", binaryPath)
		return nil
	}

	c.logger.Info("Copying gatewayd binary", "source", binaryPath, "gateway_role", required)

	if err := c.validateTargetBinary(binaryPath); err != nil {
		return &WrappedError{Msg: "gatewayd binary validation failed", Err: err}
	}

	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create destination directory", Err: err}
	}
	destPath := filepath.Join(destDir, gatewaydBinaryName)
	if err := copyFile(binaryPath, destPath); err != nil {
		return &WrappedError{Msg: "failed to copy gatewayd binary", Err: err}
	}
	if err := os.Chmod(destPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("gatewayd binary copied successfully", "destination", destPath, "sha256", checksum)
	}
	return nil
}
