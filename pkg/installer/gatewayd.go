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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// gatewaydBinaryName is the edge daemon's binary, shipped beside platformd
// in the ISO's platformd-bin/ directory and installed to /usr/bin with a
// /usr/sbin symlink — the same layout platformd uses, and the path the
// OpenRC script firstboot writes (/usr/sbin/gatewayd) expects.
const gatewaydBinaryName = "gatewayd"

// isoBinaryMounts are the mount points the installer searches for the
// ISO's platformd-bin/ directory.
var isoBinaryMounts = []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"}

// ErrGatewaydBinaryMissing is returned when a gateway-role installation
// finds no gatewayd on the ISO. A gateway node without its edge daemon is
// not a degraded gateway, it is a worker with the wrong configuration, so
// the install fails closed (#66) — the same rule the boot-critical
// binaries follow.
type ErrGatewaydBinaryMissing struct {
	Searched []string
}

// Error implements the error interface.
func (e *ErrGatewaydBinaryMissing) Error() string {
	return fmt.Sprintf("gatewayd is required by this node's gateway role and was not found under platformd-bin/ on %v; "+
		"build the ISO with gatewayd beside platformd (iso create copies it from the platformd binary's directory)", e.Searched)
}

// installGatewaydBinary installs gatewayd onto the target root for a
// gateway-role node (#66). It runs after the platformd binary is in place
// and before the UKI build, from the same platformd-bin/ ISO directory.
//
// required is the node's role: when the platform configuration enables
// the gateway role a missing binary is ErrGatewaydBinaryMissing; otherwise
// a present binary is still installed (a worker image that carries it
// loses nothing) and an absent one is skipped.
func (i *installer) installGatewaydBinary(ctx context.Context, mountPoint string, required bool) error {
	return installGatewaydBinaryFrom(ctx, i.logger, isoBinaryMounts, mountPoint, required)
}

// installGatewaydBinaryFrom is installGatewaydBinary with the ISO mounts
// injected, so the search, the copy, the symlink and the role decision are
// testable against a temporary tree.
func installGatewaydBinaryFrom(ctx context.Context, logger *logging.Logger, isoMounts []string, mountPoint string, required bool) error {
	var src string
	for _, isoMount := range isoMounts {
		candidate := filepath.Join(isoMount, "platformd-bin", gatewaydBinaryName)
		if _, err := os.Stat(candidate); err == nil {
			src = candidate
			break
		}
	}
	if src == "" {
		if required {
			return &ErrGatewaydBinaryMissing{Searched: isoMounts}
		}
		logger.Info("[GATEWAYD] gatewayd not on the ISO and this node is not a gateway; skipping")
		return nil
	}

	targetBinDir := filepath.Join(mountPoint, "usr", "bin")
	if err := os.MkdirAll(targetBinDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create /usr/bin directory for gatewayd", Err: err}
	}
	target := filepath.Join(targetBinDir, gatewaydBinaryName)
	if err := copyBinaryWithVerification(src, target); err != nil {
		return &WrappedError{Msg: "failed to install gatewayd binary", Err: err}
	}
	if err := syncFilesystem(ctx); err != nil {
		logger.Warn("[GATEWAYD] Failed to sync filesystem after gatewayd install", "error", err)
	}

	targetSbinDir := filepath.Join(mountPoint, "usr", "sbin")
	if err := os.MkdirAll(targetSbinDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create /usr/sbin directory for gatewayd", Err: err}
	}
	symlink := filepath.Join(targetSbinDir, gatewaydBinaryName)
	if err := os.Remove(symlink); err != nil && !os.IsNotExist(err) {
		return &WrappedError{Msg: "failed to replace /usr/sbin/gatewayd", Err: err}
	}
	if err := os.Symlink("/usr/bin/"+gatewaydBinaryName, symlink); err != nil {
		return &WrappedError{Msg: "failed to create /usr/sbin/gatewayd symlink", Err: err}
	}

	logger.Info("[GATEWAYD] Installed gatewayd binary",
		"source", src, "path", target, "symlink", symlink, "gateway_role", required)
	return nil
}

// gatewayRoleFromConfig reports whether the platform configuration the
// installer will seal into the target enables the gateway role. A missing
// or unparseable configuration is reported as an error by the caller's
// own config step; here it simply means "not a gateway", logged.
func (i *installer) gatewayRoleFromConfig() bool {
	configData, err := i.findPlatformConfig()
	if err != nil {
		i.logger.Info("[GATEWAYD] No platform config available for the role decision; treating the node as not a gateway", "error", err)
		return false
	}
	enabled, err := tpconfig.GatewayRoleEnabled(configData)
	if err != nil {
		i.logger.Warn("[GATEWAYD] Platform config unreadable for the role decision; treating the node as not a gateway", "error", err)
		return false
	}
	return enabled
}

// syncFilesystem flushes the target's writes so a power loss between the
// copy and the UKI build cannot leave a truncated daemon on disk.
func syncFilesystem(ctx context.Context) error {
	return exec.CommandContext(ctx, "sync").Run()
}
