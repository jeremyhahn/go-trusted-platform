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

//go:build integration
// +build integration

// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

// vmExitTimeout bounds the wait for a stopped VM's process to exit.
const vmExitTimeout = 10 * time.Second

// Cleanup handles cleanup of all test infrastructure
func Cleanup(t *testing.T, infra *TestInfrastructure) {
	t.Helper()

	if infra == nil {
		return
	}

	logger := infra.Logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	logger.Info("Starting test infrastructure cleanup")

	// Stop VMs first
	cleanupVM(t, logger, "server", infra.ServerVM, infra.ServerTPM)
	cleanupVM(t, logger, "client", infra.ClientVM, infra.ClientTPM)

	// Remove TAP interfaces (they are attached to bridges, so remove from bridges first)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if infra.OVSClient != nil && infra.ServerTapName != "" {
		cleanupPortFromBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProvisioningNetwork.Bridge, infra.ServerTapName)
	}
	if infra.OVSClient != nil && infra.ClientTapName != "" {
		cleanupPortFromBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProvisioningNetwork.Bridge, infra.ClientTapName)
		// Client might also be on production bridge
		cleanupPortFromBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProductionNetwork.Bridge, infra.ClientTapName)
	}
	cleanupTAP(t, logger, infra.ServerTapName)
	cleanupTAP(t, logger, infra.ClientTapName)

	// Remove OVS bridges
	if infra.OVSClient != nil {
		cleanupBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProvisioningNetwork.Bridge)
		cleanupBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProductionNetwork.Bridge)
	}

	// Clean up work directories (optional - comment out to preserve artifacts)
	// cleanupWorkDir(t, logger, infra.Config.WorkDir)

	logger.Info("Test infrastructure cleanup complete")
}

// cleanupVM stops and cleans up a VM and its TPM
func cleanupVM(t *testing.T, logger *logging.Logger, name string, vm *qemu.VM, tpm *swtpm.SWTPM) {
	t.Helper()

	// The parameters are concrete pointer types so a VM or TPM that setup
	// never created is a real nil here. Passed as interface{}, a nil *qemu.VM
	// was a non-nil interface and IsRunning dereferenced it.
	// Setup can fail between starting the TPM and building the VM, so each
	// is checked on its own: a nil VM must not leave its TPM running.
	if vm != nil {
		logger.Info("Cleaning up VM", "name", name)

		if vm.IsRunning() {
			if err := vm.Stop(); err != nil {
				logger.Warn("Failed to stop VM", "name", name, "error", err)
			} else {
				logger.Info("VM stopped", "name", name)
			}
		}

		// Stop signals the VM; Wait reaps it once the process has exited
		if err := testenv.WaitFor(context.Background(), vmExitTimeout, "VM "+name+" process exit", vm.Wait); err != nil {
			logger.Debug("VM exit", "name", name, "error", err)
		}
	}

	if tpm != nil {
		if err := tpm.Stop(); err != nil {
			logger.Warn("Failed to stop TPM", "name", name, "error", err)
		} else {
			logger.Info("TPM stopped", "name", name)
		}
	}
}

// cleanupPortFromBridge removes a port from an OVS bridge
func cleanupPortFromBridge(t *testing.T, logger *logging.Logger, ctx context.Context, ovsClient interface{}, bridgeName, portName string) {
	t.Helper()

	if portName == "" || bridgeName == "" {
		return
	}

	logger.Info("Removing port from bridge", "port", portName, "bridge", bridgeName)

	type PortDeleter interface {
		DeletePort(ctx context.Context, bridgeName, portName string) error
	}

	if client, ok := ovsClient.(PortDeleter); ok {
		if err := client.DeletePort(ctx, bridgeName, portName); err != nil {
			logger.Debug("Failed to remove port from bridge (might not exist)",
				"port", portName,
				"bridge", bridgeName,
				"error", err)
		} else {
			logger.Info("Port removed from bridge", "port", portName, "bridge", bridgeName)
		}
	}
}

// cleanupBridge removes an OVS bridge
func cleanupBridge(t *testing.T, logger *logging.Logger, ctx context.Context, ovsClient interface{}, bridgeName string) {
	t.Helper()

	if bridgeName == "" || ovsClient == nil {
		return
	}

	logger.Info("Cleaning up OVS bridge", "name", bridgeName)

	type BridgeDeleter interface {
		DeleteBridge(ctx context.Context, name string) error
	}

	if client, ok := ovsClient.(BridgeDeleter); ok {
		if err := client.DeleteBridge(ctx, bridgeName); err != nil {
			logger.Warn("Failed to delete OVS bridge",
				"name", bridgeName,
				"error", err)
		} else {
			logger.Info("OVS bridge removed", "name", bridgeName)
		}
	}

	// Also try to remove with ovs-vsctl directly
	cmd := exec.Command("ovs-vsctl", "del-br", bridgeName)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Ignore "no such bridge" errors
		if !contains(string(output), "no bridge named") {
			logger.Debug("ovs-vsctl del-br output",
				"bridge", bridgeName,
				"output", string(output))
		}
	}
}

// cleanupTAP deletes a TAP device SetupServerVM or SetupClientVM created.
// Removing its OVS port does not remove the persistent kernel device.
func cleanupTAP(t *testing.T, logger *logging.Logger, tapName string) {
	t.Helper()

	if tapName == "" {
		return
	}

	if err := runIP("link", "delete", "dev", tapName); err != nil {
		logger.Warn("Failed to delete TAP device", "name", tapName, "error", err)
		return
	}
	logger.Info("TAP device removed", "name", tapName)
}

// cleanupWorkDir removes the work directory and all its contents
func cleanupWorkDir(t *testing.T, logger *logging.Logger, workDir string) {
	t.Helper()

	if workDir == "" {
		return
	}

	logger.Info("Cleaning up work directory", "path", workDir)

	if err := os.RemoveAll(workDir); err != nil {
		logger.Warn("Failed to remove work directory",
			"path", workDir,
			"error", err)
	} else {
		logger.Info("Work directory removed", "path", workDir)
	}
}

// CleanupOnFailure performs cleanup when a test fails
func CleanupOnFailure(t *testing.T, infra *TestInfrastructure) {
	t.Helper()

	if !t.Failed() {
		return
	}

	if infra == nil || infra.Logger == nil {
		return
	}

	logger := infra.Logger
	logger.Warn("Test failed - preserving artifacts for debugging")

	// Log locations of artifacts
	if infra.Config != nil {
		logger.Info("Test artifacts preserved",
			"work_dir", infra.Config.WorkDir,
			"server_work", infra.Config.ServerWorkDir,
			"client_work", infra.Config.ClientWorkDir,
			"server_disk", infra.Config.ServerDiskPath,
			"client_disk", infra.Config.ClientDiskPath)

		// Log serial console output paths
		serverSerial := infra.Config.ServerWorkDir + "/serial.log"
		clientSerial := infra.Config.ClientWorkDir + "/serial.log"

		logger.Info("Check serial console logs for debugging",
			"server_serial", serverSerial,
			"client_serial", clientSerial)
	}

	// Still clean up VMs and network to avoid resource leaks
	logger.Info("Cleaning up VMs and network (preserving disk images)")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cleanupVM(t, logger, "server", infra.ServerVM, infra.ServerTPM)
	cleanupVM(t, logger, "client", infra.ClientVM, infra.ClientTPM)

	if infra.OVSClient != nil {
		if infra.ServerTapName != "" {
			cleanupPortFromBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProvisioningNetwork.Bridge, infra.ServerTapName)
		}
		if infra.ClientTapName != "" {
			cleanupPortFromBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProvisioningNetwork.Bridge, infra.ClientTapName)
			cleanupPortFromBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProductionNetwork.Bridge, infra.ClientTapName)
		}
		cleanupBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProvisioningNetwork.Bridge)
		cleanupBridge(t, logger, ctx, infra.OVSClient, infra.Config.ProductionNetwork.Bridge)
	}
	cleanupTAP(t, logger, infra.ServerTapName)
	cleanupTAP(t, logger, infra.ClientTapName)
}
