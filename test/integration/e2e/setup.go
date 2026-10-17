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
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

// TestInfrastructure holds all infrastructure components for the test
type TestInfrastructure struct {
	Config *TestConfig
	Logger *logging.Logger

	// Network components
	OVSClient          *ovs.Client
	PolicyEngine       *policy.Engine
	ProvisioningBridge *ovs.Bridge
	ProductionBridge   *ovs.Bridge

	// Server components
	ServerVM      *qemu.VM
	ServerTPM     *swtpm.SWTPM
	ServerTapName string

	// Client components
	ClientVM      *qemu.VM
	ClientTPM     *swtpm.SWTPM
	ClientTapName string
}

// SetupTestInfrastructure creates and configures all test infrastructure
func SetupTestInfrastructure(ctx context.Context, t *testing.T, config *TestConfig) (*TestInfrastructure, error) {
	t.Helper()

	logger := createTestLogger(t)
	logger.Info("Setting up test infrastructure",
		"provisioning_vlan", config.ProvisioningNetwork.VLAN,
		"production_vlan", config.ProductionNetwork.VLAN)

	infra := &TestInfrastructure{
		Config: config,
		Logger: logger,
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create work directories
	for _, dir := range []string{config.WorkDir, config.ServerWorkDir, config.ClientWorkDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Setup OVS client
	ovsClient, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	if err != nil {
		return nil, fmt.Errorf("failed to create OVS client: %w", err)
	}

	// Connect to OVS
	if err := ovsClient.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to OVS: %w", err)
	}

	infra.OVSClient = ovsClient

	// Setup network bridges
	if err := infra.setupNetworkBridges(ctx); err != nil {
		return nil, fmt.Errorf("failed to setup network bridges: %w", err)
	}

	// The policy engine drives the real OVS flow controller, built the way
	// the daemon builds it (pkg/daemon/commands/quarantine_init.go): one
	// controller serves as both the flow and the port controller.
	flowController, err := policy.NewOVSFlowController(ovsClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create OVS flow controller: %w", err)
	}

	policyEngine, err := policy.NewEngine(policy.Config{
		BridgeName:     config.ProvisioningNetwork.Bridge,
		FlowController: flowController,
		PortController: flowController,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create policy engine: %w", err)
	}
	infra.PolicyEngine = policyEngine

	logger.Info("Test infrastructure setup complete")
	return infra, nil
}

// setupNetworkBridges creates and configures OVS bridges for both VLANs
func (i *TestInfrastructure) setupNetworkBridges(ctx context.Context) error {
	i.Logger.Info("Setting up OVS bridges",
		"provisioning", i.Config.ProvisioningNetwork.Bridge,
		"production", i.Config.ProductionNetwork.Bridge)

	// Create provisioning bridge
	provBridge, err := i.OVSClient.CreateBridge(ctx, i.Config.ProvisioningNetwork.Bridge)
	if err != nil {
		// Bridge might already exist
		provBridge, err = i.OVSClient.GetBridge(ctx, i.Config.ProvisioningNetwork.Bridge)
		if err != nil {
			return fmt.Errorf("failed to get/create provisioning bridge: %w", err)
		}
	}
	i.ProvisioningBridge = provBridge

	// Create production bridge
	prodBridge, err := i.OVSClient.CreateBridge(ctx, i.Config.ProductionNetwork.Bridge)
	if err != nil {
		// Bridge might already exist
		prodBridge, err = i.OVSClient.GetBridge(ctx, i.Config.ProductionNetwork.Bridge)
		if err != nil {
			return fmt.Errorf("failed to get/create production bridge: %w", err)
		}
	}
	i.ProductionBridge = prodBridge

	// Configure bridge IP addresses and bring them up
	if err := i.configureBridgeNetwork(i.Config.ProvisioningNetwork); err != nil {
		return fmt.Errorf("failed to configure provisioning bridge: %w", err)
	}

	if err := i.configureBridgeNetwork(i.Config.ProductionNetwork); err != nil {
		return fmt.Errorf("failed to configure production bridge: %w", err)
	}

	i.Logger.Info("OVS bridges configured successfully")
	return nil
}

// configureBridgeNetwork configures IP address and brings up a bridge
func (i *TestInfrastructure) configureBridgeNetwork(netConfig NetworkConfig) error {
	// Set IP address on bridge
	cmd := exec.Command("ip", "addr", "add", netConfig.Gateway+"/24", "dev", netConfig.Bridge)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Ignore error if address already exists
		if !contains(string(output), "File exists") {
			return fmt.Errorf("failed to set IP on bridge %s: %w: %s", netConfig.Bridge, err, string(output))
		}
	}

	// Bring bridge up
	cmd = exec.Command("ip", "link", "set", "dev", netConfig.Bridge, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring up bridge %s: %w: %s", netConfig.Bridge, err, string(output))
	}

	i.Logger.Info("Bridge network configured",
		"bridge", netConfig.Bridge,
		"ip", netConfig.Gateway+"/24")

	return nil
}

// SetupServerVM creates and configures the server VM with TPM
func (i *TestInfrastructure) SetupServerVM(ctx context.Context, t *testing.T) error {
	t.Helper()

	i.Logger.Info("Setting up server VM")

	// Create TAP interface for server on provisioning network
	tapName := "tap-server"
	if err := i.createTAPInterface(tapName); err != nil {
		return fmt.Errorf("failed to configure server TAP: %w", err)
	}
	i.ServerTapName = tapName

	if _, err := i.OVSClient.AddPort(ctx, i.Config.ProvisioningNetwork.Bridge, tapName); err != nil {
		return fmt.Errorf("failed to create server TAP: %w", err)
	}

	// Setup server TPM
	tpmStateDir := filepath.Join(i.Config.ServerWorkDir, "tpm")
	tpmSocketPath := filepath.Join(tpmStateDir, "swtpm.sock")

	if err := os.MkdirAll(tpmStateDir, 0755); err != nil {
		return fmt.Errorf("failed to create TPM state directory: %w", err)
	}

	tpmConfig := &swtpm.Config{
		StateDir:   tpmStateDir,
		SocketPath: tpmSocketPath,
		PCRBanks:   []string{"sha256"},
	}

	serverTPM, err := swtpm.NewSWTPM(tpmConfig, i.Logger)
	if err != nil {
		return fmt.Errorf("failed to create server TPM: %w", err)
	}

	if err := serverTPM.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize server TPM: %w", err)
	}

	if err := serverTPM.Start(ctx); err != nil {
		return fmt.Errorf("failed to start server TPM: %w", err)
	}

	i.ServerTPM = serverTPM
	i.Logger.Info("Server TPM started", "socket", tpmSocketPath)

	// Wait for TPM socket
	if err := waitForSocket(t, tpmSocketPath, 30*time.Second); err != nil {
		return fmt.Errorf("server TPM socket not ready: %w", err)
	}

	// Create server QEMU config
	qemuConfig := i.createServerQEMUConfig(tapName, tpmSocketPath)

	// Create disk image
	serverVM, err := qemu.NewVM(qemuConfig, i.Logger)
	if err != nil {
		return fmt.Errorf("failed to create server VM: %w", err)
	}

	if err := serverVM.CreateDisk(); err != nil {
		return fmt.Errorf("failed to create server disk: %w", err)
	}

	i.ServerVM = serverVM
	i.Logger.Info("Server VM configured successfully")

	return nil
}

// SetupClientVM creates and configures the client VM with TPM
func (i *TestInfrastructure) SetupClientVM(ctx context.Context, t *testing.T) error {
	t.Helper()

	i.Logger.Info("Setting up client VM")

	// Create TAP interface for client on provisioning network
	tapName := "tap-client"
	if err := i.createTAPInterface(tapName); err != nil {
		return fmt.Errorf("failed to configure client TAP: %w", err)
	}
	i.ClientTapName = tapName

	if _, err := i.OVSClient.AddPort(ctx, i.Config.ProvisioningNetwork.Bridge, tapName); err != nil {
		return fmt.Errorf("failed to create client TAP: %w", err)
	}

	// Setup client TPM
	tpmStateDir := filepath.Join(i.Config.ClientWorkDir, "tpm")
	tpmSocketPath := filepath.Join(tpmStateDir, "swtpm.sock")

	if err := os.MkdirAll(tpmStateDir, 0755); err != nil {
		return fmt.Errorf("failed to create TPM state directory: %w", err)
	}

	tpmConfig := &swtpm.Config{
		StateDir:   tpmStateDir,
		SocketPath: tpmSocketPath,
		PCRBanks:   []string{"sha256"},
	}

	clientTPM, err := swtpm.NewSWTPM(tpmConfig, i.Logger)
	if err != nil {
		return fmt.Errorf("failed to create client TPM: %w", err)
	}

	if err := clientTPM.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize client TPM: %w", err)
	}

	if err := clientTPM.Start(ctx); err != nil {
		return fmt.Errorf("failed to start client TPM: %w", err)
	}

	i.ClientTPM = clientTPM
	i.Logger.Info("Client TPM started", "socket", tpmSocketPath)

	// Wait for TPM socket
	if err := waitForSocket(t, tpmSocketPath, 30*time.Second); err != nil {
		return fmt.Errorf("client TPM socket not ready: %w", err)
	}

	// Create client QEMU config
	qemuConfig := i.createClientQEMUConfig(tapName, tpmSocketPath)

	// Create disk image
	clientVM, err := qemu.NewVM(qemuConfig, i.Logger)
	if err != nil {
		return fmt.Errorf("failed to create client VM: %w", err)
	}

	if err := clientVM.CreateDisk(); err != nil {
		return fmt.Errorf("failed to create client disk: %w", err)
	}

	i.ClientVM = clientVM
	i.Logger.Info("Client VM configured successfully")

	return nil
}

// createServerQEMUConfig creates QEMU configuration for the server
func (i *TestInfrastructure) createServerQEMUConfig(tapName, tpmSocket string) *qemu.Config {
	config := &qemu.Config{
		WorkDir:       i.Config.ServerWorkDir,
		DiskPath:      i.Config.ServerDiskPath,
		DiskSize:      i.Config.DiskSize,
		Memory:        i.Config.MemoryMB,
		CPUs:          i.Config.CPUCores,
		EnableKVM:     checkKVMAvailable(),
		OVMFCode:      findOVMFCode(),
		OVMFVars:      findOVMFVars(),
		TPMSocket:     tpmSocket,
		NoGraphic:     true,
		SerialLogFile: filepath.Join(i.Config.ServerWorkDir, "serial.log"),
		NetworkMode:   "tap",
		TapDevice:     tapName,
	}

	// Add ISO if configured for install mode
	if i.Config.ServerISO != "" {
		config.ISO = i.Config.ServerISO
		config.BootOrder = "d" // Boot from CD-ROM
	}

	return config
}

// createClientQEMUConfig creates QEMU configuration for the client
func (i *TestInfrastructure) createClientQEMUConfig(tapName, tpmSocket string) *qemu.Config {
	config := &qemu.Config{
		WorkDir:       i.Config.ClientWorkDir,
		DiskPath:      i.Config.ClientDiskPath,
		DiskSize:      i.Config.DiskSize,
		Memory:        i.Config.MemoryMB,
		CPUs:          i.Config.CPUCores,
		EnableKVM:     checkKVMAvailable(),
		OVMFCode:      findOVMFCode(),
		OVMFVars:      findOVMFVars(),
		TPMSocket:     tpmSocket,
		NoGraphic:     true,
		SerialLogFile: filepath.Join(i.Config.ClientWorkDir, "serial.log"),
		NetworkMode:   "tap",
		TapDevice:     tapName,
	}

	// Add ISO if configured for install mode
	if i.Config.ClientISO != "" {
		config.ISO = i.Config.ClientISO
		config.BootOrder = "d" // Boot from CD-ROM
	}

	return config
}

// createTAPInterface creates a persistent TAP device and brings it up
func (i *TestInfrastructure) createTAPInterface(tapName string) error {
	// OVS creates kernel devices only for internal ports, so a TAP port
	// added to the bridge has no device until one is created here. QEMU
	// attaches to it by name (ifname=, script=no).
	if _, err := net.InterfaceByName(tapName); err == nil {
		// A run that died before cleanup left the device behind.
		if err := runIP("link", "delete", "dev", tapName); err != nil {
			return fmt.Errorf("failed to remove stale TAP %s: %w", tapName, err)
		}
	}
	if err := runIP("tuntap", "add", "dev", tapName, "mode", "tap"); err != nil {
		return fmt.Errorf("failed to create TAP %s: %w", tapName, err)
	}
	if err := runIP("link", "set", "dev", tapName, "up"); err != nil {
		return fmt.Errorf("failed to bring up TAP %s: %w", tapName, err)
	}

	i.Logger.Info("TAP interface created", "name", tapName)
	return nil
}

// runIP runs ip(8) with args and folds its output into the error.
func runIP(args ...string) error {
	if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ip %v: %w: %s", args, err, string(output))
	}
	return nil
}

// Helper functions

func createTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	return logging.DefaultLogger()
}

func waitForSocket(t *testing.T, socketPath string, timeout time.Duration) error {
	t.Helper()

	exists := func() bool {
		_, err := os.Stat(socketPath)
		return err == nil
	}
	return testenv.WaitUntil(t.Context(), timeout, "socket "+socketPath+" created", exists)
}

func checkKVMAvailable() bool {
	_, err := os.Stat("/dev/kvm")
	return err == nil
}

func findOVMFCode() string {
	paths := []string{
		"/usr/share/OVMF/OVMF_CODE.fd",
		"/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
		"/usr/share/edk2/ovmf/OVMF_CODE.fd",
		"/usr/share/qemu/OVMF_CODE.fd",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func findOVMFVars() string {
	paths := []string{
		"/usr/share/OVMF/OVMF_VARS.fd",
		"/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
		"/usr/share/edk2/ovmf/OVMF_VARS.fd",
		"/usr/share/qemu/OVMF_VARS.fd",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(s == substr || len(s) >= len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
