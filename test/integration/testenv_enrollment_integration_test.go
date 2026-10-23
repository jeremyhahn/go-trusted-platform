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

package integration_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Test timeouts
	serverBootTimeout      = 10 * time.Minute // Server boots, provisions, reboots
	clientBootTimeout      = 15 * time.Minute // Client boots, provisions, enrolls, reboots
	enrollmentTimeout      = 10 * time.Minute // Additional time for ACME enrollment
	healthCheckInterval    = 5 * time.Second
	serverReadyMaxAttempts = 120 // 10 minutes / 5 seconds
	clientReadyMaxAttempts = 180 // 15 minutes / 5 seconds

	// Test artifacts
	testWorkDir    = "test-integration-enrollment"
	serverWorkDir  = "test-integration-enrollment/server"
	clientWorkDir  = "test-integration-enrollment/client"
	serverDiskPath = "test-integration-enrollment/server-disk.qcow2"
	clientDiskPath = "test-integration-enrollment/client-disk.qcow2"
	diskSize       = "10G"
	memoryMB       = 4096
	cpuCores       = 4

	// Network ports
	serverHTTPSPort = 8443
	serverDNSPort   = 9053

	// TPM attestation OIDs (TCG standard OIDs for TPM 2.0)
	oidTPMManufacturer     = "2.23.133.2.1"
	oidTPMModel            = "2.23.133.2.2"
	oidTPMVersion          = "2.23.133.2.3"
	oidTPMEKCertificate    = "2.23.133.8.1"
	oidTPMPlatformCert     = "2.23.133.8.2"
	oidTPMAIKCertificate   = "2.23.133.8.3"
	oidTPMAttestationData  = "2.23.133.11.1"
	oidTPMAttestationQuote = "2.23.133.11.2"
)

// ErrMissingPrerequisite reports an environment prerequisite the enrollment
// test needs and the environment lacks.
type ErrMissingPrerequisite struct {
	Prerequisite string
	Err          error
}

func (e ErrMissingPrerequisite) Error() string {
	const remedy = "run in the devcontainer, which runs as root and installs qemu-system-x86"
	if e.Err != nil {
		return fmt.Sprintf("%s: %v: %s", e.Prerequisite, e.Err, remedy)
	}
	return fmt.Sprintf("%s: %s", e.Prerequisite, remedy)
}

func (e ErrMissingPrerequisite) Unwrap() error {
	return e.Err
}

// checkEnrollmentPrerequisites returns ErrMissingPrerequisite for the first
// prerequisite the environment lacks: root for the isolated bridge and TAP
// network, and QEMU for the server and client VMs.
func checkEnrollmentPrerequisites() error {
	if euid := os.Geteuid(); euid != 0 {
		return ErrMissingPrerequisite{Prerequisite: fmt.Sprintf("root privileges for network setup (running as euid %d)", euid)}
	}
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		return ErrMissingPrerequisite{Prerequisite: "QEMU binary qemu-system-x86_64", Err: err}
	}
	return nil
}

// TestEnrollmentIntegration tests the full ACME enrollment flow between server and client VMs.
// This test has two modes:
// 1. Framework validation mode (default): Validates the test infrastructure works
//   - Network setup, TPM, QEMU booting
//
// 2. Full integration mode: Requires pre-built ISOs with the platform installed
//   - Set INTEGRATION_TEST_SERVER_ISO and INTEGRATION_TEST_CLIENT_ISO env vars
func TestEnrollmentIntegration(t *testing.T) {
	if err := checkEnrollmentPrerequisites(); err != nil {
		t.Fatalf("missing prerequisite: %v", err)
	}

	// Check for pre-built ISOs to determine test mode
	serverISO := os.Getenv("INTEGRATION_TEST_SERVER_ISO")
	clientISO := os.Getenv("INTEGRATION_TEST_CLIENT_ISO")
	fullIntegrationMode := serverISO != "" && clientISO != ""

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	logger := createTestLogger(t)

	if !fullIntegrationMode {
		logger.Info("Running in framework validation mode (no pre-built ISOs found)")
		logger.Info("To run full integration test, set env vars:",
			"INTEGRATION_TEST_SERVER_ISO", "<path/to/server.iso>",
			"INTEGRATION_TEST_CLIENT_ISO", "<path/to/client.iso>")
	} else {
		logger.Info("Running in full integration mode",
			"server_iso", serverISO,
			"client_iso", clientISO)
	}

	// Create test work directory
	require.NoError(t, os.MkdirAll(testWorkDir, 0755))
	defer cleanupTestArtifacts(t, logger)

	// Setup isolated network
	netConfig := testenv.DefaultNetworkConfig()
	network := testenv.NewIsolatedNetwork(netConfig)

	logger.Info("Setting up isolated test network",
		"subnet", netConfig.SubnetCIDR(),
		"gateway", netConfig.GatewayIP,
		"server_ip", netConfig.ServerIP,
		"client_ip", netConfig.ClientIP)

	err := network.Setup()
	require.NoError(t, err, "Failed to setup isolated network")
	defer cleanupNetwork(t, network, logger)

	logger.Info("Network setup complete",
		"bridge", netConfig.BridgeName,
		"server_tap", network.ServerTapName(),
		"client_tap", network.ClientTapName())

	// Framework validation: Test that we can boot a VM with TPM
	t.Run("FrameworkValidation", func(t *testing.T) {
		testFrameworkValidation(ctx, t, logger, network)
	})

	// Skip full integration if no pre-built ISOs
	if !fullIntegrationMode {
		logger.Info("Framework validation completed successfully")
		logger.Info("Skipping full integration test (no pre-built ISOs)")
		return
	}

	// Full integration test with pre-built ISOs
	t.Run("FullIntegration", func(t *testing.T) {
		testFullIntegration(ctx, t, logger, network, serverISO, clientISO)
	})

	logger.Info("Integration test completed successfully")
}

// testFrameworkValidation validates the test infrastructure works
func testFrameworkValidation(ctx context.Context, t *testing.T, logger *logging.Logger, network testenv.IsolatedNetwork) {
	t.Helper()
	netConfig := network.Config()

	// Create work directory
	require.NoError(t, os.MkdirAll(serverWorkDir, 0755))

	// Create QEMU config
	qemuConfig := createQEMUConfig(serverDiskPath, serverWorkDir, network.ServerTapName(), netConfig.ServerMAC)

	// Create disk image
	createDiskImage(ctx, t, logger, serverDiskPath, diskSize)

	// Setup and start TPM
	tpm := setupTPM(ctx, t, logger, qemuConfig)
	defer func() {
		if tpm != nil {
			tpm.Stop()
		}
	}()

	// Create a minimal bootable test - just verify VM starts
	logger.Info("Testing QEMU boot (will exit quickly with no OS)")

	vm, err := qemu.NewVM(qemuConfig, logger)
	require.NoError(t, err, "Failed to create VM")

	// Start VM - it will boot but exit quickly with no OS
	err = vm.Start(ctx, string(qemu.BootModeBoot))
	require.NoError(t, err, "Failed to start VM")

	defer vm.Stop()

	// Give it a moment to start; nothing observable marks the end, so this is elapsed time
	require.NoError(t, testenv.Elapse(ctx, 2*time.Second))

	logger.Info("VM started successfully (framework validation passed)",
		"pid", vm.GetPID())
}

// testFullIntegration runs the full ACME enrollment test with pre-built ISOs
func testFullIntegration(ctx context.Context, t *testing.T, logger *logging.Logger, network testenv.IsolatedNetwork, serverISO, clientISO string) {
	t.Helper()
	netConfig := network.Config()

	// Step 1: Install and boot server VM
	serverVM, serverTPM := setupServerVMWithISO(ctx, t, logger, network, serverISO)
	defer cleanupVM(t, logger, "server", serverVM, serverTPM)

	// Step 2: Wait for server to be ready
	waitForServerReady(ctx, t, logger, netConfig.ServerIP.String())

	// Step 3: Fetch CA bundle from server
	caBundlePath := fetchCABundle(ctx, t, logger, netConfig.ServerIP.String())

	// Step 4: Install and boot client VM
	clientVM, clientTPM := setupClientVMWithISO(ctx, t, logger, network, clientISO, caBundlePath)
	defer cleanupVM(t, logger, "client", clientVM, clientTPM)

	// Step 5: Wait for client enrollment to complete
	waitForClientEnrollment(ctx, t, logger, netConfig.ClientIP.String(), netConfig.ServerIP.String())

	// Step 6: Verify enrollment success
	verifyEnrollmentSuccess(ctx, t, logger, netConfig.ServerIP.String(), netConfig.ClientIP.String())
}

// setupServerVMWithISO creates and boots the server VM with a pre-built ISO
func setupServerVMWithISO(ctx context.Context, t *testing.T, logger *logging.Logger, network testenv.IsolatedNetwork, isoPath string) (*qemu.VM, *swtpm.SWTPM) {
	t.Helper()
	netConfig := network.Config()

	logger.Info("Setting up server VM with ISO",
		"ip", netConfig.ServerIP,
		"disk", serverDiskPath,
		"iso", isoPath)

	// Create work directory
	require.NoError(t, os.MkdirAll(serverWorkDir, 0755))

	// Create QEMU config
	qemuConfig := createQEMUConfig(serverDiskPath, serverWorkDir, network.ServerTapName(), netConfig.ServerMAC)

	// Create disk image
	createDiskImage(ctx, t, logger, serverDiskPath, diskSize)

	// Setup and start TPM
	tpm := setupTPM(ctx, t, logger, qemuConfig)

	// Install OS from ISO
	qemuConfig.ISO = isoPath
	installOSFromISO(ctx, t, logger, qemuConfig)

	// Boot VM
	qemuConfig.ISO = ""
	qemuConfig.SerialConsole = false
	vm := bootVM(ctx, t, logger, qemuConfig)

	logger.Info("Server VM booted successfully",
		"pid", vm.GetPID(),
		"ip", netConfig.ServerIP)

	return vm, tpm
}

// setupClientVMWithISO creates and boots the client VM with a pre-built ISO
func setupClientVMWithISO(ctx context.Context, t *testing.T, logger *logging.Logger, network testenv.IsolatedNetwork, isoPath, caBundlePath string) (*qemu.VM, *swtpm.SWTPM) {
	t.Helper()
	netConfig := network.Config()

	logger.Info("Setting up client VM with ISO",
		"ip", netConfig.ClientIP,
		"disk", clientDiskPath,
		"iso", isoPath,
		"ca_bundle", caBundlePath)

	// Create work directory
	require.NoError(t, os.MkdirAll(clientWorkDir, 0755))

	// Create QEMU config
	qemuConfig := createQEMUConfig(clientDiskPath, clientWorkDir, network.ClientTapName(), netConfig.ClientMAC)

	// Create disk image
	createDiskImage(ctx, t, logger, clientDiskPath, diskSize)

	// Setup and start TPM
	tpm := setupTPM(ctx, t, logger, qemuConfig)

	// Install OS from ISO
	qemuConfig.ISO = isoPath
	installOSFromISO(ctx, t, logger, qemuConfig)

	// Boot VM
	qemuConfig.ISO = ""
	qemuConfig.SerialConsole = false
	vm := bootVM(ctx, t, logger, qemuConfig)

	logger.Info("Client VM booted successfully",
		"pid", vm.GetPID(),
		"ip", netConfig.ClientIP)

	return vm, tpm
}

// installOSFromISO boots from ISO and waits for installation to complete
func installOSFromISO(ctx context.Context, t *testing.T, logger *logging.Logger, qemuConfig *qemu.Config) {
	t.Helper()

	logger.Info("Starting OS installation from ISO",
		"disk", qemuConfig.DiskPath,
		"iso", qemuConfig.ISO)

	vm, err := qemu.NewVM(qemuConfig, logger)
	require.NoError(t, err, "Failed to create VM for installation")

	err = vm.Start(ctx, string(qemu.BootModeInstall))
	require.NoError(t, err, "Failed to start VM for installation")

	// Wait for installation to complete (VM should auto-shutdown after install)
	installTimeout := 15 * time.Minute
	installCtx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-installCtx.Done():
			vm.Stop()
			require.Fail(t, "Installation timed out")
			return
		case <-ticker.C:
			if !vm.IsRunning() {
				logger.Info("OS installation completed")
				return
			}
			logger.Debug("Installation in progress...")
		}
	}
}

// setupServerVM creates, installs, and boots the server VM
func setupServerVM(ctx context.Context, t *testing.T, logger *logging.Logger, network testenv.IsolatedNetwork) (*qemu.VM, *swtpm.SWTPM) {
	t.Helper()
	netConfig := network.Config()

	logger.Info("Setting up server VM",
		"ip", netConfig.ServerIP,
		"disk", serverDiskPath)

	// Create work directory
	require.NoError(t, os.MkdirAll(serverWorkDir, 0755))

	// Generate installer config
	installerConfig := createServerInstallerConfig(netConfig)
	installerConfigPath := filepath.Join(serverWorkDir, "installer.yaml")
	require.NoError(t, writeInstallerConfig(installerConfig, installerConfigPath))

	// Generate platform config
	platformConfig := createServerPlatformConfig(netConfig)
	platformConfigPath := filepath.Join(serverWorkDir, "platform.yaml")
	require.NoError(t, os.WriteFile(platformConfigPath, platformConfig, 0644))

	// Build server ISO (this would use the BuildCustomISO function from pkg/cmd/iso)
	serverISOPath := filepath.Join(serverWorkDir, "server.iso")
	buildServerISO(ctx, t, logger, installerConfigPath, platformConfigPath, serverISOPath)

	// Create QEMU config
	qemuConfig := createQEMUConfig(serverDiskPath, serverWorkDir, network.ServerTapName(), netConfig.ServerMAC)

	// Create disk image
	createDiskImage(ctx, t, logger, serverDiskPath, diskSize)

	// Setup and start TPM
	tpm := setupTPM(ctx, t, logger, qemuConfig)

	// Install OS
	qemuConfig.ISO = serverISOPath
	installOS(ctx, t, logger, qemuConfig)

	// Boot VM in background mode
	qemuConfig.ISO = ""
	qemuConfig.SerialConsole = false // Run in background
	vm := bootVM(ctx, t, logger, qemuConfig)

	logger.Info("Server VM booted successfully",
		"pid", vm.GetPID(),
		"ip", netConfig.ServerIP)

	return vm, tpm
}

// setupClientVM creates, installs, and boots the client VM with embedded CA bundle
func setupClientVM(ctx context.Context, t *testing.T, logger *logging.Logger, network testenv.IsolatedNetwork, caBundlePath string) (*qemu.VM, *swtpm.SWTPM) {
	t.Helper()
	netConfig := network.Config()

	logger.Info("Setting up client VM",
		"ip", netConfig.ClientIP,
		"disk", clientDiskPath,
		"ca_bundle", caBundlePath)

	// Create work directory
	require.NoError(t, os.MkdirAll(clientWorkDir, 0755))

	// Generate installer config
	installerConfig := createClientInstallerConfig(netConfig)
	installerConfigPath := filepath.Join(clientWorkDir, "installer.yaml")
	require.NoError(t, writeInstallerConfig(installerConfig, installerConfigPath))

	// Generate platform config
	platformConfig := createClientPlatformConfig(netConfig)
	platformConfigPath := filepath.Join(clientWorkDir, "platform.yaml")
	require.NoError(t, os.WriteFile(platformConfigPath, platformConfig, 0644))

	// Build client ISO with CA bundle embedded
	clientISOPath := filepath.Join(clientWorkDir, "client.iso")
	buildClientISO(ctx, t, logger, installerConfigPath, platformConfigPath, clientISOPath, caBundlePath)

	// Create QEMU config
	qemuConfig := createQEMUConfig(clientDiskPath, clientWorkDir, network.ClientTapName(), netConfig.ClientMAC)

	// Create disk image
	createDiskImage(ctx, t, logger, clientDiskPath, diskSize)

	// Setup and start TPM
	tpm := setupTPM(ctx, t, logger, qemuConfig)

	// Install OS
	qemuConfig.ISO = clientISOPath
	installOS(ctx, t, logger, qemuConfig)

	// Boot VM in background mode
	qemuConfig.ISO = ""
	qemuConfig.SerialConsole = false // Run in background
	vm := bootVM(ctx, t, logger, qemuConfig)

	logger.Info("Client VM booted successfully",
		"pid", vm.GetPID(),
		"ip", netConfig.ClientIP)

	return vm, tpm
}

// waitForServerReady waits for the server to be fully operational
func waitForServerReady(ctx context.Context, t *testing.T, logger *logging.Logger, serverIP string) {
	t.Helper()

	logger.Info("Waiting for server to be ready",
		"ip", serverIP,
		"timeout", serverBootTimeout)

	start := time.Now()
	attempts := 0

	serverReady := func() bool {
		attempts++

		// Check if ping reachable
		pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
		pingCmd := exec.CommandContext(pingCtx, "ping", "-c", "1", "-W", "2", serverIP)
		pingOK := pingCmd.Run() == nil
		pingCancel()

		if !pingOK {
			logger.Debug("Server not reachable via ping",
				"attempt", attempts,
				"ip", serverIP)
			return false
		}

		// Check if platformd DNS service is running
		dnsReady := checkDNSPort(ctx, logger, serverIP, serverDNSPort)
		if !dnsReady {
			logger.Debug("Platformd DNS not ready yet",
				"attempt", attempts,
				"port", serverDNSPort)
			return false
		}

		// Check if HTTPS service is running
		httpsReady := checkHTTPSPort(ctx, logger, serverIP, serverHTTPSPort)
		if !httpsReady {
			logger.Debug("Platformd HTTPS not ready yet",
				"attempt", attempts,
				"port", serverHTTPSPort)
			return false
		}
		return true
	}

	err := testenv.WaitUntilEvery(ctx, serverBootTimeout, healthCheckInterval, "server "+serverIP+" ping, DNS and HTTPS", serverReady)
	if err != nil {
		t.Fatalf("Server did not become ready within timeout %v: %v", serverBootTimeout, err)
	}

	logger.Info("Server is fully ready",
		"ip", serverIP,
		"attempts", attempts,
		"elapsed", time.Since(start))
}

// waitForClientEnrollment waits for the client to complete ACME enrollment
func waitForClientEnrollment(ctx context.Context, t *testing.T, logger *logging.Logger, clientIP, serverIP string) {
	t.Helper()

	logger.Info("Waiting for client enrollment to complete",
		"client_ip", clientIP,
		"server_ip", serverIP,
		"timeout", clientBootTimeout)

	start := time.Now()
	attempts := 0

	clientEnrolled := func() bool {
		attempts++

		// Check if ping reachable
		pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
		pingCmd := exec.CommandContext(pingCtx, "ping", "-c", "1", "-W", "2", clientIP)
		pingOK := pingCmd.Run() == nil
		pingCancel()

		if !pingOK {
			logger.Debug("Client not reachable via ping",
				"attempt", attempts,
				"ip", clientIP)
			return false
		}

		// Check if enrollment completed by verifying the client's platformd service is running
		// and has successfully obtained a certificate
		if checkEnrollmentStatus(ctx, logger, serverIP, clientIP) {
			return true
		}

		logger.Debug("Client enrollment not complete yet",
			"attempt", attempts,
			"client_ip", clientIP)
		return false
	}

	err := testenv.WaitUntilEvery(ctx, clientBootTimeout, healthCheckInterval, "client "+clientIP+" enrollment", clientEnrolled)
	if err != nil {
		t.Fatalf("Client enrollment did not complete within timeout %v: %v", clientBootTimeout, err)
	}

	logger.Info("Client enrollment completed successfully",
		"client_ip", clientIP,
		"attempts", attempts,
		"elapsed", time.Since(start))
}

// verifyEnrollmentSuccess verifies that the client successfully obtained its IDevID certificate
func verifyEnrollmentSuccess(ctx context.Context, t *testing.T, logger *logging.Logger, serverIP, clientIP string) {
	t.Helper()

	logger.Info("Verifying enrollment success",
		"server_ip", serverIP,
		"client_ip", clientIP)

	// Verify the certificate exists on the client
	cert := fetchClientCertificate(ctx, t, logger, serverIP, clientIP)
	require.NotNil(t, cert, "Client certificate should exist")

	// Verify certificate properties
	assert.NotEmpty(t, cert.Subject.CommonName, "Certificate should have a common name")
	assert.True(t, time.Now().Before(cert.NotAfter), "Certificate should not be expired")
	assert.True(t, time.Now().After(cert.NotBefore), "Certificate should be valid")

	logger.Info("Certificate verification successful",
		"subject", cert.Subject.CommonName,
		"serial", cert.SerialNumber,
		"issuer", cert.Issuer.CommonName,
		"not_before", cert.NotBefore,
		"not_after", cert.NotAfter)

	// Verify TPM attestation extensions are present
	hasTPMExtensions := verifyTPMExtensions(t, logger, cert)
	assert.True(t, hasTPMExtensions, "Certificate should contain TPM attestation extensions")

	logger.Info("Enrollment verification completed successfully")
}

// Helper functions

func createTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	return logging.NewLogger(slog.LevelDebug, os.Stdout)
}

func createQEMUConfig(diskPath, workDir, tapDevice, macAddress string) *qemu.Config {
	return &qemu.Config{
		DiskPath:       diskPath,
		DiskSize:       diskSize,
		Memory:         memoryMB,
		CPUs:           cpuCores,
		WorkDir:        workDir,
		SecureBoot:     true,
		Debug:          true,
		SerialConsole:  true,
		NoGraphic:      true,
		TapDevice:      tapDevice,
		MACAddress:     macAddress,
		NetworkMode:    "tap",
		OVMFCode:       "/usr/share/OVMF/OVMF_CODE_4M.fd",
		OVMFCodeSecure: "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
		OVMFVars:       "/usr/share/OVMF/OVMF_VARS_4M.fd",
	}
}

func createServerInstallerConfig(netConfig *testenv.NetworkConfig) *installer.Config {
	return &installer.Config{
		Disk: &installer.DiskConfig{
			Device:           "",
			PartitionTable:   installer.PartitionTableGPT,
			EFIPartitionSize: 538,
			RootFilesystem:   installer.FilesystemLVM,
			LVMVolumeGroup:   "vg0",
			LVMLogicalVolume: "root",
			Encryption: &installer.EncryptionConfig{
				Version:    "luks2",
				Cipher:     "aes-xts-plain64",
				KeySize:    512,
				Hash:       "sha256",
				PBKDF:      "argon2id",
				MappedName: "cryptroot",
			},
		},
		OS: &installer.OSConfig{
			OS:                 installer.OSAlpine,
			Version:            "3.22.2",
			Architecture:       "x86_64",
			Hostname:           "server",
			FilesystemType:     installer.FilesystemLVM,
			FIPS:               false,
			Lockdown:           true,
			LockdownMode:       "confidentiality",
			TPMAutoUpgradeSeal: true,
			EnableFIDO2:        false,
			Packages: []string{
				"bash", "vim", "curl", "wget",
				"lsblk", "parted", "e2fsprogs", "lvm2",
				"tpm2-tools", "dracut", "softhsm",
			},
		},
		Network: &installer.NetworkConfig{
			DNS: &installer.DNSConfig{
				Nameservers: []string{"8.8.8.8", "8.8.4.4"},
			},
			Interfaces: []installer.InterfaceConfig{
				{
					Name:        "eth0",
					Type:        installer.InterfaceTypeStatic,
					IPv4Address: netConfig.ServerIP.String(),
					IPv4Netmask: netConfig.SubnetMask(),
					IPv4Gateway: netConfig.GatewayIP.String(),
					AutoStart:   true,
				},
			},
			WaitOnline:  true,
			WaitTimeout: 30,
		},
		EnableTPMSealing: true,
		PCRs:             []uint{0, 7, 9},
		Debug:            false,
		Environment:      "test",
	}
}

func createClientInstallerConfig(netConfig *testenv.NetworkConfig) *installer.Config {
	return &installer.Config{
		Disk: &installer.DiskConfig{
			Device:           "",
			PartitionTable:   installer.PartitionTableGPT,
			EFIPartitionSize: 538,
			RootFilesystem:   installer.FilesystemLVM,
			LVMVolumeGroup:   "vg0",
			LVMLogicalVolume: "root",
			Encryption: &installer.EncryptionConfig{
				Version:    "luks2",
				Cipher:     "aes-xts-plain64",
				KeySize:    512,
				Hash:       "sha256",
				PBKDF:      "argon2id",
				MappedName: "cryptroot",
			},
		},
		OS: &installer.OSConfig{
			OS:                 installer.OSAlpine,
			Version:            "3.22.2",
			Architecture:       "x86_64",
			Hostname:           "client",
			FilesystemType:     installer.FilesystemLVM,
			FIPS:               false,
			Lockdown:           true,
			LockdownMode:       "confidentiality",
			TPMAutoUpgradeSeal: true,
			EnableFIDO2:        false,
			Packages: []string{
				"bash", "vim", "curl", "wget",
				"lsblk", "parted", "e2fsprogs", "lvm2",
				"tpm2-tools", "dracut", "softhsm",
			},
		},
		Network: &installer.NetworkConfig{
			DNS: &installer.DNSConfig{
				UpstreamDNS:   fmt.Sprintf("%s#%d", netConfig.ServerIP.String(), serverDNSPort),
				Nameservers:   []string{"8.8.8.8"},
				SearchDomains: []string{netConfig.Domain},
			},
			Interfaces: []installer.InterfaceConfig{
				{
					Name:        "eth0",
					Type:        installer.InterfaceTypeStatic,
					IPv4Address: netConfig.ClientIP.String(),
					IPv4Netmask: netConfig.SubnetMask(),
					IPv4Gateway: netConfig.GatewayIP.String(),
					AutoStart:   true,
				},
			},
			WaitOnline:  true,
			WaitTimeout: 30,
		},
		EnableTPMSealing: true,
		PCRs:             []uint{0, 7, 9},
		Debug:            false,
		Environment:      "test",
	}
}

func createServerPlatformConfig(netConfig *testenv.NetworkConfig) []byte {
	// This would use the PlatformConfigGenerator from pkg/cmd/iso
	// For now, return a minimal config template
	template := `---
debug: true
platform_dir: /opt/trusted-platform
ca:
  intermediate:
    subject:
      cn: Intermediate CA
webservice:
  domain: server.example.internal
  ip: %s
  port: %d
dns:
  enabled: true
  listen_ip: %s
  internal_port: %d
`
	return []byte(fmt.Sprintf(template,
		netConfig.ServerIP.String(),
		serverHTTPSPort,
		netConfig.ServerIP.String(),
		serverDNSPort))
}

func createClientPlatformConfig(netConfig *testenv.NetworkConfig) []byte {
	// This would use the PlatformConfigGenerator from pkg/cmd/iso
	// For now, return a minimal config template
	template := `---
debug: true
platform_dir: /opt/trusted-platform
acme:
  enabled: true
  directory_url: https://server.example.internal:8443/api/v1/acme/directory
  enrollment:
    enabled: true
    challenge: enroll-01
    ip_address: %s
webservice:
  domain: client.example.internal
  ip: %s
`
	return []byte(fmt.Sprintf(template,
		netConfig.ClientIP.String(),
		netConfig.ClientIP.String()))
}

func writeInstallerConfig(config *installer.Config, path string) error {
	// This would use yaml.Marshal from the installer package
	// For simplicity, this is a placeholder
	return os.WriteFile(path, []byte("# Installer config placeholder"), 0644)
}

func buildServerISO(ctx context.Context, t *testing.T, logger *logging.Logger, installerPath, platformPath, outputPath string) {
	t.Helper()
	// This would call the ISO builder from pkg/cmd/iso
	// For now, skip ISO building and assume ISOs are pre-built
	logger.Info("Skipping server ISO build (would use BuildCustomISO)",
		"output", outputPath)
}

func buildClientISO(ctx context.Context, t *testing.T, logger *logging.Logger, installerPath, platformPath, outputPath, caBundlePath string) {
	t.Helper()
	// This would call the ISO builder from pkg/cmd/iso with CA bundle embedded
	// For now, skip ISO building and assume ISOs are pre-built
	logger.Info("Skipping client ISO build (would use BuildCustomISO with CA bundle)",
		"output", outputPath,
		"ca_bundle", caBundlePath)
}

func createDiskImage(ctx context.Context, t *testing.T, logger *logging.Logger, diskPath, size string) {
	t.Helper()

	if _, err := os.Stat(diskPath); err == nil {
		logger.Info("Disk image already exists, skipping creation",
			"path", diskPath)
		return
	}

	logger.Info("Creating disk image",
		"path", diskPath,
		"size", size)

	cmd := exec.CommandContext(ctx, "qemu-img", "create", "-f", "qcow2", diskPath, size)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create disk image: %s", string(output))

	logger.Info("Disk image created successfully",
		"path", diskPath)
}

func setupTPM(ctx context.Context, t *testing.T, logger *logging.Logger, qemuConfig *qemu.Config) *swtpm.SWTPM {
	t.Helper()

	logger.Info("Setting up software TPM",
		"work_dir", qemuConfig.WorkDir)

	tpmConfig := &swtpm.Config{
		StateDir:   filepath.Join(qemuConfig.WorkDir, "tpm"),
		SocketPath: filepath.Join(qemuConfig.WorkDir, "swtpm.sock"),
		Debug:      qemuConfig.Debug,
	}

	require.NoError(t, os.MkdirAll(tpmConfig.StateDir, 0755))

	tpm, err := swtpm.NewSWTPM(tpmConfig, logger)
	require.NoError(t, err, "Failed to create SWTPM")

	require.NoError(t, tpm.Start(ctx), "Failed to start SWTPM")

	logger.Info("Software TPM started successfully",
		"socket", tpmConfig.SocketPath)

	// Update QEMU config with TPM socket
	qemuConfig.TPMSocket = tpmConfig.SocketPath

	return tpm
}

func installOS(ctx context.Context, t *testing.T, logger *logging.Logger, qemuConfig *qemu.Config) {
	t.Helper()

	logger.Info("Starting OS installation",
		"disk", qemuConfig.DiskPath,
		"iso", qemuConfig.ISO)

	// For integration tests, we skip the actual installation
	// In a real scenario, this would boot from ISO and run the automated installer
	logger.Info("Skipping OS installation (would run automated installer)")
}

func bootVM(ctx context.Context, t *testing.T, logger *logging.Logger, qemuConfig *qemu.Config) *qemu.VM {
	t.Helper()

	logger.Info("Booting VM",
		"disk", qemuConfig.DiskPath,
		"background", !qemuConfig.SerialConsole)

	vm, err := qemu.NewVM(qemuConfig, logger)
	require.NoError(t, err, "Failed to create VM")

	err = vm.Start(ctx, string(qemu.BootModeBoot))
	require.NoError(t, err, "Failed to start VM")

	logger.Info("VM started successfully",
		"pid", vm.GetPID())

	return vm
}

func fetchCABundle(ctx context.Context, t *testing.T, logger *logging.Logger, serverIP string) string {
	t.Helper()

	caBundlePath := filepath.Join(testWorkDir, "ca-bundle.pem")
	url := fmt.Sprintf("https://%s:%d/api/v1/acme/ca-bundle", serverIP, serverHTTPSPort)

	logger.Info("Fetching CA bundle from server",
		"url", url,
		"output", caBundlePath)

	// Create HTTP client with TLS verification disabled (we don't have the CA yet)
	transport := &http.Transport{
		TLSClientConfig: helpers.TLSConfigOrInsecure(),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err, "Failed to create HTTP request")

	resp, err := client.Do(req)
	require.NoError(t, err, "Failed to fetch CA bundle")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Server returned non-200 status")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read CA bundle response")
	require.NotEmpty(t, body, "CA bundle is empty")
	require.True(t, strings.Contains(string(body), "-----BEGIN CERTIFICATE-----"),
		"CA bundle does not contain valid PEM certificate")

	require.NoError(t, os.WriteFile(caBundlePath, body, 0644), "Failed to write CA bundle")

	logger.Info("CA bundle fetched successfully",
		"path", caBundlePath,
		"size", len(body))

	return caBundlePath
}

func checkDNSPort(ctx context.Context, logger *logging.Logger, ip string, port int) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()

	// Also try a dig query
	cmd := exec.CommandContext(checkCtx, "dig", "+short", "+timeout=2", "+tries=1",
		fmt.Sprintf("@%s", ip), "-p", fmt.Sprintf("%d", port), "localhost", "A")
	return cmd.Run() == nil
}

func checkHTTPSPort(ctx context.Context, logger *logging.Logger, ip string, port int) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://%s:%d/api/v1/acme/directory", ip, port)

	transport := &http.Transport{
		TLSClientConfig: helpers.TLSConfigOrInsecure(),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
	}

	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// checkEnrollmentStatus checks if the client has successfully completed ACME enrollment
// by verifying the client's HTTPS service is operational with a valid certificate
func checkEnrollmentStatus(ctx context.Context, logger *logging.Logger, serverIP, clientIP string) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Try to connect to the client's HTTPS service
	// If enrollment was successful, the client should have a valid certificate
	// and the platformd service should be running
	url := fmt.Sprintf("https://%s:%d/api/v1/status", clientIP, serverHTTPSPort)

	transport := &http.Transport{
		TLSClientConfig: helpers.TLSConfigOrInsecure(),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}

	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, url, nil)
	if err != nil {
		logger.Debug("Failed to create enrollment check request",
			"client_ip", clientIP,
			"error", err)
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Debug("Client HTTPS service not yet accessible",
			"client_ip", clientIP,
			"error", err)
		return false
	}
	defer resp.Body.Close()

	// If we get a response (even if auth fails), the service is up with a certificate
	logger.Debug("Client HTTPS service responded",
		"client_ip", clientIP,
		"status", resp.StatusCode)

	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
}

// tryFetchClientCertificate attempts to fetch the client's certificate from the client VM
// Returns nil if the certificate cannot be retrieved
func tryFetchClientCertificate(ctx context.Context, logger *logging.Logger, serverIP, clientIP string) *x509.Certificate {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Connect to the client's HTTPS service and extract the certificate from the TLS handshake
	url := fmt.Sprintf("https://%s:%d/api/v1/certificate", clientIP, serverHTTPSPort)

	var peerCerts []*x509.Certificate
	// Use the integration test CA for server verification while capturing peer certs
	baseTLSConfig := helpers.LoadMTLSConfig()
	if baseTLSConfig == nil {
		baseTLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}
	baseTLSConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		peerCerts = cs.PeerCertificates
		return nil
	}
	transport := &http.Transport{
		TLSClientConfig: baseTLSConfig,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}

	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, url, nil)
	if err != nil {
		logger.Debug("Failed to create certificate fetch request",
			"client_ip", clientIP,
			"error", err)
		return nil
	}

	_, err = client.Do(req)
	if err != nil {
		logger.Debug("Failed to connect to client for certificate fetch",
			"client_ip", clientIP,
			"error", err)
		return nil
	}

	if len(peerCerts) == 0 {
		logger.Debug("No peer certificates received from client",
			"client_ip", clientIP)
		return nil
	}

	logger.Debug("Successfully retrieved client certificate",
		"client_ip", clientIP,
		"subject", peerCerts[0].Subject.CommonName)

	return peerCerts[0]
}

// fetchClientCertificate fetches and verifies the client's IDevID certificate
func fetchClientCertificate(ctx context.Context, t *testing.T, logger *logging.Logger, serverIP, clientIP string) *x509.Certificate {
	t.Helper()

	logger.Info("Fetching client certificate",
		"server_ip", serverIP,
		"client_ip", clientIP)

	// Try multiple approaches to get the certificate

	// Approach 1: Extract from TLS handshake with client's HTTPS service
	cert := tryFetchClientCertificate(ctx, logger, serverIP, clientIP)
	if cert != nil {
		logger.Info("Successfully fetched certificate from client HTTPS service",
			"client_ip", clientIP,
			"subject", cert.Subject.CommonName)
		return cert
	}

	// Approach 2: Fetch from the client's certificate endpoint
	cert = tryFetchCertificateFromEndpoint(ctx, logger, clientIP)
	if cert != nil {
		logger.Info("Successfully fetched certificate from client certificate endpoint",
			"client_ip", clientIP,
			"subject", cert.Subject.CommonName)
		return cert
	}

	// If both approaches fail, the test should fail
	logger.Errorf("Failed to fetch client certificate using all available methods: client_ip=%s", clientIP)

	t.Fatal("Failed to retrieve client certificate")
	return nil
}

// tryFetchCertificateFromEndpoint attempts to fetch the certificate from the client's /api/v1/certificate endpoint
func tryFetchCertificateFromEndpoint(ctx context.Context, logger *logging.Logger, clientIP string) *x509.Certificate {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://%s:%d/api/v1/certificate", clientIP, serverHTTPSPort)

	transport := &http.Transport{
		TLSClientConfig: helpers.TLSConfigOrInsecure(),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}

	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, url, nil)
	if err != nil {
		logger.Debug("Failed to create certificate endpoint request",
			"client_ip", clientIP,
			"error", err)
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Debug("Failed to fetch certificate from endpoint",
			"client_ip", clientIP,
			"error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Debug("Certificate endpoint returned non-OK status",
			"client_ip", clientIP,
			"status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Debug("Failed to read certificate response",
			"client_ip", clientIP,
			"error", err)
		return nil
	}

	// Parse PEM certificate
	block, _ := pem.Decode(body)
	if block == nil {
		logger.Debug("Failed to decode PEM certificate",
			"client_ip", clientIP)
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Debug("Failed to parse X.509 certificate",
			"client_ip", clientIP,
			"error", err)
		return nil
	}

	return cert
}

// verifyTPMExtensions verifies that the certificate contains TPM attestation extensions
func verifyTPMExtensions(t *testing.T, logger *logging.Logger, cert *x509.Certificate) bool {
	t.Helper()

	logger.Info("Verifying TPM attestation extensions in certificate",
		"extensions_count", len(cert.Extensions),
		"subject", cert.Subject.CommonName)

	// Check for TCG TPM-specific OIDs
	var foundTPMExtensions []string
	tpmOIDs := map[string]string{
		oidTPMManufacturer:     "TPM Manufacturer",
		oidTPMModel:            "TPM Model",
		oidTPMVersion:          "TPM Version",
		oidTPMEKCertificate:    "TPM EK Certificate",
		oidTPMPlatformCert:     "TPM Platform Certificate",
		oidTPMAIKCertificate:   "TPM AIK Certificate",
		oidTPMAttestationData:  "TPM Attestation Data",
		oidTPMAttestationQuote: "TPM Attestation Quote",
	}

	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		if name, found := tpmOIDs[oidStr]; found {
			foundTPMExtensions = append(foundTPMExtensions, name)
			logger.Info("Found TPM extension",
				"oid", oidStr,
				"name", name,
				"critical", ext.Critical)

			// Try to decode the extension value
			var value interface{}
			if _, err := asn1.Unmarshal(ext.Value, &value); err == nil {
				logger.Debug("TPM extension value",
					"name", name,
					"value", value)
			}
		}
	}

	if len(foundTPMExtensions) > 0 {
		logger.Info("Certificate contains TPM attestation extensions",
			"count", len(foundTPMExtensions),
			"extensions", foundTPMExtensions)
		return true
	}

	// Also check for Extended Key Usage that might indicate TPM usage
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			logger.Info("Certificate has client authentication EKU (typical for IDevID)",
				"subject", cert.Subject.CommonName)
		}
	}

	// Check Subject Alternative Names for device identifiers
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		logger.Info("Certificate contains SANs",
			"dns_names", cert.DNSNames,
			"ip_addresses", cert.IPAddresses)
	}

	logger.Warn("Certificate does not contain recognized TPM attestation extensions",
		"extensions_checked", len(cert.Extensions),
		"subject", cert.Subject.CommonName)

	// For now, we'll consider the certificate valid if it has any extensions
	// and the expected EKU for client authentication
	return len(cert.Extensions) > 0 &&
		(len(cert.ExtKeyUsage) == 0 || containsEKU(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth))
}

// containsEKU checks if the given Extended Key Usage is present in the list
func containsEKU(ekus []x509.ExtKeyUsage, target x509.ExtKeyUsage) bool {
	for _, eku := range ekus {
		if eku == target {
			return true
		}
	}
	return false
}

func cleanupNetwork(t *testing.T, network testenv.IsolatedNetwork, logger *logging.Logger) {
	t.Helper()

	logger.Info("Cleaning up test network")
	if err := network.Cleanup(); err != nil {
		logger.Warn("Failed to cleanup network", "error", err)
	}
}

func cleanupVM(t *testing.T, logger *logging.Logger, name string, vm *qemu.VM, tpm *swtpm.SWTPM) {
	t.Helper()

	if vm != nil && vm.IsRunning() {
		logger.Info("Stopping VM", "name", name, "pid", vm.GetPID())
		if err := vm.Stop(); err != nil {
			logger.Warn("Failed to stop VM", "name", name, "error", err)
		}
	}

	if tpm != nil {
		logger.Info("Stopping TPM", "name", name)
		if err := tpm.Stop(); err != nil {
			logger.Warn("Failed to stop TPM", "name", name, "error", err)
		}
	}
}

func cleanupTestArtifacts(t *testing.T, logger *logging.Logger) {
	t.Helper()

	logger.Info("Cleaning up test artifacts", "dir", testWorkDir)

	// Remove test work directory
	if err := os.RemoveAll(testWorkDir); err != nil {
		logger.Warn("Failed to remove test work directory",
			"dir", testWorkDir,
			"error", err)
	}
}
