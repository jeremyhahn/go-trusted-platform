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

package qemu

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildQEMUCommand_BootMode_WithVNC(t *testing.T) {
	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	nvramDir := filepath.Join(tmpDir, "nvram")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(nvramDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

	config := &Config{
		DiskPath:      diskPath,
		Memory:        4096,
		CPUs:          2,
		DiskSize:      "10G",
		WorkDir:       tmpDir,
		SecureBoot:    false,
		EnableKVM:     true,
		SerialConsole: false,
		NoGraphic:     false,
		VNCDisplay:    2,
		NetworkMode:   "user",
		OVMFCode:      ovmfCode,
		OVMFVars:      ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	cmd, err := vm.buildQEMUCommand(context.TODO(), BootModeBoot)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	args := cmd.Args
	assert.Contains(t, args, "-vnc")
	assert.Contains(t, args, ":2")
}

func TestBuildQEMUCommand_TapNetwork(t *testing.T) {
	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	nvramDir := filepath.Join(tmpDir, "nvram")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(nvramDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

	config := &Config{
		DiskPath:    diskPath,
		Memory:      2048,
		CPUs:        2,
		DiskSize:    "10G",
		WorkDir:     tmpDir,
		NetworkMode: "tap",
		TapDevice:   "tap0",
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	cmd, err := vm.buildQEMUCommand(context.TODO(), BootModeBoot)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// TAP networking configuration should be present
	args := cmd.Args
	foundTap := false
	for i, arg := range args {
		if arg == "-netdev" && i+1 < len(args) {
			if len(args[i+1]) >= 3 && args[i+1][:3] == "tap" {
				foundTap = true
				break
			}
		}
	}
	assert.True(t, foundTap, "TAP network configuration not found")
}

func TestBuildQEMUCommand_CustomQEMUBinary(t *testing.T) {
	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	nvramDir := filepath.Join(tmpDir, "nvram")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(nvramDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

	config := &Config{
		DiskPath:    diskPath,
		Memory:      2048,
		CPUs:        2,
		DiskSize:    "10G",
		WorkDir:     tmpDir,
		QEMUBinary:  "/custom/qemu-system-x86_64",
		NetworkMode: "user",
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	cmd, err := vm.buildQEMUCommand(context.TODO(), BootModeBoot)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Should have -L flag for custom binary if /usr/share/seabios exists
	args := cmd.Args
	foundL := false
	for _, arg := range args {
		if arg == "-L" {
			foundL = true
			break
		}
	}
	// Will be true if /usr/share/seabios exists
	if _, err := os.Stat("/usr/share/seabios/vgabios-stdvga.bin"); err == nil {
		assert.True(t, foundL, "-L flag not found for custom QEMU binary")
	}
}

func TestBuildQEMUCommand_NoKVM(t *testing.T) {
	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	nvramDir := filepath.Join(tmpDir, "nvram")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(nvramDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

	config := &Config{
		DiskPath:    diskPath,
		Memory:      2048,
		CPUs:        2,
		DiskSize:    "10G",
		WorkDir:     tmpDir,
		EnableKVM:   false,
		NetworkMode: "user",
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	cmd, err := vm.buildQEMUCommand(context.TODO(), BootModeBoot)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Should not have -enable-kvm
	args := cmd.Args
	assert.NotContains(t, args, "-enable-kvm")
}

func TestBuildQEMUCommand_InstallModeNoISO(t *testing.T) {
	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	nvramDir := filepath.Join(tmpDir, "nvram")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(nvramDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

	config := &Config{
		DiskPath:    diskPath,
		Memory:      2048,
		CPUs:        2,
		DiskSize:    "10G",
		WorkDir:     tmpDir,
		ISO:         "", // No ISO
		NetworkMode: "user",
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	cmd, err := vm.buildQEMUCommand(context.TODO(), BootModeInstall)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Should not have -cdrom since ISO is empty
	args := cmd.Args
	assert.NotContains(t, args, "-cdrom")
	// But should still have VGA for UEFI
	assert.Contains(t, args, "VGA")
}

func TestGetPID_AfterStartAttempt(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// PID should be 0 before starting
	assert.Equal(t, 0, vm.GetPID())
}

func TestConfigValidate_BridgeNetworkWithoutBridgeName(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath:    filepath.Join(tmpDir, "test.qcow2"),
		Memory:      4096,
		CPUs:        2,
		DiskSize:    "10G",
		WorkDir:     tmpDir,
		NetworkMode: "bridge",
		BridgeName:  "", // Empty bridge name
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
	}

	err := config.Validate()
	// Validation only checks OVMF files exist, not network configuration
	// Network validation happens at runtime in buildQEMUCommand
	assert.NoError(t, err)
}

func TestConfigValidate_TapNetworkWithoutTapDevice(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath:    filepath.Join(tmpDir, "test.qcow2"),
		Memory:      4096,
		CPUs:        2,
		DiskSize:    "10G",
		WorkDir:     tmpDir,
		NetworkMode: "tap",
		TapDevice:   "", // Empty tap device
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
	}

	err := config.Validate()
	// Validation only checks OVMF files exist, not network configuration
	// Network validation happens at runtime in buildQEMUCommand
	assert.NoError(t, err)
}

func TestVMStartAlreadyRunning(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Simulate VM already running
	vm.running.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = vm.Start(ctx, "boot")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrVMAlreadyRunning)
}

func TestCopyFile_DestinationCreateFails(t *testing.T) {
	tmpDir := t.TempDir()

	srcPath := filepath.Join(tmpDir, "source.txt")
	require.NoError(t, os.WriteFile(srcPath, []byte("test"), 0644))

	// Try to write to a directory that doesn't exist and can't be created
	dstPath := "/root/nonexistent/should-fail/dest.txt"

	err := copyFile(srcPath, dstPath)
	assert.Error(t, err)
}

func TestCreateFlagFile_DirectoryDoesNotExist(t *testing.T) {
	tmpDir := t.TempDir()

	// Try to create flag in non-existent directory
	flagPath := filepath.Join(tmpDir, "nonexistent", "test.flag")

	err := createFlagFile(flagPath)
	assert.Error(t, err)
}

func TestBuildQEMUCommand_PXEModeNoGraphic(t *testing.T) {
	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	nvramDir := filepath.Join(tmpDir, "nvram")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(nvramDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

	config := &Config{
		DiskPath:      diskPath,
		Memory:        2048,
		CPUs:          2,
		DiskSize:      "1G",
		WorkDir:       tmpDir,
		NetworkMode:   "user",
		PXEEnabled:    true,
		PXEServerIP:   "192.168.1.100",
		NoGraphic:     true,
		SerialConsole: true,
		OVMFCode:      ovmfCode,
		OVMFVars:      ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	cmd, err := vm.buildQEMUCommand(context.TODO(), BootModePXE)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	args := cmd.Args
	// In NoGraphic mode with PXE, should not have virtio-vga
	assert.NotContains(t, args, "virtio-vga")
	assert.Contains(t, args, "-nographic")
}

func TestInitializeNVRAM_Error(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock vars"), 0644))

	// Make OVMFVars unreadable to trigger error in initializeNVRAM
	require.NoError(t, os.Chmod(ovmfVars, 0000))
	defer func() { _ = os.Chmod(ovmfVars, 0644) }() // Restore for cleanup

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Should fail to read OVMF template due to permission denied
	err = vm.initializeNVRAM()
	assert.Error(t, err)
}

func TestFIDO2Config_CanoKeyWithFile(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	canoKeyFile := filepath.Join(tmpDir, "canokey.state")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
		FIDO2: &FIDO2Config{
			Enable:      true,
			Mode:        "canokey",
			CanoKeyFile: canoKeyFile,
		},
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	args, err := vm.buildFIDO2Args()
	require.NoError(t, err)
	assert.NotEmpty(t, args)

	// Should contain file= parameter
	found := false
	for _, arg := range args {
		if len(arg) > 7 && arg[:7] == "canokey" {
			assert.Contains(t, arg, "file="+canoKeyFile)
			found = true
			break
		}
	}
	assert.True(t, found, "CanoKey file parameter not found")
}

func TestGetCanoKeyFilePath_NilFIDO2(t *testing.T) {
	config := &Config{
		WorkDir: "/test/work",
		FIDO2:   nil,
	}

	vm := &VM{
		config: config,
		logger: logging.DefaultLogger(),
	}

	path := vm.GetCanoKeyFilePath()
	assert.Equal(t, "", path)
}

func TestConfigValidate_InvalidNetworkMode(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath:    filepath.Join(tmpDir, "test.qcow2"),
		Memory:      4096,
		CPUs:        2,
		DiskSize:    "10G",
		WorkDir:     tmpDir,
		NetworkMode: "invalid-mode",
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
	}

	err := config.Validate()
	// Validation only checks OVMF files exist, not network mode
	assert.NoError(t, err)
}
