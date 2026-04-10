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
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVMCreateDisk(t *testing.T) {
	// Skip if qemu-img is not available
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not found in PATH")
	}

	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: diskPath,
		Memory:   4096,
		CPUs:     2,
		DiskSize: "1G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Create disk
	err = vm.CreateDisk()
	assert.NoError(t, err)

	// Verify disk exists
	_, err = os.Stat(diskPath)
	assert.NoError(t, err)

	// Verify disk format using qemu-img
	cmd := exec.Command("qemu-img", "info", "--output=json", diskPath)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(output), "qcow2")
}

func TestVMCreateDiskAlreadyExists(t *testing.T) {
	// Skip if qemu-img is not available
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not found in PATH")
	}

	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: diskPath,
		Memory:   4096,
		CPUs:     2,
		DiskSize: "1G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Create disk first time
	err = vm.CreateDisk()
	require.NoError(t, err)

	// Get file info
	info1, err := os.Stat(diskPath)
	require.NoError(t, err)

	// Try to create again - should not error, just warn
	err = vm.CreateDisk()
	assert.NoError(t, err)

	// Verify file wasn't modified
	info2, err := os.Stat(diskPath)
	require.NoError(t, err)
	assert.Equal(t, info1.ModTime(), info2.ModTime())
}

func TestVMCreateDiskInvalidPath(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	// Use an invalid path that can't be created
	config := &Config{
		DiskPath: "/root/should-fail/test.qcow2",
		Memory:   4096,
		CPUs:     2,
		DiskSize: "1G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Should fail to create disk directory
	err = vm.CreateDisk()
	assert.Error(t, err)
}

func TestVMInitializeNVRAM(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	// Create template OVMF_VARS
	templateContent := []byte("test OVMF VARS template")
	require.NoError(t, os.WriteFile(ovmfVars, templateContent, 0644))

	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "1G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Initialize NVRAM
	err = vm.initializeNVRAM()
	assert.NoError(t, err)

	// Verify NVRAM file exists
	nvramPath := config.GetNVRAMPath()
	_, err = os.Stat(nvramPath)
	assert.NoError(t, err)

	// Verify content matches template
	content, err := os.ReadFile(nvramPath)
	require.NoError(t, err)
	assert.Equal(t, templateContent, content)
}

func TestVMInitializeNVRAMAlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(ovmfVars, []byte("template"), 0644))

	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "1G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	// Create NVRAM directory and file manually
	nvramPath := config.GetNVRAMPath()
	require.NoError(t, os.MkdirAll(filepath.Dir(nvramPath), 0755))

	existingContent := []byte("existing NVRAM content")
	require.NoError(t, os.WriteFile(nvramPath, existingContent, 0644))

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Initialize NVRAM - should use existing
	err = vm.initializeNVRAM()
	assert.NoError(t, err)

	// Verify content wasn't changed
	content, err := os.ReadFile(nvramPath)
	require.NoError(t, err)
	assert.Equal(t, existingContent, content)
}

func TestVMBuildQEMUCommandInstallMode(t *testing.T) {
	tmpDir := t.TempDir()
	isoPath := filepath.Join(tmpDir, "test.iso")
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(isoPath, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		ISO:           isoPath,
		DiskPath:      diskPath,
		Memory:        2048,
		CPUs:          2,
		DiskSize:      "10G",
		WorkDir:       tmpDir,
		SecureBoot:    true,
		EnableKVM:     true,
		SerialConsole: true,
		NoGraphic:     true,
		BootOrder:     "d",
		NetworkMode:   "user",
		OVMFCode:      ovmfCode,
		OVMFVars:      ovmfVars,
		Debug:         true,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	cmd, err := vm.buildQEMUCommand(context.TODO(), BootModeInstall)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	args := cmd.Args
	assert.Contains(t, args, "-enable-kvm")
	assert.Contains(t, args, "-machine")
	assert.Contains(t, args, "q35,smm=on") // Secure Boot requires SMM
	assert.Contains(t, args, "-m")
	assert.Contains(t, args, "2048")
	assert.Contains(t, args, "-smp")
	assert.Contains(t, args, "-boot")
	assert.Contains(t, args, "-cdrom")
	assert.Contains(t, args, isoPath)
	assert.Contains(t, args, "-device")
	assert.Contains(t, args, "VGA")
	assert.Contains(t, args, "-serial")
	assert.Contains(t, args, "stdio")
	assert.Contains(t, args, "-nographic")
}

func TestVMBuildQEMUCommandBootMode(t *testing.T) {
	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	tpmSocket := filepath.Join(tmpDir, "tpm", "swtpm.sock")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Dir(tpmSocket), 0755))
	require.NoError(t, os.WriteFile(tpmSocket, []byte{}, 0644))

	config := &Config{
		DiskPath:       diskPath,
		Memory:         4096,
		CPUs:           4,
		DiskSize:       "10G",
		WorkDir:        tmpDir,
		SecureBoot:     true,
		EnableKVM:      true,
		SerialConsole:  false,
		NoGraphic:      false,
		VNCDisplay:     1,
		NetworkMode:    "user",
		OVMFCode:       ovmfCode,
		OVMFCodeSecure: ovmfCode,
		OVMFVars:       ovmfVars,
		TPMSocket:      tpmSocket,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	cmd, err := vm.buildQEMUCommand(context.Background(), BootModeBoot)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	args := cmd.Args
	assert.Contains(t, args, "-enable-kvm")
	assert.Contains(t, args, "-m")
	assert.Contains(t, args, "4096")
	assert.Contains(t, args, "-boot")
	assert.Contains(t, args, "menu=on,strict=off")
	assert.Contains(t, args, "-device")
	assert.Contains(t, args, "virtio-vga")
	assert.Contains(t, args, "-vnc")
	assert.Contains(t, args, ":1")
	assert.Contains(t, args, "-chardev")
	assert.Contains(t, args, "-tpmdev")
	assert.Contains(t, args, "-global")
	assert.Contains(t, args, "driver=cfi.pflash01,property=secure,value=on")
}

func TestVMBuildQEMUCommandNoNetwork(t *testing.T) {
	tmpDir := t.TempDir()
	diskPath := filepath.Join(tmpDir, "test.qcow2")
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath:    diskPath,
		Memory:      4096,
		CPUs:        2,
		DiskSize:    "10G",
		WorkDir:     tmpDir,
		NetworkMode: "none",
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	cmd, err := vm.buildQEMUCommand(context.Background(), BootModeBoot)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	args := cmd.Args
	assert.NotContains(t, args, "-netdev")
	assert.NotContains(t, args, "virtio-net-pci")
}
