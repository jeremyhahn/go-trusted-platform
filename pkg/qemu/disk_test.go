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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errFakeImage is the failure fakeImageTool returns when told to fail.
var errFakeImage = &MessageError{Msg: "fake qemu-img failure"}

// fakeImageTool stands in for qemu-img: it records each call and writes the
// image file, or fails with errFakeImage and some output.
type fakeImageTool struct {
	fail  bool
	calls [][]string
}

func (f *fakeImageTool) create(format, path, size string) ([]byte, error) {
	f.calls = append(f.calls, []string{format, path, size})
	if f.fail {
		return []byte("qemu-img: cannot create"), errFakeImage
	}
	return nil, os.WriteFile(path, []byte(format), 0600)
}

// newDiskTestVM returns a VM for diskPath whose qemu-img is fake.
func newDiskTestVM(t *testing.T, diskPath string, fake *fakeImageTool) *VM {
	t.Helper()
	tmpDir := t.TempDir()
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
	vm.createImage = fake.create
	return vm
}

func TestNewVMUsesQEMUImg(t *testing.T) {
	faked := newDiskTestVM(t, filepath.Join(t.TempDir(), "test.qcow2"), &fakeImageTool{})

	vm, err := NewVM(faked.config, nil)

	require.NoError(t, err)
	assert.Equal(t, reflect.ValueOf(runQEMUImgCreate).Pointer(), reflect.ValueOf(vm.createImage).Pointer())
}

func TestVMCreateDisk(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "disks", "test.qcow2")
	fake := &fakeImageTool{}
	vm := newDiskTestVM(t, diskPath, fake)

	require.NoError(t, vm.CreateDisk())

	assert.Equal(t, [][]string{{"qcow2", diskPath, "1G"}}, fake.calls)
	content, err := os.ReadFile(diskPath)
	require.NoError(t, err)
	assert.Equal(t, "qcow2", string(content))
}

func TestVMCreateDiskConfiguredFormat(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "test.raw")
	fake := &fakeImageTool{}
	vm := newDiskTestVM(t, diskPath, fake)
	vm.config.DiskFormat = "raw"

	require.NoError(t, vm.CreateDisk())

	assert.Equal(t, [][]string{{"raw", diskPath, "1G"}}, fake.calls)
}

func TestVMCreateDiskAlreadyExists(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "test.qcow2")
	require.NoError(t, os.WriteFile(diskPath, []byte("existing"), 0600))
	fake := &fakeImageTool{}
	vm := newDiskTestVM(t, diskPath, fake)

	require.NoError(t, vm.CreateDisk())

	assert.Empty(t, fake.calls, "an existing disk must not be recreated")
	content, err := os.ReadFile(diskPath)
	require.NoError(t, err)
	assert.Equal(t, "existing", string(content))
}

func TestVMCreateDiskToolFails(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "test.qcow2")
	vm := newDiskTestVM(t, diskPath, &fakeImageTool{fail: true})

	err := vm.CreateDisk()

	var cmdErr *CommandOutputError
	require.ErrorAs(t, err, &cmdErr)
	assert.ErrorIs(t, err, errFakeImage)
	assert.Contains(t, err.Error(), "qemu-img: cannot create")
	assert.NoFileExists(t, diskPath)
}

func TestVMCreateDiskInvalidPath(t *testing.T) {
	// The disk directory sits under a regular file, so it cannot be created.
	parent := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(parent, nil, 0600))
	fake := &fakeImageTool{}
	vm := newDiskTestVM(t, filepath.Join(parent, "disks", "test.qcow2"), fake)

	err := vm.CreateDisk()

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to create disk directory", wrapped.Msg)
	assert.Empty(t, fake.calls)
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
	assert.Contains(t, args, fmt.Sprintf("file=%s,if=none,media=cdrom,readonly=on,id=cd0", isoPath))
	assert.Contains(t, args, "ide-cd,drive=cd0,bus=ahci0.1")
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
