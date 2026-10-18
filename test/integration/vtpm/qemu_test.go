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

package vtpm_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newQEMUDiskVM returns a VM whose disk is diskPath. The firmware files are
// placeholders: CreateDisk never reads them.
func newQEMUDiskVM(t *testing.T, diskPath string) *qemu.VM {
	t.Helper()
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(ovmfCode, []byte("placeholder"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("placeholder"), 0644))

	vm, err := qemu.NewVM(&qemu.Config{
		DiskPath: diskPath,
		DiskSize: "1G",
		Memory:   1024,
		CPUs:     1,
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}, logging.DefaultLogger())
	require.NoError(t, err)
	return vm
}

// TestQEMUVM_CreateDisk creates a disk with the real qemu-img and checks the
// image it wrote. A missing qemu-img fails the test.
func TestQEMUVM_CreateDisk(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "disks", "test.qcow2")
	vm := newQEMUDiskVM(t, diskPath)

	require.NoError(t, vm.CreateDisk())

	output, err := exec.Command("qemu-img", "info", "--output=json", diskPath).CombinedOutput()
	require.NoError(t, err, string(output))
	assert.Contains(t, string(output), `"format": "qcow2"`)
	assert.Contains(t, string(output), `"virtual-size": 1073741824`)
}

// TestQEMUVM_CreateDiskAlreadyExists keeps an existing disk untouched.
func TestQEMUVM_CreateDiskAlreadyExists(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "test.qcow2")
	vm := newQEMUDiskVM(t, diskPath)
	require.NoError(t, vm.CreateDisk())
	before, err := os.Stat(diskPath)
	require.NoError(t, err)

	require.NoError(t, vm.CreateDisk())

	after, err := os.Stat(diskPath)
	require.NoError(t, err)
	assert.Equal(t, before.ModTime(), after.ModTime())
	assert.Equal(t, before.Size(), after.Size())
}

// TestQEMUVM_CreateDiskBadSize fails with qemu-img's own message.
func TestQEMUVM_CreateDiskBadSize(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "test.qcow2")
	vm := newQEMUDiskVM(t, diskPath)
	vm.GetConfig().DiskSize = "not-a-size"

	err := vm.CreateDisk()

	var cmdErr *qemu.CommandOutputError
	require.ErrorAs(t, err, &cmdErr)
	assert.NotEmpty(t, cmdErr.Detail)
	assert.NoFileExists(t, diskPath)
}
