package qemu

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newSleepingIncomingVM builds a VM whose QEMU binary is a sleeping shell
// script, so StartIncoming launches a real process that stays alive.
func newSleepingIncomingVM(t *testing.T) *VM {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "qemu-system-x86_64")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755))
	cfg := DefaultConfig()
	cfg.Arch = ArchX86_64
	cfg.QEMUBinary = bin
	cfg.WorkDir = filepath.Join(dir, "work")
	cfg.DiskPath = filepath.Join(cfg.WorkDir, "disk.qcow2")
	cfg.DiskSize = "1G"
	cfg.Memory = 512
	cfg.CPUs = 1
	cfg.OVMFCode = filepath.Join(dir, "OVMF_CODE.fd")
	cfg.OVMFVars = filepath.Join(dir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(cfg.OVMFCode, nil, 0o600))
	require.NoError(t, os.WriteFile(cfg.OVMFVars, nil, 0o600))
	require.NoError(t, os.MkdirAll(cfg.WorkDir, 0o755))
	require.NoError(t, os.WriteFile(cfg.DiskPath, []byte("disk"), 0o600))
	nvram := cfg.GetNVRAMPath()
	require.NoError(t, os.MkdirAll(filepath.Dir(nvram), 0o755))
	require.NoError(t, os.WriteFile(nvram, []byte("vars"), 0o600))
	vm, err := NewVM(cfg, logging.DefaultLogger())
	require.NoError(t, err)
	return vm
}

func TestProcessKiller_KillsOnlyTheCapturedProcess(t *testing.T) {
	vm := newSleepingIncomingVM(t)
	_, err := vm.StartIncoming(context.Background(), "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vm.ProcessKiller()(); _ = vm.Wait() })

	kill := vm.ProcessKiller()
	require.NoError(t, kill())
	_ = vm.Wait()

	_, err = vm.StartIncoming(context.Background(), "")
	require.NoError(t, err)
	pid := vm.GetPID()

	if err := kill(); err != nil {
		require.True(t, errors.Is(err, os.ErrProcessDone), "the captured killer answered %v", err)
	}
	require.True(t, vm.IsRunning(), "the captured killer stopped the VM's new process")
	require.Equal(t, pid, vm.GetPID())
	require.NoError(t, syscall.Kill(pid, 0), "the new process was killed by the old killer")
}

func TestKill_SecondIncomingProcessIsKilled(t *testing.T) {
	vm := newSleepingIncomingVM(t)
	_, err := vm.StartIncoming(context.Background(), "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vm.Kill(); _ = vm.Wait() })

	require.NoError(t, vm.Kill())
	_ = vm.Wait()

	_, err = vm.StartIncoming(context.Background(), "")
	require.NoError(t, err)
	pid := vm.GetPID()

	require.NoError(t, vm.Kill(), "Kill refused the second incoming process")
	_ = vm.Wait()
	require.Error(t, syscall.Kill(pid, 0), "the second incoming process is still alive")
}
