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

package compute

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// plainCreator is an orchestrator without VMCreator. Only the methods the
// create helpers call are implemented; any other call panics on the nil
// embedded interface.
type plainCreator struct {
	Orchestrator
	calls     []string
	startErr  error
	deleteErr error
}

func (p *plainCreator) Create(_ context.Context, profile *entities.DeviceProfile) (*Instance, error) {
	p.calls = append(p.calls, "create")
	return &Instance{ID: profile.Name + "-id", Name: profile.Name}, nil
}

func (p *plainCreator) Start(_ context.Context, id string) error {
	p.calls = append(p.calls, "start "+id)
	return p.startErr
}

func (p *plainCreator) Delete(ctx context.Context, id string) error {
	p.calls = append(p.calls, "delete "+id)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return p.deleteErr
}

// specCreator is an orchestrator with VMCreator; it records the spec.
type specCreator struct {
	plainCreator
	specs []VMSpec
}

func (s *specCreator) CreateWithSpec(_ context.Context, profile *entities.DeviceProfile, spec VMSpec) (*Instance, error) {
	s.specs = append(s.specs, spec)
	return &Instance{ID: profile.Name + "-id", Name: profile.Name}, nil
}

func TestVMSpecValidate(t *testing.T) {
	tests := []struct {
		name    string
		spec    VMSpec
		wantErr bool
	}{
		{name: "zero value", spec: VMSpec{}},
		{name: "every field", spec: VMSpec{
			MemoryMB: 4096, CPUs: 4, DiskSizeGB: 40, DiskBus: DiskBusVirtio, SecureBoot: true,
			DisableTPM: true, BootMode: BootModePXE, MACAddress: "52:54:00:12:34:56", Bridge: "br-int",
			Description: "web", Labels: map[string]string{"tier": "web"}, Metadata: map[string]string{"owner": "ops"},
		}},
		{name: "sata bus", spec: VMSpec{DiskBus: DiskBusSATA}},
		{name: "disk boot", spec: VMSpec{BootMode: BootModeDisk}},
		{name: "negative memory", spec: VMSpec{MemoryMB: -1}, wantErr: true},
		{name: "negative cpus", spec: VMSpec{CPUs: -1}, wantErr: true},
		{name: "negative disk", spec: VMSpec{DiskSizeGB: -1}, wantErr: true},
		{name: "unknown bus", spec: VMSpec{DiskBus: "scsi"}, wantErr: true},
		{name: "install mode", spec: VMSpec{BootMode: "install"}, wantErr: true},
		{name: "bad MAC", spec: VMSpec{MACAddress: "52:54:00"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, ErrInvalidVMSpec)
		})
	}
}

func TestVMSpecIsDefault(t *testing.T) {
	assert.True(t, VMSpec{}.IsDefault())
	assert.True(t, VMSpec{Labels: map[string]string{}}.IsDefault(), "an empty map asks for nothing")
	assert.False(t, VMSpec{Labels: map[string]string{"a": "b"}}.IsDefault())
	assert.False(t, VMSpec{DisableTPM: true}.IsDefault())
	assert.False(t, VMSpec{Description: "x"}.IsDefault())
}

func TestCreateWithSpec_UsesVMCreator(t *testing.T) {
	o := &specCreator{}
	spec := VMSpec{MemoryMB: 2048, Labels: map[string]string{"tier": "web"}}

	inst, err := CreateWithSpec(context.Background(), o, &entities.DeviceProfile{Name: "vm"}, spec)

	require.NoError(t, err)
	assert.Equal(t, "vm-id", inst.ID)
	assert.Equal(t, []VMSpec{spec}, o.specs)
	assert.Empty(t, o.calls, "the plain Create is not used")
}

func TestCreateWithSpec_PlainOrchestratorTakesDefaultCreate(t *testing.T) {
	o := &plainCreator{}

	inst, err := CreateWithSpec(context.Background(), o, &entities.DeviceProfile{Name: "vm"}, VMSpec{})

	require.NoError(t, err)
	assert.Equal(t, "vm-id", inst.ID)
	assert.Equal(t, []string{"create"}, o.calls)
}

func TestCreateWithSpec_PlainOrchestratorRefusesSpec(t *testing.T) {
	o := &plainCreator{}

	inst, err := CreateWithSpec(context.Background(), o, &entities.DeviceProfile{Name: "vm"}, VMSpec{CPUs: 2})

	assert.Nil(t, inst)
	assert.ErrorIs(t, err, ErrUnsupportedOperation)
	assert.Empty(t, o.calls)
}

func TestCreateWithSpec_InvalidSpecRefused(t *testing.T) {
	o := &specCreator{}

	inst, err := CreateWithSpec(context.Background(), o, &entities.DeviceProfile{Name: "vm"}, VMSpec{BootMode: "install"})

	assert.Nil(t, inst)
	assert.ErrorIs(t, err, ErrInvalidVMSpec)
	assert.Empty(t, o.specs)
}

func TestStartOrDelete_StartSucceeds(t *testing.T) {
	o := &plainCreator{}

	require.NoError(t, StartOrDelete(context.Background(), o, "vm-id"))
	assert.Equal(t, []string{"start vm-id"}, o.calls)
}

func TestStartOrDelete_StartFailureDeletes(t *testing.T) {
	o := &plainCreator{startErr: ErrInvalidState}

	err := StartOrDelete(context.Background(), o, "vm-id")

	assert.ErrorIs(t, err, ErrInvalidState)
	assert.Equal(t, []string{"start vm-id", "delete vm-id"}, o.calls)
}

func TestStartOrDelete_DeletesAfterCancelledStart(t *testing.T) {
	o := &plainCreator{startErr: context.Canceled}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := StartOrDelete(ctx, o, "vm-id")

	assert.ErrorIs(t, err, context.Canceled)
	var cleanup *StartCleanupError
	assert.False(t, errors.As(err, &cleanup), "the delete must not inherit the cancelled context: %v", err)
}

func TestStartOrDelete_CleanupFailureReportsBoth(t *testing.T) {
	o := &plainCreator{startErr: ErrInvalidState, deleteErr: ErrInstanceNotFound}

	err := StartOrDelete(context.Background(), o, "vm-id")

	var cleanup *StartCleanupError
	require.ErrorAs(t, err, &cleanup)
	assert.ErrorIs(t, err, ErrInvalidState, "the error classifies as the start failure")
	assert.NotErrorIs(t, err, ErrInstanceNotFound)
	assert.Contains(t, err.Error(), ErrInstanceNotFound.Error())
}

func TestQEMUCheckVMSpec(t *testing.T) {
	tests := []struct {
		name       string
		arch       qemu.Arch
		secureCode string
		bridge     string
		spec       VMSpec
		wantErr    string
	}{
		{name: "default", arch: qemu.ArchX86_64},
		{name: "x86 sata", arch: qemu.ArchX86_64, spec: VMSpec{DiskBus: DiskBusSATA}},
		{name: "x86 virtio", arch: qemu.ArchX86_64, spec: VMSpec{DiskBus: DiskBusVirtio}, wantErr: "disk bus virtio"},
		{name: "aarch64 virtio", arch: qemu.ArchAArch64, spec: VMSpec{DiskBus: DiskBusVirtio}},
		{name: "aarch64 sata", arch: qemu.ArchAArch64, spec: VMSpec{DiskBus: DiskBusSATA}, wantErr: "disk bus sata"},
		{name: "secure boot", arch: qemu.ArchX86_64, secureCode: "/fw/OVMF_CODE.secboot.fd", spec: VMSpec{SecureBoot: true}},
		{name: "secure boot without image", arch: qemu.ArchX86_64, spec: VMSpec{SecureBoot: true}, wantErr: "ovmf_code_secure"},
		{name: "configured bridge", arch: qemu.ArchX86_64, bridge: "br-vm", spec: VMSpec{Bridge: "br-vm"}},
		{name: "default bridge", arch: qemu.ArchX86_64, spec: VMSpec{Bridge: qemu.DefaultBridgeName}},
		{name: "other bridge", arch: qemu.ArchX86_64, bridge: "br-vm", spec: VMSpec{Bridge: "br-trunk"}, wantErr: "bridge br-trunk"},
		{name: "invalid spec", arch: qemu.ArchX86_64, spec: VMSpec{CPUs: -2}, wantErr: "cpus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			orch.config.Arch = tt.arch
			orch.config.OVMFCodeSecure = tt.secureCode
			orch.config.NetworkBridge = tt.bridge

			err := orch.checkVMSpec(tt.spec)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, ErrInvalidVMSpec)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestQEMUInstanceConfig_SpecReachesTheVM(t *testing.T) {
	orch := newOpsOrchestrator(t)
	spec := VMSpec{
		MemoryMB: 4096, CPUs: 4, DiskSizeGB: 40, SecureBoot: true, DisableTPM: true,
		BootMode: BootModePXE, MACAddress: "52:54:00:12:34:56",
		Description: "web", Labels: map[string]string{"tier": "web"}, Metadata: map[string]string{"owner": "ops"},
	}

	cfg := orch.instanceConfig("vm1", spec)

	assert.Equal(t, 4096, cfg.Memory)
	assert.Equal(t, 4, cfg.CPUs)
	assert.Equal(t, "40G", cfg.DiskSize)
	assert.True(t, cfg.SecureBoot)
	assert.False(t, cfg.TPMEnabled)
	assert.Equal(t, BootModePXE, cfg.BootMode)
	assert.Equal(t, "52:54:00:12:34:56", cfg.MACAddress)
	assert.Equal(t, "web", cfg.Description)
	assert.Equal(t, map[string]string{"tier": "web"}, cfg.Labels)
	assert.Equal(t, map[string]string{"owner": "ops"}, cfg.Metadata)
	assert.Equal(t, filepath.Join(orch.config.WorkDir, "vm1", "disk.qcow2"), cfg.DiskPath)

	spec.Labels["tier"] = "db"
	assert.Equal(t, "web", cfg.Labels["tier"], "the instance keeps its own copy of the labels")
}

func TestQEMUInstanceConfig_EmptySpecIsTheDefaultVM(t *testing.T) {
	orch := newOpsOrchestrator(t)

	cfg := orch.instanceConfig("vm1", VMSpec{})

	assert.Equal(t, orch.config.DefaultMemory, cfg.Memory)
	assert.Equal(t, orch.config.DefaultCPUs, cfg.CPUs)
	assert.Equal(t, orch.config.DefaultDiskSize, cfg.DiskSize)
	assert.False(t, cfg.SecureBoot)
	assert.True(t, cfg.TPMEnabled, "a VM has a vTPM unless the spec disables it")
	assert.Equal(t, BootModeDisk, cfg.BootMode)
	assert.Equal(t, "bridge", cfg.NetworkMode)
	assert.Empty(t, cfg.MACAddress)
	assert.Nil(t, cfg.Labels)
}

func TestQEMUCreateWithSpec_RefusedSpecCreatesNothing(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.OVMFCodeSecure = ""

	inst, err := orch.CreateWithSpec(context.Background(), &entities.DeviceProfile{Name: "vm"}, VMSpec{SecureBoot: true})

	assert.Nil(t, inst)
	assert.ErrorIs(t, err, ErrInvalidVMSpec)
	entries, readErr := os.ReadDir(orch.config.WorkDir)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "no work directory is made for a refused VM")
	instances, listErr := orch.List(context.Background(), nil)
	require.NoError(t, listErr)
	assert.Empty(t, instances)
}

func TestQEMUCreateWithSpec_NilProfile(t *testing.T) {
	orch := newOpsOrchestrator(t)

	inst, err := orch.CreateWithSpec(context.Background(), nil, VMSpec{})

	assert.Nil(t, inst)
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

// TestQEMUStartOrDelete_FailedStartLeavesNoVM starts a VM whose disk is
// missing: QEMU refuses before spawning anything, the instance lands in the
// error state, and the delete that follows must still remove it.
func TestQEMUStartOrDelete_FailedStartLeavesNoVM(t *testing.T) {
	orch := newOpsOrchestrator(t)
	fw := t.TempDir()
	cfg := orch.config.qemuBase()
	cfg.Arch = qemu.ArchX86_64
	cfg.OVMFCode = filepath.Join(fw, "OVMF_CODE.fd")
	cfg.OVMFVars = filepath.Join(fw, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(cfg.OVMFCode, nil, 0o600))
	require.NoError(t, os.WriteFile(cfg.OVMFVars, nil, 0o600))
	cfg.WorkDir = filepath.Join(orch.config.WorkDir, "vm1")
	cfg.DiskPath = filepath.Join(cfg.WorkDir, "disk.qcow2")
	cfg.DiskSize = "1G"
	cfg.Memory = 512
	cfg.CPUs = 1
	vm, err := qemu.NewVM(cfg, logging.DefaultLogger())
	require.NoError(t, err)
	qi := insertVMInstance(t, orch, "vm1", false, &InstanceConfig{WorkDir: cfg.WorkDir, BootMode: BootModeDisk})
	qi.vm = vm

	err = StartOrDelete(context.Background(), orch, "vm1")

	assert.ErrorIs(t, err, qemu.ErrDiskNotFound)
	var cleanup *StartCleanupError
	assert.False(t, errors.As(err, &cleanup), "the errored VM must be deletable: %v", err)
	_, getErr := orch.Get(context.Background(), "vm1")
	assert.ErrorIs(t, getErr, ErrInstanceNotFound)
}
