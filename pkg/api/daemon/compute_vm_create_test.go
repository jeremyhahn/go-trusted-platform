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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newVMCreateService() (*ComputeGRPCService, *grpcMockOrchestrator) {
	orch := newGRPCMockOrchestrator()
	return NewComputeGRPCService(logging.DefaultLogger(), orch), orch
}

func TestCreateVM_HonouredFieldsReachTheOrchestrator(t *testing.T) {
	svc, orch := newVMCreateService()
	labels := map[string]string{"tier": "web"}
	metadata := map[string]string{"owner": "ops"}

	resp, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{
		Name:        "vm-honoured",
		Description: "web front end",
		Firmware:    platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT,
		BootDevice:  platformv1.BootDevice_BOOT_DEVICE_NETWORK,
		Cpu:         &platformv1.CPUConfig{Cores: 4, Sockets: 1, Threads: 1},
		Memory:      &platformv1.MemoryConfig{SizeMb: 4096},
		Disks: []*platformv1.DiskConfig{{
			Type: platformv1.DiskType_DISK_TYPE_QCOW2, Bus: platformv1.DiskBus_DISK_BUS_VIRTIO,
			SizeGb: 40, Bootable: true,
		}},
		Networks: []*platformv1.NetworkConfig{{
			Bridge: "br-vms", MacAddress: "52:54:00:12:34:56", Model: platformv1.NetworkModel_NETWORK_MODEL_VIRTIO,
		}},
		Graphics: &platformv1.GraphicsConfig{Type: platformv1.GraphicsType_GRAPHICS_TYPE_NONE},
		Tpm:      &platformv1.TPMConfig{Enabled: true, Version: platformv1.TPMVersion_TPM_VERSION_2_0, Emulated: true},
		Labels:   labels,
		Metadata: metadata,
	}})
	require.NoError(t, err)

	assert.Equal(t, []compute.VMSpec{{
		MemoryMB: 4096, CPUs: 4, DiskSizeGB: 40, DiskBus: compute.DiskBusVirtio,
		SecureBoot: true, BootMode: compute.BootModePXE,
		MACAddress: "52:54:00:12:34:56", Bridge: "br-vms",
		Description: "web front end", Labels: labels, Metadata: metadata,
	}}, orch.recordedSpecs())

	config := resp.GetVm().GetConfig()
	assert.Equal(t, "web front end", config.GetDescription())
	assert.Equal(t, platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT, config.GetFirmware())
	assert.Equal(t, platformv1.BootDevice_BOOT_DEVICE_NETWORK, config.GetBootDevice())
	assert.Equal(t, labels, config.GetLabels())
	assert.Equal(t, metadata, config.GetMetadata())
}

func TestCreateVM_SecureBootFlagAndDisabledTPM(t *testing.T) {
	svc, orch := newVMCreateService()

	_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{
		Name:       "vm-flags",
		Firmware:   platformv1.FirmwareType_FIRMWARE_TYPE_UEFI,
		SecureBoot: true,
		Disks:      []*platformv1.DiskConfig{{Bus: platformv1.DiskBus_DISK_BUS_SATA}},
		Tpm:        &platformv1.TPMConfig{Enabled: false},
	}})
	require.NoError(t, err)

	assert.Equal(t, []compute.VMSpec{{DiskBus: compute.DiskBusSATA, SecureBoot: true, DisableTPM: true}}, orch.recordedSpecs())
}

func TestCreateVM_EmptyConfigIsTheDefaultVM(t *testing.T) {
	svc, orch := newVMCreateService()

	resp, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: "vm-default"}})
	require.NoError(t, err)

	assert.Equal(t, []compute.VMSpec{{}}, orch.recordedSpecs())
	assert.Equal(t, platformv1.FirmwareType_FIRMWARE_TYPE_UEFI, resp.GetVm().GetConfig().GetFirmware())
	assert.Equal(t, platformv1.BootDevice_BOOT_DEVICE_DISK, resp.GetVm().GetConfig().GetBootDevice())
}

func TestCreateVM_RefusesUnsupportedFields(t *testing.T) {
	disk := func(d *platformv1.DiskConfig) *platformv1.VMConfig {
		return &platformv1.VMConfig{Disks: []*platformv1.DiskConfig{d}}
	}
	nic := func(n *platformv1.NetworkConfig) *platformv1.VMConfig {
		return &platformv1.VMConfig{Networks: []*platformv1.NetworkConfig{n}}
	}
	tests := []struct {
		field  string
		config *platformv1.VMConfig
	}{
		{"firmware", &platformv1.VMConfig{Firmware: platformv1.FirmwareType_FIRMWARE_TYPE_BIOS}},
		{"boot_device", &platformv1.VMConfig{BootDevice: platformv1.BootDevice_BOOT_DEVICE_CDROM}},
		{"cpu.sockets", &platformv1.VMConfig{Cpu: &platformv1.CPUConfig{Sockets: 2}}},
		{"cpu.threads", &platformv1.VMConfig{Cpu: &platformv1.CPUConfig{Threads: 2}}},
		{"cpu.model", &platformv1.VMConfig{Cpu: &platformv1.CPUConfig{Model: "host"}}},
		{"cpu.features", &platformv1.VMConfig{Cpu: &platformv1.CPUConfig{Features: []string{"vmx"}}}},
		{"memory.size_mb", &platformv1.VMConfig{Memory: &platformv1.MemoryConfig{SizeMb: math.MaxInt32 + 1}}},
		{"memory.hugepages", &platformv1.VMConfig{Memory: &platformv1.MemoryConfig{Hugepages: true}}},
		{"memory.shared", &platformv1.VMConfig{Memory: &platformv1.MemoryConfig{Shared: true}}},
		{"disks", &platformv1.VMConfig{Disks: []*platformv1.DiskConfig{{}, {}}}},
		{"disks[0].id", disk(&platformv1.DiskConfig{Id: "disk-1"})},
		{"disks[0].path", disk(&platformv1.DiskConfig{Path: "/srv/images/base.qcow2"})},
		{"disks[0].type", disk(&platformv1.DiskConfig{Type: platformv1.DiskType_DISK_TYPE_RAW})},
		{"disks[0].bus", disk(&platformv1.DiskConfig{Bus: platformv1.DiskBus_DISK_BUS_NVME})},
		{"disks[0].size_gb", disk(&platformv1.DiskConfig{SizeGb: math.MaxInt32 + 1})},
		{"disks[0].readonly", disk(&platformv1.DiskConfig{Readonly: true})},
		{"disks[0].backing_file", disk(&platformv1.DiskConfig{BackingFile: "/srv/images/base.qcow2"})},
		{"networks", &platformv1.VMConfig{Networks: []*platformv1.NetworkConfig{{}, {}}}},
		{"networks[0].id", nic(&platformv1.NetworkConfig{Id: "nic-1"})},
		{"networks[0].model", nic(&platformv1.NetworkConfig{Model: platformv1.NetworkModel_NETWORK_MODEL_E1000})},
		{"networks[0].vlan", nic(&platformv1.NetworkConfig{Vlan: 100})},
		{"networks[0].bandwidth_limit_mbps", nic(&platformv1.NetworkConfig{BandwidthLimitMbps: 100})},
		{"graphics", &platformv1.VMConfig{Graphics: &platformv1.GraphicsConfig{Type: platformv1.GraphicsType_GRAPHICS_TYPE_VNC}}},
		{"graphics", &platformv1.VMConfig{Graphics: &platformv1.GraphicsConfig{Port: 5900}}},
		{"tpm.version", &platformv1.VMConfig{Tpm: &platformv1.TPMConfig{Enabled: true, Version: platformv1.TPMVersion_TPM_VERSION_1_2}}},
		{"tpm.device_path", &platformv1.VMConfig{Tpm: &platformv1.TPMConfig{Enabled: true, DevicePath: "/dev/tpm0"}}},
		{"tpm.state_dir", &platformv1.VMConfig{Tpm: &platformv1.TPMConfig{Enabled: true, StateDir: "/var/lib/tpm"}}},
		{"nvram", &platformv1.VMConfig{Nvram: []byte{1}}},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			svc, orch := newVMCreateService()
			tt.config.Name = "vm-refused"

			_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{Config: tt.config, Start: true})

			var refusal ErrVMCreateUnsupportedField
			require.True(t, errors.As(err, &refusal), "want ErrVMCreateUnsupportedField, got %v", err)
			assert.Equal(t, tt.field, refusal.Field)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Contains(t, err.Error(), "config."+tt.field+" ")
			assert.Empty(t, orch.recordedSpecs(), "a refused create must not reach the orchestrator")
		})
	}
}

func TestCreateVM_InvalidMACIsInvalidArgument(t *testing.T) {
	svc, orch := newVMCreateService()

	_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{
		Name:     "vm-mac",
		Networks: []*platformv1.NetworkConfig{{MacAddress: "not-a-mac"}},
	}})

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "not-a-mac")
	assert.Empty(t, orch.recordedSpecs())
}

func TestCreateVM_PlainOrchestratorRefusesASpec(t *testing.T) {
	svc := NewComputeGRPCService(logging.DefaultLogger(), &mockOrchestrator{})

	_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{
		Name:   "vm-plain",
		Memory: &platformv1.MemoryConfig{SizeMb: 2048},
	}})

	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestCreateVM_StartReportsTheRunningVM(t *testing.T) {
	svc, _ := newVMCreateService()

	resp, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{
		Config: &platformv1.VMConfig{Name: "vm-start"},
		Start:  true,
	})
	require.NoError(t, err)

	assert.Equal(t, platformv1.VMState_VM_STATE_RUNNING, resp.GetVm().GetState())
}

func TestCreateVM_StartFailureLeavesNoVM(t *testing.T) {
	svc, orch := newVMCreateService()
	orch.startFunc = func(context.Context, string) error { return compute.ErrDiskNotFound }

	_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{
		Config: &platformv1.VMConfig{Name: "vm-nostart"},
		Start:  true,
	})

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), "the start error's class is returned")
	assert.Contains(t, err.Error(), "failed to start VM")
	_, getErr := orch.Get(context.Background(), "vm-nostart-instance")
	assert.Error(t, getErr, "the VM that failed to start must be deleted")
}

func TestCreateVM_StartAndCleanupFailureReportsBoth(t *testing.T) {
	svc, orch := newVMCreateService()
	orch.startFunc = func(context.Context, string) error { return compute.ErrDiskNotFound }
	orch.deleteFunc = func(context.Context, string) error { return compute.ErrInvalidState }

	_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{
		Config: &platformv1.VMConfig{Name: "vm-stuck"},
		Start:  true,
	})

	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Contains(t, err.Error(), "deleting the instance also failed")
}

func TestCreateVM_LabelsFindTheVMByMatchLabels(t *testing.T) {
	svc, _ := newVMCreateService()
	for name, tier := range map[string]string{"vm-web": "web", "vm-db": "db"} {
		_, err := svc.CreateVM(context.Background(), &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{
			Name:   name,
			Labels: map[string]string{"tier": tier},
		}})
		require.NoError(t, err)
	}

	resp, err := svc.ListVMs(context.Background(), &platformv1.ListVMsRequest{
		Selector: &platformv1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
	})
	require.NoError(t, err)

	require.Len(t, resp.GetVms(), 1)
	assert.Equal(t, "vm-web", resp.GetVms()[0].GetConfig().GetName())
}
