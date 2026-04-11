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
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// Proto-to-domain enum maps

// protoVMStateToState maps proto VMState to domain VMState.
var protoVMStateToState = map[platformv1.VMState]VMState{
	platformv1.VMState_VM_STATE_UNSPECIFIED: StateUnspecified,
	platformv1.VMState_VM_STATE_STOPPED:     StateStopped,
	platformv1.VMState_VM_STATE_STARTING:    StateStarting,
	platformv1.VMState_VM_STATE_RUNNING:     StateRunning,
	platformv1.VMState_VM_STATE_PAUSED:      StatePaused,
	platformv1.VMState_VM_STATE_STOPPING:    StateStopping,
	platformv1.VMState_VM_STATE_REBOOTING:   StateRebooting,
	platformv1.VMState_VM_STATE_MIGRATING:   StateMigrating,
	platformv1.VMState_VM_STATE_ERROR:       StateError,
}

// protoFirmwareTypeToFirmware maps proto FirmwareType to domain FirmwareType.
var protoFirmwareTypeToFirmware = map[platformv1.FirmwareType]FirmwareType{
	platformv1.FirmwareType_FIRMWARE_TYPE_UNSPECIFIED:      FirmwareUnspecified,
	platformv1.FirmwareType_FIRMWARE_TYPE_BIOS:             FirmwareBIOS,
	platformv1.FirmwareType_FIRMWARE_TYPE_UEFI:             FirmwareUEFI,
	platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT: FirmwareUEFISecureBoot,
}

// protoBootDeviceToBoot maps proto BootDevice to domain BootDevice.
var protoBootDeviceToBoot = map[platformv1.BootDevice]BootDevice{
	platformv1.BootDevice_BOOT_DEVICE_UNSPECIFIED: BootDeviceUnspecified,
	platformv1.BootDevice_BOOT_DEVICE_DISK:        BootDeviceDisk,
	platformv1.BootDevice_BOOT_DEVICE_CDROM:       BootDeviceCDROM,
	platformv1.BootDevice_BOOT_DEVICE_NETWORK:     BootDeviceNetwork,
}

// protoDiskBusToBus maps proto DiskBus to domain DiskBus.
var protoDiskBusToBus = map[platformv1.DiskBus]DiskBus{
	platformv1.DiskBus_DISK_BUS_UNSPECIFIED: DiskBusUnspecified,
	platformv1.DiskBus_DISK_BUS_IDE:         DiskBusIDE,
	platformv1.DiskBus_DISK_BUS_SATA:        DiskBusSATA,
	platformv1.DiskBus_DISK_BUS_SCSI:        DiskBusSCSI,
	platformv1.DiskBus_DISK_BUS_VIRTIO:      DiskBusVirtIO,
	platformv1.DiskBus_DISK_BUS_NVME:        DiskBusNVMe,
}

// protoDiskTypeToType maps proto DiskType to domain DiskType.
var protoDiskTypeToType = map[platformv1.DiskType]DiskType{
	platformv1.DiskType_DISK_TYPE_UNSPECIFIED: DiskTypeUnspecified,
	platformv1.DiskType_DISK_TYPE_RAW:         DiskTypeRAW,
	platformv1.DiskType_DISK_TYPE_QCOW2:       DiskTypeQCOW2,
	platformv1.DiskType_DISK_TYPE_VDI:         DiskTypeVDI,
	platformv1.DiskType_DISK_TYPE_VMDK:        DiskTypeVMDK,
}

// protoNetworkModelToModel maps proto NetworkModel to domain NetworkModel.
var protoNetworkModelToModel = map[platformv1.NetworkModel]NetworkModel{
	platformv1.NetworkModel_NETWORK_MODEL_UNSPECIFIED: NetworkModelUnspecified,
	platformv1.NetworkModel_NETWORK_MODEL_E1000:       NetworkModelE1000,
	platformv1.NetworkModel_NETWORK_MODEL_VIRTIO:      NetworkModelVirtIO,
	platformv1.NetworkModel_NETWORK_MODEL_RTL8139:     NetworkModelRTL8139,
}

// Domain-to-proto enum maps

// firmwareToProto maps domain FirmwareType to proto FirmwareType.
var firmwareToProto = map[FirmwareType]platformv1.FirmwareType{
	FirmwareUnspecified:    platformv1.FirmwareType_FIRMWARE_TYPE_UNSPECIFIED,
	FirmwareBIOS:           platformv1.FirmwareType_FIRMWARE_TYPE_BIOS,
	FirmwareUEFI:           platformv1.FirmwareType_FIRMWARE_TYPE_UEFI,
	FirmwareUEFISecureBoot: platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT,
}

// bootDeviceToProto maps domain BootDevice to proto BootDevice.
var bootDeviceToProto = map[BootDevice]platformv1.BootDevice{
	BootDeviceUnspecified: platformv1.BootDevice_BOOT_DEVICE_UNSPECIFIED,
	BootDeviceDisk:        platformv1.BootDevice_BOOT_DEVICE_DISK,
	BootDeviceCDROM:       platformv1.BootDevice_BOOT_DEVICE_CDROM,
	BootDeviceNetwork:     platformv1.BootDevice_BOOT_DEVICE_NETWORK,
}

// vmStateToProto maps domain VMState to proto VMState.
var vmStateToProto = map[VMState]platformv1.VMState{
	StateUnspecified: platformv1.VMState_VM_STATE_UNSPECIFIED,
	StateStopped:     platformv1.VMState_VM_STATE_STOPPED,
	StateStarting:    platformv1.VMState_VM_STATE_STARTING,
	StateRunning:     platformv1.VMState_VM_STATE_RUNNING,
	StatePaused:      platformv1.VMState_VM_STATE_PAUSED,
	StateStopping:    platformv1.VMState_VM_STATE_STOPPING,
	StateRebooting:   platformv1.VMState_VM_STATE_REBOOTING,
	StateMigrating:   platformv1.VMState_VM_STATE_MIGRATING,
	StateError:       platformv1.VMState_VM_STATE_ERROR,
}

// String-to-domain enum maps (for CLI input parsing)

// StringToFirmwareType maps user-facing firmware strings to domain FirmwareType.
var StringToFirmwareType = map[string]FirmwareType{
	"bios":             FirmwareBIOS,
	"uefi":             FirmwareUEFI,
	"uefi-secure-boot": FirmwareUEFISecureBoot,
}

// StringToBootDevice maps user-facing boot device strings to domain BootDevice.
var StringToBootDevice = map[string]BootDevice{
	"disk":    BootDeviceDisk,
	"cdrom":   BootDeviceCDROM,
	"network": BootDeviceNetwork,
}

// StringToVMState maps user-facing state strings to domain VMState.
var StringToVMState = map[string]VMState{
	"STOPPED":   StateStopped,
	"STARTING":  StateStarting,
	"RUNNING":   StateRunning,
	"PAUSED":    StatePaused,
	"STOPPING":  StateStopping,
	"REBOOTING": StateRebooting,
	"MIGRATING": StateMigrating,
	"ERROR":     StateError,
}

// ParseVMState parses a user-facing state string to a domain VMState.
// Returns the VMState and true if found, or StateUnspecified and false otherwise.
func ParseVMState(state string) (VMState, bool) {
	s, ok := StringToVMState[strings.ToUpper(strings.TrimSpace(state))]
	return s, ok
}

// VMStateFromProto converts a proto VMState enum to a domain VMState.
// Returns StateUnspecified for unknown values.
func VMStateFromProto(s platformv1.VMState) VMState {
	if state, ok := protoVMStateToState[s]; ok {
		return state
	}
	return StateUnspecified
}

// VMStateToProto converts a domain VMState to a proto VMState enum.
// Returns VMState_VM_STATE_UNSPECIFIED for unknown values.
func VMStateToProto(s VMState) platformv1.VMState {
	if proto, ok := vmStateToProto[s]; ok {
		return proto
	}
	return platformv1.VMState_VM_STATE_UNSPECIFIED
}

// FirmwareTypeFromProto converts a proto FirmwareType enum to a domain FirmwareType.
// Returns FirmwareUnspecified for unknown values.
func FirmwareTypeFromProto(f platformv1.FirmwareType) FirmwareType {
	if fw, ok := protoFirmwareTypeToFirmware[f]; ok {
		return fw
	}
	return FirmwareUnspecified
}

// Proto-to-domain converters

// VMFromProto converts a platformv1.VM to a domain VM.
func VMFromProto(p *platformv1.VM) *VM {
	if p == nil {
		return nil
	}

	state, ok := protoVMStateToState[p.State]
	if !ok {
		state = StateUnspecified
	}

	vm := &VM{
		ID:        p.Id,
		State:     state,
		HostID:    p.HostId,
		CreatedAt: timestampToTime(p.CreatedAt),
		UpdatedAt: timestampToTime(p.UpdatedAt),
	}

	if p.Config != nil {
		vm.Config = vmConfigFromProto(p.Config)
	}

	if p.Metrics != nil {
		vm.Metrics = vmMetricsFromProto(p.Metrics)
	}

	return vm
}

// vmConfigFromProto converts a platformv1.VMConfig to a domain VMConfig.
func vmConfigFromProto(p *platformv1.VMConfig) *VMConfig {
	if p == nil {
		return nil
	}

	fw, ok := protoFirmwareTypeToFirmware[p.Firmware]
	if !ok {
		fw = FirmwareUnspecified
	}

	bd, ok := protoBootDeviceToBoot[p.BootDevice]
	if !ok {
		bd = BootDeviceUnspecified
	}

	cfg := &VMConfig{
		Name:        p.Name,
		Description: p.Description,
		Firmware:    fw,
		BootDevice:  bd,
		SecureBoot:  p.SecureBoot,
		Labels:      p.Labels,
		Metadata:    p.Metadata,
	}

	if p.Cpu != nil {
		cfg.CPU = cpuConfigFromProto(p.Cpu)
	}

	if p.Memory != nil {
		cfg.Memory = memoryConfigFromProto(p.Memory)
	}

	if len(p.Disks) > 0 {
		cfg.Disks = make([]*DiskConfig, len(p.Disks))
		for i, d := range p.Disks {
			cfg.Disks[i] = diskConfigFromProto(d)
		}
	}

	if len(p.Networks) > 0 {
		cfg.Networks = make([]*NetworkConfig, len(p.Networks))
		for i, n := range p.Networks {
			cfg.Networks[i] = networkConfigFromProto(n)
		}
	}

	if p.Tpm != nil {
		cfg.TPM = tpmConfigFromProto(p.Tpm)
	}

	return cfg
}

// cpuConfigFromProto converts a platformv1.CPUConfig to a domain CPUConfig.
func cpuConfigFromProto(p *platformv1.CPUConfig) *CPUConfig {
	if p == nil {
		return nil
	}
	return &CPUConfig{
		Cores:    p.Cores,
		Sockets:  p.Sockets,
		Threads:  p.Threads,
		Model:    p.Model,
		Features: p.Features,
	}
}

// memoryConfigFromProto converts a platformv1.MemoryConfig to a domain MemoryConfig.
func memoryConfigFromProto(p *platformv1.MemoryConfig) *MemoryConfig {
	if p == nil {
		return nil
	}
	return &MemoryConfig{
		SizeMB:    p.SizeMb,
		Hugepages: p.Hugepages,
		Shared:    p.Shared,
	}
}

// diskConfigFromProto converts a platformv1.DiskConfig to a domain DiskConfig.
func diskConfigFromProto(p *platformv1.DiskConfig) *DiskConfig {
	if p == nil {
		return nil
	}

	dt, ok := protoDiskTypeToType[p.Type]
	if !ok {
		dt = DiskTypeUnspecified
	}

	db, ok := protoDiskBusToBus[p.Bus]
	if !ok {
		db = DiskBusUnspecified
	}

	return &DiskConfig{
		ID:       p.Id,
		Path:     p.Path,
		Type:     dt,
		Bus:      db,
		SizeGB:   p.SizeGb,
		Readonly: p.Readonly,
		Bootable: p.Bootable,
	}
}

// networkConfigFromProto converts a platformv1.NetworkConfig to a domain NetworkConfig.
func networkConfigFromProto(p *platformv1.NetworkConfig) *NetworkConfig {
	if p == nil {
		return nil
	}

	nm, ok := protoNetworkModelToModel[p.Model]
	if !ok {
		nm = NetworkModelUnspecified
	}

	return &NetworkConfig{
		ID:                 p.Id,
		Bridge:             p.Bridge,
		MACAddress:         p.MacAddress,
		Model:              nm,
		VLAN:               p.Vlan,
		BandwidthLimitMbps: p.BandwidthLimitMbps,
	}
}

// tpmConfigFromProto converts a platformv1.TPMConfig to a domain TPMConfig.
func tpmConfigFromProto(p *platformv1.TPMConfig) *TPMConfig {
	if p == nil {
		return nil
	}
	return &TPMConfig{
		Enabled:  p.Enabled,
		Emulated: p.Emulated,
	}
}

// vmMetricsFromProto converts a platformv1.VMMetrics to a domain VMMetrics.
func vmMetricsFromProto(p *platformv1.VMMetrics) *VMMetrics {
	if p == nil {
		return nil
	}
	return &VMMetrics{
		CPUUsagePercent:   p.CpuUsagePercent,
		MemoryUsedMB:     p.MemoryUsedMb,
		MemoryAvailableMB: p.MemoryAvailableMb,
		DiskReadBytes:    p.DiskReadBytes,
		DiskWriteBytes:   p.DiskWriteBytes,
		NetworkRxBytes:   p.NetworkRxBytes,
		NetworkTxBytes:   p.NetworkTxBytes,
		UptimeSeconds:    p.UptimeSeconds,
	}
}

// statusFromProto converts a platformv1.Status to a domain VMStatus.
func statusFromProto(p *platformv1.Status) *VMStatus {
	if p == nil {
		return nil
	}
	return &VMStatus{
		Success: p.Success,
		Message: p.Message,
	}
}

// Domain-to-proto converters

// createParamsToProto converts CreateVMParams to a platformv1.CreateVMRequest.
func createParamsToProto(params *CreateVMParams) *platformv1.CreateVMRequest {
	fw, ok := firmwareToProto[params.Firmware]
	if !ok {
		fw = platformv1.FirmwareType_FIRMWARE_TYPE_UNSPECIFIED
	}

	bd, ok := bootDeviceToProto[params.BootDevice]
	if !ok {
		bd = platformv1.BootDevice_BOOT_DEVICE_UNSPECIFIED
	}

	config := &platformv1.VMConfig{
		Name:       params.Name,
		Firmware:   fw,
		BootDevice: bd,
		Cpu:        &platformv1.CPUConfig{Cores: params.CPUs},
		Memory:     &platformv1.MemoryConfig{SizeMb: params.MemoryMB},
		Disks:      []*platformv1.DiskConfig{{SizeGb: params.DiskSizeGB, Bootable: true}},
		SecureBoot: params.SecureBoot,
		Tpm:        &platformv1.TPMConfig{Enabled: params.TPM},
		Labels:     params.Labels,
	}

	if params.Description != "" {
		config.Description = params.Description
	}

	if params.NetworkBridge != "" {
		config.Networks = []*platformv1.NetworkConfig{{Bridge: params.NetworkBridge}}
	}

	return &platformv1.CreateVMRequest{
		Config: config,
		Start:  params.Start,
	}
}

// listParamsToProto converts ListVMsParams to a platformv1.ListVMsRequest.
func listParamsToProto(params *ListVMsParams) *platformv1.ListVMsRequest {
	req := &platformv1.ListVMsRequest{
		Pagination: &platformv1.PaginationRequest{
			PageSize: params.PageSize,
			Page:     params.Page,
		},
	}

	if len(params.States) > 0 {
		protoStates := make([]platformv1.VMState, len(params.States))
		for i, s := range params.States {
			ps, ok := vmStateToProto[s]
			if !ok {
				ps = platformv1.VMState_VM_STATE_UNSPECIFIED
			}
			protoStates[i] = ps
		}
		req.States = protoStates
	}

	if len(params.Labels) > 0 {
		req.Selector = &platformv1.LabelSelector{
			MatchLabels: params.Labels,
		}
	}

	return req
}

// timestampToTime converts a protobuf Timestamp to time.Time.
func timestampToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}
