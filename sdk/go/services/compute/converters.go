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

// VM Proto-to-domain enum maps

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

// VM Domain-to-proto enum maps

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

// VM String-to-domain enum maps (for CLI input parsing)

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

// VM Proto-to-domain converters

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

// VM Domain-to-proto converters

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

// Container Proto-to-domain enum maps

// protoContainerStateToState maps proto ContainerState to domain ContainerState.
var protoContainerStateToState = map[platformv1.ContainerState]ContainerState{
	platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED: ContainerStateUnspecified,
	platformv1.ContainerState_CONTAINER_STATE_CREATED:     ContainerStateCreated,
	platformv1.ContainerState_CONTAINER_STATE_STARTING:    ContainerStateStarting,
	platformv1.ContainerState_CONTAINER_STATE_RUNNING:     ContainerStateRunning,
	platformv1.ContainerState_CONTAINER_STATE_PAUSED:      ContainerStatePaused,
	platformv1.ContainerState_CONTAINER_STATE_STOPPING:    ContainerStateStopping,
	platformv1.ContainerState_CONTAINER_STATE_STOPPED:     ContainerStateStopped,
	platformv1.ContainerState_CONTAINER_STATE_EXITED:      ContainerStateExited,
	platformv1.ContainerState_CONTAINER_STATE_ERROR:       ContainerStateError,
}

// protoRestartPolicyToPolicy maps proto RestartPolicy to domain RestartPolicy.
var protoRestartPolicyToPolicy = map[platformv1.RestartPolicy]RestartPolicy{
	platformv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED:    RestartPolicyUnspecified,
	platformv1.RestartPolicy_RESTART_POLICY_NO:             RestartPolicyNo,
	platformv1.RestartPolicy_RESTART_POLICY_ON_FAILURE:     RestartPolicyOnFailure,
	platformv1.RestartPolicy_RESTART_POLICY_ALWAYS:         RestartPolicyAlways,
	platformv1.RestartPolicy_RESTART_POLICY_UNLESS_STOPPED: RestartPolicyUnlessStopped,
}

// Container Domain-to-proto enum maps

// containerStateToProto maps domain ContainerState to proto ContainerState.
var containerStateToProto = map[ContainerState]platformv1.ContainerState{
	ContainerStateUnspecified: platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED,
	ContainerStateCreated:     platformv1.ContainerState_CONTAINER_STATE_CREATED,
	ContainerStateStarting:    platformv1.ContainerState_CONTAINER_STATE_STARTING,
	ContainerStateRunning:     platformv1.ContainerState_CONTAINER_STATE_RUNNING,
	ContainerStatePaused:      platformv1.ContainerState_CONTAINER_STATE_PAUSED,
	ContainerStateStopping:    platformv1.ContainerState_CONTAINER_STATE_STOPPING,
	ContainerStateStopped:     platformv1.ContainerState_CONTAINER_STATE_STOPPED,
	ContainerStateExited:      platformv1.ContainerState_CONTAINER_STATE_EXITED,
	ContainerStateError:       platformv1.ContainerState_CONTAINER_STATE_ERROR,
}

// restartPolicyToProto maps domain RestartPolicy to proto RestartPolicy.
var restartPolicyToProto = map[RestartPolicy]platformv1.RestartPolicy{
	RestartPolicyUnspecified:  platformv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED,
	RestartPolicyNo:           platformv1.RestartPolicy_RESTART_POLICY_NO,
	RestartPolicyOnFailure:    platformv1.RestartPolicy_RESTART_POLICY_ON_FAILURE,
	RestartPolicyAlways:       platformv1.RestartPolicy_RESTART_POLICY_ALWAYS,
	RestartPolicyUnlessStopped: platformv1.RestartPolicy_RESTART_POLICY_UNLESS_STOPPED,
}

// Container String-to-domain enum maps (for CLI input parsing)

// StringToContainerState maps user-facing state strings to domain ContainerState.
var StringToContainerState = map[string]ContainerState{
	"CREATED":  ContainerStateCreated,
	"STARTING": ContainerStateStarting,
	"RUNNING":  ContainerStateRunning,
	"PAUSED":   ContainerStatePaused,
	"STOPPING": ContainerStateStopping,
	"STOPPED":  ContainerStateStopped,
	"EXITED":   ContainerStateExited,
	"ERROR":    ContainerStateError,
}

// StringToRestartPolicy maps user-facing restart policy strings to domain RestartPolicy.
var StringToRestartPolicy = map[string]RestartPolicy{
	"no":             RestartPolicyNo,
	"on-failure":     RestartPolicyOnFailure,
	"always":         RestartPolicyAlways,
	"unless-stopped": RestartPolicyUnlessStopped,
}

// ParseContainerState parses a user-facing state string to a domain ContainerState.
// Returns the ContainerState and true if found, or ContainerStateUnspecified and false otherwise.
func ParseContainerState(state string) (ContainerState, bool) {
	s, ok := StringToContainerState[strings.ToUpper(strings.TrimSpace(state))]
	return s, ok
}

// ParseRestartPolicy parses a user-facing restart policy string to a domain RestartPolicy.
// Returns the RestartPolicy and true if found, or RestartPolicyUnspecified and false otherwise.
func ParseRestartPolicy(policy string) (RestartPolicy, bool) {
	p, ok := StringToRestartPolicy[strings.ToLower(strings.TrimSpace(policy))]
	return p, ok
}

// Container Proto-to-domain converters

// ContainerStateFromProto converts a proto ContainerState enum to a domain ContainerState.
// Returns ContainerStateUnspecified for unknown values.
func ContainerStateFromProto(s platformv1.ContainerState) ContainerState {
	if state, ok := protoContainerStateToState[s]; ok {
		return state
	}
	return ContainerStateUnspecified
}

// ContainerStateToProto converts a domain ContainerState to a proto ContainerState enum.
// Returns CONTAINER_STATE_UNSPECIFIED for unknown values.
func ContainerStateToProto(s ContainerState) platformv1.ContainerState {
	if proto, ok := containerStateToProto[s]; ok {
		return proto
	}
	return platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED
}

// RestartPolicyFromProto converts a proto RestartPolicy enum to a domain RestartPolicy.
// Returns RestartPolicyUnspecified for unknown values.
func RestartPolicyFromProto(p platformv1.RestartPolicy) RestartPolicy {
	if policy, ok := protoRestartPolicyToPolicy[p]; ok {
		return policy
	}
	return RestartPolicyUnspecified
}

// RestartPolicyToProto converts a domain RestartPolicy to a proto RestartPolicy enum.
// Returns RESTART_POLICY_UNSPECIFIED for unknown values.
func RestartPolicyToProto(p RestartPolicy) platformv1.RestartPolicy {
	if proto, ok := restartPolicyToProto[p]; ok {
		return proto
	}
	return platformv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED
}

// ContainerFromProto converts a platformv1.Container to a domain Container.
func ContainerFromProto(p *platformv1.Container) *Container {
	if p == nil {
		return nil
	}

	state, ok := protoContainerStateToState[p.State]
	if !ok {
		state = ContainerStateUnspecified
	}

	c := &Container{
		ID:         p.Id,
		State:      state,
		CreatedAt:  timestampToTime(p.CreatedAt),
		StartedAt:  timestampToTime(p.StartedAt),
		FinishedAt: timestampToTime(p.FinishedAt),
		ExitCode:   p.ExitCode,
		HostID:     p.HostId,
	}

	if p.Config != nil {
		c.Config = ContainerConfigFromProto(p.Config)
	}

	if p.Metrics != nil {
		c.Metrics = containerMetricsFromProto(p.Metrics)
	}

	return c
}

// ContainerConfigFromProto converts a platformv1.ContainerConfig to a domain ContainerConfig.
func ContainerConfigFromProto(p *platformv1.ContainerConfig) *ContainerConfig {
	if p == nil {
		return nil
	}

	cfg := &ContainerConfig{
		Name:          p.Name,
		Image:         p.Image,
		ImageHash:     p.ImageHash,
		Command:       p.Command,
		Args:          p.Args,
		WorkingDir:    p.WorkingDir,
		Privileged:    p.Privileged,
		TpmAccess:     p.TpmAccess,
		Network:       p.Network,
		RestartPolicy: RestartPolicyFromProto(p.RestartPolicy),
		Capabilities:  p.Capabilities,
		Labels:        p.Labels,
		Metadata:      p.Metadata,
	}

	if len(p.Env) > 0 {
		cfg.Env = make([]*EnvVar, len(p.Env))
		for i, e := range p.Env {
			cfg.Env[i] = envVarFromProto(e)
		}
	}

	if len(p.Ports) > 0 {
		cfg.Ports = make([]*PortMapping, len(p.Ports))
		for i, pm := range p.Ports {
			cfg.Ports[i] = portMappingFromProto(pm)
		}
	}

	if len(p.Volumes) > 0 {
		cfg.Volumes = make([]*VolumeMount, len(p.Volumes))
		for i, v := range p.Volumes {
			cfg.Volumes[i] = volumeMountFromProto(v)
		}
	}

	if p.Resources != nil {
		cfg.Resources = resourceLimitsFromProto(p.Resources)
	}

	return cfg
}

// envVarFromProto converts a platformv1.EnvVar to a domain EnvVar.
func envVarFromProto(p *platformv1.EnvVar) *EnvVar {
	if p == nil {
		return nil
	}
	return &EnvVar{
		Name:  p.Name,
		Value: p.Value,
	}
}

// portMappingFromProto converts a platformv1.PortMapping to a domain PortMapping.
func portMappingFromProto(p *platformv1.PortMapping) *PortMapping {
	if p == nil {
		return nil
	}
	return &PortMapping{
		HostPort:      p.HostPort,
		ContainerPort: p.ContainerPort,
		Protocol:      p.Protocol,
		HostIP:        p.HostIp,
	}
}

// volumeMountFromProto converts a platformv1.VolumeMount to a domain VolumeMount.
func volumeMountFromProto(p *platformv1.VolumeMount) *VolumeMount {
	if p == nil {
		return nil
	}
	return &VolumeMount{
		Source:      p.Source,
		Destination: p.Destination,
		Readonly:    p.Readonly,
	}
}

// resourceLimitsFromProto converts a platformv1.ResourceLimits to a domain ResourceLimits.
func resourceLimitsFromProto(p *platformv1.ResourceLimits) *ResourceLimits {
	if p == nil {
		return nil
	}
	return &ResourceLimits{
		MaxMemoryMB: p.MaxMemoryMb,
		MaxCPUs:     p.MaxCpus,
	}
}

// containerMetricsFromProto converts a platformv1.ContainerMetrics to a domain ContainerMetrics.
func containerMetricsFromProto(p *platformv1.ContainerMetrics) *ContainerMetrics {
	if p == nil {
		return nil
	}
	return &ContainerMetrics{
		CPUUsagePercent: p.CpuUsagePercent,
		MemoryUsedMB:   p.MemoryUsedMb,
		MemoryLimitMB:  p.MemoryLimitMb,
		DiskReadBytes:  p.DiskReadBytes,
		DiskWriteBytes: p.DiskWriteBytes,
		NetworkRxBytes: p.NetworkRxBytes,
		NetworkTxBytes: p.NetworkTxBytes,
		UptimeSeconds:  p.UptimeSeconds,
	}
}

// containerStatusFromProto converts a platformv1.Status to a domain ContainerStatus.
func containerStatusFromProto(p *platformv1.Status) *ContainerStatus {
	if p == nil {
		return nil
	}
	return &ContainerStatus{
		Success: p.Success,
		Message: p.Message,
	}
}

// logEntryFromProto converts a platformv1.LogEntry to a domain LogEntry.
func logEntryFromProto(p *platformv1.LogEntry) *LogEntry {
	if p == nil {
		return nil
	}
	return &LogEntry{
		Timestamp: timestampToTime(p.Timestamp),
		Stream:    p.Source,
		Message:   p.Message,
	}
}

// Container Domain-to-proto converters

// createContainerParamsToProto converts CreateContainerParams to a platformv1.CreateContainerRequest.
func createContainerParamsToProto(params *CreateContainerParams) *platformv1.CreateContainerRequest {
	config := &platformv1.ContainerConfig{
		Name:         params.Name,
		Image:        params.Image,
		Command:      params.Command,
		Args:         params.Args,
		WorkingDir:   params.WorkingDir,
		Privileged:   params.Privileged,
		TpmAccess:    params.TpmAccess,
		Network:      params.Network,
		Capabilities: params.Capabilities,
		Labels:       params.Labels,
		Metadata:     params.Metadata,
	}

	rp, ok := restartPolicyToProto[params.RestartPolicy]
	if !ok {
		rp = platformv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED
	}
	config.RestartPolicy = rp

	if len(params.Env) > 0 {
		config.Env = make([]*platformv1.EnvVar, len(params.Env))
		for i, e := range params.Env {
			config.Env[i] = &platformv1.EnvVar{
				Name:  e.Name,
				Value: e.Value,
			}
		}
	}

	if len(params.Ports) > 0 {
		config.Ports = make([]*platformv1.PortMapping, len(params.Ports))
		for i, p := range params.Ports {
			config.Ports[i] = &platformv1.PortMapping{
				HostPort:      p.HostPort,
				ContainerPort: p.ContainerPort,
				Protocol:      p.Protocol,
				HostIp:        p.HostIP,
			}
		}
	}

	if len(params.Volumes) > 0 {
		config.Volumes = make([]*platformv1.VolumeMount, len(params.Volumes))
		for i, v := range params.Volumes {
			config.Volumes[i] = &platformv1.VolumeMount{
				Source:      v.Source,
				Destination: v.Destination,
				Readonly:    v.Readonly,
			}
		}
	}

	if params.Resources != nil {
		config.Resources = &platformv1.ResourceLimits{
			MaxMemoryMb: params.Resources.MaxMemoryMB,
			MaxCpus:     params.Resources.MaxCPUs,
		}
	}

	return &platformv1.CreateContainerRequest{
		Config: config,
		Start:  params.Start,
	}
}

// listContainersParamsToProto converts ListContainersParams to a platformv1.ListContainersRequest.
func listContainersParamsToProto(params *ListContainersParams) *platformv1.ListContainersRequest {
	req := &platformv1.ListContainersRequest{
		Pagination: &platformv1.PaginationRequest{
			PageSize: params.PageSize,
			Page:     params.Page,
		},
	}

	if len(params.States) > 0 {
		protoStates := make([]platformv1.ContainerState, len(params.States))
		for i, s := range params.States {
			ps, ok := containerStateToProto[s]
			if !ok {
				ps = platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED
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
