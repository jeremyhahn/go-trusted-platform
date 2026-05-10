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

import "time"

// VMState represents the lifecycle state of a virtual machine.
type VMState string

const (
	// StateUnspecified indicates the VM state is unknown.
	StateUnspecified VMState = "UNSPECIFIED"
	// StateStopped indicates the VM is stopped.
	StateStopped VMState = "STOPPED"
	// StateStarting indicates the VM is starting.
	StateStarting VMState = "STARTING"
	// StateRunning indicates the VM is running.
	StateRunning VMState = "RUNNING"
	// StatePaused indicates the VM is paused.
	StatePaused VMState = "PAUSED"
	// StateStopping indicates the VM is stopping.
	StateStopping VMState = "STOPPING"
	// StateRebooting indicates the VM is rebooting.
	StateRebooting VMState = "REBOOTING"
	// StateMigrating indicates the VM is being migrated.
	StateMigrating VMState = "MIGRATING"
	// StateError indicates the VM is in an error state.
	StateError VMState = "ERROR"
)

// FirmwareType represents the firmware type used by a virtual machine.
type FirmwareType string

const (
	// FirmwareUnspecified indicates no firmware type is set.
	FirmwareUnspecified FirmwareType = "UNSPECIFIED"
	// FirmwareBIOS indicates legacy BIOS firmware.
	FirmwareBIOS FirmwareType = "BIOS"
	// FirmwareUEFI indicates UEFI firmware.
	FirmwareUEFI FirmwareType = "UEFI"
	// FirmwareUEFISecureBoot indicates UEFI firmware with Secure Boot enabled.
	FirmwareUEFISecureBoot FirmwareType = "UEFI Secure Boot"
)

// BootDevice represents the boot device for a virtual machine.
type BootDevice string

const (
	// BootDeviceUnspecified indicates no boot device is set.
	BootDeviceUnspecified BootDevice = "UNSPECIFIED"
	// BootDeviceDisk indicates booting from disk.
	BootDeviceDisk BootDevice = "disk"
	// BootDeviceCDROM indicates booting from CD-ROM.
	BootDeviceCDROM BootDevice = "cdrom"
	// BootDeviceNetwork indicates booting from network (PXE).
	BootDeviceNetwork BootDevice = "network"
)

// DiskBus represents the bus type for a virtual disk.
type DiskBus string

const (
	// DiskBusUnspecified indicates no disk bus is set.
	DiskBusUnspecified DiskBus = "UNSPECIFIED"
	// DiskBusIDE indicates an IDE bus.
	DiskBusIDE DiskBus = "IDE"
	// DiskBusSATA indicates a SATA bus.
	DiskBusSATA DiskBus = "SATA"
	// DiskBusSCSI indicates a SCSI bus.
	DiskBusSCSI DiskBus = "SCSI"
	// DiskBusVirtIO indicates a VirtIO bus.
	DiskBusVirtIO DiskBus = "VirtIO"
	// DiskBusNVMe indicates an NVMe bus.
	DiskBusNVMe DiskBus = "NVMe"
)

// DiskType represents the format type of a virtual disk.
type DiskType string

const (
	// DiskTypeUnspecified indicates no disk type is set.
	DiskTypeUnspecified DiskType = "UNSPECIFIED"
	// DiskTypeRAW indicates a raw disk image.
	DiskTypeRAW DiskType = "RAW"
	// DiskTypeQCOW2 indicates a QCOW2 disk image.
	DiskTypeQCOW2 DiskType = "QCOW2"
	// DiskTypeVDI indicates a VDI disk image.
	DiskTypeVDI DiskType = "VDI"
	// DiskTypeVMDK indicates a VMDK disk image.
	DiskTypeVMDK DiskType = "VMDK"
)

// NetworkModel represents the network interface model.
type NetworkModel string

const (
	// NetworkModelUnspecified indicates no network model is set.
	NetworkModelUnspecified NetworkModel = "UNSPECIFIED"
	// NetworkModelE1000 indicates an Intel e1000 interface.
	NetworkModelE1000 NetworkModel = "e1000"
	// NetworkModelVirtIO indicates a VirtIO interface.
	NetworkModelVirtIO NetworkModel = "virtio"
	// NetworkModelRTL8139 indicates a Realtek RTL8139 interface.
	NetworkModelRTL8139 NetworkModel = "rtl8139"
)

// VM represents a virtual machine with its full state.
type VM struct {
	// ID is the unique identifier for the VM.
	ID string `json:"id" yaml:"id"`
	// State is the current lifecycle state.
	State VMState `json:"state" yaml:"state"`
	// Config is the VM configuration.
	Config *VMConfig `json:"config,omitempty" yaml:"config,omitempty"`
	// HostID is the host where the VM is running.
	HostID string `json:"host_id,omitempty" yaml:"host_id,omitempty"`
	// Metrics contains runtime metrics for the VM.
	Metrics *VMMetrics `json:"metrics,omitempty" yaml:"metrics,omitempty"`
	// CreatedAt is when the VM was created.
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	// UpdatedAt is when the VM was last updated.
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// VMConfig contains the configuration for a virtual machine.
type VMConfig struct {
	// Name is the VM name.
	Name string `json:"name" yaml:"name"`
	// Description is the VM description.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Firmware is the firmware type.
	Firmware FirmwareType `json:"firmware" yaml:"firmware"`
	// BootDevice is the boot device.
	BootDevice BootDevice `json:"boot_device" yaml:"boot_device"`
	// CPU is the CPU configuration.
	CPU *CPUConfig `json:"cpu,omitempty" yaml:"cpu,omitempty"`
	// Memory is the memory configuration.
	Memory *MemoryConfig `json:"memory,omitempty" yaml:"memory,omitempty"`
	// Disks is the list of disk configurations.
	Disks []*DiskConfig `json:"disks,omitempty" yaml:"disks,omitempty"`
	// Networks is the list of network configurations.
	Networks []*NetworkConfig `json:"networks,omitempty" yaml:"networks,omitempty"`
	// TPM is the TPM configuration.
	TPM *TPMConfig `json:"tpm,omitempty" yaml:"tpm,omitempty"`
	// SecureBoot indicates whether Secure Boot is enabled.
	SecureBoot bool `json:"secure_boot" yaml:"secure_boot"`
	// Labels are key-value metadata labels.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	// Metadata are key-value metadata entries.
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// CPUConfig contains CPU configuration for a VM.
type CPUConfig struct {
	// Cores is the number of CPU cores.
	Cores uint32 `json:"cores" yaml:"cores"`
	// Sockets is the number of CPU sockets.
	Sockets uint32 `json:"sockets,omitempty" yaml:"sockets,omitempty"`
	// Threads is the number of CPU threads per core.
	Threads uint32 `json:"threads,omitempty" yaml:"threads,omitempty"`
	// Model is the CPU model name.
	Model string `json:"model,omitempty" yaml:"model,omitempty"`
	// Features is the list of CPU features.
	Features []string `json:"features,omitempty" yaml:"features,omitempty"`
}

// MemoryConfig contains memory configuration for a VM.
type MemoryConfig struct {
	// SizeMB is the memory size in megabytes.
	SizeMB uint64 `json:"size_mb" yaml:"size_mb"`
	// Hugepages indicates whether hugepages are enabled.
	Hugepages bool `json:"hugepages" yaml:"hugepages"`
	// Shared indicates whether shared memory is enabled.
	Shared bool `json:"shared" yaml:"shared"`
}

// DiskConfig contains disk configuration for a VM.
type DiskConfig struct {
	// ID is the disk identifier.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Path is the disk image path.
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
	// Type is the disk image format.
	Type DiskType `json:"type" yaml:"type"`
	// Bus is the disk bus type.
	Bus DiskBus `json:"bus" yaml:"bus"`
	// SizeGB is the disk size in gigabytes.
	SizeGB uint64 `json:"size_gb" yaml:"size_gb"`
	// Readonly indicates whether the disk is read-only.
	Readonly bool `json:"readonly" yaml:"readonly"`
	// Bootable indicates whether the disk is bootable.
	Bootable bool `json:"bootable" yaml:"bootable"`
}

// NetworkConfig contains network configuration for a VM.
type NetworkConfig struct {
	// ID is the network interface identifier.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Bridge is the network bridge name.
	Bridge string `json:"bridge,omitempty" yaml:"bridge,omitempty"`
	// MACAddress is the MAC address.
	MACAddress string `json:"mac_address,omitempty" yaml:"mac_address,omitempty"`
	// Model is the network interface model.
	Model NetworkModel `json:"model" yaml:"model"`
	// VLAN is the VLAN ID.
	VLAN uint32 `json:"vlan,omitempty" yaml:"vlan,omitempty"`
	// BandwidthLimitMbps is the bandwidth limit in Mbps.
	BandwidthLimitMbps uint64 `json:"bandwidth_limit_mbps,omitempty" yaml:"bandwidth_limit_mbps,omitempty"`
}

// TPMConfig contains TPM configuration for a VM.
type TPMConfig struct {
	// Enabled indicates whether the vTPM is enabled.
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Emulated indicates whether the TPM is emulated.
	Emulated bool `json:"emulated,omitempty" yaml:"emulated,omitempty"`
}

// VMMetrics contains runtime metrics for a VM.
type VMMetrics struct {
	// CPUUsagePercent is the CPU usage percentage.
	CPUUsagePercent float64 `json:"cpu_usage_percent" yaml:"cpu_usage_percent"`
	// MemoryUsedMB is the used memory in megabytes.
	MemoryUsedMB uint64 `json:"memory_used_mb" yaml:"memory_used_mb"`
	// MemoryAvailableMB is the available memory in megabytes.
	MemoryAvailableMB uint64 `json:"memory_available_mb" yaml:"memory_available_mb"`
	// DiskReadBytes is the total disk read bytes.
	DiskReadBytes uint64 `json:"disk_read_bytes" yaml:"disk_read_bytes"`
	// DiskWriteBytes is the total disk write bytes.
	DiskWriteBytes uint64 `json:"disk_write_bytes" yaml:"disk_write_bytes"`
	// NetworkRxBytes is the total network receive bytes.
	NetworkRxBytes uint64 `json:"network_rx_bytes" yaml:"network_rx_bytes"`
	// NetworkTxBytes is the total network transmit bytes.
	NetworkTxBytes uint64 `json:"network_tx_bytes" yaml:"network_tx_bytes"`
	// UptimeSeconds is the VM uptime in seconds.
	UptimeSeconds uint32 `json:"uptime_seconds" yaml:"uptime_seconds"`
}

// CreateVMParams contains parameters for creating a new VM.
type CreateVMParams struct {
	// Name is the VM name.
	Name string
	// Description is the VM description.
	Description string
	// Firmware is the firmware type.
	Firmware FirmwareType
	// BootDevice is the boot device.
	BootDevice BootDevice
	// CPUs is the number of CPU cores.
	CPUs uint32
	// MemoryMB is the memory size in megabytes.
	MemoryMB uint64
	// DiskSizeGB is the disk size in gigabytes.
	DiskSizeGB uint64
	// SecureBoot indicates whether Secure Boot is enabled.
	SecureBoot bool
	// TPM indicates whether the vTPM is enabled.
	TPM bool
	// Start indicates whether to start the VM after creation.
	Start bool
	// NetworkBridge is the network bridge name.
	NetworkBridge string
	// Labels are key-value metadata labels.
	Labels map[string]string
}

// StopVMParams contains parameters for stopping a VM.
type StopVMParams struct {
	// ID is the VM identifier.
	ID string
	// Force indicates whether to force stop.
	Force bool
	// TimeoutSeconds is the timeout before force stop.
	TimeoutSeconds uint32
}

// DeleteVMParams contains parameters for deleting a VM.
type DeleteVMParams struct {
	// ID is the VM identifier.
	ID string
	// DeleteDisks indicates whether to delete associated disks.
	DeleteDisks bool
}

// ListVMsParams contains parameters for listing VMs.
type ListVMsParams struct {
	// States filters by VM states.
	States []VMState
	// Labels filters by label key-value pairs.
	Labels map[string]string
	// PageSize is the number of results per page.
	PageSize uint32
	// Page is the page number.
	Page uint32
}

// ListVMsResult contains the result of listing VMs.
type ListVMsResult struct {
	// VMs is the list of virtual machines.
	VMs []*VM `json:"vms" yaml:"vms"`
	// TotalItems is the total number of items.
	TotalItems uint32 `json:"total_items" yaml:"total_items"`
	// TotalPages is the total number of pages.
	TotalPages uint32 `json:"total_pages" yaml:"total_pages"`
}

// VMStatus represents the status response from a VM operation.
type VMStatus struct {
	// Success indicates whether the operation succeeded.
	Success bool `json:"success" yaml:"success"`
	// Message is the status message.
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
}

// Container Types

// ContainerState represents the lifecycle state of a container.
type ContainerState string

const (
	// ContainerStateUnspecified indicates the container state is unknown.
	ContainerStateUnspecified ContainerState = "UNSPECIFIED"
	// ContainerStateCreated indicates the container has been created.
	ContainerStateCreated ContainerState = "CREATED"
	// ContainerStateStarting indicates the container is starting.
	ContainerStateStarting ContainerState = "STARTING"
	// ContainerStateRunning indicates the container is running.
	ContainerStateRunning ContainerState = "RUNNING"
	// ContainerStatePaused indicates the container is paused.
	ContainerStatePaused ContainerState = "PAUSED"
	// ContainerStateStopping indicates the container is stopping.
	ContainerStateStopping ContainerState = "STOPPING"
	// ContainerStateStopped indicates the container is stopped.
	ContainerStateStopped ContainerState = "STOPPED"
	// ContainerStateExited indicates the container has exited.
	ContainerStateExited ContainerState = "EXITED"
	// ContainerStateError indicates the container is in an error state.
	ContainerStateError ContainerState = "ERROR"
)

// RestartPolicy represents a container restart policy.
type RestartPolicy string

const (
	// RestartPolicyUnspecified indicates no restart policy is set.
	RestartPolicyUnspecified RestartPolicy = "UNSPECIFIED"
	// RestartPolicyNo indicates the container should not be restarted.
	RestartPolicyNo RestartPolicy = "no"
	// RestartPolicyOnFailure indicates the container should restart on failure.
	RestartPolicyOnFailure RestartPolicy = "on-failure"
	// RestartPolicyAlways indicates the container should always restart.
	RestartPolicyAlways RestartPolicy = "always"
	// RestartPolicyUnlessStopped indicates the container should restart unless stopped.
	RestartPolicyUnlessStopped RestartPolicy = "unless-stopped"
)

// Container represents a container with its full state.
type Container struct {
	// ID is the unique identifier for the container.
	ID string `json:"id" yaml:"id"`
	// Config is the container configuration.
	Config *ContainerConfig `json:"config,omitempty" yaml:"config,omitempty"`
	// State is the current lifecycle state.
	State ContainerState `json:"state" yaml:"state"`
	// CreatedAt is when the container was created.
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	// StartedAt is when the container was last started.
	StartedAt time.Time `json:"started_at,omitempty" yaml:"started_at,omitempty"`
	// FinishedAt is when the container last finished.
	FinishedAt time.Time `json:"finished_at,omitempty" yaml:"finished_at,omitempty"`
	// ExitCode is the container exit code.
	ExitCode int32 `json:"exit_code,omitempty" yaml:"exit_code,omitempty"`
	// HostID is the host where the container is running.
	HostID string `json:"host_id,omitempty" yaml:"host_id,omitempty"`
	// Metrics contains runtime metrics for the container.
	Metrics *ContainerMetrics `json:"metrics,omitempty" yaml:"metrics,omitempty"`
}

// ContainerConfig contains the configuration for a container.
type ContainerConfig struct {
	// Name is the container name.
	Name string `json:"name" yaml:"name"`
	// Image is the container image.
	Image string `json:"image" yaml:"image"`
	// ImageHash is the image content hash.
	ImageHash string `json:"image_hash,omitempty" yaml:"image_hash,omitempty"`
	// Env is the list of environment variables.
	Env []*EnvVar `json:"env,omitempty" yaml:"env,omitempty"`
	// Labels are key-value metadata labels.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	// Ports is the list of port mappings.
	Ports []*PortMapping `json:"ports,omitempty" yaml:"ports,omitempty"`
	// Volumes is the list of volume mounts.
	Volumes []*VolumeMount `json:"volumes,omitempty" yaml:"volumes,omitempty"`
	// Command is the command to run.
	Command []string `json:"command,omitempty" yaml:"command,omitempty"`
	// Args is the command arguments.
	Args []string `json:"args,omitempty" yaml:"args,omitempty"`
	// WorkingDir is the working directory inside the container.
	WorkingDir string `json:"working_dir,omitempty" yaml:"working_dir,omitempty"`
	// Privileged indicates whether the container runs in privileged mode.
	Privileged bool `json:"privileged" yaml:"privileged"`
	// TpmAccess indicates whether the host TPM is mounted into the container.
	TpmAccess bool `json:"tpm_access" yaml:"tpm_access"`
	// Network is the network mode.
	Network string `json:"network,omitempty" yaml:"network,omitempty"`
	// RestartPolicy is the container restart policy.
	RestartPolicy RestartPolicy `json:"restart_policy,omitempty" yaml:"restart_policy,omitempty"`
	// Resources is the resource limits.
	Resources *ResourceLimits `json:"resources,omitempty" yaml:"resources,omitempty"`
	// Capabilities is the list of Linux capabilities to add.
	Capabilities []string `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	// Metadata are key-value metadata entries.
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// EnvVar represents an environment variable.
type EnvVar struct {
	// Name is the variable name.
	Name string `json:"name" yaml:"name"`
	// Value is the variable value.
	Value string `json:"value" yaml:"value"`
}

// PortMapping represents a container port mapping.
type PortMapping struct {
	// HostPort is the port on the host.
	HostPort uint32 `json:"host_port" yaml:"host_port"`
	// ContainerPort is the port inside the container.
	ContainerPort uint32 `json:"container_port" yaml:"container_port"`
	// Protocol is the protocol (tcp, udp).
	Protocol string `json:"protocol" yaml:"protocol"`
	// HostIP is the host IP to bind.
	HostIP string `json:"host_ip,omitempty" yaml:"host_ip,omitempty"`
}

// VolumeMount represents a container volume mount.
type VolumeMount struct {
	// Source is the host path or volume name.
	Source string `json:"source" yaml:"source"`
	// Destination is the mount path inside the container.
	Destination string `json:"destination" yaml:"destination"`
	// Readonly indicates whether the mount is read-only.
	Readonly bool `json:"readonly" yaml:"readonly"`
}

// ResourceLimits contains resource limits for a container.
type ResourceLimits struct {
	// MaxMemoryMB is the maximum memory in megabytes.
	MaxMemoryMB uint64 `json:"max_memory_mb,omitempty" yaml:"max_memory_mb,omitempty"`
	// MaxCPUs is the maximum number of CPUs.
	MaxCPUs uint32 `json:"max_cpus,omitempty" yaml:"max_cpus,omitempty"`
}

// ContainerMetrics contains runtime metrics for a container.
type ContainerMetrics struct {
	// CPUUsagePercent is the CPU usage percentage.
	CPUUsagePercent float64 `json:"cpu_usage_percent" yaml:"cpu_usage_percent"`
	// MemoryUsedMB is the used memory in megabytes.
	MemoryUsedMB uint64 `json:"memory_used_mb" yaml:"memory_used_mb"`
	// MemoryLimitMB is the memory limit in megabytes.
	MemoryLimitMB uint64 `json:"memory_limit_mb,omitempty" yaml:"memory_limit_mb,omitempty"`
	// DiskReadBytes is the total disk read bytes.
	DiskReadBytes uint64 `json:"disk_read_bytes" yaml:"disk_read_bytes"`
	// DiskWriteBytes is the total disk write bytes.
	DiskWriteBytes uint64 `json:"disk_write_bytes" yaml:"disk_write_bytes"`
	// NetworkRxBytes is the total network receive bytes.
	NetworkRxBytes uint64 `json:"network_rx_bytes" yaml:"network_rx_bytes"`
	// NetworkTxBytes is the total network transmit bytes.
	NetworkTxBytes uint64 `json:"network_tx_bytes" yaml:"network_tx_bytes"`
	// UptimeSeconds is the container uptime in seconds.
	UptimeSeconds uint32 `json:"uptime_seconds" yaml:"uptime_seconds"`
}

// LogEntry represents a container log entry.
type LogEntry struct {
	// Timestamp is when the log entry was generated.
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	// Stream is the log stream (stdout, stderr).
	Stream string `json:"stream,omitempty" yaml:"stream,omitempty"`
	// Message is the log message.
	Message string `json:"message" yaml:"message"`
}

// ContainerStatus represents the status response from a container operation.
type ContainerStatus struct {
	// Success indicates whether the operation succeeded.
	Success bool `json:"success" yaml:"success"`
	// Message is the status message.
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
}

// CreateContainerParams contains parameters for creating a new container.
type CreateContainerParams struct {
	// Name is the container name.
	Name string
	// Image is the container image.
	Image string
	// Env is the list of environment variables.
	Env []*EnvVar
	// Labels are key-value metadata labels.
	Labels map[string]string
	// Ports is the list of port mappings.
	Ports []*PortMapping
	// Volumes is the list of volume mounts.
	Volumes []*VolumeMount
	// Command is the command to run.
	Command []string
	// Args is the command arguments.
	Args []string
	// WorkingDir is the working directory inside the container.
	WorkingDir string
	// Privileged indicates whether the container runs in privileged mode.
	Privileged bool
	// TpmAccess indicates whether the host TPM is mounted into the container.
	TpmAccess bool
	// Network is the network mode.
	Network string
	// RestartPolicy is the container restart policy.
	RestartPolicy RestartPolicy
	// Resources is the resource limits.
	Resources *ResourceLimits
	// Capabilities is the list of Linux capabilities to add.
	Capabilities []string
	// Metadata are key-value metadata entries.
	Metadata map[string]string
	// Start indicates whether to start the container after creation.
	Start bool
}

// StopContainerParams contains parameters for stopping a container.
type StopContainerParams struct {
	// ID is the container identifier.
	ID string
	// TimeoutSeconds is the timeout before force stop.
	TimeoutSeconds uint32
}

// DeleteContainerParams contains parameters for deleting a container.
type DeleteContainerParams struct {
	// ID is the container identifier.
	ID string
	// Force indicates whether to force delete.
	Force bool
	// DeleteVolumes indicates whether to delete associated volumes.
	DeleteVolumes bool
}

// ListContainersParams contains parameters for listing containers.
type ListContainersParams struct {
	// States filters by container states.
	States []ContainerState
	// Labels filters by label key-value pairs.
	Labels map[string]string
	// PageSize is the number of results per page.
	PageSize uint32
	// Page is the page number.
	Page uint32
}

// ListContainersResult contains the result of listing containers.
type ListContainersResult struct {
	// Containers is the list of containers.
	Containers []*Container `json:"containers" yaml:"containers"`
	// TotalItems is the total number of items.
	TotalItems uint32 `json:"total_items" yaml:"total_items"`
	// TotalPages is the total number of pages.
	TotalPages uint32 `json:"total_pages" yaml:"total_pages"`
}

// LabelSelector contains label selection criteria for filtering.
type LabelSelector struct {
	// MatchLabels filters by exact label matches.
	MatchLabels map[string]string `json:"match_labels,omitempty" yaml:"match_labels,omitempty"`
}
