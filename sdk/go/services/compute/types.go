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
