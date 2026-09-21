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

import "errors"

var (
	// ErrISONotFound is returned when the ISO file cannot be found
	ErrISONotFound = errors.New("ISO file not found")

	// ErrDiskNotFound is returned when the disk file cannot be found
	ErrDiskNotFound = errors.New("disk file not found")

	// ErrOVMFNotFound is returned when OVMF firmware files cannot be found
	ErrOVMFNotFound = errors.New("OVMF firmware not found")

	// ErrTPMNotRunning is returned when TPM socket is not available
	ErrTPMNotRunning = errors.New("TPM socket not available")

	// ErrQEMUFailed is returned when QEMU execution fails
	ErrQEMUFailed = errors.New("QEMU execution failed")

	// ErrInvalidMode is returned when an invalid boot mode is specified
	ErrInvalidMode = errors.New("invalid boot mode: must be 'install', 'boot', or 'pxe'")

	// ErrWorkDirNotFound is returned when the work directory does not exist
	ErrWorkDirNotFound = errors.New("work directory not found")

	// ErrNVRAMNotFound is returned when NVRAM file cannot be found
	ErrNVRAMNotFound = errors.New("NVRAM file not found")

	// ErrVMAlreadyRunning is returned when attempting to start an already running VM
	ErrVMAlreadyRunning = errors.New("VM is already running")

	// ErrVMNotRunning is returned when attempting to stop a VM that is not running
	ErrVMNotRunning = errors.New("VM is not running")

	// ErrKeysNotFound is returned when the secure boot keys directory doesn't exist
	// or doesn't contain the required key files
	ErrKeysNotFound = errors.New("secure boot keys not found")

	// ErrEnrollmentFailed is returned when the secure boot key enrollment process fails
	ErrEnrollmentFailed = errors.New("secure boot enrollment failed")

	// ErrScriptNotFound is returned when the enrollment script is not found
	ErrScriptNotFound = errors.New("enrollment script not found")

	// ErrInvalidConfiguration is returned when the configuration is invalid
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrFIDO2NotSupported is returned when QEMU doesn't support the requested FIDO2 mode
	ErrFIDO2NotSupported = errors.New("FIDO2 mode not supported by this QEMU build")

	// ErrUnsupportedArch is returned when Config.Arch names no profile
	ErrUnsupportedArch = errors.New("unsupported guest architecture")

	// ErrFirmwareMissing is returned when the architecture needs a firmware
	// image (Config.Firmware) and it is unset or absent
	ErrFirmwareMissing = errors.New("firmware image not found")

	// ErrUnsupportedBootMode is returned when the architecture cannot boot
	// in the requested mode
	ErrUnsupportedBootMode = errors.New("boot mode not supported for this architecture")

	// ErrCanoKeyNotAvailable is returned when CanoKey support is not available
	ErrCanoKeyNotAvailable = errors.New("CanoKey not available (requires libcanokey-qemu)")

	// ErrOVSNotAvailable is returned when OVS is not running or not installed
	ErrOVSNotAvailable = errors.New("OVS not available or not running")

	// ErrOVSBridgeNotFound is returned when the specified OVS bridge does not exist
	ErrOVSBridgeNotFound = errors.New("OVS bridge not found")

	// ErrOVSConnectionFailed is returned when connection to OVSDB fails
	ErrOVSConnectionFailed = errors.New("failed to connect to OVSDB")

	// ErrInvalidOVSConfig is returned when OVS configuration is invalid
	ErrInvalidOVSConfig = errors.New("invalid OVS configuration")

	// ErrTAPCreationFailed is returned when TAP device creation fails
	ErrTAPCreationFailed = errors.New("TAP device creation failed")

	// ErrOVSPortCreationFailed is returned when OVS port creation fails
	ErrOVSPortCreationFailed = errors.New("OVS port creation failed")

	// ErrPXENetworkRequired is returned when PXE boot is requested without network
	ErrPXENetworkRequired = errors.New("PXE boot requires network configuration")
)

// BootMode defines the mode for starting the VM
type BootMode string

const (
	// BootModeInstall boots from the ISO for installation
	BootModeInstall BootMode = "install"

	// BootModeBoot boots from the disk
	BootModeBoot BootMode = "boot"

	// BootModePXE boots from the network via PXE
	BootModePXE BootMode = "pxe"
)

// String returns the string representation of BootMode
func (m BootMode) String() string {
	return string(m)
}

// IsValid returns true if the boot mode is valid
func (m BootMode) IsValid() bool {
	return m == BootModeInstall || m == BootModeBoot || m == BootModePXE
}
