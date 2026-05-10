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

// Package bmc provides a client for BMC (Baseboard Management Controller) operations.
package bmc

import "time"

// PowerState represents the power state of a BMC-managed system.
type PowerState string

const (
	// PowerStateUnspecified indicates the power state is unknown.
	PowerStateUnspecified PowerState = "UNSPECIFIED"
	// PowerStateOn indicates the system is powered on.
	PowerStateOn PowerState = "ON"
	// PowerStateOff indicates the system is powered off.
	PowerStateOff PowerState = "OFF"
	// PowerStateUnknown indicates the power state could not be determined.
	PowerStateUnknown PowerState = "UNKNOWN"
)

// BootDevice represents the boot device for a BMC-managed system.
type BootDevice string

const (
	// BootDeviceUnspecified indicates no boot device is set.
	BootDeviceUnspecified BootDevice = "UNSPECIFIED"
	// BootDevicePXE indicates booting from PXE network.
	BootDevicePXE BootDevice = "PXE"
	// BootDeviceDisk indicates booting from local disk.
	BootDeviceDisk BootDevice = "DISK"
	// BootDeviceCDROM indicates booting from CD-ROM.
	BootDeviceCDROM BootDevice = "CDROM"
	// BootDeviceVirtualMedia indicates booting from virtual media.
	BootDeviceVirtualMedia BootDevice = "VIRTUAL_MEDIA"
	// BootDeviceNone indicates no boot device override.
	BootDeviceNone BootDevice = "NONE"
)

// ProvisioningState represents the provisioning workflow state.
type ProvisioningState string

const (
	// ProvisioningStateUnspecified indicates the provisioning state is unknown.
	ProvisioningStateUnspecified ProvisioningState = "UNSPECIFIED"
	// ProvisioningStatePending indicates provisioning is pending.
	ProvisioningStatePending ProvisioningState = "PENDING"
	// ProvisioningStateConnecting indicates the BMC is connecting.
	ProvisioningStateConnecting ProvisioningState = "CONNECTING"
	// ProvisioningStateSettingBoot indicates the boot device is being set.
	ProvisioningStateSettingBoot ProvisioningState = "SETTING_BOOT"
	// ProvisioningStateMountingISO indicates the ISO is being mounted.
	ProvisioningStateMountingISO ProvisioningState = "MOUNTING_ISO"
	// ProvisioningStatePoweringOn indicates the system is powering on.
	ProvisioningStatePoweringOn ProvisioningState = "POWERING_ON"
	// ProvisioningStateInstalling indicates the OS is being installed.
	ProvisioningStateInstalling ProvisioningState = "INSTALLING"
	// ProvisioningStateFinalizing indicates provisioning is finalizing.
	ProvisioningStateFinalizing ProvisioningState = "FINALIZING"
	// ProvisioningStateComplete indicates provisioning is complete.
	ProvisioningStateComplete ProvisioningState = "COMPLETE"
	// ProvisioningStateFailed indicates provisioning has failed.
	ProvisioningStateFailed ProvisioningState = "FAILED"
)

// SensorStatus represents the health status of a sensor.
type SensorStatus string

const (
	// SensorStatusOK indicates the sensor reading is within normal range.
	SensorStatusOK SensorStatus = "OK"
	// SensorStatusWarning indicates the sensor reading is in a warning range.
	SensorStatusWarning SensorStatus = "WARNING"
	// SensorStatusCritical indicates the sensor reading is in a critical range.
	SensorStatusCritical SensorStatus = "CRITICAL"
)

// Privilege represents a BMC user privilege level matching IPMI 2.0 values.
type Privilege string

const (
	// PrivilegeUnspecified indicates no privilege is set.
	PrivilegeUnspecified Privilege = "UNSPECIFIED"
	// PrivilegeCallback grants callback-only access.
	PrivilegeCallback Privilege = "CALLBACK"
	// PrivilegeUser grants read-only and limited operational commands.
	PrivilegeUser Privilege = "USER"
	// PrivilegeOperator grants most operational commands.
	PrivilegeOperator Privilege = "OPERATOR"
	// PrivilegeAdministrator grants full administrative access.
	PrivilegeAdministrator Privilege = "ADMINISTRATOR"
	// PrivilegeNoAccess revokes channel access for the user.
	PrivilegeNoAccess Privilege = "NO_ACCESS"
)

// PowerResponse represents the result of a power management operation.
type PowerResponse struct {
	// PreviousState is the power state before the operation.
	PreviousState PowerState `json:"previous_state" yaml:"previous_state"`
	// CurrentState is the power state after the operation.
	CurrentState PowerState `json:"current_state" yaml:"current_state"`
}

// VirtualMediaInfo represents the status of virtual media for a BMC-managed system.
type VirtualMediaInfo struct {
	// Mounted indicates whether virtual media is currently mounted.
	Mounted bool `json:"mounted" yaml:"mounted"`
	// ImageURL is the URL of the mounted image.
	ImageURL string `json:"image_url,omitempty" yaml:"image_url,omitempty"`
	// MediaType is the type of mounted media (e.g., "CD", "USB").
	MediaType string `json:"media_type,omitempty" yaml:"media_type,omitempty"`
}

// SensorReading represents a single sensor reading from the BMC.
type SensorReading struct {
	// Name is the sensor name.
	Name string `json:"name" yaml:"name"`
	// Value is the sensor reading value.
	Value float64 `json:"value" yaml:"value"`
	// Units is the measurement units (e.g., "degrees C", "RPM", "Volts").
	Units string `json:"units" yaml:"units"`
	// Status is the sensor health status.
	Status SensorStatus `json:"status" yaml:"status"`
}

// SystemInfo represents hardware and firmware information for a BMC-managed system.
type SystemInfo struct {
	// Manufacturer is the hardware manufacturer.
	Manufacturer string `json:"manufacturer" yaml:"manufacturer"`
	// Product is the product name or model.
	Product string `json:"product" yaml:"product"`
	// SerialNumber is the system serial number.
	SerialNumber string `json:"serial_number" yaml:"serial_number"`
	// FirmwareVersion is the BMC firmware version.
	FirmwareVersion string `json:"firmware_version" yaml:"firmware_version"`
	// BIOSVersion is the system BIOS version.
	BIOSVersion string `json:"bios_version" yaml:"bios_version"`
	// PowerState is the current system power state.
	PowerState PowerState `json:"power_state" yaml:"power_state"`
}

// ProvisioningStatus represents the current state of a provisioning workflow.
type ProvisioningStatus struct {
	// State is the current provisioning state.
	State ProvisioningState `json:"state" yaml:"state"`
	// Message is the human-readable status message.
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
	// StartedAt is when the provisioning workflow started.
	StartedAt time.Time `json:"started_at" yaml:"started_at"`
	// UpdatedAt is when the provisioning status was last updated.
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// ProvisionResult represents the result of starting a provisioning workflow.
type ProvisionResult struct {
	// ProvisionID is the unique identifier for the provisioning workflow.
	ProvisionID string `json:"provision_id" yaml:"provision_id"`
	// State is the initial provisioning state.
	State ProvisioningState `json:"state" yaml:"state"`
}

// CertificateInfo represents the details of a BMC web server certificate.
type CertificateInfo struct {
	// Subject is the certificate subject distinguished name.
	Subject string `json:"subject" yaml:"subject"`
	// Issuer is the certificate issuer distinguished name.
	Issuer string `json:"issuer" yaml:"issuer"`
	// SerialNumber is the certificate serial number in hex.
	SerialNumber string `json:"serial_number" yaml:"serial_number"`
	// NotBefore is the certificate validity start time.
	NotBefore time.Time `json:"not_before" yaml:"not_before"`
	// NotAfter is the certificate validity end time.
	NotAfter time.Time `json:"not_after" yaml:"not_after"`
	// DaysRemaining is the number of days until the certificate expires.
	DaysRemaining int32 `json:"days_remaining" yaml:"days_remaining"`
	// SubjectAlternativeNames contains the DNS and IP SANs.
	SubjectAlternativeNames []string `json:"subject_alternative_names,omitempty" yaml:"subject_alternative_names,omitempty"`
	// Fingerprint is the SHA-256 fingerprint of the certificate.
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
}

// User represents a BMC user account.
type User struct {
	// Slot is the IPMI user slot (1-based).
	Slot uint32 `json:"slot" yaml:"slot"`
	// Username is the account name.
	Username string `json:"username" yaml:"username"`
	// Enabled indicates whether the user can authenticate.
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Privilege is the user's access privilege level.
	Privilege Privilege `json:"privilege" yaml:"privilege"`
	// Channel is the IPMI channel index.
	Channel uint32 `json:"channel" yaml:"channel"`
}
