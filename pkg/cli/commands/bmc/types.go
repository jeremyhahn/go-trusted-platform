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

// Package bmc provides CLI commands for Baseboard Management Controller (BMC)
// operations using direct HTTP calls to the platformd REST API.
package bmc

// bmcFlags holds common flags for all BMC commands.
type bmcFlags struct {
	serverURL string
	profileID string
}

// PowerAction represents a BMC power action.
type PowerAction string

const (
	// PowerActionOn powers the server on.
	PowerActionOn PowerAction = "on"

	// PowerActionOff powers the server off.
	PowerActionOff PowerAction = "off"

	// PowerActionReset performs a hard reset.
	PowerActionReset PowerAction = "reset"

	// PowerActionCycle performs a power cycle (off then on).
	PowerActionCycle PowerAction = "cycle"
)

// powerRequest is the request body for power operations.
type powerRequest struct {
	Action PowerAction `json:"action"`
}

// powerStatusResponse is the response from the power status endpoint.
type powerStatusResponse struct {
	ProfileID  string `json:"profile_id"`
	PowerState string `json:"power_state"`
}

// powerActionResponse is the response from power action endpoints.
type powerActionResponse struct {
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
	Status    string `json:"status"`
}

// bootDeviceRequest is the request body for setting boot device.
type bootDeviceRequest struct {
	Device     string `json:"device"`
	Persistent bool   `json:"persistent"`
}

// bootDeviceResponse is the response from boot device endpoints.
type bootDeviceResponse struct {
	ProfileID  string `json:"profile_id"`
	Device     string `json:"device"`
	Persistent bool   `json:"persistent"`
}

// mountMediaRequest is the request body for mounting virtual media.
type mountMediaRequest struct {
	ISOURL string `json:"iso_url"`
}

// mediaStatusResponse is the response from virtual media status endpoint.
type mediaStatusResponse struct {
	ProfileID string `json:"profile_id"`
	Mounted   bool   `json:"mounted"`
	ISOURL    string `json:"iso_url,omitempty"`
}

// mediaActionResponse is the response from virtual media action endpoints.
type mediaActionResponse struct {
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
	Status    string `json:"status"`
	ISOURL    string `json:"iso_url,omitempty"`
}

// sensorReading represents a single sensor reading.
type sensorReading struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Units  string  `json:"units"`
	Status string  `json:"status"`
}

// sensorsResponse is the response from the sensors endpoint.
type sensorsResponse struct {
	ProfileID string          `json:"profile_id"`
	Sensors   []sensorReading `json:"sensors"`
}

// systemInfoResponse is the response from the system info endpoint.
type systemInfoResponse struct {
	ProfileID    string `json:"profile_id"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	BIOSVersion  string `json:"bios_version"`
	BMCVersion   string `json:"bmc_version"`
	PowerState   string `json:"power_state"`
	Health       string `json:"health"`
}

// provisionRequest is the request body for bare metal provisioning.
type provisionRequest struct {
	ISOURL string `json:"iso_url,omitempty"`
}

// provisionResponse is the response from the provision endpoint.
type provisionResponse struct {
	ProfileID string `json:"profile_id"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
}

// certReplaceResponse is the response from the cert replace command.
type certReplaceResponse struct {
	ProfileID string `json:"profile_id"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
}

// userActionResponse is the response from user management commands.
type userActionResponse struct {
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
	Username  string `json:"username,omitempty"`
	Slot      uint32 `json:"slot,omitempty"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
}
