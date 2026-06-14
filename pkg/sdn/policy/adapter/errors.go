// Copyright 2025 Jeremy Hahn, Automate The Things, LLC
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-trusted-platform is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-trusted-platform. If not, see <https://www.gnu.org/licenses/>.
//
// For commercial licensing options, please contact: licensing@automatethethings.com
//
// SPDX-FileType: SOURCE
// SPDX-FileCopyrightText: 2025 Jeremy Hahn, Automate The Things, LLC
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

// Package adapter provides integration between the SDN policy engine and device
// enrollment services. It handles network event routing, flow installation, and
// device lifecycle management within the software-defined network infrastructure.
package adapter

import "errors"

// Dependency injection errors indicate missing required components during
// adapter initialization or operation.
var (
	// ErrPolicyEngineNil indicates the policy engine dependency was not provided.
	// The policy engine is required for evaluating network access policies.
	ErrPolicyEngineNil = errors.New("policy engine is nil")

	// ErrZoneFlowManagerNil indicates the zone flow manager dependency was not provided.
	// The zone flow manager is required for installing and managing OVS flow rules.
	ErrZoneFlowManagerNil = errors.New("zone flow manager is nil")

	// ErrProfileDAONil indicates the profile data access object was not provided.
	// The profile DAO is required for retrieving device network profiles.
	ErrProfileDAONil = errors.New("profile DAO is nil")

	// ErrEnrollmentHookNil indicates the enrollment hook dependency was not provided.
	// The enrollment hook is required for device enrollment callbacks.
	ErrEnrollmentHookNil = errors.New("enrollment hook is nil")
)

// Flow installation errors indicate failures when configuring OVS flow rules
// or managing port registrations within the SDN fabric.
var (
	// ErrFlowInstallFailed indicates OVS flow rule installation failed.
	// This may occur due to OVS connectivity issues or invalid flow parameters.
	ErrFlowInstallFailed = errors.New("failed to install OVS flows")

	// ErrPortNotRegistered indicates the specified port is not registered with the SDN.
	// Ports must be registered before flow rules can be installed.
	ErrPortNotRegistered = errors.New("port not registered with SDN")
)

// Device lifecycle errors indicate failures during device enrollment,
// activation, or state transitions within the trusted platform.
var (
	// ErrDeviceNotEnrolled indicates the device has not completed enrollment.
	// Devices must be enrolled before network access can be granted.
	ErrDeviceNotEnrolled = errors.New("device not enrolled")

	// ErrActivationFailed indicates device activation could not be completed.
	// This may occur due to policy violations or missing attestation data.
	ErrActivationFailed = errors.New("device activation failed")
)

// Event handling errors indicate failures when processing network events
// or routing events to the appropriate handlers.
var (
	// ErrUnknownEventType indicates an unrecognized network event was received.
	// Only registered event types can be processed by the adapter.
	ErrUnknownEventType = errors.New("unknown network event type")

	// ErrHandlerNotFound indicates no handler is registered for the event type.
	// Event handlers must be registered before events can be processed.
	ErrHandlerNotFound = errors.New("handler not found for event")
)

// Profile validation errors indicate device profiles are missing required
// configuration for network access assignment.
var (
	// ErrInvalidProfile indicates the device profile is invalid or incomplete.
	// Profiles must contain valid network configuration to assign access.
	ErrInvalidProfile = errors.New("device profile is invalid or incomplete")

	// ErrNoTrustedNetwork indicates the profile is missing post-enrollment (trusted) network config.
	// Trusted network configuration is required for authorized device access.
	ErrNoTrustedNetwork = errors.New("profile missing trusted network config")

	// ErrNoQuarantineNetwork indicates the profile is missing quarantine network config.
	// Quarantine network configuration is required for untrusted device isolation.
	ErrNoQuarantineNetwork = errors.New("profile missing quarantine network config")
)

// Event context validation errors indicate missing required fields in
// network event context structures.
var (
	// ErrPortIDEmpty indicates the port ID field is empty in the event context.
	// A valid port ID is required to identify the SDN port for flow operations.
	ErrPortIDEmpty = errors.New("port ID is empty")

	// ErrMACEmpty indicates the MAC address field is empty in the event context.
	// A valid MAC address is required for flow matching and port registration.
	ErrMACEmpty = errors.New("MAC address is empty")

	// ErrInvalidNetworkPhase indicates an invalid or unknown network phase was specified.
	// Valid phases are: provisioning, production, and quarantine.
	ErrInvalidNetworkPhase = errors.New("invalid network phase")
)
