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

package adapter

import (
	"context"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// handleConnect handles device connection events.
// Places the device in the provisioning network for initial assessment.
func (a *DeviceSDNAdapter) handleConnect(ctx context.Context, event *device.NetworkEventContext) error {
	if event.PortID == "" {
		return device.ErrPortIDEmpty
	}

	if event.MAC == "" {
		return device.ErrMACEmpty
	}

	a.logger.Info("handling device connect",
		slog.String("port_id", event.PortID),
		slog.String("mac", event.MAC),
		slog.String("device_id", event.DeviceID))

	// Register the port with the enrollment hook for MAC-to-port mapping
	a.enrollmentHook.RegisterPort(event.MAC, event.PortID)

	// Apply provisioning phase for initial network access
	event.Phase = device.NetworkPhaseProvisioning
	return a.applyPhase(ctx, event)
}

// handleEnrolled handles device enrollment completion events.
// Transitions the device to production network based on its profile.
func (a *DeviceSDNAdapter) handleEnrolled(ctx context.Context, event *device.NetworkEventContext) error {
	if event.PortID == "" {
		return device.ErrPortIDEmpty
	}

	a.logger.Info("handling device enrolled",
		slog.String("port_id", event.PortID),
		slog.String("device_id", event.DeviceID),
		slog.String("serial", event.Serial))

	if event.Profile == nil {
		return ErrInvalidProfile
	}

	// Apply production phase for enrolled device
	event.Phase = device.NetworkPhaseProduction
	return a.applyPhase(ctx, event)
}

// handleComplianceFail handles compliance failure events.
// Moves the device to the quarantine network for isolation.
func (a *DeviceSDNAdapter) handleComplianceFail(ctx context.Context, event *device.NetworkEventContext) error {
	if event.PortID == "" {
		return device.ErrPortIDEmpty
	}

	if event.MAC == "" {
		return device.ErrMACEmpty
	}

	a.logger.Warn("handling compliance failure",
		slog.String("port_id", event.PortID),
		slog.String("mac", event.MAC),
		slog.String("device_id", event.DeviceID),
		slog.String("reason", event.Reason))

	// Apply quarantine phase for non-compliant device
	event.Phase = device.NetworkPhaseQuarantine
	return a.applyPhase(ctx, event)
}

// handleDisconnect handles device disconnection events.
// Removes flows and cleans up port state.
func (a *DeviceSDNAdapter) handleDisconnect(ctx context.Context, event *device.NetworkEventContext) error {
	if event.PortID == "" {
		return device.ErrPortIDEmpty
	}

	a.logger.Info("handling device disconnect",
		slog.String("port_id", event.PortID),
		slog.String("device_id", event.DeviceID))

	// Remove all flows for the port
	if err := a.vlanManager.RemoveFlows(event.PortID); err != nil {
		a.logger.Warn("failed to remove flows on disconnect",
			slog.String("port_id", event.PortID),
			slog.String("error", err.Error()))
		// Continue with state cleanup even if flow removal fails
	}

	// Set port state to unconnected
	if err := a.policyEngine.SetPortState(event.PortID, policy.PortStateUnconnected); err != nil {
		a.logger.Warn("failed to set port state to unconnected",
			slog.String("port_id", event.PortID),
			slog.String("error", err.Error()))
		return err
	}

	return nil
}
