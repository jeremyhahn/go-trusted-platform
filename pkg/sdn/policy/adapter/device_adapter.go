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
	devicedao "github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// HandlerFunc defines the function signature for network event handlers.
// Each handler receives a context for cancellation and the network event context
// containing device information and phase details.
type HandlerFunc func(ctx context.Context, event *device.NetworkEventContext) error

// AdapterConfig contains the configuration for creating a DeviceSDNAdapter.
// All fields except Logger are required dependencies.
type AdapterConfig struct {
	// Logger is the structured logger for the adapter. If nil, slog.Default() is used.
	Logger *slog.Logger

	// PolicyEngine is the SDN policy engine for managing port states and policies.
	PolicyEngine policy.PolicyEngine

	// ZoneFlowManager manages zone-keyed flow rules for device network phases.
	ZoneFlowManager *policy.ZoneFlowManager

	// EnrollmentHook handles device enrollment callbacks and port registration.
	EnrollmentHook *policy.SDNEnrollmentHook

	// ProfileDAO provides access to device profile data for network configuration.
	ProfileDAO devicedao.DeviceProfileDAO
}

// DeviceSDNAdapter implements the device.SDNIntegration interface, bridging
// device lifecycle events to SDN policy enforcement. It uses map-based dispatch
// for O(1) handler lookup when processing network events.
type DeviceSDNAdapter struct {
	logger          *slog.Logger
	policyEngine    policy.PolicyEngine
	zoneFlowManager *policy.ZoneFlowManager
	enrollmentHook  *policy.SDNEnrollmentHook
	profileDAO      devicedao.DeviceProfileDAO
	handlers        map[device.NetworkEvent]HandlerFunc
}

// NewDeviceSDNAdapter creates a new DeviceSDNAdapter with the provided configuration.
// Returns an error if any required dependency is nil.
func NewDeviceSDNAdapter(config AdapterConfig) (*DeviceSDNAdapter, error) {
	if config.PolicyEngine == nil {
		return nil, ErrPolicyEngineNil
	}

	if config.ZoneFlowManager == nil {
		return nil, ErrZoneFlowManagerNil
	}

	if config.EnrollmentHook == nil {
		return nil, ErrEnrollmentHookNil
	}

	if config.ProfileDAO == nil {
		return nil, ErrProfileDAONil
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	adapter := &DeviceSDNAdapter{
		logger:          logger,
		policyEngine:    config.PolicyEngine,
		zoneFlowManager: config.ZoneFlowManager,
		enrollmentHook:  config.EnrollmentHook,
		profileDAO:      config.ProfileDAO,
		handlers:        make(map[device.NetworkEvent]HandlerFunc, 4),
	}

	adapter.initHandlers()

	return adapter, nil
}

// initHandlers initializes the handler map for O(1) event dispatch.
// Handler implementations are defined in handlers.go.
func (a *DeviceSDNAdapter) initHandlers() {
	a.handlers[device.NetworkEventConnect] = a.handleConnect
	a.handlers[device.NetworkEventEnrolled] = a.handleEnrolled
	a.handlers[device.NetworkEventComplianceFail] = a.handleComplianceFail
	a.handlers[device.NetworkEventDisconnect] = a.handleDisconnect
}

// OnDeviceConnect is called when a device connects to the network.
// It dispatches to the connect handler via the handler map.
func (a *DeviceSDNAdapter) OnDeviceConnect(ctx context.Context, event *device.NetworkEventContext) error {
	return a.dispatch(ctx, device.NetworkEventConnect, event)
}

// OnDeviceEnrolled is called when a device successfully completes enrollment.
// It dispatches to the enrolled handler via the handler map.
func (a *DeviceSDNAdapter) OnDeviceEnrolled(ctx context.Context, event *device.NetworkEventContext) error {
	return a.dispatch(ctx, device.NetworkEventEnrolled, event)
}

// OnComplianceFail is called when a device fails compliance checks.
// It dispatches to the compliance failure handler via the handler map.
func (a *DeviceSDNAdapter) OnComplianceFail(ctx context.Context, event *device.NetworkEventContext) error {
	return a.dispatch(ctx, device.NetworkEventComplianceFail, event)
}

// ApplyNetworkPhase applies the network configuration for the specified phase.
// This method directly applies the phase without going through the handler dispatch,
// as it operates based on the phase specified in the event context.
func (a *DeviceSDNAdapter) ApplyNetworkPhase(ctx context.Context, event *device.NetworkEventContext) error {
	if err := event.Validate(); err != nil {
		return err
	}

	a.logger.Info("applying network phase",
		slog.String("port_id", event.PortID),
		slog.String("phase", event.Phase.String()),
		slog.String("device_id", event.DeviceID))

	return a.applyPhase(ctx, event)
}

// GetPortState retrieves the current state of an SDN port.
// Returns the current VLAN or network configuration state as a string.
func (a *DeviceSDNAdapter) GetPortState(ctx context.Context, portID string) (string, error) {
	if portID == "" {
		return "", device.ErrPortIDEmpty
	}

	state, err := a.policyEngine.GetPortState(portID)
	if err != nil {
		a.logger.Debug("failed to get port state",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
		return "", err
	}

	return state.String(), nil
}

// dispatch routes a network event to its registered handler.
// Returns ErrHandlerNotFound if no handler is registered for the event type.
func (a *DeviceSDNAdapter) dispatch(ctx context.Context, eventType device.NetworkEvent, event *device.NetworkEventContext) error {
	handler, ok := a.handlers[eventType]
	if !ok {
		a.logger.Warn("no handler registered for event type",
			slog.String("event_type", eventType.String()))
		return ErrHandlerNotFound
	}

	return handler(ctx, event)
}

// applyPhase applies the appropriate network configuration based on the phase.
// This uses a map-based dispatch pattern for O(1) lookup.
func (a *DeviceSDNAdapter) applyPhase(ctx context.Context, event *device.NetworkEventContext) error {
	phaseHandlers := map[device.NetworkPhase]func(context.Context, *device.NetworkEventContext) error{
		device.NetworkPhaseProvisioning: a.applyProvisioningPhase,
		device.NetworkPhaseTrusted:   a.applyProductionPhase,
		device.NetworkPhaseQuarantine:   a.applyQuarantinePhase,
	}

	handler, ok := phaseHandlers[event.Phase]
	if !ok {
		a.logger.Warn("invalid network phase",
			slog.String("phase", event.Phase.String()))
		return device.ErrInvalidNetworkPhase
	}

	return handler(ctx, event)
}

// applyProvisioningPhase configures the port for provisioning network access.
// The port is placed in zone.ZoneProvisioning; VLAN is resolved via ZoneIndex.
func (a *DeviceSDNAdapter) applyProvisioningPhase(ctx context.Context, event *device.NetworkEventContext) error {
	a.logger.Info("applying provisioning phase",
		slog.String("port_id", event.PortID),
		slog.String("mac", event.MAC))

	if err := a.zoneFlowManager.ApplyZoneFlows(ctx, event.PortID, zone.ZoneProvisioning); err != nil {
		a.logger.Error("failed to apply provisioning zone flows",
			slog.String("port_id", event.PortID),
			slog.String("error", err.Error()))
		return ErrFlowInstallFailed
	}

	if err := a.policyEngine.SetPortState(event.PortID, policy.PortStateProvisioning); err != nil {
		a.logger.Error("failed to set port state to provisioning",
			slog.String("port_id", event.PortID),
			slog.String("error", err.Error()))
		return err
	}

	return nil
}

// applyProductionPhase configures the port for production (trusted) network access.
// Enrolled+authorized devices are moved to zone.ZoneTrusted; VLAN is resolved via
// ZoneIndex. Profile-level ACLs are applied through the policy engine.
func (a *DeviceSDNAdapter) applyProductionPhase(ctx context.Context, event *device.NetworkEventContext) error {
	a.logger.Info("applying production phase",
		slog.String("port_id", event.PortID),
		slog.String("device_id", event.DeviceID))

	if event.Profile == nil {
		return ErrInvalidProfile
	}

	if event.Profile.GetPostEnrollmentNetworkConfig() == nil {
		return ErrNoTrustedNetwork
	}

	if err := a.zoneFlowManager.ApplyZoneFlows(ctx, event.PortID, zone.ZoneTrusted); err != nil {
		a.logger.Error("failed to apply trusted zone flows",
			slog.String("port_id", event.PortID),
			slog.String("error", err.Error()))
		return ErrFlowInstallFailed
	}

	if err := a.policyEngine.SetPortState(event.PortID, policy.PortStateAuthorized); err != nil {
		a.logger.Error("failed to set port state to authorized",
			slog.String("port_id", event.PortID),
			slog.String("error", err.Error()))
		return err
	}

	return nil
}

// applyQuarantinePhase configures the port for quarantine network access.
// The port is placed in zone.ZoneQuarantine; VLAN is resolved via ZoneIndex.
func (a *DeviceSDNAdapter) applyQuarantinePhase(ctx context.Context, event *device.NetworkEventContext) error {
	a.logger.Info("applying quarantine phase",
		slog.String("port_id", event.PortID),
		slog.String("mac", event.MAC),
		slog.String("reason", event.Reason))

	if err := a.zoneFlowManager.ApplyZoneFlows(ctx, event.PortID, zone.ZoneQuarantine); err != nil {
		a.logger.Error("failed to apply quarantine zone flows",
			slog.String("port_id", event.PortID),
			slog.String("error", err.Error()))
		return ErrFlowInstallFailed
	}

	if err := a.policyEngine.SetPortState(event.PortID, policy.PortStateQuarantined); err != nil {
		a.logger.Error("failed to set port state to quarantined",
			slog.String("port_id", event.PortID),
			slog.String("error", err.Error()))
		return err
	}

	return nil
}
