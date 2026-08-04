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

package policy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Compliance control IDs attached to zone-related audit events.
// SC-7  — Boundary Protection (inter-zone isolation via OpenFlow deny rules).
// SC-4  — Information in Shared Resources (per-tenant micro-zone isolation).
// AC-4  — Information Flow Enforcement (inter-zone flow matrix).
//
// See docs/architecture/reference-network.md §Compliance for the authoritative
// mapping of zone enforcement to these controls.
const (
	complianceSC7 = "SC-7" // Boundary Protection
	complianceSC4 = "SC-4" // Information in Shared Resources
	complianceAC4 = "AC-4" // Information Flow Enforcement
)

// complianceAttr returns an slog.Attr whose value is a comma-joined list of
// NIST control IDs applicable to the calling event. Using a single string
// attribute keeps the log line compact while remaining grep-able.
func complianceAttr(controls ...string) slog.Attr {
	v := ""
	for i, c := range controls {
		if i > 0 {
			v += ","
		}
		v += c
	}
	return slog.String("compliance", v)
}

// ErrNoQuarantineZone is returned when the resolved zone list has no zone
// carrying LifecycleRoleQuarantine.
type ErrNoQuarantineZone struct{}

// Error implements the error interface.
func (ErrNoQuarantineZone) Error() string {
	return "policy: quarantine manager: no zone carries lifecycle role quarantine"
}

// ErrUnknownDevicePort is returned when a ViolationEvent arrives for a device
// that has no registered OVS port mapping.
type ErrUnknownDevicePort struct {
	DeviceID uint64
}

// Error implements the error interface.
func (e ErrUnknownDevicePort) Error() string {
	return fmt.Sprintf("policy: quarantine manager: no port registered for device %d", e.DeviceID)
}

// DeviceStateStore is the minimal write surface the QuarantineManager needs to
// persist device state changes. Callers supply a concrete implementation backed
// by the datastore layer.
type DeviceStateStore interface {
	// SaveDevice persists the updated device record.
	SaveDevice(ctx context.Context, device *entities.Device) error

	// GetDevice retrieves the device record by ID.
	GetDevice(ctx context.Context, id uint64) (*entities.Device, error)
}

// QuarantineManagerConfig configures the QuarantineManager.
type QuarantineManagerConfig struct {
	// PolicyEngine is the SDN policy engine used to block ports and apply
	// zone flows.
	PolicyEngine PolicyEngine

	// ZoneFlowManager applies per-zone OpenFlow rules on a port.
	ZoneFlowManager *ZoneFlowManager

	// ResolvedZones is the validated, merged zone list for the current
	// platform configuration. ZoneForRole resolves the quarantine zone from
	// this list.
	ResolvedZones []zone.ZoneConfig

	// DeviceStateStore persists device state changes.
	DeviceStateStore DeviceStateStore

	// Logger is the structured logger; uses slog.Default() when nil.
	Logger *slog.Logger
}

// portRegistry maps device IDs to OVS port IDs. It is injected by callers
// (enrollment hooks, vNIC placement) so the manager does not need to maintain
// its own ARP/DHCP table.
type portRegistry interface {
	// PortForDevice returns the OVS port name registered for deviceID.
	PortForDevice(deviceID uint64) (portName string, ok bool)
}

// QuarantineManager consumes ViolationEvents emitted by the attestation
// verification path and drives the port-level + device-level lifecycle
// transitions that enforce the quarantine loop:
//
//   - non-severe violation   → quarantine zone (restricted OpenFlow) + DeviceStateQuarantined
//   - severe / cert revoked  → port admin-down (blocked) + DeviceStateSuspended
//   - re-attestation success → restore profile zone + prior device state
//
// The manager is stateless beyond its configuration; all state is persisted
// through DeviceStateStore and the SDN policy engine.
type QuarantineManager struct {
	engine          PolicyEngine
	zoneFlowManager *ZoneFlowManager
	resolvedZones   []zone.ZoneConfig
	store           DeviceStateStore
	logger          *slog.Logger
}

// NewQuarantineManager constructs a QuarantineManager from config.
// Returns an error when required fields are missing.
func NewQuarantineManager(cfg QuarantineManagerConfig) (*QuarantineManager, error) {
	if cfg.PolicyEngine == nil {
		return nil, &MessageError{Msg: "policy: quarantine manager: policy engine is required"}
	}
	if cfg.DeviceStateStore == nil {
		return nil, &MessageError{Msg: "policy: quarantine manager: device state store is required"}
	}
	if len(cfg.ResolvedZones) == 0 {
		return nil, &MessageError{Msg: "policy: quarantine manager: resolved zones are required"}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &QuarantineManager{
		engine:          cfg.PolicyEngine,
		zoneFlowManager: cfg.ZoneFlowManager,
		resolvedZones:   cfg.ResolvedZones,
		store:           cfg.DeviceStateStore,
		logger:          logger,
	}, nil
}

// HandleViolation processes a ViolationEvent. The caller must supply portID —
// the OVS port name for the device — which is resolved externally via the
// enrollment hook's port registry.
//
// Compliance: SC-7 (inter-zone boundary enforcement), AC-4 (flow enforcement).
//
// Branches:
//   - Severe or cert-revoked → BlockPort + DeviceStateSuspended
//   - Non-severe (warning) → quarantine zone flows + DeviceStateQuarantined
func (qm *QuarantineManager) HandleViolation(ctx context.Context, ev *entities.ViolationEvent, portID string) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	if portID == "" {
		return ErrUnknownDevicePort{DeviceID: ev.DeviceID}
	}

	// Quarantine transition: SC-7 boundary enforcement, AC-4 flow enforcement.
	qm.logger.Warn("handling device violation",
		slog.Uint64("device_id", ev.DeviceID),
		slog.String("severity", ev.Severity.String()),
		slog.String("source", ev.Source.String()),
		slog.String("port_id", portID),
		slog.String("detail", ev.Detail),
		slog.String("zone", string(zone.ZoneQuarantine)),
		complianceAttr(complianceSC7, complianceAC4))

	device, err := qm.store.GetDevice(ctx, ev.DeviceID)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("policy: quarantine manager: get device %d", ev.DeviceID), Err: err}
	}

	switch ev.Severity {
	case entities.ViolationSeveritySevere:
		return qm.suspendDevice(ctx, device, portID, ev.Detail)
	case entities.ViolationSeverityWarning:
		return qm.quarantineDevice(ctx, device, portID, ev.Detail)
	default:
		return entities.ErrInvalidViolationSeverity{Value: ev.Severity}
	}
}

// HandleRestoreAttestation is called when re-attestation succeeds for a
// previously quarantined device. It restores the device to its prior zone and
// prior state (typically DeviceStateAttested).
//
// Compliance: SC-7 (zone boundary restored), AC-4 (flow matrix re-applied).
func (qm *QuarantineManager) HandleRestoreAttestation(ctx context.Context, deviceID uint64, portID string) error {
	if portID == "" {
		return ErrUnknownDevicePort{DeviceID: deviceID}
	}

	device, err := qm.store.GetDevice(ctx, deviceID)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("policy: quarantine manager: get device %d", deviceID), Err: err}
	}

	if device.State != entities.DeviceStateQuarantined {
		return &MessageError{Msg: fmt.Sprintf("policy: quarantine manager: device %d is not quarantined (state=%s)", deviceID, device.State)}
	}

	restoreZone := zone.Zone(device.PriorZone)
	restoreState := device.PriorState
	if restoreState == "" {
		restoreState = entities.DeviceStateAttested
	}

	// Re-attestation: restoring zone boundary — SC-7, AC-4.
	qm.logger.Info("restoring quarantined device",
		slog.Uint64("device_id", deviceID),
		slog.String("port_id", portID),
		slog.String("zone", string(restoreZone)),
		slog.String("restore_state", restoreState.String()),
		complianceAttr(complianceSC7, complianceAC4))

	// Apply the prior zone flows (or trusted zone as default).
	if qm.zoneFlowManager != nil && restoreZone != "" {
		if err := qm.zoneFlowManager.ApplyZoneFlows(ctx, portID, restoreZone); err != nil {
			return &WrappedError{Msg: "policy: quarantine manager: restore zone flows", Err: err}
		}
	}

	if err := device.Transition(restoreState); err != nil {
		return &WrappedError{Msg: "policy: quarantine manager: restore device state", Err: err}
	}
	device.PriorState = ""
	device.PriorZone = ""
	device.StateReason = "re-attestation passed"

	if err := qm.store.SaveDevice(ctx, device); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("policy: quarantine manager: save device %d", deviceID), Err: err}
	}

	qm.logger.Info("device restored from quarantine",
		slog.Uint64("device_id", deviceID),
		slog.String("new_state", device.State.String()),
		slog.String("zone", string(restoreZone)),
		complianceAttr(complianceSC7, complianceAC4))

	return nil
}

// quarantineDevice handles a non-severe violation: moves the port to the
// quarantine zone and records DeviceStateQuarantined.
//
// Compliance: SC-7 (boundary transition to quarantine), AC-4 (flow enforcement).
func (qm *QuarantineManager) quarantineDevice(ctx context.Context, device *entities.Device, portID, detail string) error {
	// Resolve the quarantine zone from the lifecycle role.
	quarantineZone, err := zone.ZoneForRole(qm.resolvedZones, zone.LifecycleRoleQuarantine)
	if err != nil {
		return ErrNoQuarantineZone{}
	}

	if qm.zoneFlowManager == nil {
		return &MessageError{Msg: "policy: quarantine manager: zone flow manager is required for quarantine"}
	}

	// Apply quarantine zone flows (VLAN + OpenFlow rules) via ZoneFlowManager.
	if err := qm.zoneFlowManager.ApplyZoneFlows(ctx, portID, quarantineZone); err != nil {
		return &WrappedError{Msg: "policy: quarantine manager: apply quarantine zone flows", Err: err}
	}

	// Also update the policy engine port state.
	if err := qm.engine.SetPortState(portID, PortStateQuarantined); err != nil {
		qm.logger.Warn("failed to set port state to quarantined",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
		// Non-fatal: zone flows are the primary enforcement mechanism.
	}

	// Record prior state + zone for later restore; transition device state.
	device.PriorState = device.State
	device.PriorZone = qm.currentZoneFor(device)

	if err := device.Transition(entities.DeviceStateQuarantined); err != nil {
		return &WrappedError{Msg: "policy: quarantine manager: device state transition", Err: err}
	}
	device.StateReason = detail

	if err := qm.store.SaveDevice(ctx, device); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("policy: quarantine manager: save device %d", device.ID), Err: err}
	}

	// Zone boundary enforcement audit: SC-7 (boundary protection), AC-4 (flow enforcement).
	qm.logger.Info("device quarantined",
		slog.Uint64("device_id", device.ID),
		slog.String("port_id", portID),
		slog.String("zone", string(quarantineZone)),
		slog.String("reason", detail),
		complianceAttr(complianceSC7, complianceAC4))

	return nil
}

// suspendDevice handles a severe violation or certificate revocation: blocks
// the port admin-down and records DeviceStateSuspended.
//
// Compliance: SC-7 (hard boundary — port blocked), AC-4 (flow enforcement — DROP all).
func (qm *QuarantineManager) suspendDevice(ctx context.Context, device *entities.Device, portID, detail string) error {
	// BlockPort calls installBlockedFlows (DROP rules) and SetPortState admin-down
	// via OVSDB — the existing semantics in Engine.BlockPort are unchanged.
	if err := qm.engine.BlockPort(portID); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("policy: quarantine manager: block port %s", portID), Err: err}
	}

	if err := device.Transition(entities.DeviceStateSuspended); err != nil {
		return &WrappedError{Msg: "policy: quarantine manager: device state transition", Err: err}
	}
	device.StateReason = detail

	if err := qm.store.SaveDevice(ctx, device); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("policy: quarantine manager: save device %d", device.ID), Err: err}
	}

	// Hard port block: SC-7 (boundary protection), AC-4 (information flow — DROP all).
	qm.logger.Warn("device suspended (severe violation)",
		slog.Uint64("device_id", device.ID),
		slog.String("port_id", portID),
		slog.String("zone", string(zone.ZoneQuarantine)),
		slog.String("reason", detail),
		complianceAttr(complianceSC7, complianceAC4))

	return nil
}

// currentZoneFor returns the zone the device is currently in, derived from
// its policy zone or the profile's post-enrollment zone annotation.
// Returns an empty string when no zone information is available.
func (qm *QuarantineManager) currentZoneFor(device *entities.Device) string {
	// Check if the port has a known zone in the ZoneFlowManager.
	// The ZoneFlowManager's portZoneMap is not directly accessible from here,
	// but if PriorZone was already set (nested quarantine) preserve it.
	if device.PriorZone != "" {
		return device.PriorZone
	}
	// Derive from trusted zone as the default post-enrollment zone.
	return string(zone.ZoneTrusted)
}
