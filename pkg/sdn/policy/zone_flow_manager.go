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
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ZoneFlowManagerConfig configures the ZoneFlowManager.
type ZoneFlowManagerConfig struct {
	// BridgeName is the OVS bridge to manage.
	BridgeName string

	// FlowController manages OpenFlow rules.
	FlowController FlowController

	// PortController manages OVS port operations (VLAN, state).
	// Required for VLAN tagging via OVSDB.
	PortController OVSPortController

	// Plan is the network plan (sdn.Config.Plan()). Every zone VLAN and
	// port-class VLAN list is resolved through it. Required.
	Plan *netplan.Plan

	// GeneratorSet provides per-zone OpenFlow template generators. When nil
	// a default GeneratorSet with zero-value zone configs is constructed.
	GeneratorSet *zoneflows.GeneratorSet

	// Terminal is the action allow rules end in; see zoneflows.Terminal.
	// It applies to the default GeneratorSet and to the matrix rules.
	Terminal zoneflows.Terminal

	// Matrix is the compiled inter-zone allow/deny matrix. When the zero
	// value is supplied, no inter-zone matrix rules are installed.
	Matrix zone.Matrix

	// Zones is the full resolved zone list, required for CompileMatrixRules.
	Zones []zone.ZoneConfig

	// Logger is the structured logger; uses slog.Default() when nil.
	Logger *slog.Logger
}

// ZoneFlowManager manages per-zone OpenFlow rules. It is zone-keyed: every flow
// operation resolves the target zone to a VLAN through the network plan, then
// installs per-zone template flows plus inter-zone matrix rules derived from
// the compiled zone.Matrix. A port is either an access port on one zone
// (ApplyZoneFlows) or a trunk carrying a port class (ApplyPortClassFlows).
type ZoneFlowManager struct {
	mu             sync.RWMutex
	logger         *slog.Logger
	bridgeName     string
	flowController FlowController
	portController OVSPortController
	plan           *netplan.Plan
	generators     *zoneflows.GeneratorSet
	terminal       zoneflows.Terminal
	matrix         zone.Matrix
	zones          []zone.ZoneConfig
	portZoneMap    map[string]zone.Zone      // portID → current zone (access ports)
	portClassMap   map[string]zone.PortClass // portID → current class (trunk ports)
	portVLANMap    map[string]uint16         // portID → access or native VLAN
}

// NewZoneFlowManager constructs a ZoneFlowManager from the supplied config.
// Returns an error when required fields (BridgeName, FlowController,
// PortController, Plan) are missing.
func NewZoneFlowManager(cfg ZoneFlowManagerConfig) (*ZoneFlowManager, error) {
	if cfg.BridgeName == "" {
		return nil, ErrInvalidBridgeName
	}
	if cfg.FlowController == nil {
		return nil, &MessageError{Msg: "zone flow manager: flow controller is required"}
	}
	if cfg.PortController == nil {
		return nil, &MessageError{Msg: "zone flow manager: port controller is required"}
	}
	if cfg.Plan == nil {
		return nil, ErrNetworkPlanRequired{Operation: "zone flow manager"}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	generators := cfg.GeneratorSet
	if generators == nil {
		generators = zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
			BridgeName: cfg.BridgeName,
			Terminal:   cfg.Terminal,
		})
	}

	return &ZoneFlowManager{
		logger:         logger,
		bridgeName:     cfg.BridgeName,
		flowController: cfg.FlowController,
		portController: cfg.PortController,
		plan:           cfg.Plan,
		generators:     generators,
		terminal:       cfg.Terminal,
		matrix:         cfg.Matrix,
		zones:          cfg.Zones,
		portZoneMap:    make(map[string]zone.Zone),
		portClassMap:   make(map[string]zone.PortClass),
		portVLANMap:    make(map[string]uint16),
	}, nil
}

// ApplyZoneFlows makes portID an access port on zone z. It resolves the VLAN
// for z through the plan, sets the port VLAN via OVSDB (clearing any trunk),
// removes any existing OpenFlow rules, installs the per-zone template flows,
// and appends inter-zone matrix rules.
func (m *ZoneFlowManager) ApplyZoneFlows(ctx context.Context, portID string, z zone.Zone) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	vlanID, err := m.resolveVLAN(z)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Port zone application audit: AC-4 (information flow enforcement).
	m.logger.Info("applying zone flows",
		slog.String("port_id", portID),
		slog.String("zone", string(z)),
		slog.Uint64("vlan", uint64(vlanID)),
		complianceAttr(complianceAC4))

	// Remove existing flows for this port before installing new ones.
	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, portID); err != nil {
		m.logger.Warn("failed to delete existing flows",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
	}

	// Set VLAN tag via OVSDB.
	if err := m.portController.SetPortVLAN(ctx, portID, int64(vlanID)); err != nil {
		return &WrappedError{Msg: "zone flow manager: set port VLAN", Err: err}
	}

	// Install per-zone template flows as a single batch. The port is an
	// access port, so its frames reach the flow tables untagged.
	templateFlows := m.generators.Generate(portID, z, zoneflows.Untagged(vlanID))
	for _, f := range templateFlows {
		m.logger.Debug("installing template flow",
			slog.String("port_id", portID),
			slog.String("zone", string(z)),
			slog.Int("priority", f.Priority),
			slog.String("match", f.Match),
			slog.String("actions", f.Actions))
	}
	if err := m.flowController.InstallFlows(m.bridgeName, templateFlows); err != nil {
		m.logger.Error("failed to install template flows",
			slog.String("port_id", portID),
			slog.String("zone", string(z)),
			slog.String("error", err.Error()))
		return &SentinelCauseError{Sentinel: ErrFlowInstallFailed, Cause: err}
	}

	// Install inter-zone matrix rules as a single batch when matrix and
	// network summaries are available: the shared tagged-ingress rules plus
	// this port's untagged-ingress rules for its zone.
	matrixFlows := append(m.compileMatrixFlows(), m.compilePortMatrixFlows(portID, z)...)
	for _, f := range matrixFlows {
		m.logger.Debug("installing matrix flow",
			slog.String("port_id", portID),
			slog.String("zone", string(z)),
			slog.Int("priority", f.Priority),
			slog.String("match", f.Match),
			slog.String("actions", f.Actions))
	}
	if err := m.flowController.InstallFlows(m.bridgeName, matrixFlows); err != nil {
		m.logger.Warn("failed to install matrix flows",
			slog.String("port_id", portID),
			slog.String("zone", string(z)),
			slog.String("error", err.Error()))
		// Matrix rules are best-effort; do not abort on failure. A batch
		// partial failure only skips the rejected rules on the switch.
	}

	m.portZoneMap[portID] = z
	delete(m.portClassMap, portID)
	m.portVLANMap[portID] = vlanID

	// Zone enforcement complete: SC-7 (boundary protection), AC-4 (flow enforcement).
	m.logger.Info("zone flows applied",
		slog.String("port_id", portID),
		slog.String("zone", string(z)),
		slog.Uint64("vlan", uint64(vlanID)),
		slog.Int("template_flows", len(templateFlows)),
		slog.Int("matrix_flows", len(matrixFlows)),
		complianceAttr(complianceSC7, complianceAC4))

	return nil
}

// RemoveFlows removes all OpenFlow rules for portID and clears zone/VLAN tracking.
func (m *ZoneFlowManager) RemoveFlows(portID string) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("removing flows", slog.String("port_id", portID))

	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, portID); err != nil {
		return &WrappedError{Msg: "zone flow manager: remove flows", Err: err}
	}

	delete(m.portZoneMap, portID)
	delete(m.portClassMap, portID)
	delete(m.portVLANMap, portID)

	return nil
}

// GetPortZone returns the current zone for portID.
func (m *ZoneFlowManager) GetPortZone(portID string) (zone.Zone, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	z, ok := m.portZoneMap[portID]
	if !ok {
		return "", &MessageError{Msg: fmt.Sprintf("zone flow manager: port not found: %s", portID)}
	}
	return z, nil
}

// GetPortVLAN returns the current VLAN for portID.
func (m *ZoneFlowManager) GetPortVLAN(portID string) (uint16, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, ok := m.portVLANMap[portID]
	if !ok {
		return 0, &MessageError{Msg: fmt.Sprintf("zone flow manager: port not found: %s", portID)}
	}
	return v, nil
}

// ZoneForVLAN returns the zone the network plan carries on VLAN v.
func (m *ZoneFlowManager) ZoneForVLAN(v uint16) (zone.Zone, bool) {
	return m.plan.ZoneForVLAN(v)
}

// GetPortClass returns the port class a trunk port currently carries.
func (m *ZoneFlowManager) GetPortClass(portID string) (zone.PortClass, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	c, ok := m.portClassMap[portID]
	if !ok {
		return "", &MessageError{Msg: fmt.Sprintf("zone flow manager: port %s carries no port class", portID)}
	}
	return c, nil
}

// ApplyPortClassFlows admits portID to the zones of port class c: the port
// becomes a trunk carrying the class's VLAN list with the class's native
// VLAN untagged (an access class such as bmc becomes an access port), and
// the template flows of every carried zone plus the matrix rules are
// installed. This is the "role's zones" step of the device lifecycle.
func (m *ZoneFlowManager) ApplyPortClassFlows(ctx context.Context, portID string, c zone.PortClass) error {
	if portID == "" {
		return ErrInvalidPortID
	}
	pc, err := m.plan.PortClass(c)
	if err != nil {
		return ErrPortClassUnresolved{Class: string(c), Cause: err}
	}
	if pc.Mode == netplan.PortModeAccess {
		z, _ := m.plan.ZoneForVLAN(pc.Native)
		return m.ApplyZoneFlows(ctx, portID, z)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("applying port class flows",
		slog.String("port_id", portID),
		slog.String("port_class", string(c)),
		slog.Any("vlans", pc.Allowed),
		slog.Uint64("native_vlan", uint64(pc.Native)),
		complianceAttr(complianceAC4))

	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, portID); err != nil {
		m.logger.Warn("failed to delete existing flows",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
	}

	if err := m.portController.SetPortTrunk(ctx, portID, pc.Allowed, pc.Native); err != nil {
		return &WrappedError{Msg: "zone flow manager: set port trunk", Err: err}
	}

	// The native zone's frames reach the flow tables untagged, every other
	// zone's tagged (see zoneflows.Ingress).
	var templateFlows []zoneflows.FlowRule
	var nativeZone zone.Zone
	for _, vid := range pc.Allowed {
		z, ok := m.plan.ZoneForVLAN(vid)
		if !ok {
			continue
		}
		in := zoneflows.Tagged(vid)
		if vid == pc.Native {
			in = zoneflows.Untagged(vid)
			nativeZone = z
		}
		templateFlows = append(templateFlows, m.generators.Generate(portID, z, in)...)
	}
	if err := m.flowController.InstallFlows(m.bridgeName, templateFlows); err != nil {
		return &SentinelCauseError{Sentinel: ErrFlowInstallFailed, Cause: err}
	}

	matrixFlows := append(m.compileMatrixFlows(), m.compilePortMatrixFlows(portID, nativeZone)...)
	if err := m.flowController.InstallFlows(m.bridgeName, matrixFlows); err != nil {
		m.logger.Warn("failed to install matrix flows",
			slog.String("port_id", portID),
			slog.String("port_class", string(c)),
			slog.String("error", err.Error()))
	}

	delete(m.portZoneMap, portID)
	m.portClassMap[portID] = c
	m.portVLANMap[portID] = pc.Native

	m.logger.Info("port class flows applied",
		slog.String("port_id", portID),
		slog.String("port_class", string(c)),
		slog.Int("template_flows", len(templateFlows)),
		slog.Int("matrix_flows", len(matrixFlows)),
		complianceAttr(complianceSC7, complianceAC4))
	return nil
}

// resolveVLAN returns the VLAN ID of zone z from the network plan, or
// zoneflows.ErrUnresolvableNetwork when the plan has no such zone.
func (m *ZoneFlowManager) resolveVLAN(z zone.Zone) (uint16, error) {
	n, ok := m.plan.Zone(z)
	if !ok {
		return 0, zoneflows.ErrUnresolvableNetwork{Zone: z}
	}
	return n.VLAN, nil
}

// compilePortMatrixFlows returns the matrix rules for zone z's traffic that
// reaches the flow tables untagged on portID (an access port's zone, or a
// trunk's native zone). It returns nil when z is empty (a trunk with no
// native zone) or no zone set is configured.
func (m *ZoneFlowManager) compilePortMatrixFlows(portID string, z zone.Zone) []zoneflows.FlowRule {
	if len(m.zones) == 0 || z == "" {
		return nil
	}
	return zoneflows.CompileMatrixRulesForPort(zoneflows.MatrixRuleConfig{
		Matrix:         m.matrix,
		Zones:          m.zones,
		NetworksByZone: sdn.NetworkSummaries(m.plan),
		Terminal:       m.terminal,
	}, portID, z)
}

// compileMatrixFlows derives the inter-zone matrix rules from the manager's
// configured zones and the plan. Returns nil when no zones are configured.
func (m *ZoneFlowManager) compileMatrixFlows() []zoneflows.FlowRule {
	if len(m.zones) == 0 {
		return nil
	}

	return zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         m.matrix,
		Zones:          m.zones,
		NetworksByZone: sdn.NetworkSummaries(m.plan),
		Terminal:       m.terminal,
	})
}
