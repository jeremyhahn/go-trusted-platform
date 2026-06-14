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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vlan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

const (
	// DefaultProvisioningVLAN is the default VLAN ID for provisioning zones.
	// Sourced from pkg/sdn/vlan defaults (reference-network.md §VLAN table).
	DefaultProvisioningVLAN = vlan.DefaultProvisioning

	// DefaultQuarantineVLAN is the default VLAN ID for quarantine zones.
	// Sourced from pkg/sdn/vlan defaults (reference-network.md §VLAN table).
	DefaultQuarantineVLAN = vlan.DefaultQuarantine
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

	// ZoneIndex resolves zone→network→VLAN mappings. When nil the manager
	// falls back to pkg/sdn/vlan defaults for the six built-in zones.
	ZoneIndex *sdn.ZoneIndex

	// GeneratorSet provides per-zone OpenFlow template generators. When nil
	// a default GeneratorSet with zero-value zone configs is constructed.
	GeneratorSet *zoneflows.GeneratorSet

	// Matrix is the compiled inter-zone allow/deny matrix. When the zero
	// value is supplied, no inter-zone matrix rules are installed.
	Matrix zone.Matrix

	// Zones is the full resolved zone list, required for CompileMatrixRules.
	Zones []zone.ZoneConfig

	// Logger is the structured logger; uses slog.Default() when nil.
	Logger *slog.Logger
}

// ZoneFlowManager manages per-zone OpenFlow rules. It is zone-keyed: every flow
// operation resolves the target zone to a VLAN via ZoneIndex (with fallback
// to pkg/sdn/vlan defaults), then installs per-zone template flows plus
// inter-zone matrix rules derived from the compiled zone.Matrix.
type ZoneFlowManager struct {
	mu             sync.RWMutex
	logger         *slog.Logger
	bridgeName     string
	flowController FlowController
	portController OVSPortController
	zoneIndex      *sdn.ZoneIndex
	generators     *zoneflows.GeneratorSet
	matrix         zone.Matrix
	zones          []zone.ZoneConfig
	portZoneMap    map[string]zone.Zone // portID → current zone
	portVLANMap    map[string]uint16    // portID → current VLAN
}

// NewZoneFlowManager constructs a ZoneFlowManager from the supplied config.
// Returns an error when required fields (BridgeName, FlowController,
// PortController) are missing.
func NewZoneFlowManager(cfg ZoneFlowManagerConfig) (*ZoneFlowManager, error) {
	if cfg.BridgeName == "" {
		return nil, ErrInvalidBridgeName
	}
	if cfg.FlowController == nil {
		return nil, fmt.Errorf("zone flow manager: flow controller is required")
	}
	if cfg.PortController == nil {
		return nil, fmt.Errorf("zone flow manager: port controller is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	generators := cfg.GeneratorSet
	if generators == nil {
		generators = zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
			BridgeName: cfg.BridgeName,
		})
	}

	return &ZoneFlowManager{
		logger:         logger,
		bridgeName:     cfg.BridgeName,
		flowController: cfg.FlowController,
		portController: cfg.PortController,
		zoneIndex:      cfg.ZoneIndex,
		generators:     generators,
		matrix:         cfg.Matrix,
		zones:          cfg.Zones,
		portZoneMap:    make(map[string]zone.Zone),
		portVLANMap:    make(map[string]uint16),
	}, nil
}

// ApplyZoneFlows transitions portID to zone z. It resolves the VLAN for z via
// ZoneIndex (falling back to pkg/sdn/vlan defaults for built-in zones), sets
// the port VLAN via OVSDB, removes any existing OpenFlow rules, installs the
// per-zone template flows, and appends inter-zone matrix rules.
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
		return fmt.Errorf("zone flow manager: set port VLAN: %w", err)
	}

	// Install per-zone template flows.
	templateFlows := m.generators.Generate(portID, z, vlanID)
	for _, f := range templateFlows {
		if err := m.flowController.InstallFlow(m.bridgeName, f.Priority, f.Match, f.Actions); err != nil {
			m.logger.Error("failed to install template flow",
				slog.String("port_id", portID),
				slog.String("zone", string(z)),
				slog.String("error", err.Error()))
			return fmt.Errorf("%w: %v", ErrFlowInstallFailed, err)
		}
	}

	// Install inter-zone matrix rules when matrix and network summaries are
	// available.
	matrixFlows := m.compileMatrixFlows()
	for _, f := range matrixFlows {
		if err := m.flowController.InstallFlow(m.bridgeName, f.Priority, f.Match, f.Actions); err != nil {
			m.logger.Warn("failed to install matrix flow",
				slog.String("port_id", portID),
				slog.String("zone", string(z)),
				slog.String("error", err.Error()))
			// Matrix rules are best-effort; do not abort on failure.
		}
	}

	m.portZoneMap[portID] = z
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
		return fmt.Errorf("zone flow manager: remove flows: %w", err)
	}

	delete(m.portZoneMap, portID)
	delete(m.portVLANMap, portID)

	return nil
}

// GetPortZone returns the current zone for portID.
func (m *ZoneFlowManager) GetPortZone(portID string) (zone.Zone, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	z, ok := m.portZoneMap[portID]
	if !ok {
		return "", fmt.Errorf("zone flow manager: port not found: %s", portID)
	}
	return z, nil
}

// GetPortVLAN returns the current VLAN for portID.
func (m *ZoneFlowManager) GetPortVLAN(portID string) (uint16, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, ok := m.portVLANMap[portID]
	if !ok {
		return 0, fmt.Errorf("zone flow manager: port not found: %s", portID)
	}
	return v, nil
}

// resolveVLAN returns the VLAN ID for zone z. It consults the ZoneIndex first;
// when no index is configured or the zone has no network entry it falls back to
// the pkg/sdn/vlan defaults for the six built-in zones. Returns
// ErrUnresolvableNetwork when neither path can produce a VLAN.
func (m *ZoneFlowManager) resolveVLAN(z zone.Zone) (uint16, error) {
	if m.zoneIndex != nil {
		nets := m.zoneIndex.ByZone(z)
		if len(nets) > 0 && nets[0].VLAN > 0 {
			return nets[0].VLAN, nil
		}
	}

	// Fallback to built-in defaults.
	if id, ok := builtinVLAN(z); ok {
		return id, nil
	}

	return 0, zoneflows.ErrUnresolvableNetwork{Zone: z}
}

// builtinVLAN returns the pkg/sdn/vlan default for the six well-known zone
// names, or (0, false) for user-defined zones.
func builtinVLAN(z zone.Zone) (uint16, bool) {
	defaults := map[zone.Zone]uint16{
		zone.ZoneTrusted:      vlan.DefaultTrusted,
		zone.ZoneProvisioning: vlan.DefaultProvisioning,
		zone.ZoneQuarantine:   vlan.DefaultQuarantine,
		zone.ZoneStorage:      vlan.DefaultStorage,
		zone.ZoneManagement:   vlan.DefaultManagement,
	}
	id, ok := defaults[z]
	return id, ok
}

// compileMatrixFlows derives the inter-zone matrix rules from the manager's
// configured zones and ZoneIndex. Returns nil when zones or ZoneIndex are
// not configured.
func (m *ZoneFlowManager) compileMatrixFlows() []zoneflows.FlowRule {
	if len(m.zones) == 0 || m.zoneIndex == nil {
		return nil
	}

	nets := make(map[zone.Zone]zoneflows.NetworkSummary, len(m.zones))
	for _, zc := range m.zones {
		ns := m.zoneIndex.ByZone(zc.Name)
		if len(ns) == 0 {
			continue
		}
		n := ns[0]
		subnet := ""
		if n.Subnet.IsValid() {
			subnet = n.Subnet.String()
		}
		if n.VLAN > 0 {
			nets[zc.Name] = zoneflows.NetworkSummary{
				VLAN:   n.VLAN,
				Subnet: subnet,
			}
		}
	}

	return zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix:         m.matrix,
		Zones:          m.zones,
		NetworksByZone: nets,
	})
}
