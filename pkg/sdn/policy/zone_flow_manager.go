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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
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
	// Flows match and are deleted by the OpenFlow port number; OVSDB and
	// the manager's maps use the interface name (#1694).
	ofPort, err := m.openFlowPort(ctx, portID)
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
	// A failed delete fails the apply: the port's earlier allow rules
	// could outrank the new zone's default drop (fail closed, #1694).
	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, ofPort); err != nil {
		return &WrappedError{Msg: "zone flow manager: delete existing flows", Err: err}
	}

	// Set VLAN tag via OVSDB.
	// The delete above removed the port's rules: a failed VLAN update
	// restores the previous placement and rules, or blocks the port, so
	// unmatched traffic never reaches NORMAL forwarding (#1896 Codex).
	if err := m.portController.SetPortVLAN(ctx, portID, int64(vlanID)); err != nil {
		setErr := &WrappedError{Msg: "zone flow manager: set port VLAN", Err: err}
		if rbErr := m.rollbackZoneMove(ctx, portID, ofPort, nil); rbErr != nil {
			return errors.Join(setErr, rbErr)
		}
		return setErr
	}

	// Install per-zone template flows as a single batch. The port is an
	// access port, so its frames reach the flow tables untagged.
	templateFlows := m.generators.Generate(ofPort, z, zoneflows.Untagged(vlanID))
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
		// The switch may have accepted part of the batch, and the port is
		// already on the new VLAN: roll both back so the port is never on
		// the new zone's VLAN while the manager records the old zone
		// (fail closed, #1896 Codex r2).
		return m.failMove(ctx, portID, ofPort, err, templateFlows)
	}

	// Install inter-zone matrix rules as a single batch when matrix and
	// network summaries are available: the shared tagged-ingress rules plus
	// this port's untagged-ingress rules for its zone.
	portMatrix := m.compilePortMatrixFlows(ofPort, z)
	matrixFlows := append(m.compileMatrixFlows(), portMatrix...)
	for _, f := range matrixFlows {
		m.logger.Debug("installing matrix flow",
			slog.String("port_id", portID),
			slog.String("zone", string(z)),
			slog.Int("priority", f.Priority),
			slog.String("match", f.Match),
			slog.String("actions", f.Actions))
	}
	if err := m.flowController.InstallFlows(m.bridgeName, matrixFlows); err != nil {
		m.logger.Error("failed to install matrix flows",
			slog.String("port_id", portID),
			slog.String("zone", string(z)),
			slog.String("error", err.Error()))
		// The matrix's inter-zone denies outrank the zone template's
		// catch-all: without them the port is not isolated. Fail the
		// apply and roll back (fail closed, #1896 Codex).
		return m.failMove(ctx, portID, ofPort, err, templateFlows, portMatrix)
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

// ErrPortStateUnknown is returned when a failed zone move could not be
// rolled back: the port's VLAN or flows on the switch are not known. The
// manager records the port in the quarantine zone.
var ErrPortStateUnknown = errors.New("sdn/policy: zone move failed and could not be rolled back; the port is in an unknown state")

// rollbackZoneMove undoes a zone move whose template batch failed after
// SetPortVLAN: it deletes every flow of the batch (deleting an absent flow
// is harmless) and puts the port back on its previous VLAN, or on the
// quarantine VLAN when the manager had none recorded, then reinstalls that
// zone's template and per-port matrix rules, which the move had deleted.
// When any step fails it blocks the port with a drop-all, records the port
// as quarantined, forgets its VLAN and returns ErrPortStateUnknown. Callers
// hold m.mu.
func (m *ZoneFlowManager) rollbackZoneMove(ctx context.Context, portID, ofPort string, batch []zoneflows.FlowRule) error {
	var errs []error
	for _, f := range batch {
		if err := m.flowController.DeleteFlow(m.bridgeName, f.Match); err != nil {
			errs = append(errs, &WrappedError{Msg: "zone flow manager: delete flow of the failed batch", Err: err})
		}
	}

	// A trunk (gateway, hypervisor) gets its class back: allowed VLANs,
	// native VLAN and every carried zone's rules. Restoring only the
	// native VLAN would make it an access port and cut its other tagged
	// networks (#1896 Codex).
	if c, ok := m.portClassMap[portID]; ok {
		if len(errs) == 0 {
			if err := m.restoreTrunk(ctx, portID, ofPort, c); err != nil {
				errs = append(errs, err)
			} else {
				delete(m.portZoneMap, portID)
				return nil
			}
		}
		return m.blockPort(portID, ofPort, errs)
	}

	restoreVLAN, ok := m.portVLANMap[portID]
	if !ok {
		v, err := m.resolveVLAN(zone.ZoneQuarantine)
		if err != nil {
			errs = append(errs, &WrappedError{Msg: "zone flow manager: resolve quarantine VLAN for rollback", Err: err})
		}
		restoreVLAN = v
	}
	if restoreVLAN != 0 {
		if err := m.portController.SetPortVLAN(ctx, portID, int64(restoreVLAN)); err != nil {
			errs = append(errs, &WrappedError{Msg: "zone flow manager: restore port VLAN", Err: err})
		}
	}

	// The move deleted the port's earlier rules before it installed the
	// new template: reinstall the restored zone's template and per-port
	// matrix rules, or the port keeps its restricted VLAN with no drop
	// rules (#1896 Codex).
	if len(errs) == 0 {
		prev := m.rollbackZone(portID, restoreVLAN)
		if err := m.reinstallZone(ofPort, prev, restoreVLAN); err != nil {
			errs = append(errs, err)
		} else {
			m.portZoneMap[portID] = prev
			delete(m.portClassMap, portID)
			m.portVLANMap[portID] = restoreVLAN
			return nil
		}
	}
	return m.blockPort(portID, ofPort, errs)
}

// blockPort is the last step of a failed rollback: the port's rules are
// not known to be in place, so it gets a drop-all that outranks every
// other rule (fail closed) and is recorded as quarantined. The next
// apply's DeleteFlowsByPort removes the drop-all. Callers hold m.mu.
func (m *ZoneFlowManager) blockPort(portID, ofPort string, errs []error) error {
	if err := m.flowController.InstallFlows(m.bridgeName, []zoneflows.FlowRule{portBlockRule(ofPort)}); err != nil {
		errs = append(errs, &WrappedError{Msg: "zone flow manager: block port after failed rollback", Err: err})
	}

	m.portZoneMap[portID] = zone.ZoneQuarantine
	delete(m.portClassMap, portID)
	delete(m.portVLANMap, portID)
	m.logger.Error("zone move rollback failed; port state unknown, recorded as quarantined",
		slog.String("port_id", portID),
		slog.String("error", errors.Join(errs...).Error()),
		complianceAttr(complianceSC7, complianceAC4))
	return errors.Join(append([]error{ErrPortStateUnknown}, errs...)...)
}

// failMove answers a move whose flow install failed with cause: it rolls
// the port back to its previous placement, deleting the given batches'
// port rules, and returns ErrFlowInstallFailed joined with any rollback
// error. Callers hold m.mu.
func (m *ZoneFlowManager) failMove(ctx context.Context, portID, ofPort string, cause error, batches ...[]zoneflows.FlowRule) error {
	var batch []zoneflows.FlowRule
	for _, b := range batches {
		batch = append(batch, b...)
	}
	installErr := &SentinelCauseError{Sentinel: ErrFlowInstallFailed, Cause: cause}
	if rbErr := m.rollbackZoneMove(ctx, portID, ofPort, batch); rbErr != nil {
		return errors.Join(installErr, rbErr)
	}
	return installErr
}

// restoreTrunk puts trunk port class c back on portID: its allowed and
// native VLANs, every carried zone's template and the matrix rules.
// Callers hold m.mu.
func (m *ZoneFlowManager) restoreTrunk(ctx context.Context, portID, ofPort string, c zone.PortClass) error {
	pc, err := m.plan.PortClass(c)
	if err != nil {
		return ErrPortClassUnresolved{Class: string(c), Cause: err}
	}
	if err := m.portController.SetPortTrunk(ctx, portID, pc.Allowed, pc.Native); err != nil {
		return &WrappedError{Msg: "zone flow manager: restore port trunk", Err: err}
	}
	template, nativeZone := m.classTemplateFlows(ofPort, pc)
	if err := m.flowController.InstallFlows(m.bridgeName, template); err != nil {
		return &WrappedError{Msg: "zone flow manager: reinstall previous trunk flows", Err: err}
	}
	matrix := append(m.compileMatrixFlows(), m.compilePortMatrixFlows(ofPort, nativeZone)...)
	if err := m.flowController.InstallFlows(m.bridgeName, matrix); err != nil {
		return &WrappedError{Msg: "zone flow manager: reinstall previous trunk matrix flows", Err: err}
	}
	return nil
}

// classTemplateFlows answers the template flows of every zone trunk class
// pc carries, and the native zone: the native zone's frames reach the flow
// tables untagged, every other zone's tagged (see zoneflows.Ingress).
func (m *ZoneFlowManager) classTemplateFlows(ofPort string, pc netplan.PortClassPlan) ([]zoneflows.FlowRule, zone.Zone) {
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
		templateFlows = append(templateFlows, m.generators.Generate(ofPort, z, in)...)
	}
	return templateFlows, nativeZone
}

// rollbackZone answers the zone a rolled-back port returns to: its recorded
// access zone, else the zone of the VLAN it is restored to, else quarantine.
func (m *ZoneFlowManager) rollbackZone(portID string, vlan uint16) zone.Zone {
	if z, ok := m.portZoneMap[portID]; ok && z != "" {
		return z
	}
	if z, ok := m.plan.ZoneForVLAN(vlan); ok {
		return z
	}
	return zone.ZoneQuarantine
}

// reinstallZone installs zone z's template and per-port matrix rules for an
// access port on vlan. Unlike a forward apply, a matrix failure fails it:
// the per-port matrix rules carry the zone's inter-zone drops.
func (m *ZoneFlowManager) reinstallZone(ofPort string, z zone.Zone, vlan uint16) error {
	template := m.generators.Generate(ofPort, z, zoneflows.Untagged(vlan))
	if err := m.flowController.InstallFlows(m.bridgeName, template); err != nil {
		return &WrappedError{Msg: "zone flow manager: reinstall previous zone flows", Err: err}
	}
	matrix := append(m.compileMatrixFlows(), m.compilePortMatrixFlows(ofPort, z)...)
	if err := m.flowController.InstallFlows(m.bridgeName, matrix); err != nil {
		return &WrappedError{Msg: "zone flow manager: reinstall previous zone matrix flows", Err: err}
	}
	return nil
}

// portBlockPriority is the highest OpenFlow priority: a blocked port's
// drop-all outranks every zone and matrix rule.
const portBlockPriority = 65535

// portBlockRule drops every frame from the OpenFlow port.
func portBlockRule(ofPort string) zoneflows.FlowRule {
	return zoneflows.FlowRule{
		Table:    0,
		Priority: portBlockPriority,
		Match:    "in_port=" + ofPort,
		Actions:  "drop",
		Cookie:   zoneflows.QuarantineCookie,
	}
}

// RemoveFlows removes all OpenFlow rules for portID and clears zone/VLAN tracking.
// BridgeName returns the OVS bridge this manager deletes and installs
// flows on.
func (m *ZoneFlowManager) BridgeName() string {
	return m.bridgeName
}

// AllowProvisioningBootPorts adds TCP ports (the PXE server's iPXE HTTP,
// device-script HTTP and NBD ports) to the provisioning zone's allow rules,
// open only to the boot server; it applies to every provisioning flow set
// installed afterwards. The boot server is bindHost when it parses as an
// address that is neither unspecified nor loopback; otherwise the boot
// servers answer on the provisioning zone's own addresses (its gateway and,
// when the zone has an IPv6 subnet, that subnet's address), which no
// inter-zone deny covers. With no usable bind host and no provisioning zone
// in the plan the boot ports stay closed.
func (m *ZoneFlowManager) AllowProvisioningBootPorts(bindHost string, ports ...uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generators.AddProvisioningBootHTTPPorts(ports...)

	var servers []net.IP
	if ip := net.ParseIP(bindHost); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
		servers = append(servers, ip)
	} else if m.plan != nil {
		if z, ok := m.plan.Zone(zone.ZoneProvisioning); ok {
			if z.Gateway.IsValid() {
				servers = append(servers, net.IP(z.Gateway.AsSlice()))
			}
			if z.Subnet6.IsValid() {
				servers = append(servers, net.IP(z.Subnet6.Addr().AsSlice()))
			}
		}
	}
	m.generators.SetProvisioningBootServers(servers...)
}

func (m *ZoneFlowManager) RemoveFlows(portID string) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("removing flows", slog.String("port_id", portID))

	ofPort, err := m.openFlowPort(context.Background(), portID)
	if err != nil {
		return err
	}
	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, ofPort); err != nil {
		return &WrappedError{Msg: "zone flow manager: remove flows", Err: err}
	}

	delete(m.portZoneMap, portID)
	delete(m.portClassMap, portID)
	delete(m.portVLANMap, portID)

	return nil
}

// openFlowPort resolves a port name to the decimal OpenFlow port number the
// generated in_port matches and DeleteFlowsByPort need; OVSDB calls and the
// manager's maps keep the name.
func (m *ZoneFlowManager) openFlowPort(ctx context.Context, portID string) (string, error) {
	// OpenFlow port numbers are per bridge: a port on another bridge may
	// share a number with one on ours, so check membership first.
	if checker, ok := m.portController.(PortBridgeChecker); ok {
		on, err := checker.PortOnBridge(ctx, m.bridgeName, portID)
		if err != nil {
			return "", ErrPortNotOnBridge{Port: portID, Bridge: m.bridgeName, Cause: err}
		}
		if !on {
			return "", ErrPortNotOnBridge{Port: portID, Bridge: m.bridgeName}
		}
	}
	n, err := m.portController.GetOFPort(ctx, portID)
	if err != nil {
		return "", ErrNoOpenFlowPort{Port: portID, Cause: err}
	}
	if n < 1 {
		return "", ErrNoOpenFlowPort{Port: portID, OFPort: n}
	}
	return strconv.FormatInt(int64(n), 10), nil
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
	ofPort, err := m.openFlowPort(ctx, portID)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("applying port class flows",
		slog.String("port_id", portID),
		slog.String("port_class", string(c)),
		slog.Any("vlans", pc.Allowed),
		slog.Uint64("native_vlan", uint64(pc.Native)),
		complianceAttr(complianceAC4))

	// A failed delete fails the apply: the port's earlier allow rules
	// could outrank the new zone's default drop (fail closed, #1694).
	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, ofPort); err != nil {
		return &WrappedError{Msg: "zone flow manager: delete existing flows", Err: err}
	}

	// Every failure after the delete restores the port's previous
	// placement and rules, or blocks the port (fail closed, #1896 Codex).
	if err := m.portController.SetPortTrunk(ctx, portID, pc.Allowed, pc.Native); err != nil {
		setErr := &WrappedError{Msg: "zone flow manager: set port trunk", Err: err}
		if rbErr := m.rollbackZoneMove(ctx, portID, ofPort, nil); rbErr != nil {
			return errors.Join(setErr, rbErr)
		}
		return setErr
	}

	templateFlows, nativeZone := m.classTemplateFlows(ofPort, pc)
	if err := m.flowController.InstallFlows(m.bridgeName, templateFlows); err != nil {
		m.logger.Error("failed to install port class template flows",
			slog.String("port_id", portID),
			slog.String("port_class", string(c)),
			slog.String("error", err.Error()))
		return m.failMove(ctx, portID, ofPort, err, templateFlows)
	}

	portMatrix := m.compilePortMatrixFlows(ofPort, nativeZone)
	matrixFlows := append(m.compileMatrixFlows(), portMatrix...)
	if err := m.flowController.InstallFlows(m.bridgeName, matrixFlows); err != nil {
		m.logger.Error("failed to install matrix flows",
			slog.String("port_id", portID),
			slog.String("port_class", string(c)),
			slog.String("error", err.Error()))
		return m.failMove(ctx, portID, ofPort, err, templateFlows, portMatrix)
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
