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

package fabric

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Manager orchestrates the physical switch fabric on the network plan.
type Manager interface {
	// ApplyFabric converges the entire fabric to the desired state: every
	// zone VLAN of the plan on every switch, the LAGs, and the class of
	// every assigned port and peer-link port.
	ApplyFabric(ctx context.Context) error

	// ProvisionPort puts a port on the provisioning zone: a trunk carrying
	// only the provisioning VLAN, native, so a factory NIC PXE-boots.
	ProvisionPort(ctx context.Context, port PortRef) error

	// ActivatePort gives an attested node's port its class: the VLANs,
	// native VLAN and MTU the plan derives for that class.
	ActivatePort(ctx context.Context, port PortRef, class zone.PortClass) error

	// QuarantinePort puts a port on the quarantine zone: a trunk carrying
	// only the quarantine VLAN, native.
	QuarantinePort(ctx context.Context, port PortRef) error

	// DisablePort administratively shuts a blocked node's port down.
	DisablePort(ctx context.Context, port PortRef) error

	// SwitchStatus returns the health status of a switch.
	SwitchStatus(ctx context.Context, switchID string) (*SwitchStatus, error)

	// Close releases all driver connections.
	Close() error
}

// fabricManager implements Manager over per-switch drivers.
type fabricManager struct {
	config  *FabricConfig
	plan    *netplan.Plan
	logger  *slog.Logger
	drivers map[string]Driver
	peers   map[string][]string // switchID -> list of peer switchIDs
}

// NewManager validates config, creates a driver for every switch and
// returns a Manager that derives every VLAN from plan.
func NewManager(config *FabricConfig, plan *netplan.Plan, logger *slog.Logger) (Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, ErrNilPlan{}
	}

	drivers := make(map[string]Driver, len(config.Switches))
	for _, sw := range config.Switches {
		drv, err := DriverFor(sw, logger)
		if err != nil {
			return nil, ErrDriverConnect{SwitchID: sw.ID, Cause: err}
		}
		drivers[sw.ID] = drv
	}
	return newManager(config, plan, logger, drivers), nil
}

// NewManagerWithDrivers returns a Manager over caller-supplied drivers,
// keyed by switch ID.
func NewManagerWithDrivers(config *FabricConfig, plan *netplan.Plan, logger *slog.Logger, drivers map[string]Driver) (Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, ErrNilPlan{}
	}
	return newManager(config, plan, logger, drivers), nil
}

// newManager assembles a fabricManager.
func newManager(config *FabricConfig, plan *netplan.Plan, logger *slog.Logger, drivers map[string]Driver) *fabricManager {
	return &fabricManager{
		config:  config,
		plan:    plan,
		logger:  logger,
		drivers: drivers,
		peers:   buildPeerMap(config),
	}
}

// ApplyFabric converges every switch to the plan.
func (m *fabricManager) ApplyFabric(ctx context.Context) error {
	for id, drv := range m.drivers {
		if err := drv.Connect(ctx); err != nil {
			return ErrDriverConnect{SwitchID: id, Cause: err}
		}
	}

	zones := m.plan.Zones()
	for _, z := range zones {
		for id, drv := range m.drivers {
			if err := drv.EnsureVLAN(ctx, z.VLAN, string(z.Zone)); err != nil {
				return ErrDriverOperation{SwitchID: id, Operation: "EnsureVLAN", Cause: err}
			}
		}
	}

	for _, lag := range m.config.LAGs {
		for switchID := range lagSwitches(lag) {
			drv, ok := m.drivers[switchID]
			if !ok {
				return ErrUnknownSwitch{ID: switchID}
			}
			if err := drv.EnsureLAG(ctx, lag); err != nil {
				return ErrDriverOperation{SwitchID: switchID, Operation: "EnsureLAG", Cause: err}
			}
		}
	}

	for _, peer := range m.config.Peers {
		for _, sw := range []string{peer.SwitchA, peer.SwitchB} {
			for _, p := range peer.PeerLinkPorts {
				if err := m.applyClass(ctx, PortRef{SwitchID: sw, Port: p}, zone.PortClassPeerLink); err != nil {
					return err
				}
			}
		}
	}

	for _, pa := range m.config.Ports {
		if err := m.applyClass(ctx, pa.PortRef, pa.Class); err != nil {
			return err
		}
	}

	m.logger.Info("fabric: apply complete",
		slog.Int("switches", len(m.drivers)),
		slog.Int("vlans", len(zones)),
		slog.Int("lags", len(m.config.LAGs)),
		slog.Int("ports", len(m.config.Ports)))

	return nil
}

// ProvisionPort puts port (and its MC-LAG peers) on the provisioning zone.
func (m *fabricManager) ProvisionPort(ctx context.Context, port PortRef) error {
	return m.singleZoneTrunk(ctx, port, zone.ZoneProvisioning)
}

// QuarantinePort puts port (and its MC-LAG peers) on the quarantine zone.
func (m *fabricManager) QuarantinePort(ctx context.Context, port PortRef) error {
	return m.singleZoneTrunk(ctx, port, zone.ZoneQuarantine)
}

// ActivatePort gives port (and its MC-LAG peers) the plan of class.
func (m *fabricManager) ActivatePort(ctx context.Context, port PortRef, class zone.PortClass) error {
	if err := port.Validate(); err != nil {
		return err
	}
	if _, err := m.plan.PortClass(class); err != nil {
		return ErrPortClassPlan{Class: class, Cause: err}
	}
	return m.onPeers(port, "ActivatePort", func(drv Driver, p PortRef) error {
		return m.setClass(ctx, drv, p, class)
	})
}

// DisablePort shuts port (and its MC-LAG peers) down.
func (m *fabricManager) DisablePort(ctx context.Context, port PortRef) error {
	if err := port.Validate(); err != nil {
		return err
	}
	return m.onPeers(port, "DisablePort", func(drv Driver, p PortRef) error {
		return drv.DisablePort(ctx, p)
	})
}

// singleZoneTrunk makes port a trunk carrying only zone z, native, at the
// platform MTU.
func (m *fabricManager) singleZoneTrunk(ctx context.Context, port PortRef, z zone.Zone) error {
	if err := port.Validate(); err != nil {
		return err
	}
	n, err := m.plan.MustZone(z)
	if err != nil {
		return err
	}
	return m.onPeers(port, "SetPortTrunk", func(drv Driver, p PortRef) error {
		return drv.SetPortTrunk(ctx, p, []uint16{n.VLAN}, n.VLAN, netplan.MTU)
	})
}

// applyClass applies class to one port on its own switch only: the fabric
// configuration lists each switch's ports itself.
func (m *fabricManager) applyClass(ctx context.Context, port PortRef, class zone.PortClass) error {
	drv, ok := m.drivers[port.SwitchID]
	if !ok {
		return ErrUnknownSwitch{ID: port.SwitchID}
	}
	return wrapOp(port.SwitchID, "ApplyPortClass", m.setClass(ctx, drv, port, class))
}

// setClass programs one port with the plan of class.
func (m *fabricManager) setClass(ctx context.Context, drv Driver, port PortRef, class zone.PortClass) error {
	pc, err := m.plan.PortClass(class)
	if err != nil {
		return ErrPortClassPlan{Class: class, Cause: err}
	}
	if pc.Mode == netplan.PortModeAccess {
		return drv.SetPortAccess(ctx, port, pc.Native, pc.MTU)
	}
	return drv.SetPortTrunk(ctx, port, pc.Allowed, pc.Native, pc.MTU)
}

// onPeers runs op on port's switch and on the same port of every MC-LAG
// peer switch, so a dual-homed node's links stay identical.
func (m *fabricManager) onPeers(port PortRef, operation string, op func(Driver, PortRef) error) error {
	drv, ok := m.drivers[port.SwitchID]
	if !ok {
		return ErrUnknownSwitch{ID: port.SwitchID}
	}
	if err := op(drv, port); err != nil {
		return wrapOp(port.SwitchID, operation, err)
	}
	for _, peerID := range m.peers[port.SwitchID] {
		peerDrv, exists := m.drivers[peerID]
		if !exists {
			continue
		}
		peerPort := PortRef{SwitchID: peerID, Port: port.Port, LAGID: port.LAGID}
		if err := op(peerDrv, peerPort); err != nil {
			return wrapOp(peerID, operation, err)
		}
	}
	return nil
}

// wrapOp wraps a driver failure in ErrDriverOperation; nil stays nil and a
// plan error passes through unchanged.
func wrapOp(switchID, operation string, err error) error {
	if err == nil {
		return nil
	}
	var planErr ErrPortClassPlan
	if errors.As(err, &planErr) {
		return err
	}
	return ErrDriverOperation{SwitchID: switchID, Operation: operation, Cause: err}
}

// SwitchStatus returns the status of a switch by pinging its driver.
func (m *fabricManager) SwitchStatus(ctx context.Context, switchID string) (*SwitchStatus, error) {
	drv, ok := m.drivers[switchID]
	if !ok {
		return nil, ErrUnknownSwitch{ID: switchID}
	}

	// Find the switch config for metadata.
	var swCfg *SwitchConfig
	for i := range m.config.Switches {
		if m.config.Switches[i].ID == switchID {
			swCfg = &m.config.Switches[i]
			break
		}
	}

	status := &SwitchStatus{
		ID:     switchID,
		Vendor: swCfg.Vendor,
		Model:  swCfg.Model,
		MgmtIP: swCfg.MgmtIP,
	}

	if err := drv.Ping(ctx); err != nil {
		status.Connected = false
		return status, nil
	}
	status.Connected = true
	return status, nil
}

// Close releases all driver connections.
func (m *fabricManager) Close() error {
	var lastErr error
	for id, drv := range m.drivers {
		if err := drv.Close(); err != nil {
			m.logger.Warn("fabric: driver close failed",
				slog.String("switch", id),
				slog.String("error", err.Error()))
			lastErr = err
		}
	}
	return lastErr
}

// buildPeerMap creates a bidirectional map of switch peers from PeerConfig entries.
func buildPeerMap(config *FabricConfig) map[string][]string {
	peers := make(map[string][]string)
	for _, pc := range config.Peers {
		peers[pc.SwitchA] = append(peers[pc.SwitchA], pc.SwitchB)
		peers[pc.SwitchB] = append(peers[pc.SwitchB], pc.SwitchA)
	}
	return peers
}

// lagSwitches returns the set of unique switch IDs referenced by a LAG's members.
func lagSwitches(lag LAGConfig) map[string]struct{} {
	switches := make(map[string]struct{})
	for _, m := range lag.Members {
		switches[m.SwitchID] = struct{}{}
	}
	return switches
}
