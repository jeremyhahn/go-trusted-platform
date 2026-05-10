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
	"log/slog"
)

// Manager orchestrates fabric-wide operations across all switches.
type Manager interface {
	// ApplyFabric converges the entire fabric to the desired state:
	// VLANs, VNIs, and LAGs on every switch.
	ApplyFabric(ctx context.Context) error

	// ProvisionPort places a port onto the provisioning VLAN segment.
	ProvisionPort(ctx context.Context, port PortRef, segment string) error

	// ActivatePort moves a port from provisioning to a production segment.
	ActivatePort(ctx context.Context, port PortRef, segment string) error

	// QuarantinePort moves a port to the quarantine segment.
	QuarantinePort(ctx context.Context, port PortRef, segment string) error

	// SegmentByName returns the resolved Segment for the given name.
	SegmentByName(name string) (*Segment, error)

	// SwitchStatus returns the health status of a switch.
	SwitchStatus(ctx context.Context, switchID string) (*SwitchStatus, error)

	// Close releases all driver connections.
	Close() error
}

// fabricManager implements Manager using a set of per-switch drivers.
type fabricManager struct {
	config   *FabricConfig
	logger   *slog.Logger
	drivers  map[string]Driver
	segments map[string]*Segment
	peers    map[string][]string // switchID -> list of peer switchIDs
}

// NewManager creates a new fabric Manager from the given configuration.
// It resolves all segments, builds the peer map, and instantiates a
// driver for each configured switch.
func NewManager(config *FabricConfig, logger *slog.Logger) (Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	segments := resolveSegments(config)
	peers := buildPeerMap(config)

	drivers := make(map[string]Driver, len(config.Switches))
	for _, sw := range config.Switches {
		drv, err := DriverFor(sw, logger)
		if err != nil {
			return nil, ErrDriverConnect{SwitchID: sw.ID, Cause: err}
		}
		drivers[sw.ID] = drv
	}

	return &fabricManager{
		config:   config,
		logger:   logger,
		drivers:  drivers,
		segments: segments,
		peers:    peers,
	}, nil
}

// NewManagerWithDrivers creates a fabric Manager with pre-built drivers,
// used primarily for testing.
func NewManagerWithDrivers(config *FabricConfig, logger *slog.Logger, drivers map[string]Driver) (Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	segments := resolveSegments(config)
	peers := buildPeerMap(config)

	return &fabricManager{
		config:   config,
		logger:   logger,
		drivers:  drivers,
		segments: segments,
		peers:    peers,
	}, nil
}

// ApplyFabric converges the entire fabric: connects to all switches,
// ensures VLANs and VNIs for each segment, and configures all LAGs.
func (m *fabricManager) ApplyFabric(ctx context.Context) error {
	// Connect all drivers.
	for id, drv := range m.drivers {
		if err := drv.Connect(ctx); err != nil {
			return ErrDriverConnect{SwitchID: id, Cause: err}
		}
	}

	// Ensure VLANs and VNIs on every switch.
	for _, seg := range m.segments {
		for id, drv := range m.drivers {
			if err := drv.EnsureVLAN(ctx, seg.VLAN, seg.Name); err != nil {
				return ErrDriverOperation{SwitchID: id, Operation: "EnsureVLAN", Cause: err}
			}
			if seg.VNI > 0 {
				if err := drv.EnsureVNI(ctx, seg.VNI, seg.VLAN); err != nil {
					return ErrDriverOperation{SwitchID: id, Operation: "EnsureVNI", Cause: err}
				}
			}
		}
	}

	// Ensure LAGs on the appropriate switches.
	for _, lag := range m.config.LAGs {
		switchesInLAG := lagSwitches(lag)
		for switchID := range switchesInLAG {
			drv, ok := m.drivers[switchID]
			if !ok {
				return ErrUnknownSwitch{ID: switchID}
			}
			if err := drv.EnsureLAG(ctx, lag); err != nil {
				return ErrDriverOperation{SwitchID: switchID, Operation: "EnsureLAG", Cause: err}
			}
		}
	}

	m.logger.Info("fabric: apply complete",
		slog.Int("switches", len(m.drivers)),
		slog.Int("segments", len(m.segments)),
		slog.Int("lags", len(m.config.LAGs)))

	return nil
}

// ProvisionPort places a port on the given segment's VLAN in access mode.
// If the port belongs to an MC-LAG, the operation is applied to all peer switches.
func (m *fabricManager) ProvisionPort(ctx context.Context, port PortRef, segment string) error {
	seg, err := m.SegmentByName(segment)
	if err != nil {
		return err
	}
	if seg.Role != RoleProvisioning {
		return ErrSegmentRoleMismatch{
			Segment:  segment,
			Expected: RoleProvisioning,
			Got:      seg.Role,
		}
	}
	return m.setPortAccessOnPeers(ctx, port, seg.VLAN)
}

// ActivatePort moves a port to the given production segment's VLAN.
func (m *fabricManager) ActivatePort(ctx context.Context, port PortRef, segment string) error {
	seg, err := m.SegmentByName(segment)
	if err != nil {
		return err
	}
	return m.setPortAccessOnPeers(ctx, port, seg.VLAN)
}

// QuarantinePort moves a port to the given quarantine segment's VLAN.
func (m *fabricManager) QuarantinePort(ctx context.Context, port PortRef, segment string) error {
	seg, err := m.SegmentByName(segment)
	if err != nil {
		return err
	}
	if seg.Role != RoleQuarantine {
		return ErrSegmentRoleMismatch{
			Segment:  segment,
			Expected: RoleQuarantine,
			Got:      seg.Role,
		}
	}
	return m.setPortAccessOnPeers(ctx, port, seg.VLAN)
}

// SegmentByName returns the resolved Segment for the given name.
func (m *fabricManager) SegmentByName(name string) (*Segment, error) {
	seg, ok := m.segments[name]
	if !ok {
		return nil, ErrUnknownSegment{Name: name}
	}
	return seg, nil
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

// setPortAccessOnPeers applies SetPortAccess on the port's switch and all
// MC-LAG peer switches.
func (m *fabricManager) setPortAccessOnPeers(ctx context.Context, port PortRef, vlan uint16) error {
	if err := port.Validate(); err != nil {
		return err
	}

	drv, ok := m.drivers[port.SwitchID]
	if !ok {
		return ErrUnknownSwitch{ID: port.SwitchID}
	}

	if err := drv.SetPortAccess(ctx, port, vlan); err != nil {
		return ErrDriverOperation{SwitchID: port.SwitchID, Operation: "SetPortAccess", Cause: err}
	}

	// Apply to MC-LAG peer switches.
	if peerIDs, ok := m.peers[port.SwitchID]; ok {
		for _, peerID := range peerIDs {
			peerDrv, exists := m.drivers[peerID]
			if !exists {
				continue
			}
			peerPort := PortRef{SwitchID: peerID, Port: port.Port, LAGID: port.LAGID}
			if err := peerDrv.SetPortAccess(ctx, peerPort, vlan); err != nil {
				return ErrDriverOperation{SwitchID: peerID, Operation: "SetPortAccess", Cause: err}
			}
		}
	}

	return nil
}

// resolveSegments converts SegmentConfig entries into runtime Segment values,
// computing VNI when EVPN mode is active.
func resolveSegments(config *FabricConfig) map[string]*Segment {
	segments := make(map[string]*Segment, len(config.Segments))
	for _, sc := range config.Segments {
		seg := &Segment{
			Name:    sc.Name,
			VLAN:    sc.VLAN,
			CIDR:    sc.CIDR,
			Gateway: sc.Gateway,
			DNS:     sc.DNS,
			DHCP:    sc.DHCP,
			Role:    sc.Role,
		}
		if config.Mode == ModeEVPN && config.EVPN != nil {
			seg.VNI = config.EVPN.VNIBase + uint32(sc.VLAN)
		}
		segments[sc.Name] = seg
	}
	return segments
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
