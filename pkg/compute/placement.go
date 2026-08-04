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

package compute

import (
	"context"
	"fmt"
	"sort"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ErrNoNetworkInZone is returned when no network exists in the zone specified
// by the device profile. The caller must configure at least one network for
// the profile's zone before placing vNICs.
type ErrNoNetworkInZone struct {
	Zone zone.Zone
}

// Error implements the error interface.
func (e ErrNoNetworkInZone) Error() string {
	return fmt.Sprintf("compute: no network found in zone %q for vNIC placement", e.Zone)
}

// VNICPlacement describes the result of a successful zone-aware vNIC placement.
type VNICPlacement struct {
	// NetworkName is the name of the selected network.
	NetworkName string

	// Zone is the zone the vNIC has been placed in.
	Zone zone.Zone

	// VLAN is the 802.1Q VLAN ID assigned to the port.
	VLAN uint16
}

// PlaceVNICConfig holds the inputs required for zone-aware vNIC placement.
type PlaceVNICConfig struct {
	// Profile is the device profile whose Zone field determines the target zone.
	Profile *entities.DeviceProfile

	// ZoneIndex provides the set of networks available in each zone.
	ZoneIndex *sdn.ZoneIndex

	// PolicyEngine applies zone flows to the OVS port after placement.
	// When nil, VLAN tagging is skipped (useful for offline tests).
	PolicyEngine policy.PolicyEngine

	// ZoneFlowManager applies zone-aware OpenFlow rules to the port.
	// Required when PolicyEngine is non-nil.
	ZoneFlowManager *policy.ZoneFlowManager

	// PortID is the OVS tap port name for the vNIC being placed.
	PortID string

	// TenantID is passed to the PortPolicy constructed after placement.
	TenantID string
}

// PlaceVNIC resolves which network to place a VM vNIC on, tags the OVS port
// with the network's VLAN, and applies zone flows.
//
// Selection rule: all networks in the profile's zone are collected from
// ZoneIndex.ByZone; they are sorted deterministically by name (ascending),
// and the first is selected. This ensures stable, reproducible placement when
// multiple networks exist in the same zone.
//
// Returns ErrNoNetworkInZone when the zone has no network entries.
// Returns an error when the profile is nil or has no zone configured.
func PlaceVNIC(ctx context.Context, cfg *PlaceVNICConfig) (*VNICPlacement, error) {
	if cfg == nil {
		return nil, &MessageError{Msg: "compute: place vnic: config is required"}
	}
	if cfg.Profile == nil {
		return nil, ErrInvalidProfile
	}
	if cfg.ZoneIndex == nil {
		return nil, &MessageError{Msg: "compute: place vnic: zone index is required"}
	}
	if cfg.PortID == "" {
		return nil, &MessageError{Msg: "compute: place vnic: port ID is required"}
	}

	profileZone := zone.Zone(cfg.Profile.Zone)
	if profileZone == "" {
		// Fall back to the trusted zone when the profile has no explicit zone.
		profileZone = zone.ZoneTrusted
	}

	networks := cfg.ZoneIndex.ByZone(profileZone)
	if len(networks) == 0 {
		return nil, ErrNoNetworkInZone{Zone: profileZone}
	}

	// Sort by name ascending for deterministic selection.
	sort.Slice(networks, func(i, j int) bool {
		return networks[i].Name < networks[j].Name
	})
	selected := networks[0]

	placement := &VNICPlacement{
		NetworkName: selected.Name,
		Zone:        profileZone,
		VLAN:        selected.VLAN,
	}

	// Apply zone flows via ZoneFlowManager when available.
	if cfg.ZoneFlowManager != nil {
		if err := cfg.ZoneFlowManager.ApplyZoneFlows(ctx, cfg.PortID, profileZone); err != nil {
			return nil, &WrappedError{Msg: "compute: place vnic: apply zone flows", Err: err}
		}
		// Refresh VLAN from the flow manager in case it resolved differently.
		if v, err := cfg.ZoneFlowManager.GetPortVLAN(cfg.PortID); err == nil {
			placement.VLAN = v
		}
		return placement, nil
	}

	// Without a ZoneFlowManager, fall back to direct VLAN tagging via the
	// PolicyEngine when configured.
	if cfg.PolicyEngine != nil && selected.VLAN > 0 {
		tenantID := cfg.TenantID
		if tenantID == "" {
			tenantID = "default"
		}
		portPolicy := &policy.PortPolicy{
			TenantID: tenantID,
			Zone:     profileZone,
			VLAN:     selected.VLAN,
		}
		if err := cfg.PolicyEngine.ApplyPolicy(cfg.PortID, portPolicy); err != nil {
			return nil, &WrappedError{Msg: "compute: place vnic: apply policy", Err: err}
		}
	}

	return placement, nil
}
