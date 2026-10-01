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

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ErrProfileZoneRequired is returned when a vNIC is placed for a profile that
// names no zone. There is no default zone: workloads belong on overlays, and
// placing one on an underlay zone is an explicit profile decision.
type ErrProfileZoneRequired struct {
	// Profile is the profile name.
	Profile string
}

// Error implements the error interface.
func (e ErrProfileZoneRequired) Error() string {
	return fmt.Sprintf("compute: profile %q names no zone; vNIC placement needs an explicit zone", e.Profile)
}

// ErrNoNetworkInZone is returned when the network plan holds no zone of the
// name the device profile specifies.
type ErrNoNetworkInZone struct {
	Zone zone.Zone
}

// Error implements the error interface.
func (e ErrNoNetworkInZone) Error() string {
	return fmt.Sprintf("compute: no network found in zone %q for vNIC placement", e.Zone)
}

// VNICPlacement describes the result of a successful zone-aware vNIC placement.
type VNICPlacement struct {
	// NetworkName is the name of the selected network: the zone name.
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

	// Plan is the network plan that numbers each zone.
	Plan *netplan.Plan

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

// PlaceVNIC places a VM vNIC on the profile's zone: it resolves the zone's
// VLAN from the network plan, tags the OVS port with it and applies zone
// flows. The profile must name the zone explicitly; there is no fallback.
//
// Returns ErrProfileZoneRequired when the profile names no zone and
// ErrNoNetworkInZone when the plan holds no such zone.
func PlaceVNIC(ctx context.Context, cfg *PlaceVNICConfig) (*VNICPlacement, error) {
	if cfg == nil {
		return nil, &MessageError{Msg: "compute: place vnic: config is required"}
	}
	if cfg.Profile == nil {
		return nil, ErrInvalidProfile
	}
	if cfg.Plan == nil {
		return nil, &MessageError{Msg: "compute: place vnic: network plan is required"}
	}
	if cfg.PortID == "" {
		return nil, &MessageError{Msg: "compute: place vnic: port ID is required"}
	}

	profileZone := zone.Zone(cfg.Profile.Zone)
	if profileZone == "" {
		return nil, ErrProfileZoneRequired{Profile: cfg.Profile.Name}
	}

	selected, ok := cfg.Plan.Zone(profileZone)
	if !ok {
		return nil, ErrNoNetworkInZone{Zone: profileZone}
	}

	placement := &VNICPlacement{
		NetworkName: string(selected.Zone),
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
