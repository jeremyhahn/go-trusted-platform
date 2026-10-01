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

package sdn

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// NetworkSummaries projects a network plan into the per-zone VLAN and
// subnet summaries consumed by zoneflows matrix compilation and the gateway
// datapath services: one summary per zone, carrying its VLAN, IPv4 subnet
// and (when the environment has a ULA) IPv6 subnet. A nil plan yields an
// empty map.
func NetworkSummaries(plan *netplan.Plan) map[zone.Zone]zoneflows.NetworkSummary {
	if plan == nil {
		return map[zone.Zone]zoneflows.NetworkSummary{}
	}
	zones := plan.Zones()
	out := make(map[zone.Zone]zoneflows.NetworkSummary, len(zones))
	for _, z := range zones {
		out[z.Zone] = zoneflows.NewNetworkSummary(z.VLAN, z.Subnet4, z.Subnet6)
	}
	return out
}
