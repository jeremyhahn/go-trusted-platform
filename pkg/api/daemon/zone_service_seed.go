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

package daemon

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// zoneServiceSeed returns what the zone service starts from: the configured
// sdn.zones and sdn.environment, so the operator's zones and numbering reach
// every transport. Both are nil when SDN is absent or disabled; the zone
// service then serves the built-in zones without numbering.
func zoneServiceSeed(a *app.App) ([]zone.ZoneConfig, *netplan.Environment) {
	if a == nil || a.SDNConfig == nil || !a.SDNConfig.Enabled {
		return nil, nil
	}
	return a.SDNConfig.Zones, a.SDNConfig.Environment
}
