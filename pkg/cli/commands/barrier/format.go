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

package barrier

import (
	barriersvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/barrier"
)

// strategyNames provides O(1) lookup from domain Strategy to display string.
var strategyNames = map[barriersvc.Strategy]string{
	barriersvc.StrategyUnspecified: "unspecified",
	barriersvc.StrategySingleKey:   "single-key",
	barriersvc.StrategyShamir:      "shamir",
}

// formatStrategy returns a human-readable string for the barrier strategy.
func formatStrategy(strategy barriersvc.Strategy) string {
	name, ok := strategyNames[strategy]
	if !ok {
		return "unknown"
	}
	return name
}
