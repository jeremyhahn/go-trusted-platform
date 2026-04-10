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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// strategyNames provides O(1) lookup from BarrierStrategy to display string.
var strategyNames = map[platformv1.BarrierStrategy]string{
	platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED: "unspecified",
	platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY:  "single-key",
	platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR:      "shamir",
}

// formatStrategy returns a human-readable string for the barrier strategy.
func formatStrategy(strategy platformv1.BarrierStrategy) string {
	name, ok := strategyNames[strategy]
	if !ok {
		return "unknown"
	}
	return name
}
