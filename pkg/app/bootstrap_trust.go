// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package app

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// scopeIsEmbeddedOnly reports whether the scope's strategy chain consists
// solely of the embedded strategy, meaning trust comes from the ISO-embedded
// CA bundle and no runtime fetch is needed.
//
// The TOFU resolver wiring helpers (trustConfigNeedsTOFU,
// buildTOFUResolverOpts) and the bootstrap TOFU error types live in app.go
// and errors.go respectively.
func scopeIsEmbeddedOnly(scope *trust.ScopeConfig) bool {
	if scope == nil || len(scope.Strategies) == 0 {
		return false
	}
	for _, s := range scope.Strategies {
		if s != trust.StrategyEmbedded {
			return false
		}
	}
	return true
}
