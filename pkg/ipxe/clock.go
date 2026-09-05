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

package ipxe

import "time"

// clock is this package's entire view of time. Both lease tables use it: the
// two allocators in ipam_allocator.go, and DHCPServer's built-in table, which
// keeps its own leases whenever no allocator is injected.
//
// ONE method, because nothing here blocks on a computed interval: every use is
// either a comparison against a lease's ExpiresAt or an ExpiresAt computed from
// it. That was verified across all eighteen call sites before this seam was
// written, not after. pkg/security/ratelimit needed two methods (NowNano and
// After) precisely because its WaitN blocks, and a fake controlling only the
// instant would have left it waiting on real time for a deadline fake time
// never reaches. Same shape as pkg/sdn/bgp's dampeningClock and
// pkg/tenant/quota's quotaClock; a different shape from ratelimit's. Worth
// knowing before anyone extracts a shared one.
type clock interface {
	Now() time.Time
}

// realClock is the production clock: the standard library, unmodified.
type realClock struct{}

// Now returns the current wall-clock time.
func (realClock) Now() time.Time { return time.Now() }
