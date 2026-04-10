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

package webservice

import "sync"

type LoadBalancerFunc func(backends []string) string

func RoundRobinBalancer() LoadBalancerFunc {
	var mu sync.Mutex
	var idx int
	return func(backends []string) string {
		mu.Lock()
		defer mu.Unlock()
		selected := backends[idx]
		idx = (idx + 1) % len(backends)
		return selected
	}
}
