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

package health

import "context"

// HealthChecker is the interface that all health checkers must implement.
type HealthChecker interface {
	// Name returns the unique identifier for this health checker.
	Name() string

	// Check performs the health check and returns the component health status.
	Check(ctx context.Context) ComponentHealth
}
