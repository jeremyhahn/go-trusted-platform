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

package metrics

import "fmt"

// ErrCollectorAlreadyRegistered indicates a collector is already registered
type ErrCollectorAlreadyRegistered struct {
	Name string
}

func (e ErrCollectorAlreadyRegistered) Error() string {
	return fmt.Sprintf("collector already registered: %s", e.Name)
}

// ErrInvalidConfiguration indicates invalid metrics configuration
type ErrInvalidConfiguration struct {
	Field string
	Err   error
}

func (e ErrInvalidConfiguration) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("invalid metrics configuration for field %s: %v", e.Field, e.Err)
	}
	return fmt.Sprintf("invalid metrics configuration for field %s", e.Field)
}

// ErrMetricsNotEnabled indicates metrics collection is not enabled
type ErrMetricsNotEnabled struct{}

func (e ErrMetricsNotEnabled) Error() string {
	return "metrics collection is not enabled"
}

// ErrCollectorRegistration indicates failure to register a collector
type ErrCollectorRegistration struct {
	Name string
	Err  error
}

func (e ErrCollectorRegistration) Error() string {
	return fmt.Sprintf("failed to register collector %s: %v", e.Name, e.Err)
}

// ErrInvalidMetricName indicates an invalid metric name
type ErrInvalidMetricName struct {
	Name string
}

func (e ErrInvalidMetricName) Error() string {
	return fmt.Sprintf("invalid metric name: %s", e.Name)
}
