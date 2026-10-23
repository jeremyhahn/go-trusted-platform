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

package app

import "fmt"

// HostnameError is returned by Init when no hostname is configured and the
// operating system's hostname cannot be read.
type HostnameError struct {
	Cause error
}

// Error returns the error message.
func (e HostnameError) Error() string {
	return fmt.Sprintf("app: failed to read the local hostname: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e HostnameError) Unwrap() error { return e.Cause }

// TestConfigError is returned by TestConfigWithStorage when a step of
// writing or loading the test configuration fails.
type TestConfigError struct {
	Step  string
	Path  string
	Cause error
}

// Error returns the error message.
func (e TestConfigError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("app: test config: %s: %v", e.Step, e.Cause)
	}
	return fmt.Sprintf("app: test config: %s %q: %v", e.Step, e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e TestConfigError) Unwrap() error { return e.Cause }
