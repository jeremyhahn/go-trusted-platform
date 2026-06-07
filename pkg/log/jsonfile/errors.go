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

package jsonfile

import "fmt"

// ErrInvalidConfig is returned when handler options are inconsistent.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("jsonfile: %s: %s", e.Field, e.Reason)
}

// ErrIO wraps file I/O failures inside the handler so callers can
// distinguish them from configuration errors via errors.As.
type ErrIO struct {
	Op   string
	Path string
	Err  error
}

func (e ErrIO) Error() string {
	return fmt.Sprintf("jsonfile: %s %s: %v", e.Op, e.Path, e.Err)
}

func (e ErrIO) Unwrap() error { return e.Err }
