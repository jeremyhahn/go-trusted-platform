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

//go:build !linux

package nbd

import "os"

// errPunchHoleUnsupported sends trim to the zero-writing fallback on
// platforms without fallocate.
type errPunchHoleUnsupported struct{}

func (errPunchHoleUnsupported) Error() string {
	return "nbd: hole punching is not supported on this platform"
}

func punchHole(_ *os.File, _ int64, _ int64) error {
	return errPunchHoleUnsupported{}
}
