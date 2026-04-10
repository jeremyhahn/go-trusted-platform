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

//go:build linux

package main

import "os"

// hasDisplay returns true when a graphical display environment is
// available on Linux. It checks for both X11 (DISPLAY) and Wayland
// (WAYLAND_DISPLAY) session variables.
func hasDisplay() bool {
	if os.Getenv("DISPLAY") != "" {
		return true
	}
	return os.Getenv("WAYLAND_DISPLAY") != ""
}
