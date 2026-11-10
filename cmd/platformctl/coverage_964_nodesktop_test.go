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

//go:build !desktop

package main

import (
	"errors"
	"testing"
)

// The binary built without the desktop tag never opens a window.
func TestCov964_LaunchGUIWithoutTheDesktopTag(t *testing.T) {
	var unavailable *GUIUnavailableError
	if err := launchGUI(cov964Logger()); !errors.As(err, &unavailable) {
		t.Fatalf("launchGUI = %v, want GUIUnavailableError", err)
	}
}
