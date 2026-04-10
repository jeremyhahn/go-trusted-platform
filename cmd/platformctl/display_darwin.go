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

//go:build darwin

package main

import "os"

// hasDisplay returns true when a graphical display is available on
// macOS. The GUI is always available unless the session is an SSH
// connection (indicated by SSH_TTY).
func hasDisplay() bool {
	return os.Getenv("SSH_TTY") == ""
}
