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

package main

import "log/slog"

// newGUIBindings builds the bindings the desktop window exposes to its
// frontend, all sharing one connection. The connection binding is also
// returned on its own: the window's lifecycle hooks drive it.
func newGUIBindings(logger *slog.Logger) (*ConnectionBinding, []interface{}) {
	conn := NewConnectionBinding(logger)
	return conn, []interface{}{
		conn,
		NewDaemonBinding(logger, conn),
		NewCABinding(logger, conn),
	}
}
