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

//go:build desktop

package main

import "context"

// startup is called by Wails on application startup. It stores the
// Wails context for use in event emission.
func (c *ConnectionBinding) startup(ctx context.Context) {
	c.logger.Debug("ConnectionBinding startup")
	c.ctx = ctx
}

// shutdown is called by Wails on application shutdown. It disconnects
// the client if connected.
func (c *ConnectionBinding) shutdown(_ context.Context) {
	c.logger.Debug("ConnectionBinding shutdown")
	if cl := c.client.Load(); cl != nil {
		_ = (*cl).Close()
	}
}
