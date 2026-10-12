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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

// AttachNodeCA loads the node's certificate authority through
// config.App, initializing it on first use, and sets it as
// config.CAService so the daemon serves CA calls on every transport.
// platformd serve and the embedded host both call it. On error
// config.CAService is left unset and CA calls answer ErrCANotInitialized.
func AttachNodeCA(ctx context.Context, config *Config, initParams *app.AppInitParams) error {
	if config.App == nil {
		return app.ErrCANotConfigured{}
	}
	if err := config.App.LoadOrInitCA(ctx, initParams); err != nil {
		return err
	}
	config.CAService = config.App.CA
	return nil
}
