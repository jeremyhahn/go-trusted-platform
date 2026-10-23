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

import (
	"context"
	"embed"
	"log/slog"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

// launchGUI creates all Wails bindings and launches the desktop
// application window. It blocks until the user closes the window.
func launchGUI(logger *slog.Logger) error {
	logger.Debug("creating Wails bindings")

	conn, bindings := newGUIBindings(logger)

	logger.Debug("launching Wails application")

	return wails.Run(&options.App{
		Title:  "Trusted Platform",
		Width:  1400,
		Height: 900,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup: func(ctx context.Context) {
			logger.Debug("Wails OnStartup")
			conn.startup(ctx)
		},
		OnShutdown: func(ctx context.Context) {
			logger.Debug("Wails OnShutdown")
			conn.shutdown(ctx)
		},
		Bind: bindings,
	})
}
