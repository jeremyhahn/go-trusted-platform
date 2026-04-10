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

//go:build platform_web

// Package embed provides optional embedding of the web frontend.
// When built with the platform_web tag, web assets are embedded into the binary.
package embed

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var webDist embed.FS

// WebFS provides access to the embedded web frontend filesystem.
var WebFS fs.FS

// IsEmbedded returns true when web frontend is embedded in the binary.
func IsEmbedded() bool {
	return true
}

func init() {
	var err error
	WebFS, err = fs.Sub(webDist, "dist")
	if err != nil {
		panic("failed to create sub filesystem for embedded web: " + err.Error())
	}
}
