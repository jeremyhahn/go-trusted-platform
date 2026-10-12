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

// placeholderName is the tracked file that keeps //go:embed all:dist matching
// when no console has been built into dist.
const placeholderName = ".gitkeep"

// IsEmbedded returns true when the binary carries a web console, that is when
// the embedded dist holds anything besides the tracked placeholder. A build
// with the platform_web tag but an unpopulated dist reports false, so callers
// fall back to the filesystem path instead of serving nothing.
func IsEmbedded() bool {
	return hasConsole(WebFS)
}

// hasConsole reports whether fsys has at least one entry other than the
// placeholder. An unreadable or nil filesystem has no console.
func hasConsole(fsys fs.FS) bool {
	if fsys == nil {
		return false
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() != placeholderName {
			return true
		}
	}
	return false
}

func init() {
	var err error
	WebFS, err = fs.Sub(webDist, "dist")
	if err != nil {
		panic("failed to create sub filesystem for embedded web: " + err.Error())
	}
}
