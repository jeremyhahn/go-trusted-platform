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

package install

import (
	"os"
	"testing"
)

// shortSocketDir returns a fresh directory short enough to hold a unix
// socket: sun_path is limited to 108 bytes, and t.TempDir() under a long
// TMPDIR plus a long test name exceeds it.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "s")
	if err == nil && len(dir) > 60 {
		_ = os.RemoveAll(dir)
		dir, err = os.MkdirTemp("/tmp", "s")
	}
	if err != nil {
		t.Fatalf("short socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
