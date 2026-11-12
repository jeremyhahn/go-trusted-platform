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

// Package socktest gives tests a short directory for unix sockets. It is a
// stdlib-only leaf package so any test package can import it without cycles.
//
// Linux limits a unix socket path (sun_path) to 108 bytes including the NUL.
// t.TempDir() is $TMPDIR plus the full (sub)test name, so under a long TMPDIR
// or a long test name net.Listen("unix", ...) fails with
// "bind: invalid argument".
package socktest

import (
	"os"
	"testing"
)

// Dir returns a fresh directory with a short path for unix sockets, removed when t ends.
// It is made under /tmp when that is usable, else under os.TempDir(), because t.TempDir()
// embeds the test name and can exceed the 108-byte sun_path limit.
func Dir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sock")
	if err != nil {
		dir, err = os.MkdirTemp("", "sock")
		if err != nil {
			t.Fatalf("socktest: create socket dir: %v", err)
		}
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("socktest: remove socket dir %s: %v", dir, err)
		}
	})
	return dir
}
