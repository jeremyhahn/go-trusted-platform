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

package socktest

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sunPathMax is the Linux sun_path size, including the terminating NUL.
const sunPathMax = 108

func TestDirStaysShortUnderLongTMPDIR(t *testing.T) {
	long := t.TempDir()
	if pad := 120 - len(long) - 1; pad > 0 {
		long = filepath.Join(long, strings.Repeat("x", pad))
	}
	if err := os.MkdirAll(long, 0o700); err != nil {
		t.Fatalf("make long TMPDIR: %v", err)
	}
	if len(long) < 120 {
		t.Fatalf("long TMPDIR is %d bytes, want at least 120", len(long))
	}
	t.Setenv("TMPDIR", long)

	sock := filepath.Join(Dir(t), "platformd.sock")
	if len(sock) >= sunPathMax {
		t.Fatalf("socket path %q is %d bytes, want under %d", sock, len(sock), sunPathMax)
	}
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen on %s: %v", sock, err)
	}
	if err := lis.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
}

func TestDirIsFreshAndRemovedAtCleanup(t *testing.T) {
	var dir string
	t.Run("inner", func(t *testing.T) {
		dir = Dir(t)
		if other := Dir(t); other == dir {
			t.Fatalf("Dir returned %s twice", dir)
		}
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
	})
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir %s still present after cleanup (err %v)", dir, err)
	}
}
