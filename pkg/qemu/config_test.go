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

package qemu

import (
	"errors"
	"testing"
)

// TestValidateDiskCache asserts the exported validator accepts every QEMU
// cache mode plus the empty default, and rejects unknown modes with the
// typed error — CLI paths rely on it BEFORE destructive setup.
func TestValidateDiskCache(t *testing.T) {
	for _, mode := range []string{"", "writethrough", "writeback", "none", "unsafe", "directsync"} {
		if err := ValidateDiskCache(mode); err != nil {
			t.Errorf("mode %q must validate, got %v", mode, err)
		}
	}

	err := ValidateDiskCache("turbo")
	if err == nil {
		t.Fatal("expected error for unknown cache mode")
	}
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("expected *MessageError, got %T", err)
	}
}
