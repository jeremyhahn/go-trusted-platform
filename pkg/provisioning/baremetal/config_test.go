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

package baremetal

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.InstallTimeout != 30*time.Minute {
		t.Errorf("InstallTimeout = %v, want 30m", cfg.InstallTimeout)
	}
	if cfg.PowerOnDelay != 5*time.Second {
		t.Errorf("PowerOnDelay = %v, want 5s", cfg.PowerOnDelay)
	}
}

func TestDefaultConfig_NonNil(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
}
