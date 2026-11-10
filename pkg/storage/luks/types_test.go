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

package luks

import (
	"testing"
)

func TestLUKSVersionConstants(t *testing.T) {
	if LUKS1 != 1 {
		t.Errorf("expected LUKS1 to be 1, got %d", LUKS1)
	}
	if LUKS2 != 2 {
		t.Errorf("expected LUKS2 to be 2, got %d", LUKS2)
	}
	if LUKSVersion1 != 1 {
		t.Errorf("expected LUKSVersion1 to be 1, got %d", LUKSVersion1)
	}
	if LUKSVersion2 != 2 {
		t.Errorf("expected LUKSVersion2 to be 2, got %d", LUKSVersion2)
	}
}
