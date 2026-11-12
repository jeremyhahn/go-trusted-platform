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

package iso

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDefaultConfig_SealPCRs pins the SPEC default seal PCR selection (7 and
// 11, docs/SPEC.md installer row) in the ISO build defaults.
func TestDefaultConfig_SealPCRs(t *testing.T) {
	want := []uint{7, 11}

	cfg := DefaultISOBuildConfig()
	assert.Equal(t, want, cfg.TPMSealPCR)

	// Each default config gets its own slice.
	cfg.TPMSealPCR[0] = 99
	assert.Equal(t, want, DefaultISOBuildConfig().TPMSealPCR)
}
