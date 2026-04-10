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

package modes

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
	"github.com/stretchr/testify/assert"
)

// TestOverlayModeConfig_Validate_InvalidVTEP verifies that an invalid VTEP
// config propagates the validation error through Validate.
func TestOverlayModeConfig_Validate_InvalidVTEP(t *testing.T) {
	cfg := &OverlayModeConfig{
		VTEPConfig: &vxlan.VTEPConfig{
			// Missing LocalIP, UnderlayIface, etc.
		},
		BridgeName: "br-test",
		Logger:     createTestLogger(),
	}
	err := cfg.Validate()
	assert.Error(t, err)
}
