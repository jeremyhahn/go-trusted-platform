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

package firstboot

import (
	"strings"
	"testing"
)

// TestPlatformdUnits_EnableMTLS pins --enable-mtls on both shipped platformd
// units. Without it gRPC TCP authorizes tokens through the IAM policy
// enforcement point, which the embedded quicbaas SDK does not implement, and
// daemon.New refuses to start (#770) — the installed host would never come up.
func TestPlatformdUnits_EnableMTLS(t *testing.T) {
	units := map[string]string{
		"systemd": platformdServiceContent,
		"openrc":  platformdOpenRCScript,
	}
	for name, unit := range units {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(unit, "platformd serve") && !strings.Contains(unit, `command_args="serve`) {
				t.Fatalf("%s unit no longer starts platformd serve; update this test", name)
			}
			if !strings.Contains(unit, "--enable-mtls") {
				t.Errorf("%s unit starts platformd serve without --enable-mtls", name)
			}
		})
	}
}
