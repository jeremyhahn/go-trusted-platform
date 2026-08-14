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

package mcp

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestNTPMethodsMapToTheServerTools pins the MCP wire contract against the
// tools registered by pkg/api/mcp/ntp_tools.go. A drift here makes
// `platformctl --protocol mcp ntp ...` fail with Unimplemented.
func TestNTPMethodsMapToTheServerTools(t *testing.T) {
	cases := map[string]string{
		platformv1.NTPService_GetStatus_FullMethodName:   "ntp_status",
		platformv1.NTPService_ListSources_FullMethodName: "ntp_sources",
		platformv1.NTPService_Step_FullMethodName:        "ntp_step",
	}

	for method, want := range cases {
		t.Run(method, func(t *testing.T) {
			got, ok := grpcMethodToMCPToolMap[method]
			if !ok {
				t.Fatalf("%s has no MCP tool mapping", method)
			}
			if got != want {
				t.Fatalf("tool = %q, want %q", got, want)
			}
		})
	}
}

// TestNTPToolNamesAreDistinct guards against a copy-paste collision that
// would route two RPCs to the same tool.
func TestNTPToolNamesAreDistinct(t *testing.T) {
	seen := make(map[string]string, 3)
	for _, method := range []string{
		platformv1.NTPService_GetStatus_FullMethodName,
		platformv1.NTPService_ListSources_FullMethodName,
		platformv1.NTPService_Step_FullMethodName,
	} {
		tool := grpcMethodToMCPToolMap[method]
		if other, clash := seen[tool]; clash {
			t.Fatalf("tool %q is shared by %s and %s", tool, other, method)
		}
		seen[tool] = method
	}
}
