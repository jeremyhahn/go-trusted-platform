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

package device

import (
	"sort"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// The JavaScript SDK declares the field names it expects on the wire. This
// asserts they are the names this package actually emits.
//
// #329 was filed naming three mismatched fields. Measured against the wire it
// was THIRTY-NINE — the issue's list was drawn by hand, which is the same way
// #342's "nine" turned out to be ten and #321's "nine" turned out to be 94.
// The point of this test is that the population is measured by the build
// rather than by the next person's grep.
//
// The pairing below is EXPLICIT. Matching Go types to TypeScript interfaces by
// name would just move the hand-drawn table in here, and it would silently
// stop covering a type someone renamed.
var clientServerPairs = map[string]any{
	// TypeScript interface        Go type whose JSON tags it must match
	"Device":                      DeviceResponse{},
	"DeviceProfile":               ProfileFullResponse{},
	"DeviceTemplate":              TemplateResponse{},
	"CreateDeviceRequest":         DeviceRequest{},
	"CreateProfileRequest":        ProfileRequest{},
	"CreateDeviceTemplateRequest": TemplateRequest{},
}

// TestClientDeclaresTheWireNames is the ratchet.
//
// For every paired type it compares the two field-name sets and reports any
// name the server emits whose camelCase spelling the client declares instead.
// A field present on only one side is not a failure — the client may model a
// subset, and the server may serve fields no client reads. What fails is the
// SAME field under two spellings, which is the defect that decodes to
// undefined at runtime and type-checks perfectly.
func TestClientDeclaresTheWireNames(t *testing.T) {
	src := testutil.RepoFile(t, "sdk/javascript/src/types/device.ts")

	if len(clientServerPairs) == 0 {
		t.Fatal("clientServerPairs is empty; this test would pass while asserting nothing")
	}

	for iface, goType := range clientServerPairs {
		t.Run(iface, func(t *testing.T) {
			clientFields := testutil.TSInterfaceFields(t, src, iface)
			serverTags := testutil.GoJSONTagNames(goType)

			var mismatched []string
			for tag := range serverTags {
				if !strings.Contains(tag, "_") {
					continue // already single-word; no case question to get wrong
				}
				if clientFields[tag] {
					continue // client uses the wire name
				}
				if clientFields[testutil.CamelOf(tag)] {
					mismatched = append(mismatched, tag+" (client declares "+testutil.CamelOf(tag)+")")
				}
			}

			sort.Strings(mismatched)
			if len(mismatched) > 0 {
				t.Errorf("%s declares camelCase for %d field(s) this package emits in snake_case.\n"+
					"  Each one decodes to undefined at runtime and type-checks perfectly.\n"+
					"  %s\n"+
					"  Fix the TypeScript declaration to the wire name; do not add a converter — the\n"+
					"  device surface has two documented conventions (docs/device/api.md §3.2 for the\n"+
					"  mTLS device-facing shape, docs/device/api.md §3.5 for this one).",
					iface, len(mismatched), strings.Join(mismatched, "\n  "))
			}
		})
	}
}
