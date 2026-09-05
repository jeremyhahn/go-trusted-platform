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

// The device-facing profile (GET /device/profile, handler.go) is the SECOND
// wire on this surface and it is camelCase by contract (docs/device/api.md
// §3.2). The JavaScript SDK models it in its own file; this pins that file to
// the Go tags field-for-field in BOTH directions — a field added to
// ProfileResponse without a TypeScript twin fails, and so does a TypeScript
// field the server never emits. The pairing is explicit for the same reason
// #395's operator-surface ratchet is: matching by name would move the table
// into the test and stop covering a renamed type silently.
//
// This is a separate file from #395's clientServerPairs because the two
// surfaces carry different policies; the parsing helpers are shared from
// pkg/testutil (#434).
var selfServicePairs = map[string]any{
	// TypeScript interface          Go type whose JSON tags it must match exactly
	"DeviceSelfServiceProfile":   ProfileResponse{},
	"DeviceSelfServiceNetwork":   NetworkConfig{},
	"DeviceSelfServiceACL":       ACLConfig{},
	"DeviceSelfServiceRateLimit": RateLimitConfig{},
}

// TestSelfServiceClientDeclaresExactlyTheWire is the ratchet for the
// device-facing surface. Unlike the operator ratchet it demands equality:
// this type was written against the wire from day one, so any difference in
// either direction is a drift, not a "client models a subset".
func TestSelfServiceClientDeclaresExactlyTheWire(t *testing.T) {
	src := testutil.RepoFile(t, "sdk/javascript/src/types/device-self-service.ts")

	if len(selfServicePairs) == 0 {
		t.Fatal("selfServicePairs is empty; this test would pass while asserting nothing")
	}

	for iface, goType := range selfServicePairs {
		t.Run(iface, func(t *testing.T) {
			client := testutil.TSInterfaceFields(t, src, iface)
			server := testutil.GoJSONTagNames(goType)

			var missing, extra []string
			for tag := range server {
				if !client[tag] {
					missing = append(missing, tag)
				}
			}
			for field := range client {
				if !server[field] {
					extra = append(extra, field)
				}
			}
			sort.Strings(missing)
			sort.Strings(extra)

			if len(missing) > 0 {
				t.Errorf("%s: the server emits %v and the client does not declare them — a node reading this type sees undefined for a value it was sent", iface, missing)
			}
			if len(extra) > 0 {
				t.Errorf("%s: the client declares %v and the server never emits them — every read is undefined", iface, extra)
			}
		})
	}
}

// TestSelfServiceWireIsCamelCase pins the contract docs/device/api.md §3.2
// states in words: no snake_case name on this surface. It guards the Go side,
// so a future field cannot arrive as `static_ip` beside `staticIP`.
func TestSelfServiceWireIsCamelCase(t *testing.T) {
	for iface, goType := range selfServicePairs {
		for tag := range testutil.GoJSONTagNames(goType) {
			if strings.Contains(tag, "_") {
				t.Errorf("%s (%T): wire name %q is snake_case on a surface documented as camelCase", iface, goType, tag)
			}
		}
	}
}
