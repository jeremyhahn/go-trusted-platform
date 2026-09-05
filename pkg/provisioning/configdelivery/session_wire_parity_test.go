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

package configdelivery

import (
	"sort"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// The provisioning-session surface is the third wire the JavaScript SDK
// declares field names for, and until #425 it declared camelCase for every
// snake_case tag on Session — so each read on the console's session pages was
// undefined and typechecked perfectly. This pins the client's declarations to
// the Go tags the same way #395 and #417 pin the device surfaces.
//
// The parsing helpers are shared from pkg/testutil (#434); the pairing table
// and the policy stay here, because they are this surface's decisions.
//
// The policy is explicit per pairing. `exact` demands the client model the
// whole wire field for field, both ways; a non-exact pairing would only forbid
// spelling a snake_case wire name in camelCase. Both pairings here are exact —
// FulfillSessionRequest IS the body the SDK posts, so its session_id is a wire
// field, not a client-side path carrier — and the flag stays so a future
// client-only carrier can be declared deliberately rather than by loosening
// the rule for everyone.
type sessionPairing struct {
	goType any
	exact  bool
}

var sessionClientServerPairs = map[string]sessionPairing{
	"ProvisioningSession":   {goType: Session{}, exact: true},
	"FulfillSessionRequest": {goType: FulfillRequest{}, exact: true},
}

// TestSessionClientDeclaresTheWireNames is the ratchet for this surface.
func TestSessionClientDeclaresTheWireNames(t *testing.T) {
	src := testutil.RepoFile(t, "sdk/javascript/src/types/device.ts")
	if len(sessionClientServerPairs) == 0 {
		t.Fatal("sessionClientServerPairs is empty; this test would pass while asserting nothing")
	}

	for iface, pairing := range sessionClientServerPairs {
		t.Run(iface, func(t *testing.T) {
			client := testutil.TSInterfaceFields(t, src, iface)
			server := testutil.GoJSONTagNames(pairing.goType)

			var missing, camel, extra []string
			for tag := range server {
				switch {
				case client[tag]:
				case client[testutil.CamelOf(tag)]:
					camel = append(camel, tag+" (client declares "+testutil.CamelOf(tag)+")")
				default:
					missing = append(missing, tag)
				}
			}
			for field := range client {
				if !server[field] {
					extra = append(extra, field)
				}
			}
			sort.Strings(missing)
			sort.Strings(camel)
			sort.Strings(extra)

			if len(camel) > 0 {
				t.Errorf("%s declares camelCase for %d snake_case wire name(s); each decodes to undefined at runtime:\n  %s",
					iface, len(camel), strings.Join(camel, "\n  "))
			}
			if pairing.exact {
				if len(missing) > 0 {
					t.Errorf("%s: the server emits %v and the client does not declare them", iface, missing)
				}
				if len(extra) > 0 {
					t.Errorf("%s: the client declares %v and the server never emits them — every read is undefined", iface, extra)
				}
			}
		})
	}
}
