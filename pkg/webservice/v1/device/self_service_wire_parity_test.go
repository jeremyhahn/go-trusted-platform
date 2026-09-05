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
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
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
// This is a separate file with its own helpers rather than an addition to
// #395's clientServerPairs, so that the two land in either order without a
// conflict; the helper names differ from #395's on purpose.
var selfServicePairs = map[string]any{
	// TypeScript interface          Go type whose JSON tags it must match exactly
	"DeviceSelfServiceProfile":   ProfileResponse{},
	"DeviceSelfServiceNetwork":   NetworkConfig{},
	"DeviceSelfServiceACL":       ACLConfig{},
	"DeviceSelfServiceRateLimit": RateLimitConfig{},
}

// selfServiceTSFields extracts the declared field names of one exported
// TypeScript interface from the SDK source.
func selfServiceTSFields(t *testing.T, src, iface string) map[string]bool {
	t.Helper()

	start := regexp.MustCompile(`(?m)^export interface ` + regexp.QuoteMeta(iface) + `\s*\{`)
	loc := start.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("TypeScript interface %q not found — renamed or removed; update selfServicePairs rather than deleting the entry", iface)
	}
	body := src[loc[1]:]
	if end := strings.Index(body, "\n}"); end >= 0 {
		body = body[:end]
	}

	fields := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s{2}([A-Za-z_][A-Za-z0-9_]*)\??:`).FindAllStringSubmatch(body, -1) {
		fields[m[1]] = true
	}
	if len(fields) == 0 {
		t.Fatalf("TypeScript interface %q parsed to zero fields — the parser stopped matching, so a green result would prove nothing", iface)
	}
	return fields
}

// selfServiceGoTags returns the wire names a Go struct emits.
func selfServiceGoTags(v any) map[string]bool {
	tags := map[string]bool{}
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		if name := strings.Split(tag, ",")[0]; name != "" {
			tags[name] = true
		}
	}
	return tags
}

// TestSelfServiceClientDeclaresExactlyTheWire is the ratchet for the
// device-facing surface. Unlike the operator ratchet it demands equality:
// this type was written against the wire from day one, so any difference in
// either direction is a drift, not a "client models a subset".
func TestSelfServiceClientDeclaresExactlyTheWire(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "sdk", "javascript", "src", "types", "device-self-service.ts"))
	if err != nil {
		t.Fatalf("cannot read the JavaScript SDK device-self-service types: %v", err)
	}
	src := string(raw)

	if len(selfServicePairs) == 0 {
		t.Fatal("selfServicePairs is empty; this test would pass while asserting nothing")
	}

	for iface, goType := range selfServicePairs {
		t.Run(iface, func(t *testing.T) {
			client := selfServiceTSFields(t, src, iface)
			server := selfServiceGoTags(goType)

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
		for tag := range selfServiceGoTags(goType) {
			if strings.Contains(tag, "_") {
				t.Errorf("%s (%T): wire name %q is snake_case on a surface documented as camelCase", iface, goType, tag)
			}
		}
	}
}
