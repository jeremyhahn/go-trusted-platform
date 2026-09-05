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
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The provisioning-session surface is the third wire the JavaScript SDK
// declares field names for, and until #425 it declared camelCase for every
// snake_case tag on Session — so each read on the console's session pages was
// undefined and typechecked perfectly. This pins the client's declarations to
// the Go tags the same way #395 and #417 pin the device surfaces.
//
// Third copy of the two helpers by design: #434 unifies them once all three
// are on main. The names differ from both earlier copies so this lands in any
// order without a redeclaration.
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

func sessionTSFields(t *testing.T, src, iface string) map[string]bool {
	t.Helper()
	start := regexp.MustCompile(`(?m)^export interface ` + regexp.QuoteMeta(iface) + `\s*\{`)
	loc := start.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("TypeScript interface %q not found — renamed or removed; update sessionClientServerPairs rather than deleting the entry", iface)
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

func sessionGoTags(v any) map[string]bool {
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

func sessionCamelOf(snake string) string {
	parts := strings.Split(snake, "_")
	out := parts[0]
	for _, p := range parts[1:] {
		if p != "" {
			out += strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return out
}

// TestSessionClientDeclaresTheWireNames is the ratchet for this surface.
func TestSessionClientDeclaresTheWireNames(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "javascript", "src", "types", "device.ts"))
	if err != nil {
		t.Fatalf("cannot read the JavaScript SDK device types: %v", err)
	}
	src := string(raw)
	if len(sessionClientServerPairs) == 0 {
		t.Fatal("sessionClientServerPairs is empty; this test would pass while asserting nothing")
	}

	for iface, pairing := range sessionClientServerPairs {
		t.Run(iface, func(t *testing.T) {
			client := sessionTSFields(t, src, iface)
			server := sessionGoTags(pairing.goType)

			var missing, camel, extra []string
			for tag := range server {
				switch {
				case client[tag]:
				case client[sessionCamelOf(tag)]:
					camel = append(camel, tag+" (client declares "+sessionCamelOf(tag)+")")
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
