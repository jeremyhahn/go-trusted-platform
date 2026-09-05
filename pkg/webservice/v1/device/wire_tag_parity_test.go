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

// tsFieldsFor extracts the declared field names of one exported TypeScript
// interface. It reads the SDK source rather than a generated manifest, because
// a manifest is a second record and this test exists to stop those.
func tsFieldsFor(t *testing.T, src, iface string) map[string]bool {
	t.Helper()

	start := regexp.MustCompile(`(?m)^export interface ` + regexp.QuoteMeta(iface) + `\s*(?:extends [^{]+)?\{`)
	loc := start.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("TypeScript interface %q not found — it was renamed or removed, and this pairing "+
			"no longer covers anything. Update clientServerPairs rather than deleting the entry.", iface)
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
		t.Fatalf("TypeScript interface %q parsed to zero fields — the parser stopped matching, "+
			"so a green result here would prove nothing", iface)
	}
	return fields
}

// goJSONTags returns the wire names a Go struct emits, skipping `-` and
// unwrapping the `,omitempty` / `,string` options.
func goJSONTags(v any) map[string]bool {
	tags := map[string]bool{}
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			tags[name] = true
		}
	}
	return tags
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
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "sdk", "javascript", "src", "types", "device.ts"))
	if err != nil {
		t.Fatalf("cannot read the JavaScript SDK device types: %v", err)
	}
	src := string(raw)

	if len(clientServerPairs) == 0 {
		t.Fatal("clientServerPairs is empty; this test would pass while asserting nothing")
	}

	for iface, goType := range clientServerPairs {
		t.Run(iface, func(t *testing.T) {
			clientFields := tsFieldsFor(t, src, iface)
			serverTags := goJSONTags(goType)

			var mismatched []string
			for tag := range serverTags {
				if !strings.Contains(tag, "_") {
					continue // already single-word; no case question to get wrong
				}
				if clientFields[tag] {
					continue // client uses the wire name
				}
				if clientFields[camelOf(tag)] {
					mismatched = append(mismatched, tag+" (client declares "+camelOf(tag)+")")
				}
			}

			sort.Strings(mismatched)
			if len(mismatched) > 0 {
				t.Errorf("%s declares camelCase for %d field(s) this package emits in snake_case.\n"+
					"  Each one decodes to undefined at runtime and type-checks perfectly.\n"+
					"  %s\n"+
					"  Fix the TypeScript declaration to the wire name; do not add a converter — the\n"+
					"  device surface has two documented conventions (docs/device/api.md:140-151 for the\n"+
					"  mTLS device-facing shape, docs/device/configuration.md:170 for this one).",
					iface, len(mismatched), strings.Join(mismatched, "\n  "))
			}
		})
	}
}

// camelOf converts a snake_case wire name to the camelCase a TypeScript author
// reaches for by habit — which is exactly the mistake this test catches.
func camelOf(snake string) string {
	parts := strings.Split(snake, "_")
	out := parts[0]
	for _, p := range parts[1:] {
		if p == "" {
			continue
		}
		out += strings.ToUpper(p[:1]) + p[1:]
	}
	return out
}
