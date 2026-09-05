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

package testutil

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Wire-parity helpers: the three client/server field-name ratchets
// (pkg/webservice/v1/device wire_tag_parity_test.go and
// self_service_wire_parity_test.go, pkg/provisioning/configdelivery
// session_wire_parity_test.go) compare the JavaScript SDK's declared
// interface fields against a Go struct's JSON tags. Each ratchet keeps its own
// explicit pairing table and its own policy (subset-tolerant or exact); what
// they share is how a TypeScript interface is parsed and how Go tags are read,
// and that lives here once (#434). The policies are deliberately NOT here — a
// shared policy would be a decision made for every future surface at once.

// tsInterfaceStart matches `export interface Name {`, with an optional
// `extends` clause, at the start of a line.
func tsInterfaceStart(iface string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^export interface ` + regexp.QuoteMeta(iface) + `\s*(?:extends [^{]+)?\{`)
}

// tsField matches one declared field at the interface's two-space indent:
// `  name: T;` or `  name?: T;`. Nested object literals are indented deeper and
// therefore not matched, which is the intent — the wire compares top-level
// names.
var tsField = regexp.MustCompile(`(?m)^\s{2}([A-Za-z_][A-Za-z0-9_]*)\??:`)

// TSInterfaceFields returns the top-level field names one exported TypeScript
// interface declares, read from the SDK source rather than a generated
// manifest: a manifest is a second record, and the ratchets exist to stop
// those. It fails the test when the interface is absent — a renamed type must
// update the pairing table, not silently drop out of coverage — and when it
// parses to zero fields, because a parser that stopped matching would
// otherwise report a clean surface.
func TSInterfaceFields(t testing.TB, src, iface string) map[string]bool {
	t.Helper()

	loc := tsInterfaceStart(iface).FindStringIndex(src)
	if loc == nil {
		t.Fatalf("TypeScript interface %q not found — it was renamed or removed, and its pairing "+
			"no longer covers anything. Update the pairing table rather than deleting the entry.", iface)
		return nil
	}

	body := src[loc[1]:]
	if end := strings.Index(body, "\n}"); end >= 0 {
		body = body[:end]
	}

	fields := map[string]bool{}
	for _, m := range tsField.FindAllStringSubmatch(body, -1) {
		fields[m[1]] = true
	}
	if len(fields) == 0 {
		t.Fatalf("TypeScript interface %q parsed to zero fields — the parser stopped matching, "+
			"so a green result would prove nothing", iface)
		return nil
	}
	return fields
}

// GoJSONTagNames returns the wire names a Go struct emits: the name part of
// each `json` tag, skipping `-` and untagged fields and dropping the
// `,omitempty` / `,string` options.
func GoJSONTagNames(v any) map[string]bool {
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

// CamelOf converts a snake_case wire name to the camelCase a TypeScript author
// reaches for by habit — exactly the mistake the ratchets catch.
func CamelOf(snake string) string {
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

// RepoFile reads a file by its path relative to the repository root, found by
// walking up from the working directory to the directory holding go.mod. The
// ratchets in different packages used to count `..` segments by hand — three
// in one package, four in another — and a wrong count reads as "file not
// found", not as "wrong file".
func RepoFile(t testing.TB, rel string) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot determine working directory: %v", err)
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found above the working directory; RepoFile needs to run inside the repository")
			return ""
		}
		dir = parent
	}

	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("cannot read %s from the repository root %s: %v", rel, dir, err)
		return ""
	}
	return string(raw)
}
