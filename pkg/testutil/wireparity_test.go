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
	"fmt"
	"strings"
	"testing"
)

// recordingTB captures Fatalf so the helpers' failure paths can be asserted.
// Embedding the interface satisfies testing.TB's unexported method; only the
// methods the helpers call are overridden.
type recordingTB struct {
	testing.TB
	fatal string
}

func (r *recordingTB) Helper() {}
func (r *recordingTB) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
}

const tsSource = `
export interface Device {
  /** Device ID */
  id: string;
  attest_pub?: string;
  serial: string;
  nested: {
    inner: number;
  };
}

export interface DeviceDetail extends Device {
  name?: string;
}

export interface Empty {
}
`

func TestTSInterfaceFields_ReadsTopLevelDeclarations(t *testing.T) {
	fields := TSInterfaceFields(t, tsSource, "Device")

	for _, want := range []string{"id", "attest_pub", "serial", "nested"} {
		if !fields[want] {
			t.Errorf("field %q not parsed; got %v", want, fields)
		}
	}
	// The optional marker is not part of the name, and nested object members
	// are not top-level wire fields.
	if fields["attest_pub?"] || fields["inner"] {
		t.Errorf("parser leaked a marker or a nested member: %v", fields)
	}
	if len(fields) != 4 {
		t.Errorf("expected 4 fields, got %d: %v", len(fields), fields)
	}
}

func TestTSInterfaceFields_HandlesExtends(t *testing.T) {
	fields := TSInterfaceFields(t, tsSource, "DeviceDetail")
	if !fields["name"] || len(fields) != 1 {
		t.Errorf("extends clause broke the match: %v", fields)
	}
}

func TestTSInterfaceFields_FailsOnMissingInterface(t *testing.T) {
	rec := &recordingTB{}
	TSInterfaceFields(rec, tsSource, "Renamed")
	if !strings.Contains(rec.fatal, `"Renamed" not found`) {
		t.Fatalf("a missing interface must fail the test naming it; got %q", rec.fatal)
	}
}

func TestTSInterfaceFields_FailsOnZeroFields(t *testing.T) {
	// The control that keeps a green ratchet honest: an interface the parser
	// cannot read must not pass as "no mismatches".
	rec := &recordingTB{}
	TSInterfaceFields(rec, tsSource, "Empty")
	if !strings.Contains(rec.fatal, "zero fields") {
		t.Fatalf("an unparseable interface must fail loudly; got %q", rec.fatal)
	}
}

func TestGoJSONTagNames(t *testing.T) {
	type wire struct {
		ID        uint64 `json:"id,string"`
		Serial    string `json:"serial,omitempty"`
		Skipped   string `json:"-"`
		Untagged  string
		EventLog  []byte `json:"event_log,omitempty"`
		EmptyName string `json:",omitempty"`
	}

	tags := GoJSONTagNames(wire{})
	for _, want := range []string{"id", "serial", "event_log"} {
		if !tags[want] {
			t.Errorf("tag %q not read; got %v", want, tags)
		}
	}
	for _, absent := range []string{"-", "Skipped", "Untagged", "", "id,string"} {
		if tags[absent] {
			t.Errorf("%q must not be reported as a wire name; got %v", absent, tags)
		}
	}
	if len(tags) != 3 {
		t.Errorf("expected 3 wire names, got %d: %v", len(tags), tags)
	}
}

func TestCamelOf(t *testing.T) {
	cases := map[string]string{
		"attest_pub":              "attestPub",
		"post_enrollment_network": "postEnrollmentNetwork",
		"id":                      "id",
		"double__underscore":      "doubleUnderscore",
	}
	for in, want := range cases {
		if got := CamelOf(in); got != want {
			t.Errorf("CamelOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRepoFile_ReadsRelativeToTheModuleRoot(t *testing.T) {
	// go.mod itself is the one file guaranteed to exist at the root, and it
	// names this module, so a wrong root would read the wrong file.
	src := RepoFile(t, "go.mod")
	if !strings.Contains(src, "module github.com/jeremyhahn/go-trusted-platform") {
		t.Fatalf("RepoFile did not read this repository's go.mod: %q", src[:min(len(src), 80)])
	}
}

func TestRepoFile_FailsOnMissingFile(t *testing.T) {
	rec := &recordingTB{}
	RepoFile(rec, "sdk/javascript/src/types/does-not-exist.ts")
	if !strings.Contains(rec.fatal, "cannot read sdk/javascript/src/types/does-not-exist.ts") {
		t.Fatalf("a missing file must fail naming the path; got %q", rec.fatal)
	}
}
