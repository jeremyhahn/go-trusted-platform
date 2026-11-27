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

package ovs

import "testing"

// A field with an all-zero mask matches every value: on the switch it is
// the same entry as a match that omits the field, so both must share a key.
func TestCanonicalMatch_ZeroMaskEqualsOmittedField(t *testing.T) {
	tests := []struct {
		name  string
		a, b  string
		equal bool
	}{
		{"zero prefix source equals no source", "tcp,nw_src=0.0.0.0/0,tp_dst=443", "tcp,tp_dst=443", true},
		{"zero prefix destination equals no destination", "nw_dst=0.0.0.0/0,nw_proto=6", "nw_proto=6", true},
		{"slash 1 is not a wildcard", "tcp,nw_src=0.0.0.0/1,tp_dst=443", "tcp,tp_dst=443", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ka, err := CanonicalMatch(tt.a)
			if err != nil {
				t.Fatalf("CanonicalMatch(%q): %v", tt.a, err)
			}
			kb, err := CanonicalMatch(tt.b)
			if err != nil {
				t.Fatalf("CanonicalMatch(%q): %v", tt.b, err)
			}
			if (ka == kb) != tt.equal {
				t.Fatalf("CanonicalMatch(%q)=%q, CanonicalMatch(%q)=%q, want equal=%v", tt.a, ka, tt.b, kb, tt.equal)
			}
		})
	}
}
