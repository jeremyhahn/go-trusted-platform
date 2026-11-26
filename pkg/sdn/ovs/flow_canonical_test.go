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

func TestCanonicalMatch_EquivalentStringsShareAKey(t *testing.T) {
	tests := []struct {
		name  string
		a, b  string
		equal bool
	}{
		{"host bits zeroed", "nw_src=192.0.2.7/24", "nw_src=192.0.2.0/24", true},
		{"slash 32 equals bare ip", "nw_src=192.0.2.1/32", "nw_src=192.0.2.1", true},
		{"whitespace ignored", "nw_dst=198.51.100.0/24, tp_dst=443", "nw_dst=198.51.100.0/24,tp_dst=443", true},
		{"field order ignored", "nw_proto=6,tp_dst=443,nw_src=192.0.2.0/24", "nw_src=192.0.2.0/24,nw_proto=6,tp_dst=443", true},
		{"prefix length differs", "nw_src=192.0.2.0/24", "nw_src=192.0.2.0/25", false},
		{"empty", "", "", true},
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

func TestCanonicalMatch_UnparseableIsAnError(t *testing.T) {
	if _, err := CanonicalMatch("nw_src=not-an-ip"); err == nil {
		t.Fatal("CanonicalMatch(nw_src=not-an-ip) returned no error")
	}
}
