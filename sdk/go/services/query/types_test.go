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

package query

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/query"
)

// TestTypes_AreUpstreamAliases proves every re-exported type IS the upstream
// type, so a value crosses the boundary without conversion. A defined type
// in place of an alias would be a distinct reflect.Type.
func TestTypes_AreUpstreamAliases(t *testing.T) {
	cases := []struct {
		name     string
		got      reflect.Type
		upstream reflect.Type
	}{
		{"Client", reflect.TypeFor[Client](), reflect.TypeFor[upstream.Client]()},
		{"Operator", reflect.TypeFor[Operator](), reflect.TypeFor[upstream.Operator]()},
		{"QueryRequest", reflect.TypeFor[QueryRequest](), reflect.TypeFor[upstream.QueryRequest]()},
		{"QueryResponse", reflect.TypeFor[QueryResponse](), reflect.TypeFor[upstream.QueryResponse]()},
		{"QueryResult", reflect.TypeFor[QueryResult](), reflect.TypeFor[upstream.QueryResult]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported operator carries the
// upstream value and type, so a query built through this package means what
// the server reads.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"OpEqual", OpEqual, upstream.OpEqual},
		{"OpNotEqual", OpNotEqual, upstream.OpNotEqual},
		{"OpLessThan", OpLessThan, upstream.OpLessThan},
		{"OpLessThanOrEqual", OpLessThanOrEqual, upstream.OpLessThanOrEqual},
		{"OpGreaterThan", OpGreaterThan, upstream.OpGreaterThan},
		{"OpGreaterThanOrEqual", OpGreaterThanOrEqual, upstream.OpGreaterThanOrEqual},
		{"OpPrefix", OpPrefix, upstream.OpPrefix},
		{"OpRange", OpRange, upstream.OpRange},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
