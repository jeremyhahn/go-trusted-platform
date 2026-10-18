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

package transaction

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/transaction"
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
		{"Compare", reflect.TypeFor[Compare](), reflect.TypeFor[upstream.Compare]()},
		{"CompareTarget", reflect.TypeFor[CompareTarget](), reflect.TypeFor[upstream.CompareTarget]()},
		{"CompareResult", reflect.TypeFor[CompareResult](), reflect.TypeFor[upstream.CompareResult]()},
		{"TxnOp", reflect.TypeFor[TxnOp](), reflect.TypeFor[upstream.TxnOp]()},
		{"TxnOpType", reflect.TypeFor[TxnOpType](), reflect.TypeFor[upstream.TxnOpType]()},
		{"TxnOpResponse", reflect.TypeFor[TxnOpResponse](), reflect.TypeFor[upstream.TxnOpResponse]()},
		{"TxnRequest", reflect.TypeFor[TxnRequest](), reflect.TypeFor[upstream.TxnRequest]()},
		{"TxnResponse", reflect.TypeFor[TxnResponse](), reflect.TypeFor[upstream.TxnResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported compare target, compare
// result and operation type carries the upstream value and type, so a
// transaction built through this package means what the server reads.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"CompareVersion", CompareVersion, upstream.CompareVersion},
		{"CompareValue", CompareValue, upstream.CompareValue},
		{"CompareModRevision", CompareModRevision, upstream.CompareModRevision},
		{"CompareCreateRevision", CompareCreateRevision, upstream.CompareCreateRevision},
		{"CompareEqual", CompareEqual, upstream.CompareEqual},
		{"CompareNotEqual", CompareNotEqual, upstream.CompareNotEqual},
		{"CompareLess", CompareLess, upstream.CompareLess},
		{"CompareGreater", CompareGreater, upstream.CompareGreater},
		{"TxnOpPut", TxnOpPut, upstream.TxnOpPut},
		{"TxnOpGet", TxnOpGet, upstream.TxnOpGet},
		{"TxnOpDelete", TxnOpDelete, upstream.TxnOpDelete},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
