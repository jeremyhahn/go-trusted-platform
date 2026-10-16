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

package batch

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/batch"
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
		{"BatchOperation", reflect.TypeFor[BatchOperation](), reflect.TypeFor[upstream.BatchOperation]()},
		{"OpType", reflect.TypeFor[OpType](), reflect.TypeFor[upstream.OpType]()},
		{"BatchResult", reflect.TypeFor[BatchResult](), reflect.TypeFor[upstream.BatchResult]()},
		{"BatchRequest", reflect.TypeFor[BatchRequest](), reflect.TypeFor[upstream.BatchRequest]()},
		{"BatchResponse", reflect.TypeFor[BatchResponse](), reflect.TypeFor[upstream.BatchResponse]()},
		{"BatchPutResponse", reflect.TypeFor[BatchPutResponse](), reflect.TypeFor[upstream.BatchPutResponse]()},
		{"PutResultItem", reflect.TypeFor[PutResultItem](), reflect.TypeFor[upstream.PutResultItem]()},
		{"BatchGetResponse", reflect.TypeFor[BatchGetResponse](), reflect.TypeFor[upstream.BatchGetResponse]()},
		{"GetResultItem", reflect.TypeFor[GetResultItem](), reflect.TypeFor[upstream.GetResultItem]()},
		{"BatchDeleteResponse", reflect.TypeFor[BatchDeleteResponse](), reflect.TypeFor[upstream.BatchDeleteResponse]()},
		{"DeleteResultItem", reflect.TypeFor[DeleteResultItem](), reflect.TypeFor[upstream.DeleteResultItem]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported operation type carries
// the upstream value and type, so a batch built through this package means
// what the server reads.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"OpPut", OpPut, upstream.OpPut},
		{"OpDelete", OpDelete, upstream.OpDelete},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
