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

package objecttransfer

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/objecttransfer"
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
		{"ObjectFetchItem", reflect.TypeFor[ObjectFetchItem](), reflect.TypeFor[upstream.ObjectFetchItem]()},
		{"CompressionAlgo", reflect.TypeFor[CompressionAlgo](), reflect.TypeFor[upstream.CompressionAlgo]()},
		{"FetchObjectRequest", reflect.TypeFor[FetchObjectRequest](), reflect.TypeFor[upstream.FetchObjectRequest]()},
		{"FetchObjectResponse", reflect.TypeFor[FetchObjectResponse](), reflect.TypeFor[upstream.FetchObjectResponse]()},
		{"StreamFetchObjectsRequest", reflect.TypeFor[StreamFetchObjectsRequest](), reflect.TypeFor[upstream.StreamFetchObjectsRequest]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported compression algorithm
// carries the upstream value and type, so a fetch built through this package
// asks for what the server reads.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"CompressionNone", CompressionNone, upstream.CompressionNone},
		{"CompressionLZ4", CompressionLZ4, upstream.CompressionLZ4},
		{"CompressionZstd", CompressionZstd, upstream.CompressionZstd},
		{"CompressionSnappy", CompressionSnappy, upstream.CompressionSnappy},
		{"CompressionGzip", CompressionGzip, upstream.CompressionGzip},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
