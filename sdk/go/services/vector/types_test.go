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

package vector

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/vector"
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
		{"VectorEntity", reflect.TypeFor[VectorEntity](), reflect.TypeFor[upstream.VectorEntity]()},
		{"SearchResult", reflect.TypeFor[SearchResult](), reflect.TypeFor[upstream.SearchResult]()},
		{"MetadataFilter", reflect.TypeFor[MetadataFilter](), reflect.TypeFor[upstream.MetadataFilter]()},
		{"FilterOperator", reflect.TypeFor[FilterOperator](), reflect.TypeFor[upstream.FilterOperator]()},
		{"NamespaceConfig", reflect.TypeFor[NamespaceConfig](), reflect.TypeFor[upstream.NamespaceConfig]()},
		{"NamespaceInfo", reflect.TypeFor[NamespaceInfo](), reflect.TypeFor[upstream.NamespaceInfo]()},
		{"IndexType", reflect.TypeFor[IndexType](), reflect.TypeFor[upstream.IndexType]()},
		{"UpsertRequest", reflect.TypeFor[UpsertRequest](), reflect.TypeFor[upstream.UpsertRequest]()},
		{"UpsertResponse", reflect.TypeFor[UpsertResponse](), reflect.TypeFor[upstream.UpsertResponse]()},
		{"BatchUpsertRequest", reflect.TypeFor[BatchUpsertRequest](), reflect.TypeFor[upstream.BatchUpsertRequest]()},
		{"BatchUpsertResponse", reflect.TypeFor[BatchUpsertResponse](), reflect.TypeFor[upstream.BatchUpsertResponse]()},
		{"GetRequest", reflect.TypeFor[GetRequest](), reflect.TypeFor[upstream.GetRequest]()},
		{"GetResponse", reflect.TypeFor[GetResponse](), reflect.TypeFor[upstream.GetResponse]()},
		{"DeleteRequest", reflect.TypeFor[DeleteRequest](), reflect.TypeFor[upstream.DeleteRequest]()},
		{"DeleteResponse", reflect.TypeFor[DeleteResponse](), reflect.TypeFor[upstream.DeleteResponse]()},
		{"BatchDeleteRequest", reflect.TypeFor[BatchDeleteRequest](), reflect.TypeFor[upstream.BatchDeleteRequest]()},
		{"BatchDeleteResponse", reflect.TypeFor[BatchDeleteResponse](), reflect.TypeFor[upstream.BatchDeleteResponse]()},
		{"ListVectorsRequest", reflect.TypeFor[ListVectorsRequest](), reflect.TypeFor[upstream.ListVectorsRequest]()},
		{"ListVectorsResponse", reflect.TypeFor[ListVectorsResponse](), reflect.TypeFor[upstream.ListVectorsResponse]()},
		{"UpdateMetadataRequest", reflect.TypeFor[UpdateMetadataRequest](), reflect.TypeFor[upstream.UpdateMetadataRequest]()},
		{"UpdateMetadataResponse", reflect.TypeFor[UpdateMetadataResponse](), reflect.TypeFor[upstream.UpdateMetadataResponse]()},
		{"SearchSimilarRequest", reflect.TypeFor[SearchSimilarRequest](), reflect.TypeFor[upstream.SearchSimilarRequest]()},
		{"SearchSimilarResponse", reflect.TypeFor[SearchSimilarResponse](), reflect.TypeFor[upstream.SearchSimilarResponse]()},
		{"SearchByIDRequest", reflect.TypeFor[SearchByIDRequest](), reflect.TypeFor[upstream.SearchByIDRequest]()},
		{"SearchByIDResponse", reflect.TypeFor[SearchByIDResponse](), reflect.TypeFor[upstream.SearchByIDResponse]()},
		{"SearchByMetadataRequest", reflect.TypeFor[SearchByMetadataRequest](), reflect.TypeFor[upstream.SearchByMetadataRequest]()},
		{"SearchByMetadataResponse", reflect.TypeFor[SearchByMetadataResponse](), reflect.TypeFor[upstream.SearchByMetadataResponse]()},
		{"HybridSearchRequest", reflect.TypeFor[HybridSearchRequest](), reflect.TypeFor[upstream.HybridSearchRequest]()},
		{"HybridSearchResponse", reflect.TypeFor[HybridSearchResponse](), reflect.TypeFor[upstream.HybridSearchResponse]()},
		{"CreateNamespaceRequest", reflect.TypeFor[CreateNamespaceRequest](), reflect.TypeFor[upstream.CreateNamespaceRequest]()},
		{"CreateNamespaceResponse", reflect.TypeFor[CreateNamespaceResponse](), reflect.TypeFor[upstream.CreateNamespaceResponse]()},
		{"DeleteNamespaceRequest", reflect.TypeFor[DeleteNamespaceRequest](), reflect.TypeFor[upstream.DeleteNamespaceRequest]()},
		{"DeleteNamespaceResponse", reflect.TypeFor[DeleteNamespaceResponse](), reflect.TypeFor[upstream.DeleteNamespaceResponse]()},
		{"GetNamespaceInfoRequest", reflect.TypeFor[GetNamespaceInfoRequest](), reflect.TypeFor[upstream.GetNamespaceInfoRequest]()},
		{"GetNamespaceInfoResponse", reflect.TypeFor[GetNamespaceInfoResponse](), reflect.TypeFor[upstream.GetNamespaceInfoResponse]()},
		{"ListNamespacesRequest", reflect.TypeFor[ListNamespacesRequest](), reflect.TypeFor[upstream.ListNamespacesRequest]()},
		{"ListNamespacesResponse", reflect.TypeFor[ListNamespacesResponse](), reflect.TypeFor[upstream.ListNamespacesResponse]()},
		{"GetStatsRequest", reflect.TypeFor[GetStatsRequest](), reflect.TypeFor[upstream.GetStatsRequest]()},
		{"GetStatsResponse", reflect.TypeFor[GetStatsResponse](), reflect.TypeFor[upstream.GetStatsResponse]()},
		{"RebuildIndexRequest", reflect.TypeFor[RebuildIndexRequest](), reflect.TypeFor[upstream.RebuildIndexRequest]()},
		{"RebuildIndexResponse", reflect.TypeFor[RebuildIndexResponse](), reflect.TypeFor[upstream.RebuildIndexResponse]()},
		{"GetIndexProgressRequest", reflect.TypeFor[GetIndexProgressRequest](), reflect.TypeFor[upstream.GetIndexProgressRequest]()},
		{"GetIndexProgressResponse", reflect.TypeFor[GetIndexProgressResponse](), reflect.TypeFor[upstream.GetIndexProgressResponse]()},
		{"CompactRequest", reflect.TypeFor[CompactRequest](), reflect.TypeFor[upstream.CompactRequest]()},
		{"CompactResponse", reflect.TypeFor[CompactResponse](), reflect.TypeFor[upstream.CompactResponse]()},
		{"GetCompactionProgressRequest", reflect.TypeFor[GetCompactionProgressRequest](), reflect.TypeFor[upstream.GetCompactionProgressRequest]()},
		{"GetCompactionProgressResponse", reflect.TypeFor[GetCompactionProgressResponse](), reflect.TypeFor[upstream.GetCompactionProgressResponse]()},
		{"ExportRequest", reflect.TypeFor[ExportRequest](), reflect.TypeFor[upstream.ExportRequest]()},
		{"ExportResponse", reflect.TypeFor[ExportResponse](), reflect.TypeFor[upstream.ExportResponse]()},
		{"ImportRequest", reflect.TypeFor[ImportRequest](), reflect.TypeFor[upstream.ImportRequest]()},
		{"ImportResponse", reflect.TypeFor[ImportResponse](), reflect.TypeFor[upstream.ImportResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported operator and index type
// carries the upstream value and type, so a filter or namespace built through
// this package means what the server reads.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"FilterOperatorEquals", FilterOperatorEquals, upstream.FilterOperatorEquals},
		{"FilterOperatorNotEquals", FilterOperatorNotEquals, upstream.FilterOperatorNotEquals},
		{"FilterOperatorGreaterThan", FilterOperatorGreaterThan, upstream.FilterOperatorGreaterThan},
		{"FilterOperatorGreaterThanOrEqual", FilterOperatorGreaterThanOrEqual, upstream.FilterOperatorGreaterThanOrEqual},
		{"FilterOperatorLessThan", FilterOperatorLessThan, upstream.FilterOperatorLessThan},
		{"FilterOperatorLessThanOrEqual", FilterOperatorLessThanOrEqual, upstream.FilterOperatorLessThanOrEqual},
		{"FilterOperatorIn", FilterOperatorIn, upstream.FilterOperatorIn},
		{"FilterOperatorContains", FilterOperatorContains, upstream.FilterOperatorContains},
		{"IndexTypeHNSW", IndexTypeHNSW, upstream.IndexTypeHNSW},
		{"IndexTypeFlat", IndexTypeFlat, upstream.IndexTypeFlat},
		{"IndexTypeIVF", IndexTypeIVF, upstream.IndexTypeIVF},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
