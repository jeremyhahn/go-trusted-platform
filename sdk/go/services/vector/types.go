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
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/vector"
)

// Client is the vector similarity-search client returned by
// quicbaas.Client.Vector().
type Client = upstream.Client

// Vectors, namespaces and the value types they carry.
type (
	// VectorEntity is a stored vector with its ID and metadata.
	VectorEntity = upstream.VectorEntity
	// SearchResult is one match of a similarity search.
	SearchResult = upstream.SearchResult
	// MetadataFilter restricts a search by a metadata field.
	MetadataFilter = upstream.MetadataFilter
	// FilterOperator is the comparison a MetadataFilter applies.
	FilterOperator = upstream.FilterOperator
	// NamespaceConfig configures a namespace's dimensionality and index.
	NamespaceConfig = upstream.NamespaceConfig
	// NamespaceInfo is a namespace as the server reports it.
	NamespaceInfo = upstream.NamespaceInfo
	// IndexType is the index structure a namespace uses.
	IndexType = upstream.IndexType
)

// Requests and responses of the Client verbs.
type (
	UpsertRequest                 = upstream.UpsertRequest
	UpsertResponse                = upstream.UpsertResponse
	BatchUpsertRequest            = upstream.BatchUpsertRequest
	BatchUpsertResponse           = upstream.BatchUpsertResponse
	GetRequest                    = upstream.GetRequest
	GetResponse                   = upstream.GetResponse
	DeleteRequest                 = upstream.DeleteRequest
	DeleteResponse                = upstream.DeleteResponse
	BatchDeleteRequest            = upstream.BatchDeleteRequest
	BatchDeleteResponse           = upstream.BatchDeleteResponse
	ListVectorsRequest            = upstream.ListVectorsRequest
	ListVectorsResponse           = upstream.ListVectorsResponse
	UpdateMetadataRequest         = upstream.UpdateMetadataRequest
	UpdateMetadataResponse        = upstream.UpdateMetadataResponse
	SearchSimilarRequest          = upstream.SearchSimilarRequest
	SearchSimilarResponse         = upstream.SearchSimilarResponse
	SearchByIDRequest             = upstream.SearchByIDRequest
	SearchByIDResponse            = upstream.SearchByIDResponse
	SearchByMetadataRequest       = upstream.SearchByMetadataRequest
	SearchByMetadataResponse      = upstream.SearchByMetadataResponse
	HybridSearchRequest           = upstream.HybridSearchRequest
	HybridSearchResponse          = upstream.HybridSearchResponse
	CreateNamespaceRequest        = upstream.CreateNamespaceRequest
	CreateNamespaceResponse       = upstream.CreateNamespaceResponse
	DeleteNamespaceRequest        = upstream.DeleteNamespaceRequest
	DeleteNamespaceResponse       = upstream.DeleteNamespaceResponse
	GetNamespaceInfoRequest       = upstream.GetNamespaceInfoRequest
	GetNamespaceInfoResponse      = upstream.GetNamespaceInfoResponse
	ListNamespacesRequest         = upstream.ListNamespacesRequest
	ListNamespacesResponse        = upstream.ListNamespacesResponse
	GetStatsRequest               = upstream.GetStatsRequest
	GetStatsResponse              = upstream.GetStatsResponse
	RebuildIndexRequest           = upstream.RebuildIndexRequest
	RebuildIndexResponse          = upstream.RebuildIndexResponse
	GetIndexProgressRequest       = upstream.GetIndexProgressRequest
	GetIndexProgressResponse      = upstream.GetIndexProgressResponse
	CompactRequest                = upstream.CompactRequest
	CompactResponse               = upstream.CompactResponse
	GetCompactionProgressRequest  = upstream.GetCompactionProgressRequest
	GetCompactionProgressResponse = upstream.GetCompactionProgressResponse
	ExportRequest                 = upstream.ExportRequest
	ExportResponse                = upstream.ExportResponse
	ImportRequest                 = upstream.ImportRequest
	ImportResponse                = upstream.ImportResponse
)

// Metadata filter operators.
const (
	FilterOperatorEquals             = upstream.FilterOperatorEquals
	FilterOperatorNotEquals          = upstream.FilterOperatorNotEquals
	FilterOperatorGreaterThan        = upstream.FilterOperatorGreaterThan
	FilterOperatorGreaterThanOrEqual = upstream.FilterOperatorGreaterThanOrEqual
	FilterOperatorLessThan           = upstream.FilterOperatorLessThan
	FilterOperatorLessThanOrEqual    = upstream.FilterOperatorLessThanOrEqual
	FilterOperatorIn                 = upstream.FilterOperatorIn
	FilterOperatorContains           = upstream.FilterOperatorContains
)

// Index types.
const (
	IndexTypeHNSW = upstream.IndexTypeHNSW
	IndexTypeFlat = upstream.IndexTypeFlat
	IndexTypeIVF  = upstream.IndexTypeIVF
)
