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

package embedding

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/embedding"
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
		{"Metadata", reflect.TypeFor[Metadata](), reflect.TypeFor[upstream.Metadata]()},
		{"BatchEmbeddingItem", reflect.TypeFor[BatchEmbeddingItem](), reflect.TypeFor[upstream.BatchEmbeddingItem]()},
		{"BatchEmbeddingResult", reflect.TypeFor[BatchEmbeddingResult](), reflect.TypeFor[upstream.BatchEmbeddingResult]()},
		{"ProviderInfo", reflect.TypeFor[ProviderInfo](), reflect.TypeFor[upstream.ProviderInfo]()},
		{"Provider", reflect.TypeFor[Provider](), reflect.TypeFor[upstream.Provider]()},
		{"InputType", reflect.TypeFor[InputType](), reflect.TypeFor[upstream.InputType]()},
		{"Status", reflect.TypeFor[Status](), reflect.TypeFor[upstream.Status]()},
		{"GenerateEmbeddingRequest", reflect.TypeFor[GenerateEmbeddingRequest](), reflect.TypeFor[upstream.GenerateEmbeddingRequest]()},
		{"GenerateEmbeddingResponse", reflect.TypeFor[GenerateEmbeddingResponse](), reflect.TypeFor[upstream.GenerateEmbeddingResponse]()},
		{"BatchGenerateEmbeddingsRequest", reflect.TypeFor[BatchGenerateEmbeddingsRequest](), reflect.TypeFor[upstream.BatchGenerateEmbeddingsRequest]()},
		{"BatchGenerateEmbeddingsResponse", reflect.TypeFor[BatchGenerateEmbeddingsResponse](), reflect.TypeFor[upstream.BatchGenerateEmbeddingsResponse]()},
		{"ListProvidersRequest", reflect.TypeFor[ListProvidersRequest](), reflect.TypeFor[upstream.ListProvidersRequest]()},
		{"ListProvidersResponse", reflect.TypeFor[ListProvidersResponse](), reflect.TypeFor[upstream.ListProvidersResponse]()},
		{"GetProviderInfoRequest", reflect.TypeFor[GetProviderInfoRequest](), reflect.TypeFor[upstream.GetProviderInfoRequest]()},
		{"GetProviderInfoResponse", reflect.TypeFor[GetProviderInfoResponse](), reflect.TypeFor[upstream.GetProviderInfoResponse]()},
		{"SetDefaultProviderRequest", reflect.TypeFor[SetDefaultProviderRequest](), reflect.TypeFor[upstream.SetDefaultProviderRequest]()},
		{"SetDefaultProviderResponse", reflect.TypeFor[SetDefaultProviderResponse](), reflect.TypeFor[upstream.SetDefaultProviderResponse]()},
		{"GetEmbeddingCacheStatsRequest", reflect.TypeFor[GetEmbeddingCacheStatsRequest](), reflect.TypeFor[upstream.GetEmbeddingCacheStatsRequest]()},
		{"GetEmbeddingCacheStatsResponse", reflect.TypeFor[GetEmbeddingCacheStatsResponse](), reflect.TypeFor[upstream.GetEmbeddingCacheStatsResponse]()},
		{"ClearEmbeddingCacheRequest", reflect.TypeFor[ClearEmbeddingCacheRequest](), reflect.TypeFor[upstream.ClearEmbeddingCacheRequest]()},
		{"ClearEmbeddingCacheResponse", reflect.TypeFor[ClearEmbeddingCacheResponse](), reflect.TypeFor[upstream.ClearEmbeddingCacheResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported provider, input type
// and status carries the upstream value and type, so a request built through
// this package means what the server reads.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"ProviderVoyage", ProviderVoyage, upstream.ProviderVoyage},
		{"ProviderOpenAI", ProviderOpenAI, upstream.ProviderOpenAI},
		{"ProviderOllama", ProviderOllama, upstream.ProviderOllama},
		{"ProviderLMStudio", ProviderLMStudio, upstream.ProviderLMStudio},
		{"ProviderNPU", ProviderNPU, upstream.ProviderNPU},
		{"InputTypeDocument", InputTypeDocument, upstream.InputTypeDocument},
		{"InputTypeQuery", InputTypeQuery, upstream.InputTypeQuery},
		{"InputTypeCode", InputTypeCode, upstream.InputTypeCode},
		{"StatusAvailable", StatusAvailable, upstream.StatusAvailable},
		{"StatusUnavailable", StatusUnavailable, upstream.StatusUnavailable},
		{"StatusRateLimited", StatusRateLimited, upstream.StatusRateLimited},
		{"StatusError", StatusError, upstream.StatusError},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
