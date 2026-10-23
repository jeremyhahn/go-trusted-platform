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
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/embedding"
)

// Client is the embedding generation client returned by
// quicbaas.Client.Embedding().
type Client = upstream.Client

// Embeddings, providers and the value types they carry.
type (
	// Metadata describes how an embedding was generated.
	Metadata = upstream.Metadata
	// BatchEmbeddingItem is one text of a batch request.
	BatchEmbeddingItem = upstream.BatchEmbeddingItem
	// BatchEmbeddingResult is the outcome of one item of a batch request.
	BatchEmbeddingResult = upstream.BatchEmbeddingResult
	// ProviderInfo is an embedding provider as the server reports it.
	ProviderInfo = upstream.ProviderInfo
	// Provider names an embedding provider.
	Provider = upstream.Provider
	// InputType is the kind of text being embedded.
	InputType = upstream.InputType
	// Status is a provider's availability.
	Status = upstream.Status
)

// Requests and responses of the Client verbs.
type (
	GenerateEmbeddingRequest        = upstream.GenerateEmbeddingRequest
	GenerateEmbeddingResponse       = upstream.GenerateEmbeddingResponse
	BatchGenerateEmbeddingsRequest  = upstream.BatchGenerateEmbeddingsRequest
	BatchGenerateEmbeddingsResponse = upstream.BatchGenerateEmbeddingsResponse
	ListProvidersRequest            = upstream.ListProvidersRequest
	ListProvidersResponse           = upstream.ListProvidersResponse
	GetProviderInfoRequest          = upstream.GetProviderInfoRequest
	GetProviderInfoResponse         = upstream.GetProviderInfoResponse
	SetDefaultProviderRequest       = upstream.SetDefaultProviderRequest
	SetDefaultProviderResponse      = upstream.SetDefaultProviderResponse
	GetEmbeddingCacheStatsRequest   = upstream.GetEmbeddingCacheStatsRequest
	GetEmbeddingCacheStatsResponse  = upstream.GetEmbeddingCacheStatsResponse
	ClearEmbeddingCacheRequest      = upstream.ClearEmbeddingCacheRequest
	ClearEmbeddingCacheResponse     = upstream.ClearEmbeddingCacheResponse
)

// Embedding providers.
const (
	ProviderVoyage   = upstream.ProviderVoyage
	ProviderOpenAI   = upstream.ProviderOpenAI
	ProviderOllama   = upstream.ProviderOllama
	ProviderLMStudio = upstream.ProviderLMStudio
	ProviderNPU      = upstream.ProviderNPU
)

// Input types.
const (
	InputTypeDocument = upstream.InputTypeDocument
	InputTypeQuery    = upstream.InputTypeQuery
	InputTypeCode     = upstream.InputTypeCode
)

// Provider availability states.
const (
	StatusAvailable   = upstream.StatusAvailable
	StatusUnavailable = upstream.StatusUnavailable
	StatusRateLimited = upstream.StatusRateLimited
	StatusError       = upstream.StatusError
)
