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

package ollama

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/ollama"
)

// Client is the Ollama embedding client returned by quicbaas.Client.Ollama().
type Client = upstream.Client

// Models and the value types they carry.
type (
	// ModelInfo is an Ollama model as the server reports it.
	ModelInfo = upstream.ModelInfo
	// ModelDetails is the detailed description of a model.
	ModelDetails = upstream.ModelDetails
)

// Requests and responses of the Client verbs. EmbedWithModel answers with
// an EmbedResponse, so it has no response type of its own.
type (
	EmbedRequest          = upstream.EmbedRequest
	EmbedResponse         = upstream.EmbedResponse
	EmbedWithModelRequest = upstream.EmbedWithModelRequest
	EmbedBatchRequest     = upstream.EmbedBatchRequest
	EmbedBatchResponse    = upstream.EmbedBatchResponse
	ListModelsRequest     = upstream.ListModelsRequest
	ListModelsResponse    = upstream.ListModelsResponse
	GetModelInfoRequest   = upstream.GetModelInfoRequest
	GetModelInfoResponse  = upstream.GetModelInfoResponse
	HealthRequest         = upstream.HealthRequest
	HealthResponse        = upstream.HealthResponse
)
