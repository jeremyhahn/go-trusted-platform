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

package parameterstore

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/parameterstore"
)

// Client is the parameter store client returned by
// quicbaas.Client.ParameterStore().
type Client = upstream.Client

// Parameters and the per-parameter results of the batch verbs.
type (
	// ParameterValue is a stored parameter with its value and metadata.
	ParameterValue = upstream.ParameterValue
	// SetParameterResult is the outcome of one parameter of a SetParameters
	// batch.
	SetParameterResult = upstream.SetParameterResult
	// DeleteParameterResult is the outcome of one parameter of a
	// DeleteParameters batch.
	DeleteParameterResult = upstream.DeleteParameterResult
)

// Requests and responses of the Client verbs.
type (
	SetParameterRequest      = upstream.SetParameterRequest
	SetParameterResponse     = upstream.SetParameterResponse
	GetParameterRequest      = upstream.GetParameterRequest
	GetParameterResponse     = upstream.GetParameterResponse
	DeleteParameterRequest   = upstream.DeleteParameterRequest
	DeleteParameterResponse  = upstream.DeleteParameterResponse
	ListParametersRequest    = upstream.ListParametersRequest
	ListParametersResponse   = upstream.ListParametersResponse
	SetParametersRequest     = upstream.SetParametersRequest
	SetParametersResponse    = upstream.SetParametersResponse
	GetParametersRequest     = upstream.GetParametersRequest
	GetParametersResponse    = upstream.GetParametersResponse
	DeleteParametersRequest  = upstream.DeleteParametersRequest
	DeleteParametersResponse = upstream.DeleteParametersResponse
	SearchByTagsRequest      = upstream.SearchByTagsRequest
	SearchByTagsResponse     = upstream.SearchByTagsResponse
)
