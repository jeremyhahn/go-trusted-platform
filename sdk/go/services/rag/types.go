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

package rag

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/rag"
)

// Client is the retrieval-augmented generation client returned by
// quicbaas.Client.RAG().
type Client = upstream.Client

// Search results and the citations built from them.
type (
	// ResultInput is one caller-supplied search result for BuildContext.
	ResultInput = upstream.ResultInput
	// Citation is a source the built context cites.
	Citation = upstream.Citation
)

// Requests and responses of the Client verbs.
type (
	QueryRequest         = upstream.QueryRequest
	QueryResponse        = upstream.QueryResponse
	BuildContextRequest  = upstream.BuildContextRequest
	BuildContextResponse = upstream.BuildContextResponse
)
