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

package query

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/query"
)

// Client is the secondary-index query client returned by
// quicbaas.Client.Query().
type Client = upstream.Client

// Operator is the comparison a query applies to the index value.
type Operator = upstream.Operator

// Request, response and result of the Client verb.
type (
	QueryRequest  = upstream.QueryRequest
	QueryResponse = upstream.QueryResponse
	QueryResult   = upstream.QueryResult
)

// Query operators.
const (
	OpEqual              = upstream.OpEqual
	OpNotEqual           = upstream.OpNotEqual
	OpLessThan           = upstream.OpLessThan
	OpLessThanOrEqual    = upstream.OpLessThanOrEqual
	OpGreaterThan        = upstream.OpGreaterThan
	OpGreaterThanOrEqual = upstream.OpGreaterThanOrEqual
	OpPrefix             = upstream.OpPrefix
	OpRange              = upstream.OpRange
)
