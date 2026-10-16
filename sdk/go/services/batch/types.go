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
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/batch"
)

// Client is the atomic batch client returned by quicbaas.Client.Batch().
type Client = upstream.Client

// Operations of an Execute batch.
type (
	// BatchOperation is one put or delete in a batch.
	BatchOperation = upstream.BatchOperation
	// OpType says whether a BatchOperation is a put or a delete.
	OpType = upstream.OpType
	// BatchResult is the outcome of one BatchOperation.
	BatchResult = upstream.BatchResult
)

// Requests and responses of the Client verbs.
type (
	BatchRequest        = upstream.BatchRequest
	BatchResponse       = upstream.BatchResponse
	BatchPutResponse    = upstream.BatchPutResponse
	PutResultItem       = upstream.PutResultItem
	BatchGetResponse    = upstream.BatchGetResponse
	GetResultItem       = upstream.GetResultItem
	BatchDeleteResponse = upstream.BatchDeleteResponse
	DeleteResultItem    = upstream.DeleteResultItem
)

// Batch operation types.
const (
	OpPut    = upstream.OpPut
	OpDelete = upstream.OpDelete
)
