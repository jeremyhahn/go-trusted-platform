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

package transaction

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/transaction"
)

// Client is the compare-and-swap transaction client returned by
// quicbaas.Client.Transaction().
type Client = upstream.Client

// Conditions and operations of a transaction.
type (
	// Compare is one condition the transaction checks.
	Compare = upstream.Compare
	// CompareTarget is what a Compare reads: version, value or a revision.
	CompareTarget = upstream.CompareTarget
	// CompareResult is the comparison a Compare applies.
	CompareResult = upstream.CompareResult
	// TxnOp is one operation of the success or failure branch.
	TxnOp = upstream.TxnOp
	// TxnOpType says whether a TxnOp is a put, get or delete.
	TxnOpType = upstream.TxnOpType
	// TxnOpResponse is the outcome of one TxnOp.
	TxnOpResponse = upstream.TxnOpResponse
)

// Request and response of the Client verb.
type (
	TxnRequest  = upstream.TxnRequest
	TxnResponse = upstream.TxnResponse
)

// Compare targets.
const (
	CompareVersion        = upstream.CompareVersion
	CompareValue          = upstream.CompareValue
	CompareModRevision    = upstream.CompareModRevision
	CompareCreateRevision = upstream.CompareCreateRevision
)

// Compare results.
const (
	CompareEqual    = upstream.CompareEqual
	CompareNotEqual = upstream.CompareNotEqual
	CompareLess     = upstream.CompareLess
	CompareGreater  = upstream.CompareGreater
)

// Transaction operation types.
const (
	TxnOpPut    = upstream.TxnOpPut
	TxnOpGet    = upstream.TxnOpGet
	TxnOpDelete = upstream.TxnOpDelete
)
