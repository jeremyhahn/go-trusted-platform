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

package timeseries

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/timeseries"
)

// Client is the time-series client returned by quicbaas.Client.TimeSeries().
type Client = upstream.Client

// Data points and the aggregation applied when querying them.
type (
	// Point is one timestamped value of a series.
	Point = upstream.Point
	// AggregateFunction is how a query folds the points in each interval.
	AggregateFunction = upstream.AggregateFunction
)

// Requests and responses of the Client verbs.
type (
	WriteRequest  = upstream.WriteRequest
	QueryRequest  = upstream.QueryRequest
	QueryResponse = upstream.QueryResponse
)

// Aggregation functions. AggregateNone returns the raw points.
const (
	AggregateNone  = upstream.AggregateNone
	AggregateSum   = upstream.AggregateSum
	AggregateAvg   = upstream.AggregateAvg
	AggregateMin   = upstream.AggregateMin
	AggregateMax   = upstream.AggregateMax
	AggregateCount = upstream.AggregateCount
)
