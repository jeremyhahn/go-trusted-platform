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

package objecttransfer

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/objecttransfer"
)

// Client is the peer-to-peer object transfer client returned by
// quicbaas.Client.ObjectTransfer().
type Client = upstream.Client

// Objects to fetch and the compression they travel in.
type (
	// ObjectFetchItem names one object of a batch fetch.
	ObjectFetchItem = upstream.ObjectFetchItem
	// CompressionAlgo is the compression applied to fetched object data.
	CompressionAlgo = upstream.CompressionAlgo
)

// Requests and responses of the Client verbs. StreamFetchObjects answers
// with a stream of FetchObjectResponse, so it has no response type of its
// own.
type (
	FetchObjectRequest        = upstream.FetchObjectRequest
	FetchObjectResponse       = upstream.FetchObjectResponse
	StreamFetchObjectsRequest = upstream.StreamFetchObjectsRequest
)

// Compression algorithms.
const (
	CompressionNone   = upstream.CompressionNone
	CompressionLZ4    = upstream.CompressionLZ4
	CompressionZstd   = upstream.CompressionZstd
	CompressionSnappy = upstream.CompressionSnappy
	CompressionGzip   = upstream.CompressionGzip
)
