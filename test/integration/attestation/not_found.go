//go:build integration

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

package attestation

import (
	"encoding/json"
	"errors"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// IsNotFound reports whether err is a transport's typed not-found answer for
// a resource the daemon looked up: gRPC (TCP or Unix) codes.NotFound, QUIC
// StatusNotFound, the MCP NotFound error code, or a REST 404 that carries the
// daemon's JSON error envelope. A REST 404 without the envelope is the
// router's "404 page not found" for a path nobody registered, and an
// operation the adapter serves no route for (ErrRESTNoRoute) never reached
// the daemon: neither is a missing resource (docs/attestation/api.md §3).
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}

	var restErr *RESTAdapterError
	if errors.As(err, &restErr) {
		return restErr.StatusCode == http.StatusNotFound && carriesRESTEnvelope(restErr.Body)
	}

	var quicErr ErrQUICStatus
	if errors.As(err, &quicErr) {
		return quicErr.Status == quicwire.StatusNotFound
	}

	var mcpErr *MCPAdapterError
	if errors.As(err, &mcpErr) {
		return mcpErr.Code == mcpwire.NotFound
	}

	return status.Code(err) == codes.NotFound
}

// carriesRESTEnvelope reports whether body is the daemon's JSON error
// envelope with a non-empty error message.
func carriesRESTEnvelope(body string) bool {
	var envelope restEnvelope
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return false
	}
	return envelope.Error != ""
}
