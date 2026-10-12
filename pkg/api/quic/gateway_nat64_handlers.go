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

package quic

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// gatewayNAT64Handlers dispatches NAT64 sub-opcodes (map-based for O(1)
// lookup, matching the load balancer and perf handler convention).
var gatewayNAT64Handlers = map[byte]func(*GatewayHandler, context.Context, *quicwire.Request) *quicwire.Response{
	quicwire.OpGatewayNAT64Status: (*GatewayHandler).handleNAT64Status,
}

// handleNAT64Status returns the NAT64 translator's health snapshot.
func (h *GatewayHandler) handleNAT64Status(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.gatewayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	status, err := h.gatewayService.NAT64Status(ctx)
	if err != nil {
		h.logger.Error(err, "failed to get NAT64 status")
		return h.gatewayErrorResponse(err)
	}

	resp := &quicwire.GatewayNAT64StatusResponse{Status: status, Timestamp: time.Now().Unix()}
	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}
