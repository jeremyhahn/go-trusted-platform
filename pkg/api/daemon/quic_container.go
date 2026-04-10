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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// handleContainerOperation routes container opcodes to the container handler.
// This handles container operations (0xFC-0xFF and additional codes).
func (h *QUICServiceHandler) handleContainerOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.containerHandler == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"})
	}
	return h.containerHandler.HandleRequest(ctx, req)
}
