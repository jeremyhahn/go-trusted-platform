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

// handleVMOperation routes VM opcodes to the VM handler.
// This handles VM operations (0x60-0x6A range and extended codes).
func (h *QUICServiceHandler) handleVMServiceOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.vmHandler == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "vm"})
	}
	return h.vmHandler.HandleRequest(ctx, req)
}
