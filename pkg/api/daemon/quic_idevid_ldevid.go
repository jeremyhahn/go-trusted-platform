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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// handleLDevIDCreate serves the LDevID (IEEE 802.1AR) create operation over
// QUIC. It is reached through the physical-TPM category opcode
// (quicwire.OpTPM2Category) with the LDevID sub-opcode
// (quicwire.SubOpTPM2LDevIDCSR) in payload[0]; subPayload is the remaining
// request body carrying an encoded platformv1.CreateLDevIDRequest.
//
// The handler delegates to the shared IDevIDGRPCService.CreateLDevID so the
// QUIC transport has byte-for-byte identical semantics — TPM-resident key
// creation, PKCS#10 CSR, platform-CA issuance, and the proven-IDevID gate —
// as the gRPC, Unix, and embedded transports. No LDevID logic is duplicated
// on the wire path; only pb encode/decode framing lives here. The wire uses
// the pb Go field names via the protocol codec, matching the SDK QUIC
// adapter which encodes the same pb request.
func (h *QUICServiceHandler) handleLDevIDCreate(ctx context.Context, subPayload []byte) *quicwire.Response {
	if h.idevidService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrLDevIDServiceNotConfigured{})
	}

	req := &platformv1.CreateLDevIDRequest{}
	if len(subPayload) > 0 {
		if err := quicwire.DecodePayload(subPayload, req); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	resp, err := h.idevidService.CreateLDevID(ctx, req)
	if err != nil {
		h.logger.Error(err, "Failed to issue LDevID over QUIC")
		return h.errorResponse(ldevidGRPCToQUICStatus(err),
			ErrQUICOperationFailed{Op: "create LDevID", Cause: err})
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("LDevID certificate issued over QUIC")

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}
