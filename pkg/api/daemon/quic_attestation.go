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

// =============================================================================
// Attestation QUIC wire contract
// =============================================================================
//
// The attestation surface has two disjoint wire contracts that share the
// 0x70-0x7F opcode range:
//
//  1. The platform.v1 AttestationService quote surface (GetAttestationQuote,
//     VerifyAttestationQuote, CollectHostAttestation). The SDK QUIC transport
//     adapter hands the generated pb request struct to the wire, so the daemon
//     decodes the payload into the SAME pb message and delegates to the shared
//     *AttestationServiceServer — identical semantics to the gRPC transport.
//     These messages carry no protobuf oneofs, so they round-trip the msgpack
//     payload codec cleanly (see quic_attestation_wire_compat_test.go).
//
//       OpAttestQuote       (0x70) -> GetAttestationQuote
//       OpAttestVerify      (0x71) -> VerifyAttestationQuote
//       OpAttestCollectHost (0x72) -> CollectHostAttestation
//
//     CollectHostAttestation was moved off the OpAttestQuote opcode onto its
//     own OpAttestCollectHost (0x72): the SDK adapter previously mapped both
//     GetAttestationQuote and CollectHostAttestation onto OpAttestQuote with
//     byte-identical request shapes but different response messages, which the
//     daemon could not disambiguate. The dedicated opcode restores a
//     one-to-one RPC/opcode contract.
//
//  2. The daemon-native manifest surface (build/verify manifest, host/VM/
//     container/device workload attestation, reports, policies) on opcodes
//     0x76/0x77/0x7C-0x7F and the extended codes. These have no SDK QUIC
//     client and remain flat-struct operations served by the local
//     AttestationHandler, exercised by the CLI and the integration harness.

// attestQuoteOpcodes is the set of opcodes served by the pb quote surface;
// everything else routes to the daemon-native manifest handler.

// handleAttestationOperation routes attestation opcodes. The three
// AttestationService quote opcodes decode the platform.v1 pb request and
// delegate to the shared *AttestationServiceServer; every other opcode is
// served by the daemon-native manifest AttestationHandler.
func (h *QUICServiceHandler) handleAttestationOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	switch req.Opcode {
	case quicwire.OpAttestQuote:
		return h.handleAttestationGetQuote(ctx, req)
	case quicwire.OpAttestVerify:
		return h.handleAttestationVerifyQuote(ctx, req)
	case quicwire.OpAttestCollectHost:
		return h.handleAttestationCollectHost(ctx, req)
	default:
		if h.attestationHandler == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "attestation"})
		}
		return h.attestationHandler.HandleRequest(ctx, req)
	}
}

// handleAttestationGetQuote decodes GetAttestationQuoteRequest and delegates
// to the shared *AttestationServiceServer.
func (h *QUICServiceHandler) handleAttestationGetQuote(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.attestGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "attestation"})
	}

	var quoteReq platformv1.GetAttestationQuoteRequest
	if err := quicwire.DecodePayload(req.Payload, &quoteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.attestGRPC.GetAttestationQuote(ctx, &quoteReq)
	if err != nil {
		return h.grpcStatusToQUICResponse("AttestGetQuote", err)
	}
	return h.encodeQUICOK(resp)
}

// handleAttestationVerifyQuote decodes VerifyAttestationQuoteRequest and
// delegates to the shared *AttestationServiceServer.
func (h *QUICServiceHandler) handleAttestationVerifyQuote(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.attestGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "attestation"})
	}

	var verifyReq platformv1.VerifyAttestationQuoteRequest
	if err := quicwire.DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.attestGRPC.VerifyAttestationQuote(ctx, &verifyReq)
	if err != nil {
		return h.grpcStatusToQUICResponse("AttestVerifyQuote", err)
	}
	return h.encodeQUICOK(resp)
}

// handleAttestationCollectHost decodes CollectHostAttestationRequest and
// delegates to the shared *AttestationServiceServer.
func (h *QUICServiceHandler) handleAttestationCollectHost(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.attestGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "attestation"})
	}

	var collectReq platformv1.CollectHostAttestationRequest
	if err := quicwire.DecodePayload(req.Payload, &collectReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.attestGRPC.CollectHostAttestation(ctx, &collectReq)
	if err != nil {
		return h.grpcStatusToQUICResponse("AttestCollectHost", err)
	}
	return h.encodeQUICOK(resp)
}
