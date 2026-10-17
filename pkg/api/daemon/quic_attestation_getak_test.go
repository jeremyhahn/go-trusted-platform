// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// getAKOverQUIC sends one OpAttestGetAK request through the daemon's
// attestation router.
func getAKOverQUIC(t *testing.T, h *QUICServiceHandler, payload []byte) *quicwire.Response {
	t.Helper()
	return h.handleAttestationOperation(context.Background(), &quicwire.Request{Opcode: quicwire.OpAttestGetAK, Payload: payload})
}

// TestQUICAttestGetAK: 0x73 answers the IAK the gRPC TPMService.GetAK
// answers, decoded from the same pb message.
func TestQUICAttestGetAK(t *testing.T) {
	svc := newTPMGRPCServiceWith(newIAKTPM(t, true))
	want, err := svc.GetAK(context.Background(), &platformv1.GetAKRequest{})
	require.NoError(t, err)

	h := newTestQUICServiceHandler(logging.DefaultLogger())
	h.SetTPMGRPCService(svc)
	payload, err := quicwire.EncodePayload(&platformv1.GetAKRequest{})
	require.NoError(t, err)

	resp := getAKOverQUIC(t, h, payload)
	require.Equal(t, quicwire.StatusOK, resp.Status, "payload %q", resp.Payload)
	var got platformv1.GetAKResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	assert.Equal(t, want.GetHandle(), got.GetHandle())
	assert.Equal(t, want.GetPublicKey(), got.GetPublicKey())
	assert.Equal(t, want.GetAlgorithm(), got.GetAlgorithm())
}

// TestQUICAttestGetAKRefusals: each refusal carries the status the gRPC
// code maps to, and a missing servicer or a bad payload is refused before it.
func TestQUICAttestGetAKRefusals(t *testing.T) {
	withTPM := func(svc *TPMGRPCService) *QUICServiceHandler {
		h := newTestQUICServiceHandler(logging.DefaultLogger())
		h.SetTPMGRPCService(svc)
		return h
	}

	tests := []struct {
		name    string
		h       *QUICServiceHandler
		payload []byte
		want    byte
	}{
		{"TPM holds no IAK", withTPM(newTPMGRPCServiceWith(newIAKTPM(t, false))), nil, quicwire.StatusNotFound},
		{"servicer has no TPM", withTPM(NewTPMGRPCService(logging.NewLogger(0, nil))), nil, quicwire.StatusUnavailable},
		{"no servicer", newTestQUICServiceHandler(logging.DefaultLogger()), nil, quicwire.StatusUnavailable},
		{"undecodable payload", withTPM(newTPMGRPCServiceWith(newIAKTPM(t, true))), []byte{0xc1}, quicwire.StatusInvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := getAKOverQUIC(t, tt.h, tt.payload)
			assert.Equal(t, tt.want, resp.Status, "payload %q", resp.Payload)
		})
	}
}

// TestQUICAttestRetiredChallengeByteIsUnknown: challenge / response is served
// by no transport (docs/13 G7), so QUIC carries no opcode for it. The retired
// byte 0x74 is unclassified, so the daemon refuses it before dispatch with the
// reserved-byte answer, not a stub refusal, even with every attestation
// servicer wired.
func TestQUICAttestRetiredChallengeByteIsUnknown(t *testing.T) {
	h := newTestQUICServiceHandler(logging.DefaultLogger())
	h.SetTPMGRPCService(newTPMGRPCServiceWith(newIAKTPM(t, true)))
	attestation := quic.NewAttestationHandler(logging.DefaultLogger(), nil)
	h.SetAttestationHandler(attestation)

	const retiredChallenge byte = 0x74
	req := &quicwire.Request{Opcode: retiredChallenge, Payload: []byte{}}

	// The authorization catalog does not classify 0x74, so the wire refuses
	// it before any dispatcher sees it.
	resp := h.HandleRequest(context.Background(), req)
	assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
	assert.Equal(t, quic.ErrOperationNotClassified{Opcode: retiredChallenge}.Error(), string(resp.Payload))

	// Behind the guard the attestation dispatcher has no case for the byte
	// either: it falls to the attestation handler's unknown-operation answer.
	resp = h.handleAttestationOperation(context.Background(), req)
	unknown := attestation.HandleRequest(context.Background(), req)
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	assert.Equal(t, string(unknown.Payload), string(resp.Payload))
}
