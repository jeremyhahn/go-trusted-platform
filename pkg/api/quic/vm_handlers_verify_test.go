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

//go:build codec_msgpack

package quic

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test: Extended Operations - VerifyAttestation
// =============================================================================

func TestVMHandleVerifyAttestation(t *testing.T) {
	ctx := context.Background()

	t.Run("verifies attestation successfully", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		verifyReq := &VMVerifyAttestRequest{
			ID:        "vm-1",
			Quote:     []byte("quote"),
			Signature: []byte("signature"),
			Nonce:     []byte("nonce"),
			ExpectedPCRs: map[int][]byte{
				0: {0x01},
			},
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMVerifyAttest,
			Payload: payload,
		})

		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))

		var verifyResp VMVerifyAttestResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &verifyResp))
		assert.Equal(t, "vm-1", verifyResp.VMID)
		assert.True(t, verifyResp.Verified)
		assert.True(t, verifyResp.SignatureValid)
		assert.True(t, verifyResp.NonceValid)
		assert.True(t, verifyResp.PCRsValid)
		assert.Equal(t, "attestation verified", verifyResp.Message)
	})

	t.Run("returns error when VM ID missing", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		payload, err := quicwire.EncodePayload(&VMVerifyAttestRequest{})
		require.NoError(t, err)

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMVerifyAttest,
			Payload: payload,
		})

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns not implemented for base orchestrator", func(t *testing.T) {
		handler, orchestrator := createTestVMHandler()
		createTestVM(orchestrator, "vm-1", "test-vm")

		payload, err := quicwire.EncodePayload(&VMVerifyAttestRequest{ID: "vm-1"})
		require.NoError(t, err)

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMVerifyAttest,
			Payload: payload,
		})

		assert.Equal(t, quicwire.StatusNotImplemented, resp.Status)
	})

	t.Run("maps invalid evidence to invalid argument", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")
		orchestrator.verifyAttestError = &compute.SentinelCauseError{
			Sentinel: compute.ErrInvalidAttestationEvidence,
			Cause:    &compute.MessageError{Msg: "quote is required"},
		}

		payload, err := quicwire.EncodePayload(&VMVerifyAttestRequest{ID: "vm-1"})
		require.NoError(t, err)

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMVerifyAttest,
			Payload: payload,
		})

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Extended category multiplexing (OpVMExtendedCategory)
// =============================================================================

func TestVMHandleExtendedCategory(t *testing.T) {
	ctx := context.Background()

	t.Run("routes sub-opcode to snapshot list", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		listReq := &VMSnapshotListRequest{ID: "vm-1"}
		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		// Category framing: payload[0] = sub-opcode, rest = inner payload.
		framed := append([]byte{quicwire.OpVMSnapshotList}, payload...)

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMExtendedCategory,
			Payload: framed,
		})

		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))

		var listResp VMSnapshotListResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &listResp))
		assert.Equal(t, "vm-1", listResp.VMID)
	})

	t.Run("routes sub-opcode to attest", func(t *testing.T) {
		handler, orchestrator := createExtendedTestVMHandler()
		createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

		attestReq := &VMAttestRequest{ID: "vm-1"}
		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		framed := append([]byte{quicwire.OpVMAttest}, payload...)

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMExtendedCategory,
			Payload: framed,
		})

		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))

		var attestResp VMAttestResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &attestResp))
		assert.Equal(t, "vm-1", attestResp.VMID)
	})

	t.Run("rejects empty payload", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMExtendedCategory,
			Payload: nil,
		})

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("rejects unknown sub-opcode", func(t *testing.T) {
		handler, _ := createExtendedTestVMHandler()

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMExtendedCategory,
			Payload: []byte{0x01, 0x00},
		})

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: attest request forwards nonce and PCR selection
// =============================================================================

func TestVMHandleAttest_ForwardsNonceAndPCRs(t *testing.T) {
	ctx := context.Background()

	handler, orchestrator := createExtendedTestVMHandler()
	createTestVM(orchestrator.mockVMOrchestrator, "vm-1", "test-vm")

	attestReq := &VMAttestRequest{
		ID:    "vm-1",
		Nonce: []byte("caller-nonce"),
		PCRs:  []int{0, 7},
	}
	payload, err := quicwire.EncodePayload(attestReq)
	require.NoError(t, err)

	resp := handler.HandleRequest(ctx, &quicwire.Request{
		Opcode:  quicwire.OpVMAttest,
		Payload: payload,
	})

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))

	var attestResp VMAttestResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &attestResp))
	assert.Equal(t, []byte("caller-nonce"), attestResp.Nonce)
}
