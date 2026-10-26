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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// quicVMAttestOps are the attestation sub-opcodes, each with a valid
// request for vmID and the orchestrator field that makes it fail.
var quicVMAttestOps = []struct {
	name     string
	opcode   byte
	request  func(vmID string) any
	failWith func(orch *vmCapableMockOrchestrator, err error)
}{
	{
		name:   "attest",
		opcode: quicwire.OpVMAttest,
		request: func(vmID string) any {
			return &platformv1.AttestVMRequest{VmId: vmID, Nonce: []byte("nonce"), PcrIndices: []uint32{0, 7}}
		},
		failWith: func(orch *vmCapableMockOrchestrator, err error) { orch.attestErr = err },
	},
	{
		name:   "verify",
		opcode: quicwire.OpVMVerifyAttest,
		request: func(vmID string) any {
			return &platformv1.VerifyVMAttestationRequest{
				VmId:               vmID,
				Quote:              []byte("quote"),
				Signature:          []byte("signature"),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Nonce:              []byte("nonce"),
				ExpectedPcrs: []*platformv1.PCRValue{
					{Index: 0, Bank: platformv1.PCRBank_PCR_BANK_SHA256, Value: []byte{0x01}},
				},
			}
		},
		failWith: func(orch *vmCapableMockOrchestrator, err error) { orch.verifyErr = err },
	},
}

func TestQUICVMAttest_AttestReturnsTheQuote(t *testing.T) {
	h, orch := newQUICVMSnapshotHandler()
	request := &platformv1.AttestVMRequest{VmId: "vm-1", Nonce: []byte("nonce"), PcrIndices: []uint32{0, 7}}

	resp := sendVMLifecycle(t, h, quicwire.OpVMAttest, encodeVMLifecycle(t, request))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got platformv1.AttestVMResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	assert.Equal(t, []byte("quote-bytes"), got.GetQuote())
	assert.Equal(t, []byte("signature-bytes"), got.GetSignature())
	assert.Equal(t, x509.SHA256WithRSAPSS.String(), got.GetSignatureAlgorithm())
	assert.Equal(t, []byte("ak-public"), got.GetAkPublic())
	assert.Len(t, got.GetPcrValues(), 2)
	assert.Equal(t, []byte("nonce"), orch.recordedAttestNonce())
	assert.Equal(t, []int{0, 7}, orch.recordedAttestPCRs())
}

func TestQUICVMAttest_VerifyPassesTheEvidence(t *testing.T) {
	h, orch := newQUICVMSnapshotHandler()
	request := quicVMAttestOps[1].request("vm-1")

	resp := sendVMLifecycle(t, h, quicwire.OpVMVerifyAttest, encodeVMLifecycle(t, request))

	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got platformv1.VerifyVMAttestationResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	assert.True(t, got.GetVerified())
	assert.Equal(t, "attestation verified", got.GetMessage())
	require.Len(t, got.GetActualPcrs(), 1)
	require.NotNil(t, orch.recordedEvidence())
	assert.Equal(t, []byte("quote"), orch.recordedEvidence().Quote)
	assert.Equal(t, x509.SHA256WithRSAPSS.String(), orch.recordedEvidence().SignatureAlgorithm)
	assert.Equal(t, []byte{0x01}, orch.recordedEvidence().ExpectedPCRs[0])
}

// TestQUICVMAttest_ErrorClasses checks each orchestrator refusal answers
// the QUIC status matching the gRPC code the shared service returns.
func TestQUICVMAttest_ErrorClasses(t *testing.T) {
	failures := []struct {
		name string
		err  error
		want byte
	}{
		{"unknown vm", compute.ErrInstanceNotFound, quicwire.StatusNotFound},
		{"vm not running", compute.ErrInstanceNotRunning, quicwire.StatusFailedPrecondition},
		{"no vtpm", compute.ErrVTPMNotAvailable, quicwire.StatusFailedPrecondition},
		{"invalid evidence", compute.ErrInvalidAttestationEvidence, quicwire.StatusInvalidArgument},
		{"backend failure", errSnapshotBackend, quicwire.StatusInternalError},
	}
	for _, op := range quicVMAttestOps {
		for _, failure := range failures {
			t.Run(op.name+"/"+failure.name, func(t *testing.T) {
				h, orch := newQUICVMSnapshotHandler()
				op.failWith(orch, failure.err)

				resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("vm-1")))

				assert.Equal(t, failure.want, resp.Status, string(resp.Payload))
			})
		}
	}
}

func TestQUICVMAttest_MissingVMIDIsInvalidArgument(t *testing.T) {
	for _, op := range quicVMAttestOps {
		t.Run(op.name, func(t *testing.T) {
			h, _ := newQUICVMSnapshotHandler()

			resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("")))

			assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, string(resp.Payload))
		})
	}
}

// TestQUICVMAttest_UnsupportedPCRBankIsInvalidArgument checks a bank the
// vTPM quote does not cover is refused before it reaches the orchestrator.
func TestQUICVMAttest_UnsupportedPCRBankIsInvalidArgument(t *testing.T) {
	requests := map[byte]any{
		quicwire.OpVMAttest: &platformv1.AttestVMRequest{VmId: "vm-1", PcrBank: platformv1.PCRBank_PCR_BANK_SHA1},
		quicwire.OpVMVerifyAttest: &platformv1.VerifyVMAttestationRequest{
			VmId:         "vm-1",
			ExpectedPcrs: []*platformv1.PCRValue{{Index: 0, Bank: platformv1.PCRBank_PCR_BANK_SHA1, Value: []byte{0x01}}},
		},
	}
	for opcode, request := range requests {
		h, orch := newQUICVMSnapshotHandler()

		resp := sendVMLifecycle(t, h, opcode, encodeVMLifecycle(t, request))

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, "opcode 0x%02x: %s", opcode, resp.Payload)
		assert.Nil(t, orch.recordedAttestNonce(), "a refused request must not reach the orchestrator")
		assert.Nil(t, orch.recordedEvidence(), "a refused request must not reach the orchestrator")
	}
}

func TestQUICVMAttest_MalformedPayloadIsInvalidRequest(t *testing.T) {
	for _, op := range quicVMAttestOps {
		t.Run(op.name, func(t *testing.T) {
			h, _ := newQUICVMSnapshotHandler()

			resp := sendVMLifecycle(t, h, op.opcode, []byte("invalid payload"))

			assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		})
	}
}

// TestQUICVMAttest_UnsupportedOrchestratorIsFailedPrecondition checks an
// orchestrator without attestation answers FailedPrecondition, as on gRPC.
func TestQUICVMAttest_UnsupportedOrchestratorIsFailedPrecondition(t *testing.T) {
	for _, op := range quicVMAttestOps {
		t.Run(op.name, func(t *testing.T) {
			h, _ := newQUICVMLifecycleHandler(nil)

			resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("vm-1")))

			assert.Equal(t, quicwire.StatusFailedPrecondition, resp.Status, string(resp.Payload))
		})
	}
}

func TestQUICVMAttest_NoComputeServiceIsUnavailable(t *testing.T) {
	for _, op := range quicVMAttestOps {
		t.Run(op.name, func(t *testing.T) {
			h := &QUICServiceHandler{logger: logging.DefaultLogger()}

			resp := sendVMLifecycle(t, h, op.opcode, encodeVMLifecycle(t, op.request("vm-1")))

			assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
		})
	}
}
