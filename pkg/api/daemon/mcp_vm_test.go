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
	"context"
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// decodeMCPProto decodes an MCP provider reply, the RPC's protojson, into
// resp.
func decodeMCPProto(t *testing.T, result interface{}, resp proto.Message) {
	t.Helper()
	raw, ok := result.(json.RawMessage)
	require.True(t, ok, "reply is %T, want the RPC's protojson", result)
	require.NoError(t, protojson.Unmarshal(raw, resp))
}

// The MCP VM attestation tools answer with AttestVM's response, so the
// quote's declared signature scheme travels out of vm_attest and back into
// vm_attest_verify and a verifier never infers it from the AK key type (#482).
func TestMCPServiceProvider_VMAttest_CarriesSignatureAlgorithm(t *testing.T) {
	provider := &MCPServiceProvider{computeOrchestrator: newVMCapableMockOrchestrator()}

	result, err := provider.VMAttest(context.Background(),
		&platformv1.AttestVMRequest{VmId: "vm1", Nonce: []byte("nonce"), PcrIndices: []uint32{0, 7}})
	require.NoError(t, err)

	var resp platformv1.AttestVMResponse
	decodeMCPProto(t, result, &resp)
	assert.Equal(t, x509.SHA256WithRSAPSS.String(), resp.GetSignatureAlgorithm())
	assert.Equal(t, []byte("quote-bytes"), resp.GetQuote())
}

// Without a compute orchestrator the tools answer as the RPCs do:
// FailedPrecondition.
func TestMCPServiceProvider_VMAttest_NoCompute(t *testing.T) {
	provider := &MCPServiceProvider{}

	_, err := provider.VMAttest(context.Background(), &platformv1.AttestVMRequest{VmId: "vm1"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestMCPServiceProvider_VMAttestVerify_ForwardsEvidence(t *testing.T) {
	orchestrator := newVMCapableMockOrchestrator()
	provider := &MCPServiceProvider{computeOrchestrator: orchestrator}

	result, err := provider.VMAttestVerify(context.Background(), &platformv1.VerifyVMAttestationRequest{
		VmId:               "vm1",
		Quote:              []byte("quote"),
		Signature:          []byte("signature"),
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		Nonce:              []byte("nonce"),
		ExpectedPcrs: []*platformv1.PCRValue{
			{Index: 7, Bank: platformv1.PCRBank_PCR_BANK_SHA256, Value: []byte{0x07}},
		},
	})
	require.NoError(t, err)

	var resp platformv1.VerifyVMAttestationResponse
	decodeMCPProto(t, result, &resp)
	assert.True(t, resp.GetVerified())
	require.NotNil(t, orchestrator.recordedEvidence())
	assert.Equal(t, x509.SHA256WithRSAPSS.String(), orchestrator.recordedEvidence().SignatureAlgorithm)
	assert.Equal(t, []byte{0x07}, orchestrator.recordedEvidence().ExpectedPCRs[7])
}

// A PCR bank AttestVM does not quote over is InvalidArgument, as on gRPC.
func TestMCPServiceProvider_VMAttestVerify_RejectsOtherBank(t *testing.T) {
	orchestrator := newVMCapableMockOrchestrator()
	provider := &MCPServiceProvider{computeOrchestrator: orchestrator}

	_, err := provider.VMAttestVerify(context.Background(), &platformv1.VerifyVMAttestationRequest{
		VmId:  "vm1",
		Quote: []byte("quote"),
		ExpectedPcrs: []*platformv1.PCRValue{
			{Index: 7, Bank: platformv1.PCRBank_PCR_BANK_SHA1, Value: []byte{0x07}},
		},
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Nil(t, orchestrator.recordedEvidence())
}

// vm_snapshot_get answers ComputeService.GetSnapshot's response.
func TestMCPServiceProvider_VMSnapshotGet(t *testing.T) {
	orchestrator := newVMCapableMockOrchestrator()
	orchestrator.snapshots = []*compute.VMSnapshot{
		{Name: "hourly", VMID: "vm1"},
		{Name: "nightly", VMID: "vm1", Description: "before upgrade"},
	}
	provider := &MCPServiceProvider{computeOrchestrator: orchestrator}

	result, err := provider.VMSnapshotGet(context.Background(), "vm1", "nightly")
	require.NoError(t, err)
	var resp platformv1.GetSnapshotResponse
	decodeMCPProto(t, result, &resp)
	assert.Equal(t, "nightly", resp.GetSnapshot().GetId())
	assert.Equal(t, "before upgrade", resp.GetSnapshot().GetConfig().GetDescription())
}

func TestMCPServiceProvider_VMSnapshotGet_UnknownSnapshot(t *testing.T) {
	orchestrator := newVMCapableMockOrchestrator()
	orchestrator.snapshots = []*compute.VMSnapshot{{Name: "hourly", VMID: "vm1"}}
	provider := &MCPServiceProvider{computeOrchestrator: orchestrator}

	_, err := provider.VMSnapshotGet(context.Background(), "vm1", "nightly")
	require.ErrorAs(t, err, &ErrVMSnapshotNotFound{})
	assert.Equal(t, codes.NotFound, status.Code(err))
}
