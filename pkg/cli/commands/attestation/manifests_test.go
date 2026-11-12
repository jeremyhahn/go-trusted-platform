// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package attestation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeManifestsClient stubs the three manifest RPCs the manifests verbs call;
// the embedded interface panics on any other RPC.
type fakeManifestsClient struct {
	platformv1.AttestationServiceClient

	listReq   *platformv1.ListManifestsRequest
	listResp  *platformv1.ListManifestsResponse
	getReq    *platformv1.GetManifestRequest
	getResp   *platformv1.GetManifestResponse
	deleteReq *platformv1.DeleteManifestRequest
	err       error
}

func (f *fakeManifestsClient) ListManifests(_ context.Context, in *platformv1.ListManifestsRequest, _ ...grpc.CallOption) (*platformv1.ListManifestsResponse, error) {
	f.listReq = in
	return f.listResp, f.err
}

func (f *fakeManifestsClient) GetManifest(_ context.Context, in *platformv1.GetManifestRequest, _ ...grpc.CallOption) (*platformv1.GetManifestResponse, error) {
	f.getReq = in
	return f.getResp, f.err
}

func (f *fakeManifestsClient) DeleteManifest(_ context.Context, in *platformv1.DeleteManifestRequest, _ ...grpc.CallOption) (*platformv1.DeleteManifestResponse, error) {
	f.deleteReq = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeleteManifestResponse{}, nil
}

func sampleManifest() *platformv1.HostManifest {
	return &platformv1.HostManifest{
		Id:                 "m-1",
		HostId:             "host-a",
		Timestamp:          timestamppb.New(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)),
		Vms:                []*platformv1.VMAttestation{{}, {}},
		Containers:         []*platformv1.ContainerAttestation{{}},
		MerkleRoot:         []byte{0xab, 0xcd},
		SignatureAlgorithm: "ECDSA-P256-SHA256",
		Version:            "1",
	}
}

func TestManifestsList_Table(t *testing.T) {
	fake := &fakeManifestsClient{listResp: &platformv1.ListManifestsResponse{
		Manifests: []*platformv1.HostManifest{sampleManifest()},
		Total:     1,
	}}
	r, out := newRunner(fake, cli.OutputFormatTable)
	require.NoError(t, r.listManifests(manifestsListOptions{HostID: "host-a", Limit: 5, Offset: 2}))

	require.NotNil(t, fake.listReq)
	assert.Equal(t, "host-a", fake.listReq.GetHostId())
	assert.Equal(t, uint32(5), fake.listReq.GetLimit())
	assert.Equal(t, uint32(2), fake.listReq.GetOffset())

	got := out.String()
	for _, want := range []string{"m-1", "host-a", "2026-11-12T10:00:00Z", "ECDSA-P256-SHA256"} {
		assert.Contains(t, got, want)
	}
}

func TestManifestsList_TableEmpty(t *testing.T) {
	r, out := newRunner(&fakeManifestsClient{listResp: &platformv1.ListManifestsResponse{}}, cli.OutputFormatTable)
	require.NoError(t, r.listManifests(manifestsListOptions{}))
	assert.Contains(t, out.String(), "No attestation manifests")
}

func TestManifestsGet_JSON(t *testing.T) {
	fake := &fakeManifestsClient{getResp: &platformv1.GetManifestResponse{Manifest: sampleManifest()}}
	r, out := newRunner(fake, cli.OutputFormatJSON)
	require.NoError(t, r.getManifest("m-1"))
	assert.Equal(t, "m-1", fake.getReq.GetId())

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got), out.String())
	assert.Equal(t, "m-1", got["id"])
	assert.Equal(t, "host-a", got["host_id"])
	assert.Equal(t, "2026-11-12T10:00:00Z", got["timestamp"])
	// The stored manifest's wire shape: bytes as base64, evidence lists whole.
	assert.Equal(t, "q80=", got["merkle_root"])
	assert.Equal(t, "ECDSA-P256-SHA256", got["signature_algorithm"])
	assert.Equal(t, "1", got["version"])
	assert.Len(t, got["vms"], 2)
	assert.Len(t, got["containers"], 1)
}

// evidenceManifest is sampleManifest with every evidence field populated,
// so a projection that drops one is detected (#1686, Codex P1).
func evidenceManifest() *platformv1.HostManifest {
	m := sampleManifest()
	m.Nonce = []byte{0x01, 0x02}
	m.Signature = []byte{0x03, 0x04}
	m.Metadata = map[string]string{"site": "lab"}
	m.Host = &platformv1.HostAttestation{
		QuoteData: []byte{0x05},
		Signature: []byte{0x06},
		Pcrs:      []*platformv1.AttestationPCRValue{{Index: 7, Value: []byte{0x07}}},
		PcrDigest: []byte{0x08},
		Nonce:     []byte{0x01, 0x02},
	}
	m.Vms = []*platformv1.VMAttestation{{VmId: "vm-1", QuoteData: []byte{0x09}}}
	return m
}

func TestManifestsGet_JSONKeepsEvidence(t *testing.T) {
	fake := &fakeManifestsClient{getResp: &platformv1.GetManifestResponse{Manifest: evidenceManifest()}}
	r, out := newRunner(fake, cli.OutputFormatJSON)
	require.NoError(t, r.getManifest("m-1"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got), out.String())
	assert.Equal(t, "AQI=", got["nonce"])
	assert.Equal(t, "AwQ=", got["signature"])
	assert.Equal(t, map[string]any{"site": "lab"}, got["metadata"])
	host, ok := got["host"].(map[string]any)
	require.True(t, ok, "host evidence missing: %s", out.String())
	assert.Equal(t, "BQ==", host["quote_data"])
	assert.Equal(t, "Bg==", host["signature"])
	assert.Equal(t, "CA==", host["pcr_digest"])
	require.Len(t, host["pcrs"], 1)
	vms, ok := got["vms"].([]any)
	require.True(t, ok, "vm evidence missing: %s", out.String())
	require.Len(t, vms, 1)
	assert.Equal(t, "vm-1", vms[0].(map[string]any)["vm_id"])
	assert.Equal(t, "CQ==", vms[0].(map[string]any)["quote_data"])
}

func TestManifestsGet_YAMLKeepsEvidence(t *testing.T) {
	fake := &fakeManifestsClient{getResp: &platformv1.GetManifestResponse{Manifest: evidenceManifest()}}
	r, out := newRunner(fake, cli.OutputFormatYAML)
	require.NoError(t, r.getManifest("m-1"))
	for _, want := range []string{"nonce: AQI=", "signature: AwQ=", "quote_data: BQ==", "pcr_digest: CA==", "vm_id: vm-1", "site: lab"} {
		assert.Contains(t, out.String(), want)
	}
}

func TestManifestsDelete_Success(t *testing.T) {
	fake := &fakeManifestsClient{}
	r, out := newRunner(fake, cli.OutputFormatTable)
	require.NoError(t, r.deleteManifest("m-1"))
	require.NotNil(t, fake.deleteReq)
	assert.Equal(t, "m-1", fake.deleteReq.GetId())
	assert.Contains(t, out.String(), "m-1")
}

func TestManifests_SDKError(t *testing.T) {
	cause := status.Error(codes.Unavailable, "manifest store offline")

	t.Run("list", func(t *testing.T) {
		r, out := newRunner(&fakeManifestsClient{err: cause}, cli.OutputFormatTable)
		err := r.listManifests(manifestsListOptions{})
		var typed ErrListManifestsFailed
		require.ErrorAs(t, err, &typed)
		assert.Contains(t, err.Error(), "manifest store offline")
		assert.Empty(t, out.String())
	})
	t.Run("get", func(t *testing.T) {
		r, out := newRunner(&fakeManifestsClient{err: cause}, cli.OutputFormatJSON)
		err := r.getManifest("m-1")
		var typed ErrGetManifestFailed
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, "m-1", typed.ID)
		assert.Contains(t, err.Error(), "manifest store offline")
		assert.Empty(t, out.String())
	})
	t.Run("delete", func(t *testing.T) {
		r, out := newRunner(&fakeManifestsClient{err: cause}, cli.OutputFormatTable)
		err := r.deleteManifest("m-1")
		var typed ErrDeleteManifestFailed
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, "m-1", typed.ID)
		assert.Contains(t, err.Error(), "manifest store offline")
		assert.Empty(t, out.String())
	})
}

func TestManifests_Surface(t *testing.T) {
	manifests, _, err := quietCommand().Find([]string{"manifests"})
	require.NoError(t, err)
	verbs := map[string]bool{}
	for _, sub := range manifests.Commands() {
		verbs[sub.Name()] = true
	}
	assert.Equal(t, map[string]bool{"list": true, "get": true, "delete": true}, verbs)
}

func TestManifests_EmptyIDIsRefusedBeforeConnecting(t *testing.T) {
	for _, verb := range []string{"get", "delete"} {
		t.Run(verb, func(t *testing.T) {
			cmd := quietCommand()
			cmd.SetArgs([]string{"manifests", verb, " "})
			err := cmd.Execute()
			var typed ErrInvalidManifestID
			require.ErrorAs(t, err, &typed)
		})
	}
}
