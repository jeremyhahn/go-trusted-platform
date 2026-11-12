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
	assert.Equal(t, "abcd", got["merkle_root"])
	assert.Equal(t, "ECDSA-P256-SHA256", got["signature_algorithm"])
	assert.Equal(t, "1", got["version"])
	assert.EqualValues(t, 2, got["vms"])
	assert.EqualValues(t, 1, got["containers"])
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
