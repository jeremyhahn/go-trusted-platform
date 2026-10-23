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
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var manifestFixtureTime = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// errFakeManifestNotFound is the in-memory store's miss, worded as the
// real store's so the gRPC error mapping classes it the same way.
type errFakeManifestNotFound struct{ id string }

func (e errFakeManifestNotFound) Error() string { return "manifest " + e.id + " not found" }

// memoryManifestService is an in-memory AttestationService serving the
// manifest methods with the real service's refusals: an empty id, an
// unknown id, and a public key it cannot check.
type memoryManifestService struct {
	AttestationService
	manifests  map[string]*manifest.HostManifest
	built      *manifest.BuilderConfig
	buildNonce []byte
	buildOpts  *BuildManifestOptions
	verified   int
}

func newMemoryManifestService() *memoryManifestService {
	return &memoryManifestService{manifests: map[string]*manifest.HostManifest{
		"m-1": {ID: "m-1", HostID: "host-a", Timestamp: manifestFixtureTime, Nonce: []byte{1, 2, 3}, MerkleRoot: []byte{9}, Version: "1"},
	}}
}

func (s *memoryManifestService) GetManifest(_ context.Context, id string) (*manifest.HostManifest, error) {
	if id == "" {
		return nil, ErrAttestationManifestIDRequired{}
	}
	m, ok := s.manifests[id]
	if !ok {
		return nil, errFakeManifestNotFound{id: id}
	}
	return m, nil
}

func (s *memoryManifestService) ListManifests(_ context.Context, _ *ListManifestsFilter) ([]*manifest.HostManifest, int, error) {
	out := make([]*manifest.HostManifest, 0, len(s.manifests))
	for _, m := range s.manifests {
		out = append(out, m)
	}
	return out, len(out), nil
}

func (s *memoryManifestService) DeleteManifest(ctx context.Context, id string) error {
	if _, err := s.GetManifest(ctx, id); err != nil {
		return err
	}
	delete(s.manifests, id)
	return nil
}

func (s *memoryManifestService) BuildManifest(_ context.Context, config *manifest.BuilderConfig, nonce []byte, options *BuildManifestOptions) (*manifest.HostManifest, error) {
	s.built, s.buildNonce, s.buildOpts = config, nonce, options
	return &manifest.HostManifest{ID: "built", HostID: config.HostID, Timestamp: manifestFixtureTime, Nonce: nonce}, nil
}

func (s *memoryManifestService) VerifyManifest(_ context.Context, _ *manifest.HostManifest, _ *manifest.VerifierConfig, _ []byte, publicKey []byte, _ map[int][]byte) (*manifest.VerificationResult, error) {
	s.verified++
	if len(publicKey) > 0 {
		return nil, ErrAttestationManifestSignatureUnchecked{}
	}
	return &manifest.VerificationResult{Status: manifest.VerificationStatusVerified, NonceValid: true, VerifiedAt: manifestFixtureTime}, nil
}

// manifestParity is one fake backend served over gRPC and over MCP.
type manifestParity struct {
	svc   *memoryManifestService
	grpc  *AttestationServiceServer
	tools *mcp.ToolRegistry
}

func newManifestParity() *manifestParity {
	svc := newMemoryManifestService()
	server := NewAttestationServiceServer(svc, slog.Default())
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{AttestationServer: server})
	return &manifestParity{svc: svc, grpc: server, tools: mcp.NewToolRegistry(provider, logging.DefaultLogger())}
}

func (f *manifestParity) mcp(t *testing.T, tool string, args map[string]interface{}) (interface{}, error) {
	t.Helper()
	return f.tools.ExecuteTool(context.Background(), tool, args)
}

// asToolResult renders a gRPC response the way the MCP tool returns it.
func asToolResult(t *testing.T, resp proto.Message) interface{} {
	t.Helper()
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(resp)
	require.NoError(t, err)
	var out interface{}
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

// assertSameClass requires both transports to fail with want. It lives in
// this untagged file so every parity test sees it in every build.
func assertSameClass(t *testing.T, want codes.Code, mcpErr, grpcErr error) {
	t.Helper()
	require.Error(t, mcpErr)
	require.Error(t, grpcErr)
	assert.Equal(t, want, status.Code(grpcErr), "gRPC class")
	assert.Equal(t, want, status.Code(mcpErr), "MCP class must match gRPC")
}

func TestMCPManifestParity_Get(t *testing.T) {
	f := newManifestParity()
	ctx := context.Background()

	want, err := f.grpc.GetManifest(ctx, &platformv1.GetManifestRequest{Id: "m-1"})
	require.NoError(t, err)
	got, err := f.mcp(t, "attestation_get_manifest", map[string]interface{}{"id": "m-1"})
	require.NoError(t, err)
	assert.Equal(t, asToolResult(t, want), got)

	_, grpcErr := f.grpc.GetManifest(ctx, &platformv1.GetManifestRequest{Id: "absent"})
	_, mcpErr := f.mcp(t, "attestation_get_manifest", map[string]interface{}{"id": "absent"})
	assertSameClass(t, codes.NotFound, mcpErr, grpcErr)

	_, grpcErr = f.grpc.GetManifest(ctx, &platformv1.GetManifestRequest{})
	_, mcpErr = f.mcp(t, "attestation_get_manifest", map[string]interface{}{})
	assertSameClass(t, codes.InvalidArgument, mcpErr, grpcErr)
}

func TestMCPManifestParity_List(t *testing.T) {
	f := newManifestParity()
	want, err := f.grpc.ListManifests(context.Background(), &platformv1.ListManifestsRequest{Limit: 5})
	require.NoError(t, err)
	got, err := f.mcp(t, "attestation_list_manifests", map[string]interface{}{"limit": float64(5)})
	require.NoError(t, err)
	assert.Equal(t, asToolResult(t, want), got)
}

func TestMCPManifestParity_Delete(t *testing.T) {
	ctx := context.Background()
	grpcSide, mcpSide := newManifestParity(), newManifestParity()

	want, err := grpcSide.grpc.DeleteManifest(ctx, &platformv1.DeleteManifestRequest{Id: "m-1"})
	require.NoError(t, err)
	got, err := mcpSide.mcp(t, "attestation_delete_manifest", map[string]interface{}{"id": "m-1"})
	require.NoError(t, err)
	assert.Equal(t, asToolResult(t, want), got)
	assert.Empty(t, mcpSide.svc.manifests, "the MCP delete reached the store")

	_, grpcErr := grpcSide.grpc.DeleteManifest(ctx, &platformv1.DeleteManifestRequest{Id: "m-1"})
	_, mcpErr := mcpSide.mcp(t, "attestation_delete_manifest", map[string]interface{}{"id": "m-1"})
	assertSameClass(t, codes.NotFound, mcpErr, grpcErr)

	_, grpcErr = grpcSide.grpc.DeleteManifest(ctx, &platformv1.DeleteManifestRequest{})
	_, mcpErr = mcpSide.mcp(t, "attestation_delete_manifest", map[string]interface{}{})
	assertSameClass(t, codes.InvalidArgument, mcpErr, grpcErr)
}

func TestMCPManifestParity_Create(t *testing.T) {
	ctx := context.Background()
	grpcSide, mcpSide := newManifestParity(), newManifestParity()

	want, err := grpcSide.grpc.BuildManifest(ctx, &platformv1.BuildManifestRequest{
		Config: &platformv1.ManifestBuilderConfig{
			HostId:        "host-a",
			HashAlgorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
			PcrIndices:    []uint32{0, 7},
		},
		Nonce:      []byte{1, 2, 3},
		IncludeVms: true,
		VmIds:      []string{"vm-1"},
		Sign:       true,
	})
	require.NoError(t, err)
	got, err := mcpSide.mcp(t, "attestation_create_manifest", map[string]interface{}{
		"host_id":        "host-a",
		"hash_algorithm": "sha256",
		"pcr_indices":    []interface{}{float64(0), float64(7)},
		"nonce":          "AQID",
		"include_vms":    true,
		"vm_ids":         []interface{}{"vm-1"},
	})
	require.NoError(t, err)
	assert.Equal(t, asToolResult(t, want), got)
	assert.Equal(t, grpcSide.svc.built, mcpSide.svc.built, "same builder config")
	assert.Equal(t, grpcSide.svc.buildNonce, mcpSide.svc.buildNonce)
	assert.Equal(t, grpcSide.svc.buildOpts, mcpSide.svc.buildOpts)
}

func TestMCPManifestParity_CreateRefusesUnknownHash(t *testing.T) {
	f := newManifestParity()
	_, err := f.mcp(t, "attestation_create_manifest", map[string]interface{}{"hash_algorithm": "md5"})
	var invalid mcp.ErrInvalidManifestArgument
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "hash_algorithm", invalid.Field)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Nil(t, f.svc.built, "an unknown hash never reaches the backend")
}

func TestMCPManifestParity_Verify(t *testing.T) {
	f := newManifestParity()
	ctx := context.Background()

	stored, err := f.grpc.GetManifest(ctx, &platformv1.GetManifestRequest{Id: "m-1"})
	require.NoError(t, err)
	want, err := f.grpc.VerifyManifest(ctx, &platformv1.VerifyManifestRequest{Manifest: stored.GetManifest(), ExpectedNonce: []byte{1, 2, 3}})
	require.NoError(t, err)
	got, err := f.mcp(t, "attestation_verify_manifest", map[string]interface{}{"id": "m-1", "expected_nonce": "AQID"})
	require.NoError(t, err)
	assert.Equal(t, asToolResult(t, want), got)

	// A public key the service cannot check is refused on both transports,
	// never reported as a valid signature.
	_, grpcErr := f.grpc.VerifyManifest(ctx, &platformv1.VerifyManifestRequest{Manifest: stored.GetManifest(), PublicKeyPem: []byte("pem")})
	_, mcpErr := f.mcp(t, "attestation_verify_manifest", map[string]interface{}{"id": "m-1", "public_key_pem": "pem"})
	assertSameClass(t, codes.FailedPrecondition, mcpErr, grpcErr)

	verified := f.svc.verified
	_, grpcErr = f.grpc.GetManifest(ctx, &platformv1.GetManifestRequest{Id: "absent"})
	_, mcpErr = f.mcp(t, "attestation_verify_manifest", map[string]interface{}{"id": "absent"})
	assertSameClass(t, codes.NotFound, mcpErr, grpcErr)

	_, grpcErr = f.grpc.GetManifest(ctx, &platformv1.GetManifestRequest{})
	_, mcpErr = f.mcp(t, "attestation_verify_manifest", map[string]interface{}{})
	assertSameClass(t, codes.InvalidArgument, mcpErr, grpcErr)
	assert.Equal(t, verified, f.svc.verified, "a missing manifest is never verified")
}

func TestMCPManifestTools_NotConfigured(t *testing.T) {
	tools := mcp.NewToolRegistry(NewMCPServiceProvider(&MCPServiceProviderConfig{}), logging.DefaultLogger())
	for _, tool := range []string{
		"attestation_get_manifest", "attestation_list_manifests", "attestation_create_manifest",
		"attestation_verify_manifest", "attestation_delete_manifest",
	} {
		_, err := tools.ExecuteTool(context.Background(), tool, map[string]interface{}{"id": "m-1"})
		assert.ErrorIs(t, err, mcp.ErrAttestationManifestsNotConfigured, tool)
	}
}

func TestMCPManifestTools_UnconfiguredBackendMatchesGRPC(t *testing.T) {
	// A server with no attestation service refuses on both transports with
	// the gRPC class, not the MCP not-configured error.
	server := NewAttestationServiceServer(nil, slog.Default())
	tools := mcp.NewToolRegistry(NewMCPServiceProvider(&MCPServiceProviderConfig{AttestationServer: server}), logging.DefaultLogger())

	_, grpcErr := server.GetManifest(context.Background(), &platformv1.GetManifestRequest{Id: "m-1"})
	_, mcpErr := tools.ExecuteTool(context.Background(), "attestation_get_manifest", map[string]interface{}{"id": "m-1"})
	assertSameClass(t, codes.FailedPrecondition, mcpErr, grpcErr)
}
