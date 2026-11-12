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

package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// manifestToolScopes is each manifest tool's scope: that of its gRPC
// AttestationService twin in method_permissions.go.
var manifestToolScopes = map[string]string{
	"attestation_get_manifest":    "attestation:read",
	"attestation_list_manifests":  "attestation:read",
	"attestation_verify_manifest": "attestation:read",
	"attestation_create_manifest": "attestation:write",
	"attestation_delete_manifest": "attestation:delete",
}

// manifestProvider records what each manifest tool handed the backend.
type manifestProvider struct {
	*mockServiceProvider
	calls  int
	id     string
	hostID string
	limit  uint32
	offset uint32
	build  ManifestBuildRequest
	verify ManifestVerifyRequest
	err    error
}

func newManifestProvider() *manifestProvider {
	return &manifestProvider{mockServiceProvider: newMockServiceProvider()}
}

func (p *manifestProvider) answer() (any, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	return map[string]any{"answered": true}, nil
}

func (p *manifestProvider) AttestationGetManifest(_ context.Context, id string) (any, error) {
	p.id = id
	return p.answer()
}

func (p *manifestProvider) AttestationListManifests(_ context.Context, hostID string, limit, offset uint32) (any, error) {
	p.hostID, p.limit, p.offset = hostID, limit, offset
	return p.answer()
}

func (p *manifestProvider) AttestationBuildManifest(_ context.Context, req ManifestBuildRequest) (any, error) {
	p.build = req
	return p.answer()
}

func (p *manifestProvider) AttestationVerifyManifest(_ context.Context, req ManifestVerifyRequest) (any, error) {
	p.verify = req
	return p.answer()
}

func (p *manifestProvider) AttestationDeleteManifest(_ context.Context, id string) (any, error) {
	p.id = id
	return p.answer()
}

func TestAttestationManifestTools_ScopesAndRegistration(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)
	registered := map[string]bool{}
	for _, tool := range NewToolRegistry(nil, nil).ListTools() {
		registered[tool.Name] = true
	}
	for tool, want := range manifestToolScopes {
		assert.Equal(t, want, checker.toolPermissions[tool], tool)
		assert.True(t, registered[tool], "%s is not registered", tool)
	}
}

// callManifestTool sends tools/call through the server, so authorization
// runs before the handler as it does on the wire.
func callManifestTool(t *testing.T, p *manifestProvider, tool string, grant func(resource, action string) bool) *mcpwire.JSONRPCResponse {
	t.Helper()
	authSvc := &mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			return grant(resource, action), nil
		},
	}
	server := NewServer(p, &Config{AuthorizationService: authSvc, AuthManager: &mockAuthManager{}}, newTestLogger())
	return server.handleRequest(context.Background(), &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      tool,
			"arguments": map[string]interface{}{"id": "m-1", "_token": "tok"},
		},
	})
}

func TestAttestationManifestTools_ScopeGatesHandler(t *testing.T) {
	for tool, scope := range manifestToolScopes {
		t.Run(tool+"/without scope", func(t *testing.T) {
			p := newManifestProvider()
			resp := callManifestTool(t, p, tool, func(resource, action string) bool {
				return resource+":"+action != scope
			})
			require.NotNil(t, resp.Error)
			assert.Equal(t, mcpwire.PermissionDenied, resp.Error.Code)
			assert.Zero(t, p.calls, "handler ran without %s", scope)
		})
		t.Run(tool+"/with scope", func(t *testing.T) {
			p := newManifestProvider()
			resp := callManifestTool(t, p, tool, func(resource, action string) bool {
				return resource+":"+action == scope
			})
			require.Nil(t, resp.Error)
			assert.Equal(t, 1, p.calls)
		})
	}
}

func TestAttestationManifestTools_NotConfiguredWithoutProvider(t *testing.T) {
	r := NewToolRegistry(newMockServiceProvider(), newTestLogger())
	for tool := range manifestToolScopes {
		_, err := r.ExecuteTool(context.Background(), tool, map[string]interface{}{"id": "m-1"})
		require.ErrorIs(t, err, ErrAttestationManifestsNotConfigured, tool)
		assert.Equal(t, codes.Unavailable, status.Code(err), tool)
	}
}

func TestAttestationManifestTools_DecodeArguments(t *testing.T) {
	ctx := context.Background()
	p := newManifestProvider()
	r := NewToolRegistry(p, newTestLogger())

	out, err := r.ExecuteTool(ctx, "attestation_get_manifest", map[string]interface{}{"id": "m-1"})
	require.NoError(t, err)
	assert.Equal(t, true, out.(map[string]interface{})["answered"])
	assert.Equal(t, "m-1", p.id)

	_, err = r.ExecuteTool(ctx, "attestation_delete_manifest", map[string]interface{}{"id": "m-2"})
	require.NoError(t, err)
	assert.Equal(t, "m-2", p.id)

	_, err = r.ExecuteTool(ctx, "attestation_list_manifests", map[string]interface{}{"host_id": "host-a", "limit": float64(10), "offset": float64(20)})
	require.NoError(t, err)
	assert.Equal(t, "host-a", p.hostID)
	assert.Equal(t, uint32(10), p.limit)
	assert.Equal(t, uint32(20), p.offset)

	_, err = r.ExecuteTool(ctx, "attestation_create_manifest", map[string]interface{}{
		"host_id":            "host-a",
		"nonce":              "AQID",
		"pcr_indices":        []interface{}{float64(0), float64(7)},
		"hash_algorithm":     "sha256",
		"include_vms":        true,
		"include_containers": true,
		"vm_ids":             []interface{}{"vm-1"},
		"container_ids":      []interface{}{"c-1"},
	})
	require.NoError(t, err)
	assert.Equal(t, ManifestBuildRequest{
		HostID:            "host-a",
		Nonce:             []byte{1, 2, 3},
		PCRIndices:        []uint32{0, 7},
		HashAlgorithm:     "sha256",
		IncludeVMs:        true,
		IncludeContainers: true,
		VMIDs:             []string{"vm-1"},
		ContainerIDs:      []string{"c-1"},
		Sign:              true,
	}, p.build, "sign defaults to true")

	_, err = r.ExecuteTool(ctx, "attestation_create_manifest", map[string]interface{}{"sign": false})
	require.NoError(t, err)
	assert.False(t, p.build.Sign, "an explicit false turns signing off")

	_, err = r.ExecuteTool(ctx, "attestation_verify_manifest", map[string]interface{}{
		"id":             "m-3",
		"expected_nonce": "AQID",
		"expected_pcrs":  map[string]interface{}{"7": "BAU="},
		"public_key_pem": "-----BEGIN PUBLIC KEY-----",
	})
	require.NoError(t, err)
	assert.Equal(t, ManifestVerifyRequest{
		ID:            "m-3",
		ExpectedNonce: []byte{1, 2, 3},
		PublicKeyPEM:  []byte("-----BEGIN PUBLIC KEY-----"),
		ExpectedPCRs:  map[uint32][]byte{7: {4, 5}},
	}, p.verify)
}

func TestAttestationManifestTools_InvalidArgumentsNeverReachBackend(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"bad nonce", "attestation_create_manifest", map[string]interface{}{"nonce": "not base64!"}},
		{"string pcr index", "attestation_create_manifest", map[string]interface{}{"pcr_indices": []interface{}{"7"}}},
		{"negative pcr index", "attestation_create_manifest", map[string]interface{}{"pcr_indices": []interface{}{float64(-1)}}},
		{"fractional pcr index", "attestation_create_manifest", map[string]interface{}{"pcr_indices": []interface{}{float64(1.5)}}},
		{"pcr indices not an array", "attestation_create_manifest", map[string]interface{}{"pcr_indices": "0,7"}},
		{"negative limit", "attestation_list_manifests", map[string]interface{}{"limit": float64(-1)}},
		{"offset above uint32", "attestation_list_manifests", map[string]interface{}{"offset": float64(1 << 33)}},
		{"bad expected nonce", "attestation_verify_manifest", map[string]interface{}{"id": "m", "expected_nonce": "%%"}},
		{"pcr key not an index", "attestation_verify_manifest", map[string]interface{}{"id": "m", "expected_pcrs": map[string]interface{}{"seven": "AA=="}}},
		{"pcr value not a string", "attestation_verify_manifest", map[string]interface{}{"id": "m", "expected_pcrs": map[string]interface{}{"7": float64(1)}}},
		{"pcr value not base64", "attestation_verify_manifest", map[string]interface{}{"id": "m", "expected_pcrs": map[string]interface{}{"7": "%%"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newManifestProvider()
			r := NewToolRegistry(p, newTestLogger())
			_, err := r.ExecuteTool(context.Background(), tc.tool, tc.args)
			var invalid ErrInvalidManifestArgument
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Zero(t, p.calls)
		})
	}
}

func TestAttestationManifestTools_BackendErrorPassesThrough(t *testing.T) {
	p := newManifestProvider()
	p.err = status.Error(codes.NotFound, "manifest not found")
	r := NewToolRegistry(p, newTestLogger())
	for tool := range manifestToolScopes {
		_, err := r.ExecuteTool(context.Background(), tool, map[string]interface{}{"id": "missing"})
		assert.Equal(t, codes.NotFound, status.Code(err), tool)
	}
}
