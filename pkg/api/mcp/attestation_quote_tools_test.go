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

package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// attestationQuoteTestProvider serves an AttestationService servicer next to
// the mock service provider.
type attestationQuoteTestProvider struct {
	*mockServiceProvider
	server platformv1.AttestationServiceServer
}

func (p attestationQuoteTestProvider) AttestationServiceServer() platformv1.AttestationServiceServer {
	return p.server
}

// fakeMCPAttestation answers the five quote and collection methods, records
// the method each call reached and its request, and refuses an unknown VM.
type fakeMCPAttestation struct {
	platformv1.UnimplementedAttestationServiceServer
	called string
	got    any
}

func (f *fakeMCPAttestation) GetAttestationQuote(_ context.Context, req *platformv1.GetAttestationQuoteRequest) (*platformv1.GetAttestationQuoteResponse, error) {
	f.called, f.got = "GetAttestationQuote", req
	return &platformv1.GetAttestationQuoteResponse{
		Quote:          &platformv1.AttestationQuote{Nonce: req.GetNonce()},
		ChannelBinding: []byte{0x01},
	}, nil
}

func (f *fakeMCPAttestation) VerifyAttestationQuote(_ context.Context, req *platformv1.VerifyAttestationQuoteRequest) (*platformv1.VerifyAttestationQuoteResponse, error) {
	f.called, f.got = "VerifyAttestationQuote", req
	return &platformv1.VerifyAttestationQuoteResponse{Verified: true, Message: "ok"}, nil
}

func (f *fakeMCPAttestation) CollectHostAttestation(_ context.Context, req *platformv1.CollectHostAttestationRequest) (*platformv1.CollectHostAttestationResponse, error) {
	f.called, f.got = "CollectHostAttestation", req
	return &platformv1.CollectHostAttestationResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (f *fakeMCPAttestation) CollectVMAttestation(_ context.Context, req *platformv1.CollectVMAttestationRequest) (*platformv1.CollectVMAttestationResponse, error) {
	f.called, f.got = "CollectVMAttestation", req
	if req.GetVmId() != "vm-1" {
		return nil, status.Error(codes.NotFound, "vm not found")
	}
	return &platformv1.CollectVMAttestationResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (f *fakeMCPAttestation) CollectContainerAttestation(_ context.Context, req *platformv1.CollectContainerAttestationRequest) (*platformv1.CollectContainerAttestationResponse, error) {
	f.called, f.got = "CollectContainerAttestation", req
	return &platformv1.CollectContainerAttestationResponse{Status: &platformv1.Status{Success: true}}, nil
}

func newAttestationQuoteTestRegistry(server platformv1.AttestationServiceServer) *ToolRegistry {
	provider := attestationQuoteTestProvider{mockServiceProvider: newMockServiceProvider(), server: server}
	return NewToolRegistry(provider, logging.DefaultLogger())
}

// attestationQuoteToolArgs are well-formed arguments for each tool; the
// nonce is base64, as protojson carries bytes.
var attestationQuoteToolArgs = map[string]map[string]interface{}{
	"attestation_get_quote": {"config": map[string]interface{}{"pcr_indices": []interface{}{0, 7}}, "nonce": "bm9uY2U="},
	"attestation_verify_quote": {"quote": map[string]interface{}{"quote_data": "cQ==", "signature": "cw=="},
		"ak_public_key_pem": "cGVt", "expected_nonce": "bm9uY2U="},
	"attestation_collect_host":      {"nonce": "bm9uY2U="},
	"attestation_collect_vm":        {"vm_id": "vm-1", "config": map[string]interface{}{}, "nonce": "bm9uY2U="},
	"attestation_collect_container": {"container_id": "c-1"},
}

// Each tool is classified with the scope its gRPC method requires.
func TestAttestationQuoteTools_CarryTheirGRPCScope(t *testing.T) {
	permissions := toolPermissionCatalog()
	for name, tool := range attestationQuoteTools {
		permission, classified := permissions[name]
		require.True(t, classified, "%s is not classified", name)
		assert.Equal(t, grpcapi.ScopeForMethod(tool.method), permission, name)
		assert.NotEmpty(t, permission, "%s is open", name)
	}
}

// Every tool is listed with the arguments its gRPC request cannot do without.
func TestAttestationQuoteTools_AreRegisteredWithTheirSchema(t *testing.T) {
	required := map[string][]string{
		"attestation_get_quote":         {"config", "nonce"},
		"attestation_verify_quote":      {"quote", "ak_public_key_pem"},
		"attestation_collect_host":      {"nonce"},
		"attestation_collect_vm":        {"vm_id", "config", "nonce"},
		"attestation_collect_container": {"container_id"},
	}
	registered := make(map[string]map[string]interface{})
	for _, def := range newAttestationQuoteTestRegistry(nil).ListTools() {
		registered[def.Name] = def.InputSchema
	}

	require.Len(t, required, len(attestationQuoteTools))
	for name, args := range required {
		schema, ok := registered[name]
		require.True(t, ok, "%s is not registered", name)
		assert.ElementsMatch(t, args, schema["required"], name)
	}
}

// Each tool decodes its arguments into its gRPC request and reaches its own
// method.
func TestAttestationQuoteTools_CallTheirMethod(t *testing.T) {
	want := map[string]string{
		"attestation_get_quote":         "GetAttestationQuote",
		"attestation_verify_quote":      "VerifyAttestationQuote",
		"attestation_collect_host":      "CollectHostAttestation",
		"attestation_collect_vm":        "CollectVMAttestation",
		"attestation_collect_container": "CollectContainerAttestation",
	}
	require.Len(t, want, len(attestationQuoteTools))
	for name, method := range want {
		fake := &fakeMCPAttestation{}
		registry := newAttestationQuoteTestRegistry(fake)

		result, err := registry.ExecuteTool(context.Background(), name, attestationQuoteToolArgs[name])

		require.NoError(t, err, name)
		assert.NotNil(t, result, name)
		assert.Equal(t, method, fake.called, name)
	}
}

// The request reaches the servicer with bytes decoded from base64 and the
// reply comes back in proto field names.
func TestAttestationQuoteTools_CarryTheProtoJSONForm(t *testing.T) {
	fake := &fakeMCPAttestation{}
	registry := newAttestationQuoteTestRegistry(fake)

	result, err := registry.ExecuteTool(context.Background(), "attestation_get_quote", attestationQuoteToolArgs["attestation_get_quote"])

	require.NoError(t, err)
	req, ok := fake.got.(*platformv1.GetAttestationQuoteRequest)
	require.True(t, ok)
	assert.Equal(t, []byte("nonce"), req.GetNonce())
	assert.Equal(t, []uint32{0, 7}, req.GetConfig().GetPcrIndices())
	assert.Equal(t, map[string]interface{}{
		"quote":           map[string]interface{}{"nonce": "bm9uY2U="},
		"channel_binding": "AQ==",
	}, result)
}

// The servicer's status passes through, so MCP reports the class gRPC
// reports.
func TestAttestationQuoteTools_PassTheServicerStatusThrough(t *testing.T) {
	registry := newAttestationQuoteTestRegistry(&fakeMCPAttestation{})

	_, err := registry.ExecuteTool(context.Background(), "attestation_collect_vm",
		map[string]interface{}{"vm_id": "vm-missing", "config": map[string]interface{}{}, "nonce": "bm9uY2U="})

	assert.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
}

// A provider without AttestationServiceServer, and one that serves none, are
// refused Unavailable before anything is decoded.
func TestAttestationQuoteTools_RefuseWhenTheAttestationServiceIsNotWired(t *testing.T) {
	for _, provider := range []ServiceProvider{
		newMockServiceProvider(),
		attestationQuoteTestProvider{mockServiceProvider: newMockServiceProvider()},
	} {
		registry := NewToolRegistry(provider, logging.DefaultLogger())
		for name := range attestationQuoteTools {
			_, err := registry.ExecuteTool(context.Background(), name, attestationQuoteToolArgs[name])

			require.ErrorIs(t, err, ErrAttestationServiceNotConfigured, name)
			assert.Equal(t, mcpwire.CodeForClass(codes.Unavailable), toolErrorCode(err), name)
		}
	}
}

// An argument the gRPC request has no field for is refused before the
// servicer runs.
func TestAttestationQuoteTools_RejectArgumentsTheRequestDoesNotHave(t *testing.T) {
	fake := &fakeMCPAttestation{}
	registry := newAttestationQuoteTestRegistry(fake)

	for name := range attestationQuoteTools {
		_, err := registry.ExecuteTool(context.Background(), name, map[string]interface{}{"device_id": "d"})

		var invalid ErrInvalidArgument
		require.ErrorAs(t, err, &invalid, name)
	}
	assert.Empty(t, fake.called, "a malformed call reached the servicer")
}
