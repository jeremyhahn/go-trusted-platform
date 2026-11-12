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
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The attestation_*_manifest MCP tools (#304) call the gRPC
// AttestationService methods, so each answers with the same result and
// error class as its gRPC twin.
var _ mcp.AttestationManifestProvider = (*MCPServiceProvider)(nil)

var protoResultJSON = protojson.MarshalOptions{UseProtoNames: true}

// AttestationServiceServer implements mcp.AttestationServiceProvider: the
// attestation quote and collection tools call the gRPC AttestationService
// servicer, so they answer and fail as gRPC does. It returns nil while no
// attestation servicer is wired.
func (p *MCPServiceProvider) AttestationServiceServer() platformv1.AttestationServiceServer {
	if p.attestationServer == nil {
		return nil
	}
	return p.attestationServer
}

// AttestationGetManifest serves attestation_get_manifest.
func (p *MCPServiceProvider) AttestationGetManifest(ctx context.Context, id string) (any, error) {
	if p.attestationServer == nil {
		return nil, mcp.ErrAttestationManifestsNotConfigured
	}
	return protoResult(p.attestationServer.GetManifest(ctx, &platformv1.GetManifestRequest{Id: id}))
}

// AttestationListManifests serves attestation_list_manifests.
func (p *MCPServiceProvider) AttestationListManifests(ctx context.Context, hostID string, start, end time.Time, limit, offset uint32) (any, error) {
	if p.attestationServer == nil {
		return nil, mcp.ErrAttestationManifestsNotConfigured
	}
	req := &platformv1.ListManifestsRequest{
		HostId: hostID,
		Limit:  limit,
		Offset: offset,
	}
	if !start.IsZero() {
		req.StartTime = timestamppb.New(start)
	}
	if !end.IsZero() {
		req.EndTime = timestamppb.New(end)
	}
	return protoResult(p.attestationServer.ListManifests(ctx, req))
}

// AttestationBuildManifest serves attestation_create_manifest.
func (p *MCPServiceProvider) AttestationBuildManifest(ctx context.Context, req mcp.ManifestBuildRequest) (any, error) {
	if p.attestationServer == nil {
		return nil, mcp.ErrAttestationManifestsNotConfigured
	}
	hash, err := attestationHashAlgorithm(req.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	return protoResult(p.attestationServer.BuildManifest(ctx, &platformv1.BuildManifestRequest{
		Config: &platformv1.ManifestBuilderConfig{
			HostId:        req.HostID,
			HashAlgorithm: hash,
			PcrIndices:    req.PCRIndices,
		},
		Nonce:             req.Nonce,
		IncludeVms:        req.IncludeVMs,
		IncludeContainers: req.IncludeContainers,
		VmIds:             req.VMIDs,
		ContainerIds:      req.ContainerIDs,
		Sign:              req.Sign,
	}))
}

// AttestationVerifyManifest serves attestation_verify_manifest. The tool
// names the manifest by ID, so it is fetched first, as the REST adapter
// and platformctl do, then verified.
func (p *MCPServiceProvider) AttestationVerifyManifest(ctx context.Context, req mcp.ManifestVerifyRequest) (any, error) {
	if p.attestationServer == nil {
		return nil, mcp.ErrAttestationManifestsNotConfigured
	}
	got, err := p.attestationServer.GetManifest(ctx, &platformv1.GetManifestRequest{Id: req.ID})
	if err != nil {
		return nil, err
	}
	return protoResult(p.attestationServer.VerifyManifest(ctx, &platformv1.VerifyManifestRequest{
		Manifest:      got.GetManifest(),
		ExpectedNonce: req.ExpectedNonce,
		PublicKeyPem:  req.PublicKeyPEM,
		ExpectedPcrs:  req.ExpectedPCRs,
	}))
}

// AttestationDeleteManifest serves attestation_delete_manifest.
func (p *MCPServiceProvider) AttestationDeleteManifest(ctx context.Context, id string) (any, error) {
	if p.attestationServer == nil {
		return nil, mcp.ErrAttestationManifestsNotConfigured
	}
	return protoResult(p.attestationServer.DeleteManifest(ctx, &platformv1.DeleteManifestRequest{Id: id}))
}

// protoResult renders a gRPC response as JSON in the proto's own field
// names, or passes its error on. The MCP tools that answer through their
// gRPC twin (attestation manifests, VM lifecycle) share it.
func protoResult(resp proto.Message, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	data, err := protoResultJSON.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// attestationHashAlgorithm maps the tool's hash name ("sha256") to the
// gRPC enum; empty leaves the server's default.
func attestationHashAlgorithm(name string) (platformv1.AttestationHashAlgorithm, error) {
	if name == "" {
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_UNSPECIFIED, nil
	}
	value, ok := platformv1.AttestationHashAlgorithm_value["ATTESTATION_HASH_ALGORITHM_"+strings.ToUpper(name)]
	if !ok || value == 0 {
		return 0, mcp.ErrInvalidManifestArgument{Field: "hash_algorithm", Reason: "unknown algorithm " + name}
	}
	return platformv1.AttestationHashAlgorithm(value), nil
}
