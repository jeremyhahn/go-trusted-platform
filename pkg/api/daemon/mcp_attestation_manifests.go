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

var manifestResultJSON = protojson.MarshalOptions{UseProtoNames: true}

// AttestationGetManifest serves attestation_get_manifest.
func (p *MCPServiceProvider) AttestationGetManifest(ctx context.Context, id string) (any, error) {
	if p.attestationServer == nil {
		return nil, mcp.ErrAttestationManifestsNotConfigured
	}
	return manifestResult(p.attestationServer.GetManifest(ctx, &platformv1.GetManifestRequest{Id: id}))
}

// AttestationListManifests serves attestation_list_manifests.
func (p *MCPServiceProvider) AttestationListManifests(ctx context.Context, limit, offset uint32) (any, error) {
	if p.attestationServer == nil {
		return nil, mcp.ErrAttestationManifestsNotConfigured
	}
	return manifestResult(p.attestationServer.ListManifests(ctx, &platformv1.ListManifestsRequest{
		Limit:  limit,
		Offset: offset,
	}))
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
	return manifestResult(p.attestationServer.BuildManifest(ctx, &platformv1.BuildManifestRequest{
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
	return manifestResult(p.attestationServer.VerifyManifest(ctx, &platformv1.VerifyManifestRequest{
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
	return manifestResult(p.attestationServer.DeleteManifest(ctx, &platformv1.DeleteManifestRequest{Id: id}))
}

// manifestResult renders a gRPC response as JSON, or passes its error on.
func manifestResult(resp proto.Message, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	data, err := manifestResultJSON.Marshal(resp)
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
