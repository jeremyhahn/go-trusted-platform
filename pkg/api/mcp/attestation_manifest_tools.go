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
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AttestationManifestProvider serves the attestation_*_manifest tools
// (#304). The daemon implements it by calling the gRPC
// AttestationService methods, so each tool answers with the same result
// and error class as its gRPC twin. Results are the gRPC responses
// rendered as JSON.
type AttestationManifestProvider interface {
	AttestationGetManifest(ctx context.Context, id string) (any, error)
	// A zero start or end time sets no bound on that side.
	AttestationListManifests(ctx context.Context, hostID string, start, end time.Time, limit, offset uint32) (any, error)
	AttestationBuildManifest(ctx context.Context, req ManifestBuildRequest) (any, error)
	AttestationVerifyManifest(ctx context.Context, req ManifestVerifyRequest) (any, error)
	AttestationDeleteManifest(ctx context.Context, id string) (any, error)
}

// ManifestBuildRequest carries the attestation_create_manifest
// arguments, decoded.
type ManifestBuildRequest struct {
	HostID            string
	Nonce             []byte
	PCRIndices        []uint32
	HashAlgorithm     string
	IncludeVMs        bool
	IncludeContainers bool
	VMIDs             []string
	ContainerIDs      []string
	Sign              bool
}

// ManifestVerifyRequest carries the attestation_verify_manifest
// arguments, decoded. The manifest is named by ID; the provider fetches
// it before verifying, as the REST adapter does.
type ManifestVerifyRequest struct {
	ID            string
	ExpectedNonce []byte
	PublicKeyPEM  []byte
	ExpectedPCRs  map[uint32][]byte
}

// ErrAttestationManifestsNotConfigured is returned when the MCP server
// has no attestation manifest backend.
var ErrAttestationManifestsNotConfigured = &AttestationError{
	Code:    "ATTESTATION_MANIFESTS_NOT_CONFIGURED",
	Message: "the attestation manifest service is not configured on this node",
}

// ErrInvalidManifestArgument is returned when a manifest tool argument
// cannot be decoded.
type ErrInvalidManifestArgument struct {
	Field  string
	Reason string
}

func (e ErrInvalidManifestArgument) Error() string {
	return "invalid " + e.Field + ": " + e.Reason
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrInvalidManifestArgument) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

func (r *ToolRegistry) attestationManifestProvider() AttestationManifestProvider {
	if p, ok := r.service.(AttestationManifestProvider); ok {
		return p
	}
	return nil
}

type attestationManifestToolFunc func(*ToolRegistry, context.Context, AttestationManifestProvider, map[string]interface{}) (interface{}, error)

var attestationManifestToolDispatch = map[string]attestationManifestToolFunc{
	"attestation_get_manifest":    (*ToolRegistry).executeAttestationGetManifest,
	"attestation_list_manifests":  (*ToolRegistry).executeAttestationListManifests,
	"attestation_create_manifest": (*ToolRegistry).executeAttestationCreateManifest,
	"attestation_verify_manifest": (*ToolRegistry).executeAttestationVerifyManifest,
	"attestation_delete_manifest": (*ToolRegistry).executeAttestationDeleteManifest,
}

func (r *ToolRegistry) dispatchAttestationManifestTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := attestationManifestToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	p := r.attestationManifestProvider()
	if p == nil {
		return nil, true, ErrAttestationManifestsNotConfigured
	}
	result, err := fn(r, ctx, p, args)
	if err != nil {
		return nil, true, err
	}
	out, err := marshalResult(result)
	return out, true, err
}

func (r *ToolRegistry) executeAttestationGetManifest(ctx context.Context, p AttestationManifestProvider, args map[string]interface{}) (interface{}, error) {
	return p.AttestationGetManifest(ctx, getString(args, "id"))
}

func (r *ToolRegistry) executeAttestationDeleteManifest(ctx context.Context, p AttestationManifestProvider, args map[string]interface{}) (interface{}, error) {
	return p.AttestationDeleteManifest(ctx, getString(args, "id"))
}

func (r *ToolRegistry) executeAttestationListManifests(ctx context.Context, p AttestationManifestProvider, args map[string]interface{}) (interface{}, error) {
	limit, err := manifestUint32Arg(args, "limit")
	if err != nil {
		return nil, err
	}
	offset, err := manifestUint32Arg(args, "offset")
	if err != nil {
		return nil, err
	}
	start, err := manifestTimeArg(args, "start_time")
	if err != nil {
		return nil, err
	}
	end, err := manifestTimeArg(args, "end_time")
	if err != nil {
		return nil, err
	}
	return p.AttestationListManifests(ctx, getString(args, "host_id"), start, end, limit, offset)
}

func (r *ToolRegistry) executeAttestationCreateManifest(ctx context.Context, p AttestationManifestProvider, args map[string]interface{}) (interface{}, error) {
	nonce, err := manifestBase64Arg(getString(args, "nonce"), "nonce")
	if err != nil {
		return nil, err
	}
	pcrs, err := manifestPCRIndicesArg(args)
	if err != nil {
		return nil, err
	}
	// The schema defaults sign to true; only an explicit false turns it off.
	sign := true
	if v, ok := args["sign"].(bool); ok {
		sign = v
	}
	return p.AttestationBuildManifest(ctx, ManifestBuildRequest{
		HostID:            getString(args, "host_id"),
		Nonce:             nonce,
		PCRIndices:        pcrs,
		HashAlgorithm:     getString(args, "hash_algorithm"),
		IncludeVMs:        getBool(args, "include_vms"),
		IncludeContainers: getBool(args, "include_containers"),
		VMIDs:             getStringSlice(args, "vm_ids"),
		ContainerIDs:      getStringSlice(args, "container_ids"),
		Sign:              sign,
	})
}

func (r *ToolRegistry) executeAttestationVerifyManifest(ctx context.Context, p AttestationManifestProvider, args map[string]interface{}) (interface{}, error) {
	nonce, err := manifestBase64Arg(getString(args, "expected_nonce"), "expected_nonce")
	if err != nil {
		return nil, err
	}
	var expected map[uint32][]byte
	if raw := getMap(args, "expected_pcrs"); len(raw) > 0 {
		expected = make(map[uint32][]byte, len(raw))
		for key, value := range raw {
			index, err := strconv.ParseUint(key, 10, 32)
			if err != nil {
				return nil, ErrInvalidManifestArgument{Field: "expected_pcrs", Reason: "key " + strconv.Quote(key) + " is not a PCR index"}
			}
			encoded, ok := value.(string)
			if !ok {
				return nil, ErrInvalidManifestArgument{Field: "expected_pcrs", Reason: "value for PCR " + key + " is not a base64 string"}
			}
			digest, err := manifestBase64Arg(encoded, "expected_pcrs["+key+"]")
			if err != nil {
				return nil, err
			}
			expected[uint32(index)] = digest
		}
	}
	var publicKey []byte
	if pem := getString(args, "public_key_pem"); pem != "" {
		publicKey = []byte(pem)
	}
	return p.AttestationVerifyManifest(ctx, ManifestVerifyRequest{
		ID:            getString(args, "id"),
		ExpectedNonce: nonce,
		PublicKeyPEM:  publicKey,
		ExpectedPCRs:  expected,
	})
}

// manifestBase64Arg decodes a standard base64 argument; empty is nil.
func manifestBase64Arg(encoded, field string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidManifestArgument{Field: field, Reason: "not valid base64"}
	}
	return decoded, nil
}

// manifestUint32Arg reads an optional non-negative integer argument.
func manifestUint32Arg(args map[string]interface{}, key string) (uint32, error) {
	n := getInt64(args, key)
	if n < 0 || n > math.MaxUint32 {
		return 0, ErrInvalidManifestArgument{Field: key, Reason: "must be between 0 and 4294967295"}
	}
	return uint32(n), nil
}

// manifestTimeArg reads an optional RFC 3339 time argument. An absent or
// empty value is the zero time (no bound); a value that is not an RFC 3339
// string is refused.
func manifestTimeArg(args map[string]interface{}, key string) (time.Time, error) {
	raw, ok := args[key]
	if !ok || raw == nil {
		return time.Time{}, nil
	}
	s, ok := raw.(string)
	if !ok {
		return time.Time{}, ErrInvalidManifestArgument{Field: key, Reason: "must be an RFC 3339 time string"}
	}
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, ErrInvalidManifestArgument{Field: key, Reason: "not an RFC 3339 time"}
	}
	return t, nil
}

// manifestPCRIndicesArg reads the optional pcr_indices array. Every entry
// must be a whole number in PCR range; a string or fraction is refused
// rather than read as PCR 0.
func manifestPCRIndicesArg(args map[string]interface{}) ([]uint32, error) {
	raw, ok := args["pcr_indices"]
	if !ok || raw == nil {
		return nil, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, ErrInvalidManifestArgument{Field: "pcr_indices", Reason: "must be an array of integers"}
	}
	pcrs := make([]uint32, 0, len(items))
	for _, item := range items {
		n, ok := item.(float64)
		if !ok || n != math.Trunc(n) || n < 0 || n > math.MaxUint32 {
			return nil, ErrInvalidManifestArgument{Field: "pcr_indices", Reason: "entry " + strconv.Quote(fmt.Sprint(item)) + " is not a PCR index"}
		}
		pcrs = append(pcrs, uint32(n))
	}
	return pcrs, nil
}
