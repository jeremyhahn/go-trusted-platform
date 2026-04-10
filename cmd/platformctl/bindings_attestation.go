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

package main

import (
	"log/slog"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// AttestationBinding exposes attestation service methods to the Wails frontend.
type AttestationBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewAttestationBinding creates a new AttestationBinding.
func NewAttestationBinding(logger *slog.Logger, conn *ConnectionBinding) *AttestationBinding {
	return &AttestationBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *AttestationBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// GetManifest retrieves an existing attestation manifest by ID.
func (b *AttestationBinding) GetManifest(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Attestation().GetManifest(b.conn.ctx, &platformv1.GetManifestRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// BuildManifest builds a new attestation manifest for the host and its workloads.
func (b *AttestationBinding) BuildManifest(nonce []byte, includeVMs bool, includeContainers bool, sign bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Attestation().BuildManifest(b.conn.ctx, &platformv1.BuildManifestRequest{
		Nonce:             nonce,
		IncludeVms:        includeVMs,
		IncludeContainers: includeContainers,
		Sign:              sign,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// VerifyManifest verifies an attestation manifest by ID.
func (b *AttestationBinding) VerifyManifest(manifestID string, expectedNonce []byte, publicKeyPEM []byte) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	// First retrieve the manifest.
	getResp, err := cl.Attestation().GetManifest(b.conn.ctx, &platformv1.GetManifestRequest{
		Id: manifestID,
	})
	if err != nil {
		return nil, err
	}

	resp, err := cl.Attestation().VerifyManifest(b.conn.ctx, &platformv1.VerifyManifestRequest{
		Manifest:      getResp.GetManifest(),
		ExpectedNonce: expectedNonce,
		PublicKeyPem:  publicKeyPEM,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// ListManifests lists attestation manifests with optional filtering.
func (b *AttestationBinding) ListManifests(hostID string, limit uint32, offset uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Attestation().ListManifests(b.conn.ctx, &platformv1.ListManifestsRequest{
		HostId: hostID,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// DeleteManifest removes an attestation manifest by ID.
func (b *AttestationBinding) DeleteManifest(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Attestation().DeleteManifest(b.conn.ctx, &platformv1.DeleteManifestRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetAttestationQuote generates a TPM quote for the specified PCRs.
func (b *AttestationBinding) GetAttestationQuote(nonce []byte) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Attestation().GetAttestationQuote(b.conn.ctx, &platformv1.GetAttestationQuoteRequest{
		Nonce: nonce,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// VerifyAttestationQuote verifies a TPM quote against expected values.
func (b *AttestationBinding) VerifyAttestationQuote(akPublicKeyPEM []byte, expectedNonce []byte) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Attestation().VerifyAttestationQuote(b.conn.ctx, &platformv1.VerifyAttestationQuoteRequest{
		AkPublicKeyPem: akPublicKeyPEM,
		ExpectedNonce:  expectedNonce,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// CollectHostAttestation collects attestation data from the host TPM.
func (b *AttestationBinding) CollectHostAttestation(nonce []byte) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Attestation().CollectHostAttestation(b.conn.ctx, &platformv1.CollectHostAttestationRequest{
		Nonce: nonce,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}
