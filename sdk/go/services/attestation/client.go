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

// Package attestation provides a client for attestation service operations.
package attestation

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to attestation service operations.
type Client struct {
	grpc platformv1.AttestationServiceClient
}

// NewClient creates a new attestation service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewAttestationServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new attestation service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.AttestationServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// GetManifest retrieves an existing attestation manifest by ID.
func (c *Client) GetManifest(ctx context.Context, id string) (*platformv1.HostManifest, error) {
	resp, err := c.grpc.GetManifest(ctx, &platformv1.GetManifestRequest{Id: id})
	if err != nil {
		return nil, &ErrGetManifestFailed{ID: id, Cause: err}
	}
	return resp.Manifest, nil
}

// BuildManifest builds a new attestation manifest for the host and its workloads.
func (c *Client) BuildManifest(ctx context.Context, req *platformv1.BuildManifestRequest) (*platformv1.HostManifest, error) {
	resp, err := c.grpc.BuildManifest(ctx, req)
	if err != nil {
		return nil, &ErrBuildManifestFailed{Cause: err}
	}
	return resp.Manifest, nil
}

// VerifyManifest verifies an attestation manifest including signature and Merkle root.
func (c *Client) VerifyManifest(ctx context.Context, req *platformv1.VerifyManifestRequest) (*platformv1.ManifestVerificationResult, error) {
	resp, err := c.grpc.VerifyManifest(ctx, req)
	if err != nil {
		return nil, &ErrVerifyManifestFailed{Cause: err}
	}
	return resp.Result, nil
}

// ListManifests lists attestation manifests with optional filtering.
func (c *Client) ListManifests(ctx context.Context, req *platformv1.ListManifestsRequest) ([]*platformv1.HostManifest, uint32, error) {
	resp, err := c.grpc.ListManifests(ctx, req)
	if err != nil {
		return nil, 0, &ErrListManifestsFailed{Cause: err}
	}
	return resp.Manifests, resp.Total, nil
}

// DeleteManifest removes an attestation manifest.
func (c *Client) DeleteManifest(ctx context.Context, id string) error {
	_, err := c.grpc.DeleteManifest(ctx, &platformv1.DeleteManifestRequest{Id: id})
	if err != nil {
		return &ErrDeleteManifestFailed{ID: id, Cause: err}
	}
	return nil
}

// GetAttestationQuote generates a TPM quote for the specified PCRs.
func (c *Client) GetAttestationQuote(ctx context.Context, config *platformv1.AttestationQuoteConfig, nonce []byte) (*platformv1.AttestationQuote, error) {
	resp, err := c.grpc.GetAttestationQuote(ctx, &platformv1.GetAttestationQuoteRequest{
		Config: config,
		Nonce:  nonce,
	})
	if err != nil {
		return nil, &ErrGetQuoteFailed{Cause: err}
	}
	return resp.Quote, nil
}

// VerifyAttestationQuote verifies a TPM quote against expected values.
func (c *Client) VerifyAttestationQuote(ctx context.Context, req *platformv1.VerifyAttestationQuoteRequest) (*platformv1.VerifyAttestationQuoteResponse, error) {
	resp, err := c.grpc.VerifyAttestationQuote(ctx, req)
	if err != nil {
		return nil, &ErrVerifyQuoteFailed{Cause: err}
	}
	return resp, nil
}

// CollectHostAttestation collects attestation data from the host TPM.
func (c *Client) CollectHostAttestation(ctx context.Context, config *platformv1.AttestationQuoteConfig, nonce []byte) (*platformv1.HostAttestation, error) {
	resp, err := c.grpc.CollectHostAttestation(ctx, &platformv1.CollectHostAttestationRequest{
		Config: config,
		Nonce:  nonce,
	})
	if err != nil {
		return nil, &ErrCollectHostAttestationFailed{Cause: err}
	}
	return resp.Attestation, nil
}

// CollectVMAttestation collects attestation data from a VM's vTPM.
func (c *Client) CollectVMAttestation(ctx context.Context, vmID string, config *platformv1.AttestationQuoteConfig, nonce []byte) (*platformv1.VMAttestation, error) {
	resp, err := c.grpc.CollectVMAttestation(ctx, &platformv1.CollectVMAttestationRequest{
		VmId:   vmID,
		Config: config,
		Nonce:  nonce,
	})
	if err != nil {
		return nil, &ErrCollectVMAttestationFailed{VMID: vmID, Cause: err}
	}
	return resp.Attestation, nil
}

// CollectContainerAttestation collects attestation data for a container.
func (c *Client) CollectContainerAttestation(ctx context.Context, containerID string) (*platformv1.ContainerAttestation, error) {
	resp, err := c.grpc.CollectContainerAttestation(ctx, &platformv1.CollectContainerAttestationRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return nil, &ErrCollectContainerAttestationFailed{ContainerID: containerID, Cause: err}
	}
	return resp.Attestation, nil
}
