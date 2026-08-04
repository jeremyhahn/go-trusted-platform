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

package compute

import (
	"context"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// PCRValue is a single PCR index/value pair included in an attestation quote.
type PCRValue struct {
	// Index is the PCR index.
	Index uint32 `json:"index" yaml:"index"`
	// Bank is the PCR bank algorithm (e.g. "sha256").
	Bank string `json:"bank,omitempty" yaml:"bank,omitempty"`
	// Value is the PCR hash value.
	Value []byte `json:"value" yaml:"value"`
}

// ContainerAttestation is a domain container attestation report containing
// the TPM quote, signature, and container identity digests.
type ContainerAttestation struct {
	// ContainerID is the attested container identifier.
	ContainerID string `json:"container_id" yaml:"container_id"`
	// ContainerName is the attested container name.
	ContainerName string `json:"container_name" yaml:"container_name"`
	// ImageDigest is the digest of the container image.
	ImageDigest []byte `json:"image_digest,omitempty" yaml:"image_digest,omitempty"`
	// ConfigDigest is the digest of the container configuration.
	ConfigDigest []byte `json:"config_digest,omitempty" yaml:"config_digest,omitempty"`
	// Quote is the TPM quote data.
	Quote []byte `json:"quote,omitempty" yaml:"quote,omitempty"`
	// Signature is the TPM signature over the quote.
	Signature []byte `json:"signature,omitempty" yaml:"signature,omitempty"`
	// PCRValues are the PCR values included in the quote.
	PCRValues []*PCRValue `json:"pcr_values,omitempty" yaml:"pcr_values,omitempty"`
	// EventLog is the raw measurement event log.
	EventLog []byte `json:"event_log,omitempty" yaml:"event_log,omitempty"`
	// AKPublic is the attestation key public material or certificate.
	AKPublic []byte `json:"ak_public,omitempty" yaml:"ak_public,omitempty"`
	// Verified indicates whether the attestation was verified.
	Verified bool `json:"verified" yaml:"verified"`
	// Timestamp is when the attestation was performed.
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	// Status is the operation status returned by the server.
	Status *ContainerStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// AttestContainerParams contains parameters for container attestation.
type AttestContainerParams struct {
	// ID is the container identifier.
	ID string
	// Nonce is an optional anti-replay nonce to bind into the quote.
	Nonce []byte
	// PCRIndices are optional PCR indices to include in the quote.
	PCRIndices []uint32
}

// AttestContainer generates a quote-based attestation report for a container.
// This mirrors AttestVM's proto-typed shape for callers that need full control
// over the request, including PCR bank selection.
func (c *Client) AttestContainer(ctx context.Context, id string, nonce []byte, pcrIndices []uint32, pcrBank platformv1.PCRBank) (*platformv1.AttestContainerResponse, error) {
	if id == "" {
		return nil, &ErrAttestContainerFailed{Cause: ErrContainerIDRequired}
	}
	resp, err := c.grpc.AttestContainer(ctx, &platformv1.AttestContainerRequest{
		Id:         id,
		Nonce:      nonce,
		PcrIndices: pcrIndices,
		PcrBank:    pcrBank,
	})
	if err != nil {
		return nil, &ErrAttestContainerFailed{ID: id, Cause: err}
	}
	return resp, nil
}

// AttestContainerDomain generates a quote-based attestation report for a
// container using domain types.
func (c *Client) AttestContainerDomain(ctx context.Context, params *AttestContainerParams) (*ContainerAttestation, error) {
	if params == nil || params.ID == "" {
		return nil, &ErrAttestContainerFailed{Cause: ErrContainerIDRequired}
	}
	resp, err := c.grpc.AttestContainer(ctx, &platformv1.AttestContainerRequest{
		Id:         params.ID,
		Nonce:      params.Nonce,
		PcrIndices: params.PCRIndices,
	})
	if err != nil {
		return nil, &ErrAttestContainerFailed{ID: params.ID, Cause: err}
	}
	return ContainerAttestationFromProto(resp), nil
}
