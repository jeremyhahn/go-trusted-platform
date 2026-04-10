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

//go:build !attestation_grpc

package daemon

import (
	"context"
	"log/slog"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AttestationService provides attestation operations including manifest
// building, signing, and verification. This is the stub interface when
// attestation_grpc build tag is not enabled.
type AttestationService interface{}

// BuildManifestOptions contains options for building a manifest.
type BuildManifestOptions struct{}

// ListManifestsFilter contains filters for listing manifests.
type ListManifestsFilter struct{}

// QuoteConfig contains configuration for TPM quote generation.
type QuoteConfig struct{}

// QuoteResult contains the result of a TPM quote operation.
type QuoteResult struct{}

// QuoteVerificationResult contains the result of quote verification.
type QuoteVerificationResult struct{}

// AttestationServiceServer is a stub implementation when attestation_grpc build tag is not enabled.
// Build with -tags attestation_grpc to enable the full Attestation gRPC service.
type AttestationServiceServer struct {
	platformv1.UnimplementedAttestationServiceServer
	logger *slog.Logger
}

// NewAttestationServiceServer creates a stub Attestation gRPC service.
// This returns a service that returns "Unimplemented" for all operations.
// Build with -tags attestation_grpc to enable the full implementation.
func NewAttestationServiceServer(service AttestationService, logger *slog.Logger) *AttestationServiceServer {
	return &AttestationServiceServer{
		logger: logger,
	}
}

// attestationNotAvailable returns the standard error for stub operations.
func (s *AttestationServiceServer) attestationNotAvailable() error {
	return status.Error(codes.Unimplemented, "Attestation gRPC service not available (build with -tags attestation_grpc)")
}

// =============================================================================
// Manifest Operations (Stubs)
// =============================================================================

// GetManifest stub - returns unimplemented.
func (s *AttestationServiceServer) GetManifest(
	ctx context.Context,
	req *platformv1.GetManifestRequest,
) (*platformv1.GetManifestResponse, error) {
	return nil, s.attestationNotAvailable()
}

// BuildManifest stub - returns unimplemented.
func (s *AttestationServiceServer) BuildManifest(
	ctx context.Context,
	req *platformv1.BuildManifestRequest,
) (*platformv1.BuildManifestResponse, error) {
	return nil, s.attestationNotAvailable()
}

// VerifyManifest stub - returns unimplemented.
func (s *AttestationServiceServer) VerifyManifest(
	ctx context.Context,
	req *platformv1.VerifyManifestRequest,
) (*platformv1.VerifyManifestResponse, error) {
	return nil, s.attestationNotAvailable()
}

// ListManifests stub - returns unimplemented.
func (s *AttestationServiceServer) ListManifests(
	ctx context.Context,
	req *platformv1.ListManifestsRequest,
) (*platformv1.ListManifestsResponse, error) {
	return nil, s.attestationNotAvailable()
}

// DeleteManifest stub - returns unimplemented.
func (s *AttestationServiceServer) DeleteManifest(
	ctx context.Context,
	req *platformv1.DeleteManifestRequest,
) (*platformv1.DeleteManifestResponse, error) {
	return nil, s.attestationNotAvailable()
}

// =============================================================================
// Quote Operations (Stubs)
// =============================================================================

// GetAttestationQuote stub - returns unimplemented.
func (s *AttestationServiceServer) GetAttestationQuote(
	ctx context.Context,
	req *platformv1.GetAttestationQuoteRequest,
) (*platformv1.GetAttestationQuoteResponse, error) {
	return nil, s.attestationNotAvailable()
}

// VerifyAttestationQuote stub - returns unimplemented.
func (s *AttestationServiceServer) VerifyAttestationQuote(
	ctx context.Context,
	req *platformv1.VerifyAttestationQuoteRequest,
) (*platformv1.VerifyAttestationQuoteResponse, error) {
	return nil, s.attestationNotAvailable()
}

// =============================================================================
// Attestation Collection Operations (Stubs)
// =============================================================================

// CollectHostAttestation stub - returns unimplemented.
func (s *AttestationServiceServer) CollectHostAttestation(
	ctx context.Context,
	req *platformv1.CollectHostAttestationRequest,
) (*platformv1.CollectHostAttestationResponse, error) {
	return nil, s.attestationNotAvailable()
}

// CollectVMAttestation stub - returns unimplemented.
func (s *AttestationServiceServer) CollectVMAttestation(
	ctx context.Context,
	req *platformv1.CollectVMAttestationRequest,
) (*platformv1.CollectVMAttestationResponse, error) {
	return nil, s.attestationNotAvailable()
}

// CollectContainerAttestation stub - returns unimplemented.
func (s *AttestationServiceServer) CollectContainerAttestation(
	ctx context.Context,
	req *platformv1.CollectContainerAttestationRequest,
) (*platformv1.CollectContainerAttestationResponse, error) {
	return nil, s.attestationNotAvailable()
}
