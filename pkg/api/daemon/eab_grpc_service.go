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

package daemon

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EABGRPCService implements the EAB gRPC service for External Account
// Binding credential management used in ACME device enrollment.
type EABGRPCService struct {
	platformv1.UnimplementedEABServiceServer

	logger *logging.Logger
}

// NewEABGRPCService creates a new EAB gRPC service instance.
func NewEABGRPCService(logger *logging.Logger) *EABGRPCService {
	return &EABGRPCService{
		logger: logger,
	}
}

// eabNotImplemented returns the standard error for unimplemented operations.
func (s *EABGRPCService) eabNotImplemented(method string) error {
	return status.Errorf(codes.Unimplemented, "eab: %s not implemented", method)
}

// CreateCredential creates a new EAB credential for device enrollment.
func (s *EABGRPCService) CreateCredential(
	ctx context.Context,
	req *platformv1.CreateEABCredentialRequest,
) (*platformv1.CreateEABCredentialResponse, error) {
	return nil, s.eabNotImplemented("CreateCredential")
}

// GetCredential retrieves an EAB credential by its ID.
func (s *EABGRPCService) GetCredential(
	ctx context.Context,
	req *platformv1.GetEABCredentialRequest,
) (*platformv1.GetEABCredentialResponse, error) {
	return nil, s.eabNotImplemented("GetCredential")
}

// GetCredentialByKeyID retrieves an EAB credential by its KeyID.
func (s *EABGRPCService) GetCredentialByKeyID(
	ctx context.Context,
	req *platformv1.GetEABCredentialByKeyIDRequest,
) (*platformv1.GetEABCredentialResponse, error) {
	return nil, s.eabNotImplemented("GetCredentialByKeyID")
}

// ListCredentials returns EAB credentials with optional filtering.
func (s *EABGRPCService) ListCredentials(
	ctx context.Context,
	req *platformv1.ListEABCredentialsRequest,
) (*platformv1.ListEABCredentialsResponse, error) {
	return nil, s.eabNotImplemented("ListCredentials")
}

// RevokeCredential marks an EAB credential as revoked.
func (s *EABGRPCService) RevokeCredential(
	ctx context.Context,
	req *platformv1.RevokeEABCredentialRequest,
) (*platformv1.RevokeEABCredentialResponse, error) {
	return nil, s.eabNotImplemented("RevokeCredential")
}

// ValidateCredential checks if an EAB credential is valid for use.
func (s *EABGRPCService) ValidateCredential(
	ctx context.Context,
	req *platformv1.ValidateEABCredentialRequest,
) (*platformv1.ValidateEABCredentialResponse, error) {
	return nil, s.eabNotImplemented("ValidateCredential")
}

// DeleteCredential permanently removes an EAB credential.
func (s *EABGRPCService) DeleteCredential(
	ctx context.Context,
	req *platformv1.DeleteEABCredentialRequest,
) (*platformv1.DeleteEABCredentialResponse, error) {
	return nil, s.eabNotImplemented("DeleteCredential")
}

// GetCredentialQRCode generates a QR code image for credential delivery.
func (s *EABGRPCService) GetCredentialQRCode(
	ctx context.Context,
	req *platformv1.GetEABCredentialQRCodeRequest,
) (*platformv1.GetEABCredentialQRCodeResponse, error) {
	return nil, s.eabNotImplemented("GetCredentialQRCode")
}

// GetEnrollmentURL generates an enrollment URL with embedded credentials.
func (s *EABGRPCService) GetEnrollmentURL(
	ctx context.Context,
	req *platformv1.GetEABEnrollmentURLRequest,
) (*platformv1.GetEABEnrollmentURLResponse, error) {
	return nil, s.eabNotImplemented("GetEnrollmentURL")
}

// MarkCredentialUsed marks a credential as used after successful enrollment.
func (s *EABGRPCService) MarkCredentialUsed(
	ctx context.Context,
	req *platformv1.MarkEABCredentialUsedRequest,
) (*platformv1.MarkEABCredentialUsedResponse, error) {
	return nil, s.eabNotImplemented("MarkCredentialUsed")
}

// CleanupExpiredCredentials removes all expired credentials.
func (s *EABGRPCService) CleanupExpiredCredentials(
	ctx context.Context,
	req *platformv1.CleanupExpiredEABCredentialsRequest,
) (*platformv1.CleanupExpiredEABCredentialsResponse, error) {
	return nil, s.eabNotImplemented("CleanupExpiredCredentials")
}
