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

// InvitationGRPCService implements the Invitation gRPC service for
// managing tenant membership invitations including creation, acceptance,
// revocation, and lifecycle management.
type InvitationGRPCService struct {
	platformv1.UnimplementedInvitationServiceServer

	logger *logging.Logger
}

// NewInvitationGRPCService creates a new Invitation gRPC service instance.
func NewInvitationGRPCService(logger *logging.Logger) *InvitationGRPCService {
	return &InvitationGRPCService{
		logger: logger,
	}
}

// invitationNotImplemented returns the standard error for unimplemented operations.
func (s *InvitationGRPCService) invitationNotImplemented(method string) error {
	return status.Errorf(codes.Unimplemented, "invitation: %s not implemented", method)
}

// CreateInvitation creates a new invitation for a user to join a tenant.
func (s *InvitationGRPCService) CreateInvitation(
	ctx context.Context,
	req *platformv1.CreateInvitationRequest,
) (*platformv1.CreateInvitationResponse, error) {
	return nil, s.invitationNotImplemented("CreateInvitation")
}

// GetInvitation retrieves an invitation by its ID.
func (s *InvitationGRPCService) GetInvitation(
	ctx context.Context,
	req *platformv1.GetInvitationRequest,
) (*platformv1.GetInvitationResponse, error) {
	return nil, s.invitationNotImplemented("GetInvitation")
}

// GetInvitationByToken retrieves an invitation by its secure token.
func (s *InvitationGRPCService) GetInvitationByToken(
	ctx context.Context,
	req *platformv1.GetInvitationByTokenRequest,
) (*platformv1.GetInvitationResponse, error) {
	return nil, s.invitationNotImplemented("GetInvitationByToken")
}

// ListInvitations returns invitations for a tenant with optional filtering.
func (s *InvitationGRPCService) ListInvitations(
	ctx context.Context,
	req *platformv1.ListInvitationsRequest,
) (*platformv1.ListInvitationsResponse, error) {
	return nil, s.invitationNotImplemented("ListInvitations")
}

// RevokeInvitation revokes a pending invitation.
func (s *InvitationGRPCService) RevokeInvitation(
	ctx context.Context,
	req *platformv1.RevokeInvitationRequest,
) (*platformv1.RevokeInvitationResponse, error) {
	return nil, s.invitationNotImplemented("RevokeInvitation")
}

// AcceptInvitation marks an invitation as accepted.
func (s *InvitationGRPCService) AcceptInvitation(
	ctx context.Context,
	req *platformv1.AcceptInvitationRequest,
) (*platformv1.AcceptInvitationResponse, error) {
	return nil, s.invitationNotImplemented("AcceptInvitation")
}

// DeleteInvitation permanently removes an invitation.
func (s *InvitationGRPCService) DeleteInvitation(
	ctx context.Context,
	req *platformv1.DeleteInvitationRequest,
) (*platformv1.DeleteInvitationResponse, error) {
	return nil, s.invitationNotImplemented("DeleteInvitation")
}
