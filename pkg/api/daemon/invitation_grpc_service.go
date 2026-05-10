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
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// InvitationGRPCService implements the Invitation gRPC service for
// managing tenant membership invitations including creation, acceptance,
// revocation, and lifecycle management.
//
// The service delegates to a platformservice.InvitationServicer when one
// is wired in. When the servicer is nil, every method returns
// codes.Unimplemented preserving the legacy stub behaviour for
// deployments that have not yet wired the invitation backend.
type InvitationGRPCService struct {
	platformv1.UnimplementedInvitationServiceServer

	logger *logging.Logger
	svc    platformservice.InvitationServicer
}

// NewInvitationGRPCService creates a new Invitation gRPC service instance.
// Pass a nil svc to retain the legacy "Unimplemented" stub behaviour.
func NewInvitationGRPCService(logger *logging.Logger, svc platformservice.InvitationServicer) *InvitationGRPCService {
	return &InvitationGRPCService{
		logger: logger,
		svc:    svc,
	}
}

// Service returns the underlying InvitationServicer or nil when the
// service is operating as a stub. Used by the daemon to share the same
// backing implementation with MCP/Unix/QUIC surfaces.
func (s *InvitationGRPCService) Service() platformservice.InvitationServicer {
	return s.svc
}

// SetService injects the InvitationServicer after construction. The
// daemon uses this to share the same servicer instance with the MCP
// service provider so behaviour is identical across protocols.
func (s *InvitationGRPCService) SetService(svc platformservice.InvitationServicer) {
	s.svc = svc
}

// Status fields use Success(bool)+Message(string) per the platformv1.Status
// proto contract.

// invitationNotImplemented returns the standard error for unimplemented operations.
func (s *InvitationGRPCService) invitationNotImplemented(method string) error {
	return status.Errorf(codes.Unimplemented, "invitation: %s not implemented", method)
}

// invitationToProto converts the persistence entity into the proto wire
// representation. Returns nil when inv is nil so callers can short-circuit
// safely.
func invitationToProto(inv *entities.Invitation) *platformv1.Invitation {
	if inv == nil {
		return nil
	}
	out := &platformv1.Invitation{
		Id:          inv.ID,
		Token:       inv.Token,
		TenantId:    inv.TenantID,
		Email:       inv.Email,
		Role:        inv.Role,
		Status:      invitationStatusToProto(inv.Status),
		InvitedById: inv.InvitedByID,
		ExpiresAt:   timestamppb.New(inv.ExpiresAt),
		CreatedAt:   timestamppb.New(inv.CreatedAt),
		UpdatedAt:   timestamppb.New(inv.UpdatedAt),
	}
	if inv.AcceptedAt != nil {
		out.AcceptedAt = timestamppb.New(*inv.AcceptedAt)
	}
	return out
}

// invitationStatusToProto maps the domain invitation status to the
// proto enum. Map-based dispatch keeps lookup O(1).
var invitationStatusToProtoMap = map[entities.InvitationStatus]platformv1.InvitationStatus{
	entities.InvitationStatusPending:  platformv1.InvitationStatus_INVITATION_STATUS_PENDING,
	entities.InvitationStatusAccepted: platformv1.InvitationStatus_INVITATION_STATUS_ACCEPTED,
	entities.InvitationStatusExpired:  platformv1.InvitationStatus_INVITATION_STATUS_EXPIRED,
	entities.InvitationStatusRevoked:  platformv1.InvitationStatus_INVITATION_STATUS_REVOKED,
}

func invitationStatusToProto(s entities.InvitationStatus) platformv1.InvitationStatus {
	if v, ok := invitationStatusToProtoMap[s]; ok {
		return v
	}
	return platformv1.InvitationStatus_INVITATION_STATUS_UNSPECIFIED
}

// CreateInvitation creates a new invitation for a user to join a tenant.
func (s *InvitationGRPCService) CreateInvitation(
	ctx context.Context,
	req *platformv1.CreateInvitationRequest,
) (*platformv1.CreateInvitationResponse, error) {
	if s.svc == nil {
		return nil, s.invitationNotImplemented("CreateInvitation")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invitation: request is required")
	}
	createReq := &platformservice.CreateInvitationRequest{
		TenantID:    req.TenantId,
		Email:       req.Email,
		Role:        req.Role,
		InvitedByID: req.InvitedById,
	}
	if req.ExpiresInSeconds > 0 {
		createReq.ExpiresIn = time.Duration(req.ExpiresInSeconds) * time.Second
	}
	inv, err := s.svc.Create(ctx, createReq)
	if err != nil {
		return nil, err
	}
	return &platformv1.CreateInvitationResponse{
		Invitation: invitationToProto(inv),
		Timestamp:  timestamppb.Now(),
	}, nil
}

// GetInvitation retrieves an invitation by its ID.
func (s *InvitationGRPCService) GetInvitation(
	ctx context.Context,
	req *platformv1.GetInvitationRequest,
) (*platformv1.GetInvitationResponse, error) {
	if s.svc == nil {
		return nil, s.invitationNotImplemented("GetInvitation")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invitation: request is required")
	}
	inv, err := s.svc.GetByID(ctx, req.InvitationId)
	if err != nil {
		return nil, err
	}
	return &platformv1.GetInvitationResponse{
		Invitation: invitationToProto(inv),
		Timestamp:  timestamppb.Now(),
	}, nil
}

// GetInvitationByToken retrieves an invitation by its secure token.
func (s *InvitationGRPCService) GetInvitationByToken(
	ctx context.Context,
	req *platformv1.GetInvitationByTokenRequest,
) (*platformv1.GetInvitationResponse, error) {
	if s.svc == nil {
		return nil, s.invitationNotImplemented("GetInvitationByToken")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invitation: request is required")
	}
	inv, err := s.svc.GetByToken(ctx, req.Token)
	if err != nil {
		return nil, err
	}
	return &platformv1.GetInvitationResponse{
		Invitation: invitationToProto(inv),
		Timestamp:  timestamppb.Now(),
	}, nil
}

// ListInvitations returns invitations for a tenant with optional filtering.
func (s *InvitationGRPCService) ListInvitations(
	ctx context.Context,
	req *platformv1.ListInvitationsRequest,
) (*platformv1.ListInvitationsResponse, error) {
	if s.svc == nil {
		return nil, s.invitationNotImplemented("ListInvitations")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invitation: request is required")
	}
	var (
		invs []*entities.Invitation
		err  error
	)
	if req.PendingOnly {
		invs, err = s.svc.ListPendingByTenant(ctx, req.TenantId)
	} else {
		invs, err = s.svc.ListByTenant(ctx, req.TenantId)
	}
	if err != nil {
		return nil, err
	}
	out := make([]*platformv1.Invitation, 0, len(invs))
	for _, inv := range invs {
		// Apply optional status / email filters in-process to keep the
		// servicer interface small. status_filter == UNSPECIFIED disables
		// the filter.
		if req.StatusFilter != platformv1.InvitationStatus_INVITATION_STATUS_UNSPECIFIED &&
			invitationStatusToProto(inv.Status) != req.StatusFilter {
			continue
		}
		if req.EmailFilter != "" && !containsFold(inv.Email, req.EmailFilter) {
			continue
		}
		out = append(out, invitationToProto(inv))
	}
	return &platformv1.ListInvitationsResponse{
		Invitations: out,
		Total:       int64(len(out)),
		Timestamp:   timestamppb.Now(),
	}, nil
}

// RevokeInvitation revokes a pending invitation.
func (s *InvitationGRPCService) RevokeInvitation(
	ctx context.Context,
	req *platformv1.RevokeInvitationRequest,
) (*platformv1.RevokeInvitationResponse, error) {
	if s.svc == nil {
		return nil, s.invitationNotImplemented("RevokeInvitation")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invitation: request is required")
	}
	if err := s.svc.Revoke(ctx, req.InvitationId, req.RevokerId); err != nil {
		return nil, err
	}
	return &platformv1.RevokeInvitationResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "invitation revoked",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// AcceptInvitation marks an invitation as accepted.
func (s *InvitationGRPCService) AcceptInvitation(
	ctx context.Context,
	req *platformv1.AcceptInvitationRequest,
) (*platformv1.AcceptInvitationResponse, error) {
	if s.svc == nil {
		return nil, s.invitationNotImplemented("AcceptInvitation")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invitation: request is required")
	}
	if err := s.svc.Accept(ctx, req.Token, req.UserId); err != nil {
		return nil, err
	}
	inv, err := s.svc.GetByToken(ctx, req.Token)
	if err != nil {
		// Accept succeeded but read-back failed; return success without
		// the updated invitation rather than masking the original outcome.
		return &platformv1.AcceptInvitationResponse{
			Status: &platformv1.Status{
				Success: true,
				Message: "invitation accepted",
			},
			Timestamp: timestamppb.Now(),
		}, nil
	}
	return &platformv1.AcceptInvitationResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "invitation accepted",
		},
		Invitation: invitationToProto(inv),
		Timestamp:  timestamppb.Now(),
	}, nil
}

// DeleteInvitation permanently removes an invitation.
func (s *InvitationGRPCService) DeleteInvitation(
	ctx context.Context,
	req *platformv1.DeleteInvitationRequest,
) (*platformv1.DeleteInvitationResponse, error) {
	if s.svc == nil {
		return nil, s.invitationNotImplemented("DeleteInvitation")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invitation: request is required")
	}
	if err := s.svc.Delete(ctx, req.InvitationId); err != nil {
		return nil, err
	}
	return &platformv1.DeleteInvitationResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "invitation deleted",
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// containsFold reports whether needle is a case-insensitive substring of
// haystack. An empty needle matches everything.
func containsFold(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
