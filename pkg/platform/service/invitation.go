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

package service

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// DefaultInvitationExpiry is the default duration until an invitation expires.
const DefaultInvitationExpiry = 7 * 24 * time.Hour

// CreateInvitationRequest contains the parameters for creating an invitation.
type CreateInvitationRequest struct {
	TenantID    string
	Email       string
	Role        string
	InvitedByID uint64
	ExpiresIn   time.Duration
}

// InvitationServicer defines the interface for invitation management operations.
//
// CreateInitialAdmin is deliberately NOT a member. Everything that holds an
// InvitationServicer serves tenant-scoped callers -- the gRPC service and MCP
// tool provider in pkg/api/daemon, the WebAuthn handler, TenantUserService --
// and putting owner-minting on this interface would hand that capability to
// every one of them. Ownership is conferred only by a call site that names
// *InvitationService.CreateInitialAdmin directly, which is the same reason it
// is a method rather than a field on CreateInvitationRequest. A consumer that
// legitimately needs it should declare its own one-method interface for it
// (see the method's doc comment for the caller obligation that comes with it).
type InvitationServicer interface {
	// Create creates a new invitation. The redeemer becomes a tenant member
	// with the requested role and does NOT become the tenant owner.
	Create(ctx context.Context, req *CreateInvitationRequest) (*entities.Invitation, error)
	// GetByToken retrieves an invitation by its secure token.
	GetByToken(ctx context.Context, token string) (*entities.Invitation, error)
	// GetByID retrieves an invitation by its ID.
	GetByID(ctx context.Context, id uint64) (*entities.Invitation, error)
	// Accept marks an invitation as accepted.
	Accept(ctx context.Context, token string, userID uint64) error
	// Revoke marks an invitation as revoked.
	Revoke(ctx context.Context, id uint64, revokerID uint64) error
	// ListByTenant returns all invitations for a tenant.
	ListByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error)
	// ListPendingByTenant returns pending invitations for a tenant.
	ListPendingByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error)
	// CleanupExpired marks expired invitations as expired and returns the count cleaned.
	CleanupExpired(ctx context.Context) (int, error)
	// Delete removes an invitation by ID.
	Delete(ctx context.Context, id uint64) error
}

// InvitationService implements InvitationServicer.
type InvitationService struct {
	logger        *logging.Logger
	invitationDAO datastore.InvitationDAO
	userDAO       datastore.UserDAO
	defaultExpiry time.Duration
}

// NewInvitationService creates a new InvitationService.
//
// It returns the concrete type rather than InvitationServicer because
// CreateInitialAdmin is deliberately not on that interface: a caller handed
// only the interface cannot confer tenant ownership, and a caller that must
// (the system admin's tenant-provisioning flow) holds the concrete service.
// Assigning the result to an InvitationServicer still works everywhere it did.
func NewInvitationService(
	logger *logging.Logger,
	invitationDAO datastore.InvitationDAO,
	userDAO datastore.UserDAO,
) *InvitationService {
	return &InvitationService{
		logger:        logger,
		invitationDAO: invitationDAO,
		userDAO:       userDAO,
		defaultExpiry: DefaultInvitationExpiry,
	}
}

// NewInvitationServiceWithExpiry creates a new InvitationService with custom default expiry.
func NewInvitationServiceWithExpiry(
	logger *logging.Logger,
	invitationDAO datastore.InvitationDAO,
	userDAO datastore.UserDAO,
	defaultExpiry time.Duration,
) *InvitationService {
	if defaultExpiry <= 0 {
		defaultExpiry = DefaultInvitationExpiry
	}
	return &InvitationService{
		logger:        logger,
		invitationDAO: invitationDAO,
		userDAO:       userDAO,
		defaultExpiry: defaultExpiry,
	}
}

// InvitationService satisfies the tenant-scoped interface every transport
// holder consumes; the owner-minting method it additionally carries is
// reachable only through the concrete type.
var _ InvitationServicer = (*InvitationService)(nil)

// invitationFactory builds the entity a create path persists. Create and
// CreateInitialAdmin run identical validation, identical duplicate-email
// checks and a single identical save, and differ ONLY in which constructor
// they name. That is deliberate: the difference between an ordinary
// invitation and one that confers tenant ownership is a choice made by the
// call site, never a value carried in CreateInvitationRequest.
type invitationFactory func(
	tenantID, email, role string,
	invitedByID uint64,
	expiresDuration time.Duration) (*entities.Invitation, error)

// Create creates a new invitation for the specified email address.
// The invitation will expire after the specified duration or the default expiry.
// Returns ErrEmailAlreadyRegistered if the email is already registered in the tenant.
//
// The redeemer becomes a tenant member with the requested role and does NOT
// become the tenant owner; CreateInitialAdmin is the only path that does.
func (s *InvitationService) Create(
	ctx context.Context,
	req *CreateInvitationRequest,
) (*entities.Invitation, error) {
	return s.create(ctx, req, entities.NewInvitation)
}

// create is the shared body of Create and CreateInitialAdmin.
func (s *InvitationService) create(
	ctx context.Context,
	req *CreateInvitationRequest,
	newInvitation invitationFactory,
) (*entities.Invitation, error) {
	if req == nil {
		return nil, ErrInvalidInvitation{Reason: "request cannot be nil"}
	}

	if req.TenantID == "" {
		return nil, ErrInvalidInvitation{Reason: "tenant ID is required"}
	}

	if req.Email == "" {
		return nil, ErrInvalidInvitation{Reason: "email is required"}
	}

	if req.Role == "" {
		return nil, ErrInvalidInvitation{Reason: "role is required"}
	}

	if req.InvitedByID == 0 {
		return nil, ErrInvalidInvitation{Reason: "inviter ID is required"}
	}

	s.logger.Debug("creating invitation",
		"tenant_id", req.TenantID,
		"email", req.Email,
		"role", req.Role,
		"invited_by", req.InvitedByID,
	)

	// Check if email is already registered in the tenant
	exists, err := s.emailExistsInTenant(ctx, req.Email, req.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to check if email exists in tenant")
		return nil, err
	}
	if exists {
		return nil, ErrEmailAlreadyRegistered{Email: req.Email, TenantID: req.TenantID}
	}

	// Determine expiry duration
	expiry := req.ExpiresIn
	if expiry <= 0 {
		expiry = s.defaultExpiry
	}

	invitation, err := newInvitation(req.TenantID, req.Email, req.Role, req.InvitedByID, expiry)
	if err != nil {
		s.logger.Error(err, "failed to create invitation entity")
		return nil, ErrInvitationSaveFailed{Cause: err}
	}

	// One save, so an invitation is never persisted in a state its caller did
	// not ask for. Marking a saved invitation afterwards would leave an
	// ordinary, redeemable invitation behind whenever the second write failed.
	if err := s.invitationDAO.Save(ctx, invitation); err != nil {
		s.logger.Error(err, "failed to save invitation")
		return nil, ErrInvitationSaveFailed{Cause: err}
	}

	s.logger.Info("invitation created",
		"invitation_id", invitation.ID,
		"tenant_id", req.TenantID,
		"email", req.Email,
		"expires_at", invitation.ExpiresAt,
	)

	return invitation, nil
}

// CreateInitialAdmin creates the invitation that provisions a tenant's FIRST
// administrator. Redeeming it makes the redeemer the tenant owner (#158,
// owner ruling 2026-09-01).
//
// It is a distinct method rather than a flag on CreateInvitationRequest, and
// that is a security property rather than a style choice. If ownership were a
// request field, the REST handler would decode it from the caller's body and
// any tenant administrator able to invite could mint themselves an owner by
// setting it — the same shape as #171, where a caller-supplied value decided
// something the caller should not choose. Keeping it off the request struct
// means a caller cannot ask for it: only a call site that names this method
// can confer ownership, and the ruling says that call site is the system
// admin's tenant-provisioning flow.
//
// CALLER OBLIGATION: this method does not itself check that the caller is the
// system admin — it has no session. The route or command that exposes it MUST
// be restricted to the system tenant. /api/v1/tenants already is, as of #234.
func (s *InvitationService) CreateInitialAdmin(
	ctx context.Context,
	req *CreateInvitationRequest,
) (*entities.Invitation, error) {

	invitation, err := s.create(ctx, req, entities.NewInitialAdminInvitation)
	if err != nil {
		return nil, err
	}

	s.logger.Info("initial tenant-admin invitation created",
		"invitation_id", invitation.ID,
		"tenant_id", req.TenantID,
		"email", req.Email,
		"invited_by", req.InvitedByID,
	)
	return invitation, nil
}

// GetByToken retrieves an invitation by its secure token.
// Returns ErrInvitationExpired if the invitation has expired.
func (s *InvitationService) GetByToken(ctx context.Context, token string) (*entities.Invitation, error) {
	if token == "" {
		return nil, ErrInvalidInvitation{Reason: "token is required"}
	}

	s.logger.Debug("retrieving invitation by token")

	invitation, err := s.invitationDAO.GetByToken(ctx, token)
	if err != nil {
		s.logger.Debug("invitation not found by token")
		return nil, ErrInvitationNotFound{Token: token}
	}

	// Check expiration for pending invitations
	if invitation.Status == entities.InvitationStatusPending && invitation.IsExpired() {
		return nil, ErrInvitationExpired{Token: token}
	}

	return invitation, nil
}

// GetByID retrieves an invitation by its ID.
func (s *InvitationService) GetByID(ctx context.Context, id uint64) (*entities.Invitation, error) {
	if id == 0 {
		return nil, ErrInvalidInvitation{Reason: "invitation ID is required"}
	}

	s.logger.Debug("retrieving invitation by ID", "invitation_id", id)

	invitation, err := s.invitationDAO.Get(ctx, id)
	if err != nil {
		s.logger.Debug("invitation not found by ID", "invitation_id", id)
		return nil, ErrInvitationNotFound{ID: id}
	}

	return invitation, nil
}

// Accept marks an invitation as accepted.
// Only pending invitations can be accepted.
// Returns an error if the invitation is expired, already accepted, or revoked.
func (s *InvitationService) Accept(ctx context.Context, token string, userID uint64) error {
	if token == "" {
		return ErrInvalidInvitation{Reason: "token is required"}
	}

	if userID == 0 {
		return ErrInvalidInvitation{Reason: "user ID is required"}
	}

	s.logger.Debug("accepting invitation", "user_id", userID)

	invitation, err := s.invitationDAO.GetByToken(ctx, token)
	if err != nil {
		s.logger.Debug("invitation not found for acceptance")
		return ErrInvitationNotFound{Token: token}
	}

	// Check current status
	switch invitation.Status {
	case entities.InvitationStatusAccepted:
		return ErrInvitationAlreadyAccepted{Token: token}
	case entities.InvitationStatusRevoked:
		return ErrInvitationAlreadyRevoked{Token: token}
	case entities.InvitationStatusExpired:
		return ErrInvitationExpired{Token: token}
	case entities.InvitationStatusPending:
		// Continue processing
	default:
		return ErrInvalidInvitationStatus{Status: string(invitation.Status)}
	}

	// Check if invitation is expired
	if invitation.IsExpired() {
		// Update status to expired
		invitation.Status = entities.InvitationStatusExpired
		if saveErr := s.invitationDAO.Save(ctx, invitation); saveErr != nil {
			s.logger.Error(saveErr, "failed to update expired invitation")
		}
		return ErrInvitationExpired{Token: token}
	}

	// Mark as accepted
	invitation.Accept()

	if err := s.invitationDAO.Save(ctx, invitation); err != nil {
		s.logger.Error(err, "failed to save accepted invitation")
		return ErrInvitationSaveFailed{Cause: err}
	}

	s.logger.Info("invitation accepted",
		"invitation_id", invitation.ID,
		"tenant_id", invitation.TenantID,
		"email", invitation.Email,
		"user_id", userID,
	)

	return nil
}

// Revoke marks an invitation as revoked.
// Only pending invitations can be revoked.
func (s *InvitationService) Revoke(ctx context.Context, id uint64, revokerID uint64) error {
	if id == 0 {
		return ErrInvalidInvitation{Reason: "invitation ID is required"}
	}

	if revokerID == 0 {
		return ErrInvalidInvitation{Reason: "revoker ID is required"}
	}

	s.logger.Debug("revoking invitation", "invitation_id", id, "revoker_id", revokerID)

	invitation, err := s.invitationDAO.Get(ctx, id)
	if err != nil {
		s.logger.Debug("invitation not found for revocation", "invitation_id", id)
		return ErrInvitationNotFound{ID: id}
	}

	// Check current status
	switch invitation.Status {
	case entities.InvitationStatusRevoked:
		return ErrInvitationAlreadyRevoked{ID: id}
	case entities.InvitationStatusAccepted:
		return ErrInvalidInvitation{Reason: "accepted invitations cannot be revoked"}
	case entities.InvitationStatusExpired:
		return ErrInvalidInvitation{Reason: "expired invitations cannot be revoked"}
	case entities.InvitationStatusPending:
		// Continue processing
	default:
		return ErrInvalidInvitationStatus{Status: string(invitation.Status)}
	}

	invitation.Status = entities.InvitationStatusRevoked

	if err := s.invitationDAO.Save(ctx, invitation); err != nil {
		s.logger.Error(err, "failed to save revoked invitation")
		return ErrInvitationSaveFailed{Cause: err}
	}

	s.logger.Info("invitation revoked", "invitation_id", id, "revoker_id", revokerID)

	return nil
}

// ListByTenant returns all invitations for a tenant.
func (s *InvitationService) ListByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	if tenantID == "" {
		return nil, ErrInvalidInvitation{Reason: "tenant ID is required"}
	}

	s.logger.Debug("listing invitations by tenant", "tenant_id", tenantID)

	invitations, err := s.invitationDAO.GetByTenant(ctx, tenantID)
	if err != nil {
		s.logger.Error(err, "failed to list invitations by tenant")
		return nil, err
	}

	return invitations, nil
}

// ListPendingByTenant returns pending invitations for a tenant.
func (s *InvitationService) ListPendingByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	if tenantID == "" {
		return nil, ErrInvalidInvitation{Reason: "tenant ID is required"}
	}

	s.logger.Debug("listing pending invitations by tenant", "tenant_id", tenantID)

	invitations, err := s.invitationDAO.GetPendingByTenant(ctx, tenantID)
	if err != nil {
		s.logger.Error(err, "failed to list pending invitations by tenant")
		return nil, err
	}

	return invitations, nil
}

// CleanupExpired marks all expired invitations as expired.
// This should be called periodically to clean up stale invitations.
// Returns the number of invitations that were marked as expired.
func (s *InvitationService) CleanupExpired(ctx context.Context) (int, error) {
	s.logger.Debug("cleaning up expired invitations")

	// Use pagination to process all invitations
	pageQuery := datastore.NewPageQuery()
	pageQuery.PageSize = 100

	expiredCount := 0

	err := s.invitationDAO.ForEachPage(ctx, pageQuery, func(result datastore.PageResult[*entities.Invitation]) error {
		for _, invitation := range result.Entities {
			// Only process pending invitations
			if invitation.Status != entities.InvitationStatusPending {
				continue
			}

			// Check if expired
			if invitation.IsExpired() {
				invitation.Status = entities.InvitationStatusExpired
				if saveErr := s.invitationDAO.Save(ctx, invitation); saveErr != nil {
					s.logger.Error(saveErr, "failed to mark invitation as expired",
						"invitation_id", invitation.ID)
					continue
				}
				expiredCount++
			}
		}
		return nil
	})

	if err != nil {
		s.logger.Error(err, "failed during invitation cleanup")
		return expiredCount, err
	}

	if expiredCount > 0 {
		s.logger.Info("expired invitations cleaned up", "count", expiredCount)
	}

	return expiredCount, nil
}

// Delete removes an invitation by ID.
func (s *InvitationService) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return ErrInvalidInvitation{Reason: "invitation ID is required"}
	}

	s.logger.Debug("deleting invitation", "invitation_id", id)

	invitation, err := s.invitationDAO.Get(ctx, id)
	if err != nil {
		s.logger.Debug("invitation not found for deletion", "invitation_id", id)
		return ErrInvitationNotFound{ID: id}
	}

	if err := s.invitationDAO.Delete(ctx, invitation); err != nil {
		s.logger.Error(err, "failed to delete invitation")
		return ErrInvitationSaveFailed{Cause: err}
	}

	s.logger.Info("invitation deleted", "invitation_id", id)

	return nil
}

// emailExistsInTenant checks if an email is already registered in the tenant.
func (s *InvitationService) emailExistsInTenant(ctx context.Context, email, tenantID string) (bool, error) {
	pageQuery := datastore.NewPageQuery()
	pageQuery.PageSize = 100

	var found bool

	err := s.userDAO.ForEachPage(ctx, pageQuery, func(result datastore.PageResult[*entities.User]) error {
		for _, user := range result.Entities {
			if user.Email == email && user.TenantID == tenantID {
				found = true
				return datastore.ErrStopIteration
			}
		}
		return nil
	})

	if err != nil && err != datastore.ErrStopIteration {
		return false, err
	}

	return found, nil
}
