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
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// TenantManager defines the minimal interface for tenant operations.
// This interface is satisfied by the tenant.Manager struct.
type TenantManager interface {
	// CreateTenant creates a new tenant.
	CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error)
	// GetTenant retrieves a tenant by ID.
	GetTenant(ctx context.Context, id string) (*tenant.TenantEntity, error)
	// DeleteTenant deletes a tenant by ID.
	DeleteTenant(ctx context.Context, id string) error
}

// TenantUserServicer defines the interface for orchestrating user registration
// with tenant management.
type TenantUserServicer interface {
	// RegisterNewUser creates a new tenant and sets user as owner.
	RegisterNewUser(ctx context.Context, user *entities.User) (*RegisterResult, error)

	// RegisterInvitedUser validates invitation and joins user to existing tenant.
	RegisterInvitedUser(ctx context.Context, user *entities.User, invitationToken string) (*RegisterResult, error)

	// GetUserTenant returns the tenant for a user.
	GetUserTenant(ctx context.Context, userID uint64) (*tenant.TenantEntity, error)

	// IsTenantOwner checks if user owns the tenant.
	IsTenantOwner(ctx context.Context, userID uint64) (bool, error)

	// TransferOwnership transfers tenant ownership to another user.
	TransferOwnership(ctx context.Context, currentOwnerID, newOwnerID uint64) error

	// IssueToken generates a JWT token for the user with tenant claims.
	IssueToken(ctx context.Context, user *entities.User) (string, error)
}

// RegisterResult contains the result of a user registration operation.
type RegisterResult struct {
	// User is the registered user entity.
	User *entities.User
	// Tenant is the tenant the user belongs to.
	Tenant *tenant.TenantEntity
	// IsNewTenant indicates whether a new tenant was created.
	IsNewTenant bool
	// Token is an optional JWT token with tenant_id claim.
	// May be empty if token issuance is handled elsewhere.
	Token string
}

// TokenIssuer defines the interface for JWT token generation.
// This abstracts the JWT service to allow for different implementations.
type TokenIssuer interface {
	// IssueToken creates a JWT with user and tenant claims.
	IssueToken(ctx context.Context, userID uint64, tenantID string, roles []string) (string, error)
}

// TenantUserService implements TenantUserServicer.
type TenantUserService struct {
	logger            *logging.Logger
	userService       UserServicer
	invitationService InvitationServicer
	tenantManager     TenantManager
	tokenIssuer       TokenIssuer
}

// TenantUserServiceConfig holds configuration for TenantUserService.
type TenantUserServiceConfig struct {
	Logger            *logging.Logger
	UserService       UserServicer
	InvitationService InvitationServicer
	TenantManager     TenantManager
	TokenIssuer       TokenIssuer
}

// NewTenantUserService creates a new TenantUserService.
func NewTenantUserService(config *TenantUserServiceConfig) TenantUserServicer {
	return &TenantUserService{
		logger:            config.Logger,
		userService:       config.UserService,
		invitationService: config.InvitationService,
		tenantManager:     config.TenantManager,
		tokenIssuer:       config.TokenIssuer,
	}
}

// RegisterNewUser creates a new tenant and registers the user as the owner.
// Steps:
// 1. Generate a tenant UUID
// 2. Create the tenant via TenantManager
// 3. Set user.TenantID and user.IsTenantOwner = true
// 4. Save the user
// 5. Return the RegisterResult with IsNewTenant = true
// Implements rollback if user save fails after tenant creation.
func (s *TenantUserService) RegisterNewUser(
	ctx context.Context,
	user *entities.User,
) (*RegisterResult, error) {
	if user == nil {
		return nil, ErrInvalidUserInput{Reason: "user is required"}
	}

	s.logger.Info("registering new user with tenant creation",
		"email", user.Email,
	)

	// Check if user already exists
	existingUser, err := s.userService.GetByEmail(ctx, user.Email)
	if err == nil && existingUser != nil {
		return nil, ErrUserAlreadyExists{Email: user.Email}
	}

	// Generate tenant UUID
	tenantID := uuid.New().String()

	// Create tenant via TenantManager
	tenantRequest := &tenant.CreateTenantRequest{
		Name:        tenantID,
		DisplayName: user.DisplayName,
		Labels: map[string]string{
			"owner_email": user.Email,
		},
	}

	tenantEntity, err := s.tenantManager.CreateTenant(ctx, tenantRequest)
	if err != nil {
		s.logger.Error(err, "failed to create tenant")
		return nil, ErrTenantCreationFailed{Cause: err}
	}

	// Use the tenant ID returned by the manager (it may be different from our generated one)
	tenantID = tenantEntity.ID

	// Configure user as tenant owner
	now := time.Now().UTC()
	user.TenantID = tenantID
	user.IsTenantOwner = true
	user.CreatedAt = now
	user.UpdatedAt = now

	// Save the user
	if err := s.userService.Save(ctx, user); err != nil {
		s.logger.Error(err, "failed to save user, rolling back tenant creation",
			"tenant_id", tenantID,
		)
		// Rollback: attempt to clean up the tenant
		if cleanupErr := s.tenantManager.DeleteTenant(ctx, tenantID); cleanupErr != nil {
			s.logger.Error(cleanupErr, "failed to cleanup tenant after user save failure",
				"tenant_id", tenantID,
			)
		}
		return nil, ErrUserSaveFailed{Cause: err}
	}

	s.logger.Info("new user registered with tenant",
		"user_id", user.ID,
		"email", user.Email,
		"tenant_id", tenantID,
		"is_owner", true,
	)

	return &RegisterResult{
		User:        user,
		Tenant:      tenantEntity,
		IsNewTenant: true,
	}, nil
}

// RegisterInvitedUser registers a user from an invitation, joining an existing tenant.
// Steps:
// 1. Get invitation by token
// 2. Verify invitation is pending and not expired
// 3. Get tenant via tenantManager
// 4. Set user.TenantID = invitation.TenantID
// 5. Set user.IsTenantOwner = false
// 6. Add role from invitation to user
// 7. Save the user
// 8. Accept the invitation
// 9. Return the RegisterResult with IsNewTenant = false
func (s *TenantUserService) RegisterInvitedUser(
	ctx context.Context,
	user *entities.User,
	invitationToken string,
) (*RegisterResult, error) {
	if user == nil {
		return nil, ErrInvalidUserInput{Reason: "user is required"}
	}

	if invitationToken == "" {
		return nil, ErrInvitationRequired{}
	}

	s.logger.Info("registering invited user",
		"email", user.Email,
	)

	// Check if user already exists
	existingUser, err := s.userService.GetByEmail(ctx, user.Email)
	if err == nil && existingUser != nil {
		return nil, ErrUserAlreadyExists{Email: user.Email}
	}

	// Get invitation by token
	invitation, err := s.invitationService.GetByToken(ctx, invitationToken)
	if err != nil {
		s.logger.Debug("invitation not found", "token", invitationToken)
		return nil, ErrInvitationNotFound{Token: invitationToken}
	}

	// Verify email matches invitation
	if invitation.Email != user.Email {
		s.logger.Warn("invitation email mismatch",
			"invitation_email", invitation.Email,
			"user_email", user.Email,
		)
		return nil, ErrInvalidInvitation{Reason: "email does not match invitation"}
	}

	// Verify invitation is pending
	if invitation.Status != entities.InvitationStatusPending {
		switch invitation.Status {
		case entities.InvitationStatusAccepted:
			return nil, ErrInvitationAlreadyAccepted{Token: invitationToken}
		case entities.InvitationStatusRevoked:
			return nil, ErrInvitationRevoked{Token: invitationToken}
		case entities.InvitationStatusExpired:
			return nil, ErrInvitationExpired{Token: invitationToken}
		default:
			return nil, ErrInvalidInvitation{Reason: "unexpected invitation status"}
		}
	}

	// Verify invitation is not expired
	if invitation.IsExpired() {
		return nil, ErrInvitationExpired{Token: invitationToken}
	}

	// Get tenant via tenantManager
	tenantEntity, err := s.tenantManager.GetTenant(ctx, invitation.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to get tenant for invitation",
			"tenant_id", invitation.TenantID,
		)
		return nil, ErrTenantNotFound{ID: invitation.TenantID}
	}

	// Configure user with invitation details
	now := time.Now().UTC()
	user.TenantID = invitation.TenantID
	user.IsTenantOwner = false
	user.CreatedAt = now
	user.UpdatedAt = now

	// Add role from invitation to user
	if invitation.Role != "" {
		role := entities.NewRole(invitation.Role)
		if !user.HasRole(invitation.Role) {
			user.AddRole(role)
		}
	}

	// Save the user
	if err := s.userService.Save(ctx, user); err != nil {
		s.logger.Error(err, "failed to save invited user",
			"email", user.Email,
			"tenant_id", invitation.TenantID,
		)
		return nil, ErrUserSaveFailed{Cause: err}
	}

	// Accept the invitation (pass user ID for audit tracking)
	if err := s.invitationService.Accept(ctx, invitationToken, user.ID); err != nil {
		s.logger.Error(err, "failed to accept invitation after user save",
			"email", user.Email,
			"tenant_id", invitation.TenantID,
		)
		// User was saved but invitation acceptance failed.
		// This is a non-critical error - continue with result.
	}

	s.logger.Info("invited user registered",
		"user_id", user.ID,
		"email", user.Email,
		"tenant_id", invitation.TenantID,
		"role", invitation.Role,
		"is_owner", false,
	)

	return &RegisterResult{
		User:        user,
		Tenant:      tenantEntity,
		IsNewTenant: false,
	}, nil
}

// GetUserTenant returns the tenant for a user.
func (s *TenantUserService) GetUserTenant(ctx context.Context, userID uint64) (*tenant.TenantEntity, error) {
	s.logger.Debug("getting tenant for user",
		"user_id", userID,
	)

	// Get user
	user, err := s.userService.Get(ctx, userID)
	if err != nil {
		s.logger.Debug("user not found",
			"user_id", userID,
		)
		return nil, ErrUserNotFound{ID: userID}
	}

	if user.TenantID == "" {
		return nil, ErrUserNotInTenant{UserID: userID}
	}

	// Get tenant by user.TenantID
	tenantEntity, err := s.tenantManager.GetTenant(ctx, user.TenantID)
	if err != nil {
		s.logger.Error(err, "failed to get tenant for user",
			"user_id", userID,
			"tenant_id", user.TenantID,
		)
		return nil, ErrTenantNotFound{ID: user.TenantID}
	}

	return tenantEntity, nil
}

// IsTenantOwner checks if a user owns the tenant.
func (s *TenantUserService) IsTenantOwner(ctx context.Context, userID uint64) (bool, error) {
	s.logger.Debug("checking if user is tenant owner",
		"user_id", userID,
	)

	// Get user
	user, err := s.userService.Get(ctx, userID)
	if err != nil {
		s.logger.Debug("user not found",
			"user_id", userID,
		)
		return false, ErrUserNotFound{ID: userID}
	}

	return user.IsTenantOwner, nil
}

// TransferOwnership transfers tenant ownership from the current owner to a new owner.
// Both users must be in the same tenant, and the current owner must actually own the tenant.
// Implements rollback if new owner save fails after current owner update.
func (s *TenantUserService) TransferOwnership(ctx context.Context, currentOwnerID, newOwnerID uint64) error {
	s.logger.Debug("transferring tenant ownership",
		"current_owner_id", currentOwnerID,
		"new_owner_id", newOwnerID,
	)

	// Validate IDs are different
	if currentOwnerID == newOwnerID {
		return ErrInvalidUserInput{Reason: "current owner and new owner cannot be the same user"}
	}

	// Get current owner
	currentOwner, err := s.userService.Get(ctx, currentOwnerID)
	if err != nil {
		s.logger.Debug("current owner not found",
			"user_id", currentOwnerID,
		)
		return ErrUserNotFound{ID: currentOwnerID}
	}

	// Verify current owner actually owns the tenant
	if !currentOwner.IsTenantOwner {
		return ErrNotTenantOwner{UserID: currentOwnerID}
	}

	// Get new owner
	newOwner, err := s.userService.Get(ctx, newOwnerID)
	if err != nil {
		s.logger.Debug("new owner not found",
			"user_id", newOwnerID,
		)
		return ErrUserNotFound{ID: newOwnerID}
	}

	// Verify new owner is in the same tenant
	if newOwner.TenantID != currentOwner.TenantID {
		return ErrUserNotInTenant{
			UserID:   newOwnerID,
			TenantID: currentOwner.TenantID,
		}
	}

	// Update both users' IsTenantOwner flag
	currentOwner.IsTenantOwner = false
	currentOwner.UpdatedAt = time.Now().UTC()

	newOwner.IsTenantOwner = true
	newOwner.UpdatedAt = time.Now().UTC()

	// Save current owner first
	if err := s.userService.Save(ctx, currentOwner); err != nil {
		s.logger.Error(err, "failed to update current owner",
			"user_id", currentOwnerID,
		)
		return ErrUserSaveFailed{Cause: err}
	}

	// Save new owner
	if err := s.userService.Save(ctx, newOwner); err != nil {
		s.logger.Error(err, "failed to update new owner, rolling back current owner",
			"user_id", newOwnerID,
		)

		// Rollback: restore current owner's ownership
		currentOwner.IsTenantOwner = true
		currentOwner.UpdatedAt = time.Now().UTC()
		if rollbackErr := s.userService.Save(ctx, currentOwner); rollbackErr != nil {
			s.logger.Error(rollbackErr, "failed to rollback current owner ownership",
				"user_id", currentOwnerID,
			)
		}

		return ErrUserSaveFailed{Cause: err}
	}

	s.logger.Info("tenant ownership transferred",
		"tenant_id", currentOwner.TenantID,
		"previous_owner_id", currentOwnerID,
		"new_owner_id", newOwnerID,
	)

	return nil
}

// IssueToken generates a JWT token for the user with tenant claims.
// This delegates to the configured TokenIssuer implementation.
func (s *TenantUserService) IssueToken(
	ctx context.Context,
	user *entities.User,
) (string, error) {
	if s.tokenIssuer == nil {
		s.logger.Warn("token issuer not configured, returning empty token")
		return "", nil
	}

	// Extract role names
	roles := make([]string, 0, len(user.Roles))
	for _, role := range user.Roles {
		roles = append(roles, role.Name)
	}

	// Add tenant owner role if applicable
	if user.IsTenantOwner {
		roles = append(roles, "tenant_owner")
	}

	token, err := s.tokenIssuer.IssueToken(ctx, user.ID, user.TenantID, roles)
	if err != nil {
		s.logger.Error(err, "failed to issue token")
		return "", ErrTokenIssueFailed{Cause: err}
	}

	return token, nil
}

// ErrTenantNotFound is returned when a tenant cannot be found.
type ErrTenantNotFound struct {
	ID   string
	Name string
}

func (e ErrTenantNotFound) Error() string {
	if e.Name != "" {
		return fmt.Sprintf("tenant not found: name=%s", e.Name)
	}
	if e.ID != "" {
		return fmt.Sprintf("tenant not found: id=%s", e.ID)
	}
	return "tenant not found"
}

// ErrUserNotInTenant is returned when a user is not a member of a tenant.
type ErrUserNotInTenant struct {
	UserID   uint64
	TenantID string
}

func (e ErrUserNotInTenant) Error() string {
	if e.TenantID != "" {
		return fmt.Sprintf("user not in tenant: user_id=%d, tenant_id=%s", e.UserID, e.TenantID)
	}
	return fmt.Sprintf("user not in tenant: user_id=%d", e.UserID)
}

// ErrInvitationRequired is returned when an invitation token is required but not provided.
type ErrInvitationRequired struct{}

func (e ErrInvitationRequired) Error() string {
	return "invitation token is required"
}

// ErrInvalidUserInput is returned when user input is invalid.
type ErrInvalidUserInput struct {
	Reason string
}

func (e ErrInvalidUserInput) Error() string {
	return fmt.Sprintf("invalid user input: %s", e.Reason)
}
