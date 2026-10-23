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

	// Workspace returns the ID of the workspace the user with the given
	// email owns or joined. A browser login's session lands there.
	Workspace(ctx context.Context, email string) (string, error)

	// IsTenantOwner checks if user owns the tenant.
	IsTenantOwner(ctx context.Context, userID uint64) (bool, error)

	// TransferOwnership transfers tenant ownership to another user.
	TransferOwnership(ctx context.Context, currentOwnerID, newOwnerID uint64) error

	// IssueToken generates a JWT token for the user with tenant claims.
	IssueToken(ctx context.Context, user *entities.User) (string, error)

	// SetIAMMirror installs the QuicBaaS IAM mirror used by
	// RegisterNewUser to surface newly-registered users into
	// /api/v1/iam/users. Implementations that don't support mirroring
	// (test doubles) may no-op; the interface bump is the only way
	// to wire the mirror without leaking the concrete type through
	// the service registry.
	SetIAMMirror(m IAMUserMirror)
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

// IAMUserMirror is the narrow surface TenantUserService uses to
// mirror a newly-registered user into the QuicBaaS IAM tenant. The
// platform's authoritative user record lives in the platform store
// (WebAuthn credentials + tenant ownership flag); the IAM tenant
// surfaces the same identity for /iam/users, role assignment, group
// membership, and the WebUI's permission gates.
//
// Implementations are expected to be idempotent — registering the
// same email twice should not produce duplicate IAM rows. Failures
// here are non-fatal for registration: the platform user is already
// saved, the JWT is already minted; the worst case is that the user
// must be re-mirrored later by an explicit /iam/users PUT.
type IAMUserMirror interface {
	MirrorUser(ctx context.Context, tenantID, email, displayName string, roles []string) error
}

// TenantUserService implements TenantUserServicer.
type TenantUserService struct {
	logger            *logging.Logger
	userService       UserServicer
	invitationService InvitationServicer
	tenantManager     TenantManager
	tokenIssuer       TokenIssuer
	iamMirror         IAMUserMirror
}

// TenantUserServiceConfig holds configuration for TenantUserService.
type TenantUserServiceConfig struct {
	Logger            *logging.Logger
	UserService       UserServicer
	InvitationService InvitationServicer
	TenantManager     TenantManager
	TokenIssuer       TokenIssuer
	// IAMMirror, when non-nil, is called after a successful platform-
	// store save to mirror the user into the QuicBaaS IAM tenant. This
	// is what makes /api/v1/iam/users surface freshly-registered users.
	IAMMirror IAMUserMirror
}

// NewTenantUserService creates a new TenantUserService.
func NewTenantUserService(config *TenantUserServiceConfig) TenantUserServicer {
	return &TenantUserService{
		logger:            config.Logger,
		userService:       config.UserService,
		invitationService: config.InvitationService,
		tenantManager:     config.TenantManager,
		tokenIssuer:       config.TokenIssuer,
		iamMirror:         config.IAMMirror,
	}
}

// SetIAMMirror installs the IAM mirror after construction. The
// service registry wires this when the IAM client becomes available
// — registration ordering means the QuicBaaS IAM client may be set
// up after the TenantUserService.
func (s *TenantUserService) SetIAMMirror(m IAMUserMirror) {
	s.iamMirror = m
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

	// Configure user as tenant owner. First user in a tenant gets
	// the "admin" role automatically — this is how the WebUI knows
	// they have permission to manage other users without making them
	// re-elevate themselves. The role is granted alongside
	// IsTenantOwner so a JWT carrying either signal can authorize
	// admin operations.
	now := time.Now().UTC()
	user.TenantID = tenantID
	user.IsTenantOwner = true
	user.CreatedAt = now
	user.UpdatedAt = now
	user.AddRole(entities.NewRole(DefaultTenantOwnerRole))

	// Save the user
	if err := s.userService.Save(ctx, user); err != nil {
		s.logger.Error(err, "failed to save user, rolling back tenant creation",
			"tenant_id", tenantID,
		)
		s.rollbackTenant(ctx, tenantID)
		return nil, ErrUserSaveFailed{Cause: err}
	}

	// Mirror the owner into the QuicBaaS IAM tenant so /api/v1/iam/users
	// surfaces them and the per-user role / group / policy paths have an
	// entity to operate on. The owner's mirror is part of registration, not
	// best-effort: an owner the IAM surface cannot see is rolled back the
	// same way the tenant is (#641).
	if s.iamMirror != nil {
		if err := s.iamMirror.MirrorUser(ctx, tenantID, user.Email, user.DisplayName, iamMirrorRoles(user)); err != nil {
			s.logger.Error(err, "failed to mirror new owner into IAM tenant, rolling back registration",
				"user_id", user.ID,
				"email", user.Email,
				"tenant_id", tenantID,
			)
			if delErr := s.userService.Delete(ctx, user.ID); delErr != nil {
				s.logger.Error(delErr, "failed to delete user after IAM mirror failure",
					"user_id", user.ID,
				)
			}
			s.rollbackTenant(ctx, tenantID)
			return nil, ErrIAMMirrorFailed{Email: user.Email, TenantID: tenantID, Cause: err}
		}
	}

	s.logger.Info("new user registered with tenant",
		"user_id", user.ID,
		"email", user.Email,
		"tenant_id", tenantID,
		"is_owner", true,
		"role", DefaultTenantOwnerRole,
	)

	return &RegisterResult{
		User:        user,
		Tenant:      tenantEntity,
		IsNewTenant: true,
	}, nil
}

// rollbackTenant deletes a tenant created by a registration that then failed.
// A cleanup failure is logged, not returned: the caller is already returning
// the error that caused the rollback.
func (s *TenantUserService) rollbackTenant(ctx context.Context, tenantID string) {
	if err := s.tenantManager.DeleteTenant(ctx, tenantID); err != nil {
		s.logger.Error(err, "failed to clean up tenant after failed registration",
			"tenant_id", tenantID,
		)
	}
}

// iamMirrorRoles is the IAM role set a platform user is mirrored with: the
// tenant owner gets DefaultTenantOwnerRole, every other user none.
func iamMirrorRoles(user *entities.User) []string {
	if user.IsTenantOwner {
		return []string{DefaultTenantOwnerRole}
	}
	return nil
}

// DefaultTenantOwnerRole is the role granted automatically to the
// first user in a freshly-created tenant. "admin" matches the role
// name the IAM authorization middleware checks for full-tenant
// admin operations.
const DefaultTenantOwnerRole = "admin"

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

	// One reading of the clock decides expiry and stamps the user, so the
	// two can never disagree about when the redemption happened.
	now := time.Now().UTC()

	// Verify invitation is not expired
	if invitation.IsExpired(now) {
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

	// Configure user with invitation details.
	//
	// Ownership comes from the INVITATION, never from the redeemer (#158).
	// The system admin decides at creation time whether a link provisions a
	// tenant's first administrator; this was previously hardcoded false, so
	// the owner-enrollment half of the ruling could not be expressed at all.
	// Reading it from the invitation rather than from the request body is
	// what keeps a redeemer from asking to be the owner — the same reasoning
	// that made #171 read the tenant from the verified session rather than
	// from a caller-supplied field.
	user.TenantID = invitation.TenantID
	user.IsTenantOwner = invitation.InitialAdmin
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

// Workspace returns the ID of the user's workspace: the tenant
// RegisterNewUser created for them or RegisterInvitedUser joined them to.
// A browser login lands its session there (#662).
//
// The user is found by email because that is what the backbone names an
// authenticated principal by. The workspace must still exist in the
// tenant manager (the go-quicbaas IAM tenant service on the daemon), so a
// deleted workspace is refused rather than handed to a session.
func (s *TenantUserService) Workspace(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", ErrInvalidEmail{Email: email}
	}
	user, err := s.userService.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return "", ErrUserNotFound{Email: email}
	}
	if user.TenantID == "" {
		return "", ErrUserNotInTenant{UserID: user.ID}
	}
	workspace, err := s.tenantManager.GetTenant(ctx, user.TenantID)
	if err != nil || workspace == nil {
		return "", ErrTenantNotFound{ID: user.TenantID}
	}
	return workspace.ID, nil
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
