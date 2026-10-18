# WebAuthn Tenant Integration

This document describes the changes needed to integrate the WebAuthn registration flow with the TenantUserService for multi-tenant user registration.

## Overview

The current WebAuthn handler (`webauthn.go`) handles user registration and authentication using WebAuthn/FIDO2 credentials. To support multi-tenancy, the handler needs to be updated to:

1. Accept an optional invitation token during registration
2. Use TenantUserService to create users with proper tenant associations
3. Issue JWTs with tenant claims

## Required Changes

### 1. BeginRegistration Changes

The `BeginRegistration` method needs to accept an optional `invitation_token` in the request body and store it for use during `FinishRegistration`.

**Current Request Structure:**
```go
type Username struct {
    Username string `json:"username"`
}
```

**Updated Request Structure:**
```go
type BeginRegistrationRequest struct {
    Username        string `json:"username"`
    InvitationToken string `json:"invitation_token,omitempty"`
}
```

**Implementation Notes:**
- Parse the optional `invitation_token` from the request body
- Store the invitation token in the Registration entity for later retrieval
- Add `InvitationToken` field to `entities.Registration` (if not already present)
- Continue with existing WebAuthn registration flow

### 2. Registration Entity Changes

The `entities.Registration` struct needs to store the invitation token:

```go
type Registration struct {
    ID              uint64    `yaml:"id" json:"id"`
    Email           string    `yaml:"email" json:"email"`
    SessionData     []byte    `yaml:"session-data" json:"session_data"`
    InvitationToken string    `yaml:"invitation-token,omitempty" json:"invitation_token,omitempty"`
    CreatedAt       time.Time `yaml:"created-at" json:"created_at"`
    KeyValueEntity  `yaml:"-" json:"-"`
}
```

### 3. FinishRegistration Changes

The `FinishRegistration` method needs to:
1. Check if an invitation token was stored during BeginRegistration
2. Call the appropriate TenantUserService method based on whether an invitation exists
3. Use TenantUserService.IssueToken for JWT generation with tenant claims

**Updated Flow:**

```go
func (h *WebAuthnRestHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
    // ... existing WebAuthn credential verification ...

    // Get registration to check for invitation token
    registration, err := h.registrationService.Get(r.Context(), service.NewSession(), userID)
    if err != nil {
        h.responseWriter.Error404(w, r, err)
        return
    }

    // ... existing credential creation ...

    var user *entities.User
    var tenantID string

    if registration.InvitationToken != "" {
        // Invited user registration
        result, err := h.tenantUserService.RegisterInvitedUser(r.Context(), &service.RegisterInvitedUserRequest{
            InvitationToken: registration.InvitationToken,
            Email:           registration.Email,
            Credentials:     credentials,
        })
        if err != nil {
            h.responseWriter.Error400(w, r, err)
            return
        }
        user = result.User
        tenantID = result.TenantID
    } else {
        // New tenant owner registration
        result, err := h.tenantUserService.RegisterNewUser(r.Context(), &service.RegisterNewUserRequest{
            Email:       registration.Email,
            TenantName:  registration.Email, // Use email as initial tenant name
            Credentials: credentials,
        })
        if err != nil {
            h.responseWriter.Error500(w, r, err)
            return
        }
        user = result.User
        tenantID = result.TenantID
    }

    // Issue JWT with tenant claims
    tokenString, err := h.tenantUserService.IssueToken(r.Context(), &service.IssueTokenRequest{
        UserID:   user.ID,
        TenantID: tenantID,
    })
    if err != nil {
        h.responseWriter.Error500(w, r, err)
        return
    }

    // Clean up registration
    if err := h.registrationService.Delete(r.Context(), service.NewSession(), userID); err != nil {
        h.logger.Warn("failed to delete registration", slog.String("error", err.Error()))
    }

    h.responseWriter.Success200(w, r, tokenString)
}
```

### 4. ServiceParams Updates

Add TenantUserService to the handler's dependencies:

```go
type ServiceParams struct {
    Config              *Config
    Debug               bool
    Logger              *logging.Logger
    RegistrationService service.RegistrationServicer
    ResponseWriter      response.HttpWriter
    SessionService      service.WebAuthnSessionServicer
    UserService         service.UserServicer
    TenantUserService   service.TenantUserServicer  // required: sessions land in the user's workspace (#662)
}
```

### 5. TenantUserService Interface

The TenantUserService interface (to be implemented in the service layer) should support:

```go
type TenantUserServicer interface {
    // RegisterNewUser creates a new user and tenant (for first-time users without invitation)
    RegisterNewUser(ctx context.Context, req *RegisterNewUserRequest) (*RegisterUserResult, error)

    // RegisterInvitedUser creates a user for an existing tenant via invitation
    RegisterInvitedUser(ctx context.Context, req *RegisterInvitedUserRequest) (*RegisterUserResult, error)

    // IssueToken generates a JWT with tenant claims
    IssueToken(ctx context.Context, req *IssueTokenRequest) (string, error)
}

type RegisterNewUserRequest struct {
    Email       string
    TenantName  string
    Credentials []webauthn.Credential
}

type RegisterInvitedUserRequest struct {
    InvitationToken string
    Email           string
    Credentials     []webauthn.Credential
}

type RegisterUserResult struct {
    User     *entities.User
    TenantID string
    IsOwner  bool
    Role     string
}

type IssueTokenRequest struct {
    UserID   uint64
    TenantID string
}
```

### 6. JWT Claims Updates

The JWT should include tenant-related claims:

```go
type TenantClaims struct {
    jwt.RegisteredClaims
    TenantID      string   `json:"tenant_id"`
    UserID        uint64   `json:"user_id"`
    Email         string   `json:"email"`
    IsTenantOwner bool     `json:"is_tenant_owner"`
    Roles         []string `json:"roles,omitempty"`
}
```

## Error Handling

New error types to handle:

- `ErrInvitationNotFound` - Invitation token is invalid
- `ErrInvitationExpired` - Invitation has expired
- `ErrInvitationAlreadyUsed` - Invitation was already accepted
- `ErrEmailMismatch` - Registration email doesn't match invitation email
- `ErrTenantCreationFailed` - Failed to create tenant for new user

## Migration Path

1. Add `InvitationToken` field to Registration entity
2. Implement TenantUserService with the required methods
3. Update WebAuthn handler to use TenantUserService
4. Update JWT generation to include tenant claims
5. Update tests to cover both flows (new user and invited user)

## Security Considerations

- Invitation tokens should be single-use and expire after a reasonable time (e.g., 7 days)
- Email verification should match the invitation email
- Rate limiting should be applied to prevent invitation enumeration
- Invitation tokens should be cryptographically secure random values
- Failed registration attempts should not leak whether an invitation exists
