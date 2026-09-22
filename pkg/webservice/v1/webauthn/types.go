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

package webauthn

import (
	"net/http"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/login"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// BeginRegistrationRequest is the request body for /webauthn/registration/begin.
type BeginRegistrationRequest struct {
	// Email is the account's canonical tenant-unique login key. It was
	// previously spelled "username" on the wire, but the value was always
	// an email: BeginRegistration stored it as the pending registration's
	// Email and FinishRegistration writes it to entities.User.Email. The
	// backbone now resolves the account with GetByEmail and documents that
	// a username is a different identifier and is not accepted
	// (go-xkms BeginRegistrationRequest.Email), so the wire name is
	// corrected to match the value it always carried.
	Email           string `json:"email"`
	InvitationToken string `json:"invitation_token,omitempty" secret:"true"`
}

// FinishRegistrationResponse is the response body for /webauthn/registration/finish.
type FinishRegistrationResponse struct {
	Token    string `json:"token" secret:"true"`
	TenantID string `json:"tenant_id"`
}

// LoginRequest is the request body for /webauthn/login/begin.
type LoginRequest struct {
	Email string `json:"username"`
}

// RestHandler is the HTTP-bound surface registered by the WebAuthn router.
type RestHandler interface {
	BeginRegistration(w http.ResponseWriter, r *http.Request)
	FinishRegistration(w http.ResponseWriter, r *http.Request)
	BeginLogin(w http.ResponseWriter, r *http.Request)
	FinishLogin(w http.ResponseWriter, r *http.Request)
	RegistrationStatus(w http.ResponseWriter, r *http.Request)
	middleware.AuthMiddleware
}

// Config captures the relying-party parameters propagated to quicbaas.
// The actual ceremony state lives in quicbaas; the platform only keeps
// these values so the router can decide whether WebAuthn is enabled.
type Config struct {
	RPDisplayName string   `yaml:"display-name" json:"display_name" mapstructure:"display-name"`
	RPID          string   `yaml:"id" json:"id" mapstructure:"id"`
	RPOrigins     []string `yaml:"origins" json:"origins" mapstructure:"origins"`
}

// IsConfigured reports whether the supplied Config contains the minimum
// fields required to register the WebAuthn routes.
func IsConfigured(config *Config) bool {
	if config == nil {
		return false
	}
	return config.RPID != "" && len(config.RPOrigins) > 0
}

// ServiceParams collects the dependencies the SDK-backed handler needs.
type ServiceParams struct {
	Config              *Config
	Debug               bool
	JWTService          *jwt.Service
	Logger              *logging.Logger
	RegistrationService service.RegistrationServicer
	ResponseWriter      response.HttpWriter
	SessionService      service.WebAuthnSessionServicer
	// PublicRegistrationEnabled mirrors the canonical stack flag
	// iam.self_service_registration.enabled. When false (the invite-only
	// default), BeginRegistration without an invitation token is refused
	// with ErrPublicRegistrationDisabled.
	PublicRegistrationEnabled bool
	UserService               service.UserServicer
	TenantUserService         service.TenantUserServicer
	InvitationService         service.InvitationServicer
	// FIDO2Client is the SDK relying-party client the handler
	// delegates to for every ceremony operation. It is the single
	// canonical WebAuthn/FIDO2 ceremony surface. Required.
	FIDO2Client quicbaassdk.FIDO2Client
	// LoginDriver runs the unified login ceremony. The login verbs
	// delegate to it wholesale: there is one ceremony in the platform and
	// it lives in pkg/webservice/v1/login, never a second copy here.
	// Required.
	LoginDriver *login.Driver
	// TenantID is the tenant every ceremony operation is scoped to —
	// the platform's operating tenant (the firstboot system tenant
	// adopted by pkg/app). The SDK FIDO2 service is tenant-scoped and
	// the xkms wire structs carry no tenant field, so the handler
	// stamps this value onto the request context
	// (transport.ContextWithTenant) for every SDK call. Required.
	TenantID string
}

// WebAuthnRestHandler binds the REST endpoints to the SDK relying party.
type WebAuthnRestHandler struct {
	logger              *logging.Logger
	jwtService          *jwt.Service
	userService         service.UserServicer
	registrationService service.RegistrationServicer
	tenantUserService   service.TenantUserServicer
	invitationService   service.InvitationServicer
	responseWriter      response.HttpWriter
	fido2Client         quicbaassdk.FIDO2Client
	loginDriver         *login.Driver
	tenantID            string
	config              *Config
	publicRegistration  bool
	RestHandler
}
