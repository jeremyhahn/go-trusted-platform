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

//go:build iam

package daemon

import (
	"context"
	"log/slog"
	"sync/atomic"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// IAMService provides Identity and Access Management functionality for platformd.
// It wraps the QuicBaaS SDK's IAM client, providing access to:
//   - Tenant management (multi-tenant architecture)
//   - User management (CRUD, roles, groups)
//   - Group management (user organization)
//   - Role management (permission bundles)
//   - Policy management (ABAC policies)
//   - PEP (Policy Enforcement Point for authorization checks)
//   - App management (OAuth2 applications)
//   - Session management
//   - Audit logging
//   - GDPR compliance operations
//   - Delegated administration
//   - MFA (Multi-Factor Authentication)
//   - Federation (external identity providers)
//
// The service uses the QuicBaaS SDK for all IAM operations, providing a unified
// interface that works with all supported transports (embedded, gRPC, REST, QUIC, Unix).
type IAMService struct {
	app       *app.App
	logger    *slog.Logger
	iamClient quicbaassdk.IAMClient
	running   atomic.Bool
}

// NewIAMService creates a new IAM service that wraps QuicBaaS's IAM functionality.
// Returns an error if the app doesn't have QuicBaaS configured or the SDK is not available.
func NewIAMService(application *app.App, logger *slog.Logger) (*IAMService, error) {
	if application == nil {
		return nil, ErrInvalidConfig{Reason: "application is required for IAM service"}
	}

	if logger == nil {
		return nil, ErrInvalidConfig{Reason: "logger is required for IAM service"}
	}

	// Check if QuicBaaS backend is available
	factory, ok := application.DAOFactory().(*quicbaas.Factory)
	if !ok {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS backend not available for IAM"}
	}

	// Get SDK client from factory
	sdkClient := factory.SDK()
	if sdkClient == nil {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS SDK client not available"}
	}

	// Get IAM client from SDK
	iamClient := sdkClient.Identity().IAM()
	if iamClient == nil {
		return nil, ErrInvalidConfig{Reason: "IAM client not available from QuicBaaS SDK"}
	}

	return &IAMService{
		app:       application,
		logger:    logger,
		iamClient: iamClient,
	}, nil
}

// Start starts the IAM service.
func (s *IAMService) Start(ctx context.Context) error {
	if s.running.Load() {
		return nil
	}
	s.running.Store(true)
	s.logger.Info("IAM service started")
	return nil
}

// Stop stops the IAM service.
func (s *IAMService) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return nil
	}
	s.running.Store(false)

	// Close the IAM client to release resources
	if s.iamClient != nil {
		if err := s.iamClient.Close(); err != nil {
			s.logger.Warn("failed to close IAM client", "error", err)
		}
	}

	s.logger.Info("IAM service stopped")
	return nil
}

// IsRunning returns whether the IAM service is running.
func (s *IAMService) IsRunning() bool {
	return s.running.Load()
}

// Name returns the service name.
func (s *IAMService) Name() string {
	return "iam"
}

// Client returns the underlying IAM SDK client.
// This provides direct access to all IAM sub-clients:
//   - Tenant(): Tenant management
//   - User(): User management
//   - Group(): Group management
//   - Role(): Role management
//   - Policy(): Policy management
//   - PEP(): Policy enforcement point
//   - App(): OAuth2 application management
//   - Session(): Session management
//   - Audit(): Audit logging
//   - GDPR(): GDPR compliance
//   - Admin(): Delegated administration
//
// Returns nil if the service has not been initialized.
func (s *IAMService) Client() quicbaassdk.IAMClient {
	return s.iamClient
}

// Tenant returns the tenant management client.
// Returns nil if the IAM client is not available.
func (s *IAMService) Tenant() quicbaassdk.IAMTenantClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.Tenant()
}

// User returns the user management client.
// Returns nil if the IAM client is not available.
func (s *IAMService) User() quicbaassdk.IAMUserClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.User()
}

// Group returns the group management client.
// Returns nil if the IAM client is not available.
func (s *IAMService) Group() quicbaassdk.IAMGroupClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.Group()
}

// Role returns the role management client.
// Returns nil if the IAM client is not available.
func (s *IAMService) Role() quicbaassdk.IAMRoleClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.Role()
}

// Policy returns the policy management client.
// Returns nil if the IAM client is not available.
func (s *IAMService) Policy() quicbaassdk.IAMPolicyClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.Policy()
}

// PEP returns the Policy Enforcement Point client for authorization checks.
// Returns nil if the IAM client is not available.
func (s *IAMService) PEP() quicbaassdk.IAMPEPClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.PEP()
}

// App returns the OAuth2 application management client.
// Returns nil if the IAM client is not available.
func (s *IAMService) App() quicbaassdk.IAMAppClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.App()
}

// Session returns the session management client.
// Returns nil if the IAM client is not available.
func (s *IAMService) Session() iam.SessionClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.Session()
}

// Audit returns the audit logging client.
// Returns nil if the IAM client is not available.
func (s *IAMService) Audit() quicbaassdk.IAMAuditClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.Audit()
}

// GDPR returns the GDPR compliance client.
// Returns nil if the IAM client is not available.
func (s *IAMService) GDPR() quicbaassdk.IAMGDPRClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.GDPR()
}

// Admin returns the delegated administration client.
// Returns nil if the IAM client is not available.
func (s *IAMService) Admin() quicbaassdk.IAMAdminClient {
	if s.iamClient == nil {
		return nil
	}
	return s.iamClient.Admin()
}

// CheckAccess performs an authorization check using the PEP client.
// This is a convenience method for common authorization checks.
//
// Parameters:
//   - ctx: Context for the request
//   - req: The authorization check request
//
// Returns:
//   - *iam.CheckResponse: The authorization result
//   - error: Any error that occurred during the check
func (s *IAMService) CheckAccess(ctx context.Context, req *iam.CheckRequest) (*iam.CheckResponse, error) {
	if s.iamClient == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	pep := s.iamClient.PEP()
	if pep == nil {
		return nil, ErrIAMServiceNotAvailable{}
	}

	return pep.Check(ctx, req)
}
