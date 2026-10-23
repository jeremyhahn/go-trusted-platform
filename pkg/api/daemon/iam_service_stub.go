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

//go:build !iam

package daemon

import (
	"context"
	"log/slog"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

// IAMService is a stub when IAM support is not enabled.
// Build with -tags iam to enable IAM functionality.
type IAMService struct{}

// NewIAMService returns an error when IAM support is not enabled.
func NewIAMService(application *app.App, logger *slog.Logger) (*IAMService, error) {
	return nil, ErrInvalidConfig{Reason: "IAM service not enabled (build with -tags iam)"}
}

// Start is a no-op when IAM support is not enabled.
func (s *IAMService) Start(ctx context.Context) error {
	return nil
}

// Stop is a no-op when IAM support is not enabled.
func (s *IAMService) Stop(ctx context.Context) error {
	return nil
}

// IsRunning returns false when IAM support is not enabled.
func (s *IAMService) IsRunning() bool {
	return false
}

// Name returns the service name.
func (s *IAMService) Name() string {
	return "iam"
}

// Client returns nil when IAM support is not enabled.
func (s *IAMService) Client() quicbaassdk.IAMClient {
	return nil
}

// Tenant returns nil when IAM support is not enabled.
func (s *IAMService) Tenant() quicbaassdk.IAMTenantClient {
	return nil
}

// User returns nil when IAM support is not enabled.
func (s *IAMService) User() quicbaassdk.IAMUserClient {
	return nil
}

// Group returns nil when IAM support is not enabled.
func (s *IAMService) Group() quicbaassdk.IAMGroupClient {
	return nil
}

// Role returns nil when IAM support is not enabled.
func (s *IAMService) Role() quicbaassdk.IAMRoleClient {
	return nil
}

// Policy returns nil when IAM support is not enabled.
func (s *IAMService) Policy() quicbaassdk.IAMPolicyClient {
	return nil
}

// PEP returns nil when IAM support is not enabled.
func (s *IAMService) PEP() quicbaassdk.IAMPEPClient {
	return nil
}

// App returns nil when IAM support is not enabled.
func (s *IAMService) App() quicbaassdk.IAMAppClient {
	return nil
}

// Session returns nil when IAM support is not enabled.
func (s *IAMService) Session() iam.SessionClient {
	return nil
}

// Audit returns nil when IAM support is not enabled.
func (s *IAMService) Audit() quicbaassdk.IAMAuditClient {
	return nil
}

// GDPR returns nil when IAM support is not enabled.
func (s *IAMService) GDPR() quicbaassdk.IAMGDPRClient {
	return nil
}

// Admin returns nil when IAM support is not enabled.
func (s *IAMService) Admin() quicbaassdk.IAMAdminClient {
	return nil
}

// CheckAccess returns an error when IAM support is not enabled.
func (s *IAMService) CheckAccess(ctx context.Context, req *iam.CheckRequest) (*iam.CheckResponse, error) {
	return nil, ErrIAMServiceNotAvailable{}
}
