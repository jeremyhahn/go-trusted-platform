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

package jwt

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	// ErrUserGetterRequired is returned when a UserTokenIssuer is
	// constructed without a user lookup surface.
	ErrUserGetterRequired = errors.New("jwt/service: user getter is required")

	// ErrTokenServiceRequired is returned when a UserTokenIssuer is
	// constructed without the signing JWT service.
	ErrTokenServiceRequired = errors.New("jwt/service: token service is required")
)

// UserGetter is the narrow read surface UserTokenIssuer needs to load
// the full user record a token is issued for.
type UserGetter interface {
	Get(ctx context.Context, userID uint64) (*entities.User, error)
}

// UserTokenIssuer implements the platform service layer's TokenIssuer
// seam (IssueToken(ctx, userID, tenantID, roles)) on top of the
// webservice JWT Service. It re-loads the full user record so the
// issued token keeps every claim GenerateToken derives from the user —
// email, stored roles, tenant ownership — instead of collapsing to the
// three fields the seam carries.
type UserTokenIssuer struct {
	users   UserGetter
	service *Service
}

// NewUserTokenIssuer constructs a UserTokenIssuer, failing closed when
// either dependency is missing.
func NewUserTokenIssuer(users UserGetter, service *Service) (*UserTokenIssuer, error) {
	if users == nil {
		return nil, ErrUserGetterRequired
	}
	if service == nil {
		return nil, ErrTokenServiceRequired
	}
	return &UserTokenIssuer{users: users, service: service}, nil
}

// IssueToken loads the user and signs a platform JWT for it. A
// non-empty tenantID overrides the stored assignment, and a non-empty
// roles list overrides the stored roles — the tenant orchestration path
// issues the first token in the same request that created the tenant
// and resolved its roles (including the synthesized "tenant_owner"),
// before any re-read would observe them. Empty arguments fall back to
// the stored record, so a bare issuance still carries every claim
// GenerateToken derives.
func (issuer *UserTokenIssuer) IssueToken(
	ctx context.Context, userID uint64, tenantID string, roles []string) (string, error) {

	user, err := issuer.users.Get(ctx, userID)
	if err != nil {
		return "", err
	}
	stamped := *user
	if tenantID != "" {
		stamped.TenantID = tenantID
	}
	if len(roles) > 0 {
		resolved := make([]*entities.Role, 0, len(roles))
		for _, name := range roles {
			if name == "" {
				continue
			}
			resolved = append(resolved, &entities.Role{Name: name})
		}
		stamped.Roles = resolved
	}
	return issuer.service.GenerateToken(&stamped)
}
