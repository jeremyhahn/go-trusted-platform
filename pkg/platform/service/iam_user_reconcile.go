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
	"maps"
	"slices"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// reconcilePageSize is how many platform users the reconcile reads per page.
const reconcilePageSize = 100

// IAMUserDirectory lists the users already present in an IAM tenant.
type IAMUserDirectory interface {
	// MirroredEmails returns the lower-cased emails of every user in the
	// IAM tenant.
	MirroredEmails(ctx context.Context, tenantID string) (map[string]struct{}, error)
}

// IAMRoleProvisioner makes sure an IAM tenant carries its default roles.
type IAMRoleProvisioner interface {
	EnsureDefaultRoles(ctx context.Context, tenantID string) error
}

// IAMUserReconcilerConfig holds the dependencies of an IAMUserReconciler.
type IAMUserReconcilerConfig struct {
	Logger    *logging.Logger
	Users     datastore.Pager[*entities.User]
	Mirror    IAMUserMirror
	Directory IAMUserDirectory
	Roles     IAMRoleProvisioner
}

// IAMUserReconcileReport counts what one reconcile run did.
type IAMUserReconcileReport struct {
	// Scanned is the number of platform users read.
	Scanned int
	// Skipped is the number of platform users with no tenant.
	Skipped int
	// Present is the number of users already in their IAM tenant.
	Present int
	// Mirrored is the number of users this run added to their IAM tenant.
	Mirrored int
	// Failed is the number of users that could not be checked or mirrored.
	Failed int
}

// IAMUserReconciler mirrors platform users that are missing from their IAM
// tenant. It repairs users registered before the mirror was reliable (#641)
// and is safe to run on every start: users already present are left alone.
type IAMUserReconciler struct {
	logger    *logging.Logger
	users     datastore.Pager[*entities.User]
	mirror    IAMUserMirror
	directory IAMUserDirectory
	roles     IAMRoleProvisioner
}

// NewIAMUserReconciler returns a reconciler, or ErrIAMReconcilerConfig when a
// dependency is missing.
func NewIAMUserReconciler(config *IAMUserReconcilerConfig) (*IAMUserReconciler, error) {
	if config == nil {
		return nil, ErrIAMReconcilerConfig{Field: "config"}
	}
	required := []struct {
		field   string
		missing bool
	}{
		{"Logger", config.Logger == nil},
		{"Users", config.Users == nil},
		{"Mirror", config.Mirror == nil},
		{"Directory", config.Directory == nil},
		{"Roles", config.Roles == nil},
	}
	for _, dep := range required {
		if dep.missing {
			return nil, ErrIAMReconcilerConfig{Field: dep.field}
		}
	}
	return &IAMUserReconciler{
		logger:    config.Logger,
		users:     config.Users,
		mirror:    config.Mirror,
		directory: config.Directory,
		roles:     config.Roles,
	}, nil
}

// Reconcile mirrors every platform user missing from its IAM tenant. A failure
// for one user or one tenant is logged with the user ID and counted, never
// fatal. Only a failure to read the platform user store returns an error,
// ErrIAMReconcileFailed.
func (r *IAMUserReconciler) Reconcile(ctx context.Context) (*IAMUserReconcileReport, error) {
	report := &IAMUserReconcileReport{}
	byTenant, err := r.usersByTenant(ctx, report)
	if err != nil {
		return report, ErrIAMReconcileFailed{Cause: err}
	}
	for _, tenantID := range slices.Sorted(maps.Keys(byTenant)) {
		r.reconcileTenant(ctx, tenantID, byTenant[tenantID], report)
	}
	return report, nil
}

// usersByTenant reads every platform user and groups them by tenant.
func (r *IAMUserReconciler) usersByTenant(ctx context.Context, report *IAMUserReconcileReport) (map[string][]*entities.User, error) {
	byTenant := make(map[string][]*entities.User)
	query := datastore.NewPageQuery()
	query.PageSize = reconcilePageSize
	err := r.users.ForEachPage(ctx, query, func(page datastore.PageResult[*entities.User]) error {
		for _, user := range page.Entities {
			report.Scanned++
			if user.TenantID == "" {
				report.Skipped++
				continue
			}
			byTenant[user.TenantID] = append(byTenant[user.TenantID], user)
		}
		return nil
	})
	return byTenant, err
}

// reconcileTenant mirrors the users of one tenant that its IAM tenant lacks.
func (r *IAMUserReconciler) reconcileTenant(ctx context.Context, tenantID string, users []*entities.User, report *IAMUserReconcileReport) {
	present, err := r.directory.MirroredEmails(ctx, tenantID)
	if err != nil {
		for _, user := range users {
			r.logger.Warn("IAM reconcile could not list the user's IAM tenant",
				"user_id", user.ID, "tenant_id", tenantID, "error", err)
			report.Failed++
		}
		return
	}

	var missing []*entities.User
	for _, user := range users {
		if _, ok := present[strings.ToLower(user.Email)]; ok {
			report.Present++
			continue
		}
		missing = append(missing, user)
	}
	if len(missing) == 0 {
		return
	}

	// Tenants created before #641 lack the roles the mirror assigns. A
	// failure here is logged and the mirror attempted anyway: it reports
	// per user whether the role was really missing.
	if err := r.roles.EnsureDefaultRoles(ctx, tenantID); err != nil {
		r.logger.Warn("IAM reconcile could not provision default roles",
			"tenant_id", tenantID, "error", err)
	}

	for _, user := range missing {
		if err := r.mirror.MirrorUser(ctx, tenantID, user.Email, user.DisplayName, iamMirrorRoles(user)); err != nil {
			r.logger.Warn("IAM reconcile failed to mirror user",
				"user_id", user.ID, "tenant_id", tenantID, "error", err)
			report.Failed++
			continue
		}
		report.Mirrored++
	}
}
