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

package tenant

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// restartedManager builds a second manager on the same IAM client, as a
// restarted daemon does: an empty cache over the records IAM persisted.
func restartedManager(t *testing.T, iamClient *mockIAMClient) *Manager {
	t.Helper()

	cfg := &ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config:          DefaultConfig(),
		Logger:          newTestLogger(),
	}
	cfg.Config.EnableDEKIsolation = false

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	return manager
}

// assertDeclaredGap fails t unless err is ErrTenantFieldNotPersisted for
// tenantID naming field.
func assertDeclaredGap(t *testing.T, err error, tenantID, field string) {
	t.Helper()

	var gap ErrTenantFieldNotPersisted
	if !errors.As(err, &gap) {
		t.Fatalf("error = %v, want ErrTenantFieldNotPersisted", err)
	}
	if tenantID != "" && gap.TenantID != tenantID {
		t.Errorf("gap tenant = %q, want %q", gap.TenantID, tenantID)
	}
	if !slices.Contains(gap.Fields, field) {
		t.Errorf("gap fields = %v, want %q among them", gap.Fields, field)
	}
	var storageErr ErrStorageFailed
	if errors.As(err, &storageErr) {
		t.Errorf("declared gap is wrapped in ErrStorageFailed: %v", err)
	}
}

// TestManager_UnstorableWritesAreADeclaredGap proves every write that would
// change a field the pinned go-quicbaas IAM tenant update cannot store is
// refused with ErrTenantFieldNotPersisted, leaves the cache as it was, and
// never renames the IAM tenant.
func TestManager_UnstorableWritesAreADeclaredGap(t *testing.T) {
	displayName := "Acme Corporation"
	writes := []struct {
		name  string
		field string
		write func(ctx context.Context, m *Manager, id string) error
	}{
		{name: "SuspendTenant", field: "state", write: func(ctx context.Context, m *Manager, id string) error {
			return m.SuspendTenant(ctx, id)
		}},
		{name: "UpdateQuotas", field: "compute_quota", write: func(ctx context.Context, m *Manager, id string) error {
			quotas, err := m.GetQuotas(ctx, id)
			if err != nil {
				return err
			}
			quotas.Compute.MaxVMs = 99
			return m.UpdateQuotas(ctx, id, quotas)
		}},
		{name: "UpdateTenant display name", field: "display_name", write: func(ctx context.Context, m *Manager, id string) error {
			_, err := m.UpdateTenant(ctx, id, &UpdateTenantRequest{DisplayName: &displayName})
			return err
		}},
		{name: "UpdateTenant labels", field: "labels", write: func(ctx context.Context, m *Manager, id string) error {
			_, err := m.UpdateTenant(ctx, id, &UpdateTenantRequest{Labels: map[string]string{"team": "platform"}})
			return err
		}},
		{name: "UpdateTenant annotations", field: "annotations", write: func(ctx context.Context, m *Manager, id string) error {
			_, err := m.UpdateTenant(ctx, id, &UpdateTenantRequest{Annotations: map[string]string{"note": "x"}})
			return err
		}},
	}
	for _, tt := range writes {
		t.Run(tt.name, func(t *testing.T) {
			manager, iamClient := newTestManager(t)
			ctx := context.Background()

			created, err := manager.CreateTenant(ctx, &CreateTenantRequest{Name: "acme"})
			if err != nil {
				t.Fatalf("CreateTenant: %v", err)
			}

			assertDeclaredGap(t, tt.write(ctx, manager, created.ID), created.ID, tt.field)

			got, err := manager.GetTenant(ctx, created.ID)
			if err != nil {
				t.Fatalf("GetTenant: %v", err)
			}
			if got.State != StateActive || got.ComputeQuota.MaxVMs == 99 || got.DisplayName != "acme" ||
				len(got.Labels) != 0 || len(got.Annotations) != 0 {
				t.Errorf("cache holds an unsaved change: %+v", got)
			}
			if name := iamClient.tenants[created.ID].Name; name != "acme" {
				t.Errorf("IAM tenant name = %q, want %q", name, "acme")
			}
		})
	}
}

// TestManager_CreateWithUnstorableFieldsIsRolledBack proves a create carrying
// a field a reload could not rebuild is refused with the declared gap and
// leaves neither an IAM tenant nor a cache entry behind.
func TestManager_CreateWithUnstorableFieldsIsRolledBack(t *testing.T) {
	requests := []struct {
		name  string
		field string
		req   *CreateTenantRequest
	}{
		{name: "display name", field: "display_name", req: &CreateTenantRequest{Name: "acme", DisplayName: "Acme Corporation"}},
		{name: "labels", field: "labels", req: &CreateTenantRequest{Name: "acme", Labels: map[string]string{"team": "platform"}}},
		{name: "annotations", field: "annotations", req: &CreateTenantRequest{Name: "acme", Annotations: map[string]string{"note": "x"}}},
		{name: "compute quota", field: "compute_quota", req: &CreateTenantRequest{Name: "acme", ComputeQuota: &ComputeQuota{MaxVMs: 1}}},
		{name: "network quota", field: "network_quota", req: &CreateTenantRequest{Name: "acme", NetworkQuota: &NetworkQuota{MaxBridges: 1}}},
		{name: "storage quota", field: "storage_quota", req: &CreateTenantRequest{Name: "acme", StorageQuota: &StorageQuota{MaxSnapshots: 1}}},
	}
	for _, tt := range requests {
		t.Run(tt.name, func(t *testing.T) {
			manager, iamClient := newTestManager(t)

			_, err := manager.CreateTenant(context.Background(), tt.req)

			assertDeclaredGap(t, err, "", tt.field)
			if len(iamClient.tenants) != 0 {
				t.Errorf("IAM still holds %d tenant(s) after the rollback", len(iamClient.tenants))
			}
			if manager.GetCacheSize() != 0 {
				t.Errorf("cache holds %d tenant(s) after the rollback", manager.GetCacheSize())
			}
		})
	}
}

// TestManager_StorableWritesSurviveARestart proves the writes a reload can
// rebuild from the IAM tenant alone succeed without an IAM update, and a
// restarted manager serves the same tenant through every read.
func TestManager_StorableWritesSurviveARestart(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	created, err := manager.CreateTenant(ctx, &CreateTenantRequest{Name: "persisted", DisplayName: "persisted"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	// No write below changes a stored field, so none reaches IAM: an IAM
	// update failure would surface if one did.
	iamClient.updateErr = errors.New("iam update called")
	quotas, err := manager.GetQuotas(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetQuotas: %v", err)
	}
	if err := manager.UpdateQuotas(ctx, created.ID, quotas); err != nil {
		t.Fatalf("UpdateQuotas with unchanged limits: %v", err)
	}
	if _, err := manager.UpdateTenant(ctx, created.ID, &UpdateTenantRequest{}); err != nil {
		t.Fatalf("empty UpdateTenant: %v", err)
	}

	restarted := restartedManager(t, iamClient)
	defaults := DefaultConfig()
	reads := map[string]func() (*TenantEntity, error){
		"GetTenant":       func() (*TenantEntity, error) { return restarted.GetTenant(ctx, created.ID) },
		"GetTenantByName": func() (*TenantEntity, error) { return restarted.GetTenantByName(ctx, "persisted") },
		"ListTenants": func() (*TenantEntity, error) {
			tenants, _, err := restarted.ListTenants(ctx, 10, 0)
			if err != nil || len(tenants) != 1 {
				return nil, errors.Join(err, errors.New("want exactly one tenant"))
			}
			return tenants[0], nil
		},
	}
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			restarted.InvalidateCache("")

			got, err := read()
			if err != nil {
				t.Fatalf("%s after restart: %v", name, err)
			}
			if got.State != StateActive {
				t.Errorf("state = %s, want %s", got.State, StateActive)
			}
			if got.DisplayName != "persisted" {
				t.Errorf("display name = %q, want %q", got.DisplayName, "persisted")
			}
			if got.ComputeQuota != defaults.DefaultComputeQuota ||
				got.NetworkQuota != defaults.DefaultNetworkQuota ||
				got.StorageQuota != defaults.DefaultStorageQuota {
				t.Errorf("quotas = %+v %+v %+v, want the configured defaults",
					got.ComputeQuota, got.NetworkQuota, got.StorageQuota)
			}
		})
	}
}

// TestManager_ListTenantsServesTheIAMRecordOverAStaleCache proves the IAM
// record is authoritative for a list: a tenant whose record changed behind
// this manager's cache (a transport that stores the record) lists in its new
// state and the cache is reconciled to it.
func TestManager_ListTenantsServesTheIAMRecordOverAStaleCache(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	created, err := manager.CreateTenant(ctx, &CreateTenantRequest{Name: "stale"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	iamClient.tenants[created.ID].Metadata = map[string]string{
		PlatformRecordKey: `{"display_name":"Renamed Display","state":"suspended"}`,
	}

	tenants, _, err := manager.ListTenants(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != 1 {
		t.Fatalf("ListTenants returned %d tenants, want 1", len(tenants))
	}
	if tenants[0].State != StateSuspended {
		t.Errorf("listed state = %s, want %s", tenants[0].State, StateSuspended)
	}
	if tenants[0].DisplayName != "Renamed Display" {
		t.Errorf("listed display name = %q, want %q", tenants[0].DisplayName, "Renamed Display")
	}

	cached, err := manager.GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTenant after list: %v", err)
	}
	if cached.State != StateSuspended {
		t.Errorf("cached state after list = %s, want %s", cached.State, StateSuspended)
	}
}

// TestManager_DeleteNeedsNoRecordWrite proves deletion does not store the
// transient deleting state: it succeeds over an IAM whose update fails, and a
// failed IAM delete leaves the tenant in the cache as it was.
func TestManager_DeleteNeedsNoRecordWrite(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	kept, err := manager.CreateTenant(ctx, &CreateTenantRequest{Name: "kept"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	iamClient.deleteErr = errors.New("iam unavailable")
	var storageErr ErrStorageFailed
	if err := manager.DeleteTenant(ctx, kept.ID); !errors.As(err, &storageErr) {
		t.Fatalf("DeleteTenant error = %v, want ErrStorageFailed", err)
	}
	got, err := manager.GetTenant(ctx, kept.ID)
	if err != nil {
		t.Fatalf("GetTenant after a failed delete: %v", err)
	}
	if got.State != StateActive {
		t.Errorf("state after a failed delete = %s, want %s", got.State, StateActive)
	}

	iamClient.deleteErr = nil
	iamClient.updateErr = errors.New("iam update called")
	if err := manager.DeleteTenant(ctx, kept.ID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	var notFound ErrTenantNotFound
	if _, err := manager.GetTenant(ctx, kept.ID); !errors.As(err, &notFound) {
		t.Errorf("GetTenant after delete error = %v, want ErrTenantNotFound", err)
	}
}

// TestManager_TenantWithoutPlatformRecord proves a tenant with no record
// reads as the baseline every write is checked against: active (suspended
// when IAM says so) with the configured default quotas.
func TestManager_TenantWithoutPlatformRecord(t *testing.T) {
	tests := []struct {
		name   string
		status iam.TenantStatus
		want   State
	}{
		{name: "active in IAM", status: iam.TenantStatusActive, want: StateActive},
		{name: "no IAM status", status: iam.TenantStatusUnspecified, want: StateActive},
		{name: "suspended in IAM", status: iam.TenantStatusSuspended, want: StateSuspended},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, iamClient := newTestManager(t)
			iamClient.tenants["external"] = &iam.Tenant{ID: "external", Name: "external", Status: tt.status}

			got, err := manager.GetTenant(context.Background(), "external")
			if err != nil {
				t.Fatalf("GetTenant: %v", err)
			}
			if got.State != tt.want {
				t.Errorf("state = %s, want %s", got.State, tt.want)
			}
			if got.ComputeQuota != DefaultConfig().DefaultComputeQuota {
				t.Errorf("compute quota = %+v, want the configured default", got.ComputeQuota)
			}
		})
	}
}

func TestManager_UnreadablePlatformRecordIsAStorageFailure(t *testing.T) {
	tests := map[string]string{
		"malformed JSON": "{",
		"unknown state":  `{"state":"melting"}`,
	}
	for name, record := range tests {
		t.Run(name, func(t *testing.T) {
			manager, iamClient := newTestManager(t)
			iamClient.tenants["broken"] = &iam.Tenant{
				ID:       "broken",
				Name:     "broken",
				Metadata: map[string]string{PlatformRecordKey: record},
			}
			ctx := context.Background()

			var storageErr ErrStorageFailed
			if _, err := manager.GetTenant(ctx, "broken"); !errors.As(err, &storageErr) {
				t.Errorf("GetTenant error = %v, want ErrStorageFailed", err)
			}
			if _, err := manager.GetTenantByName(ctx, "broken"); !errors.As(err, &storageErr) {
				t.Errorf("GetTenantByName error = %v, want ErrStorageFailed", err)
			}
			if _, _, err := manager.ListTenants(ctx, 10, 0); !errors.As(err, &storageErr) {
				t.Errorf("ListTenants error = %v, want ErrStorageFailed", err)
			}
		})
	}
}
