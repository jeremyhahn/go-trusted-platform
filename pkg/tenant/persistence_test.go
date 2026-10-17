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
	"maps"
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

func TestManager_RestartKeepsStateQuotasAndLabels(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	labels := map[string]string{"team": "platform"}
	created, err := manager.CreateTenant(ctx, &CreateTenantRequest{
		Name:        "persisted",
		DisplayName: "Persisted Tenant",
		Labels:      labels,
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	quotas := &TenantQuotas{
		Compute: ComputeQuota{MaxVMs: 7, MaxVCPUs: 14},
		Network: NetworkQuota{MaxBridges: 3},
		Storage: StorageQuota{MaxVolumesGB: 5},
	}
	if err := manager.UpdateQuotas(ctx, created.ID, quotas); err != nil {
		t.Fatalf("UpdateQuotas: %v", err)
	}
	if err := manager.SuspendTenant(ctx, created.ID); err != nil {
		t.Fatalf("SuspendTenant: %v", err)
	}

	restarted := restartedManager(t, iamClient)

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
			if got.State != StateSuspended {
				t.Errorf("state = %s, want %s", got.State, StateSuspended)
			}
			if got.DisplayName != "Persisted Tenant" {
				t.Errorf("display name = %q, want %q", got.DisplayName, "Persisted Tenant")
			}
			if got.ComputeQuota.MaxVMs != 7 || got.ComputeQuota.MaxVCPUs != 14 {
				t.Errorf("compute quota = %+v, want MaxVMs 7 and MaxVCPUs 14", got.ComputeQuota)
			}
			if got.NetworkQuota.MaxBridges != 3 {
				t.Errorf("network quota = %+v, want MaxBridges 3", got.NetworkQuota)
			}
			if got.StorageQuota.MaxVolumesGB != 5 {
				t.Errorf("storage quota = %+v, want MaxVolumesGB 5", got.StorageQuota)
			}
			if !maps.Equal(got.Labels, labels) {
				t.Errorf("labels = %v, want %v", got.Labels, labels)
			}
		})
	}

	if status := iamClient.tenants[created.ID].Status; status != iam.TenantStatusSuspended {
		t.Errorf("IAM status = %q, want %q", status, iam.TenantStatusSuspended)
	}
}

func TestManager_ResumeIsPersisted(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	created, err := manager.CreateTenant(ctx, &CreateTenantRequest{Name: "resumed"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := manager.SuspendTenant(ctx, created.ID); err != nil {
		t.Fatalf("SuspendTenant: %v", err)
	}
	if err := manager.ResumeTenant(ctx, created.ID); err != nil {
		t.Fatalf("ResumeTenant: %v", err)
	}

	got, err := restartedManager(t, iamClient).GetTenant(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTenant after restart: %v", err)
	}
	if got.State != StateActive {
		t.Errorf("state = %s, want %s", got.State, StateActive)
	}
}

func TestManager_FailedSaveLeavesTheCacheUnchanged(t *testing.T) {
	manager, iamClient := newTestManager(t)
	ctx := context.Background()

	created, err := manager.CreateTenant(ctx, &CreateTenantRequest{Name: "unsaved"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	iamClient.updateErr = errors.New("iam unavailable")

	writes := map[string]func() error{
		"SuspendTenant": func() error { return manager.SuspendTenant(ctx, created.ID) },
		"UpdateQuotas": func() error {
			return manager.UpdateQuotas(ctx, created.ID, &TenantQuotas{Compute: ComputeQuota{MaxVMs: 99}})
		},
		"DeleteTenant": func() error { return manager.DeleteTenant(ctx, created.ID) },
	}
	for name, write := range writes {
		t.Run(name, func(t *testing.T) {
			var storageErr ErrStorageFailed
			if err := write(); !errors.As(err, &storageErr) {
				t.Fatalf("%s error = %v, want ErrStorageFailed", name, err)
			}
			if storageErr.Operation != name {
				t.Errorf("operation = %q, want %q", storageErr.Operation, name)
			}

			got, err := manager.GetTenant(ctx, created.ID)
			if err != nil {
				t.Fatalf("GetTenant: %v", err)
			}
			if got.State != StateActive || got.ComputeQuota.MaxVMs == 99 {
				t.Errorf("cache holds an unsaved change: state %s, MaxVMs %d", got.State, got.ComputeQuota.MaxVMs)
			}
		})
	}
}

func TestManager_CreateRollsBackWhenTheRecordCannotBeSaved(t *testing.T) {
	manager, iamClient := newTestManager(t)
	iamClient.updateErr = errors.New("iam unavailable")

	_, err := manager.CreateTenant(context.Background(), &CreateTenantRequest{Name: "rolled-back"})

	var storageErr ErrStorageFailed
	if !errors.As(err, &storageErr) {
		t.Fatalf("CreateTenant error = %v, want ErrStorageFailed", err)
	}
	if len(iamClient.tenants) != 0 {
		t.Errorf("IAM still holds %d tenant(s) after the rollback", len(iamClient.tenants))
	}
	if manager.GetCacheSize() != 0 {
		t.Errorf("cache holds %d tenant(s) after the rollback", manager.GetCacheSize())
	}
}

func TestManager_TenantWithoutPlatformRecord(t *testing.T) {
	tests := []struct {
		name   string
		status iam.TenantStatus
		want   State
	}{
		{name: "active in IAM", status: iam.TenantStatusActive, want: StateCreated},
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
