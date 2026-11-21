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

package quicbaas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/pkg/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/require"
)

func setupMockPXEDeviceStore(t *testing.T) (*PXEDeviceStore, *MockStorage) {
	t.Helper()
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	t.Cleanup(func() { _ = mock.Stop(context.Background()) })
	return mustPXEDeviceStore(t, mock), mock
}

func testPXEDevice(t *testing.T, id, mac string) *pxe.DeviceInfo {
	t.Helper()
	hw, err := net.ParseMAC(mac)
	require.NoError(t, err)
	return &pxe.DeviceInfo{
		ID:                id,
		MACAddress:        hw,
		State:             pxe.StateInstalling,
		StateReason:       "installer started",
		IDevIDFingerprint: "0f" + id,
		RetryCount:        3,
		Events: []*pxe.ProvisioningEvent{
			{DeviceID: id, ToState: pxe.StateBooting, Details: map[string]string{"reason": "booted"}},
		},
	}
}

// TestPXEDeviceStore_RoundTrip_Mock stores two devices, deletes one, and a
// second store over the same storage lists the other in full (#2028).
func TestPXEDeviceStore_RoundTrip_Mock(t *testing.T) {
	ctx := context.Background()
	store, mock := setupMockPXEDeviceStore(t)

	a := testPXEDevice(t, "dev-a", "02:00:00:00:00:0a")
	b := testPXEDevice(t, "dev-b", "02:00:00:00:00:0b")
	require.NoError(t, store.Put(ctx, a))
	require.NoError(t, store.Put(ctx, b))

	// A second Put of the same ID replaces the record.
	a.State = pxe.StateInstallComplete
	require.NoError(t, store.Put(ctx, a))
	require.NoError(t, store.Delete(ctx, "dev-b"))

	restarted := mustPXEDeviceStore(t, mock)
	devices, err := restarted.List(ctx)
	require.NoError(t, err)
	require.Len(t, devices, 1)
	got := devices[0]
	require.Equal(t, "dev-a", got.ID)
	require.Equal(t, a.MACAddress, got.MACAddress)
	require.Equal(t, pxe.StateInstallComplete, got.State)
	require.Equal(t, 3, got.RetryCount)
	require.Equal(t, "0fdev-a", got.IDevIDFingerprint)
	require.Len(t, got.Events, 1)
	require.Equal(t, "booted", got.Events[0].Details["reason"])
}

func TestPXEDeviceStore_Errors_Mock(t *testing.T) {
	ctx := context.Background()
	store, mock := setupMockPXEDeviceStore(t)

	require.Error(t, store.Put(ctx, nil))
	require.Error(t, store.Put(ctx, &pxe.DeviceInfo{}))

	mock.PutError = errors.New("storage unavailable")
	require.Error(t, store.Put(ctx, testPXEDevice(t, "dev-c", "02:00:00:00:00:0c")))

	mock.DeleteError = errors.New("storage unavailable")
	require.Error(t, store.Delete(ctx, "dev-c"))

	mock.ListError = errors.New("storage unavailable")
	_, err := store.List(ctx)
	require.Error(t, err)
}

// pagingStorage wraps MockStorage and serves List from listFn, failing
// after maxCalls so a List that loops ends the test instead of hanging.
type pagingStorage struct {
	*MockStorage
	listFn   func(pageToken string) ([]*service.Entity, string)
	calls    int
	maxCalls int
}

func (p *pagingStorage) List(_ context.Context, _ string, _ uint64, pageToken string, _ uint64) ([]*service.Entity, string, error) {
	p.calls++
	if p.calls > p.maxCalls {
		return nil, "", fmt.Errorf("pagingStorage: List called more than %d times", p.maxCalls)
	}
	page, next := p.listFn(pageToken)
	return page, next, nil
}

func pxeDeviceEntities(t *testing.T, from, to int) []*service.Entity {
	t.Helper()
	entities := make([]*service.Entity, 0, to-from)
	for i := from; i < to; i++ {
		id := fmt.Sprintf("dev-%04d", i)
		data, err := json.Marshal(&pxe.DeviceInfo{ID: id})
		require.NoError(t, err)
		entities = append(entities, &service.Entity{EntityType: entityTypePXEDevice, ID: pxeDeviceEntityID(id), Data: data})
	}
	return entities
}

func requireUniquePXEDevices(t *testing.T, devices []*pxe.DeviceInfo, want int) {
	t.Helper()
	require.Len(t, devices, want)
	seen := make(map[string]struct{}, len(devices))
	for _, d := range devices {
		_, dup := seen[d.ID]
		require.False(t, dup, "duplicate device %s", d.ID)
		seen[d.ID] = struct{}{}
	}
}

func TestPXEDeviceStore_List_Paging(t *testing.T) {
	mock := NewMockStorage()
	all := pxeDeviceEntities(t, 0, 1001)

	t.Run("aggregated response keeps the first batch's token", func(t *testing.T) {
		// The pinned go-quicbaas v0.12.0-alpha embedded transport ignores
		// the page token: every call returns every record and "1000".
		fake := &pagingStorage{MockStorage: mock, maxCalls: 5, listFn: func(string) ([]*service.Entity, string) {
			return all, "1000"
		}}
		devices, err := mustPXEDeviceStore(t, fake).List(context.Background())
		require.NoError(t, err)
		requireUniquePXEDevices(t, devices, 1001)
		require.LessOrEqual(t, fake.calls, 2)
	})

	t.Run("repeated token stops the walk", func(t *testing.T) {
		fake := &pagingStorage{MockStorage: mock, maxCalls: 5, listFn: func(token string) ([]*service.Entity, string) {
			if token == "" {
				return all[:500], "p1"
			}
			return all[400:900], "p1"
		}}
		devices, err := mustPXEDeviceStore(t, fake).List(context.Background())
		require.NoError(t, err)
		requireUniquePXEDevices(t, devices, 900)
		require.Equal(t, 2, fake.calls)
	})

	t.Run("true paging reads every page", func(t *testing.T) {
		fake := &pagingStorage{MockStorage: mock, maxCalls: 5, listFn: func(token string) ([]*service.Entity, string) {
			if token == "" {
				return all[:1000], "1000"
			}
			require.Equal(t, "1000", token)
			return all[1000:], ""
		}}
		devices, err := mustPXEDeviceStore(t, fake).List(context.Background())
		require.NoError(t, err)
		requireUniquePXEDevices(t, devices, 1001)
		require.Equal(t, 2, fake.calls)
	})

	t.Run("cancelled context stops the walk", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		fake := &pagingStorage{MockStorage: mock, maxCalls: 5, listFn: func(string) ([]*service.Entity, string) {
			return all[:1], ""
		}}
		_, err := mustPXEDeviceStore(t, fake).List(ctx)
		require.ErrorIs(t, err, context.Canceled)
		require.Zero(t, fake.calls)
	})
}

func mustPXEDeviceStore(t *testing.T, storage Storage) *PXEDeviceStore {
	t.Helper()
	store, err := NewPXEDeviceStore(storage, "system", logging.DefaultLogger())
	require.NoError(t, err)
	return store
}

// tenantStorage records the tenant each storage call carries in its ctx.
type tenantStorage struct {
	*MockStorage
	tenants map[string][]string
}

func (s *tenantStorage) record(ctx context.Context, op string) {
	s.tenants[op] = append(s.tenants[op], sdktransport.TenantFromContext(ctx))
	// The embedded keyspace (service/keyspace.go BuildKey) reads the
	// tenant from pkg/iam's context key, not the transport's (#2081).
	s.tenants[op+"/iam"] = append(s.tenants[op+"/iam"], iam.TenantFromContext(ctx))
}

func (s *tenantStorage) Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error {
	s.record(ctx, "put")
	return s.MockStorage.Put(ctx, entityType, id, data, shardID)
}

func (s *tenantStorage) Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error {
	s.record(ctx, "delete")
	return s.MockStorage.Delete(ctx, entityType, id, shardID)
}

func (s *tenantStorage) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	s.record(ctx, "list")
	return s.MockStorage.List(ctx, entityType, pageSize, pageToken, shardID)
}

func TestPXEDeviceStore_SystemTenant(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	t.Cleanup(func() { _ = mock.Stop(context.Background()) })

	_, err := NewPXEDeviceStore(mock, "", logging.DefaultLogger())
	require.Error(t, err, "an empty tenant must be refused")

	fake := &tenantStorage{MockStorage: mock, tenants: map[string][]string{}}
	store := mustPXEDeviceStore(t, fake)
	device := testPXEDevice(t, "dev-tenant", "aa:bb:cc:dd:ee:01")
	ctx := context.Background()
	require.NoError(t, store.Put(ctx, device))
	_, err = store.List(ctx)
	require.NoError(t, err)
	require.NoError(t, store.Delete(ctx, device.ID))

	for _, op := range []string{"put", "list", "delete", "put/iam", "list/iam", "delete/iam"} {
		require.NotEmpty(t, fake.tenants[op], op)
		for _, tenant := range fake.tenants[op] {
			require.Equal(t, "system", tenant, op)
		}
	}
}
