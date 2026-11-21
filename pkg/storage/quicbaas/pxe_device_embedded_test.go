//go:build raft

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
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/pkg/iam"
	"github.com/stretchr/testify/require"
)

// TestPXEDeviceStore_Embedded_ListPastOnePage stores 1,001 devices in a real
// embedded datastore and lists them back (#2081 F1). The pinned embedded
// transport ignores the page token and repeats the first batch's
// NextPageToken; a List that followed it would loop until the ctx deadline.
func TestPXEDeviceStore_Embedded_ListPastOnePage(t *testing.T) {
	setup := newTestClient(t)
	defer setup.cleanup()

	store := mustPXEDeviceStore(t, setup.client)
	const total = 1001
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("dev-%04d", i)
		mac := fmt.Sprintf("02:00:00:00:%02x:%02x", i>>8, i&0xff)
		require.NoError(t, store.Put(context.Background(), testPXEDevice(t, id, mac)))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	devices, err := store.List(ctx)
	require.NoError(t, err)
	requireUniquePXEDevices(t, devices, total)
	byID := make(map[string]int, len(devices))
	for i, d := range devices {
		byID[d.ID] = i
	}
	for i := 0; i < total; i++ {
		_, ok := byID[fmt.Sprintf("dev-%04d", i)]
		require.True(t, ok, "dev-%04d missing", i)
	}
	want := testPXEDevice(t, "dev-1000", "02:00:00:00:03:e8")
	got := devices[byID["dev-1000"]]
	require.Equal(t, want.State, got.State)
	require.Equal(t, want.RetryCount, got.RetryCount)
	require.Equal(t, want.IDevIDFingerprint, got.IDevIDFingerprint)
	require.Equal(t, want.MACAddress.String(), got.MACAddress.String())

	// The restart reload path: a new store over the same client.
	restarted := mustPXEDeviceStore(t, setup.client)
	reloaded, err := restarted.List(ctx)
	require.NoError(t, err)
	requireUniquePXEDevices(t, reloaded, total)

	require.NoError(t, store.Delete(ctx, "dev-0000"))
	afterDelete, err := store.List(ctx)
	require.NoError(t, err)
	requireUniquePXEDevices(t, afterDelete, total-1)
	for _, d := range afterDelete {
		require.NotEqual(t, "dev-0000", d.ID)
	}
}

// TestPXEDeviceStore_Embedded_SystemTenantNamespace checks where the store's
// records land in a real embedded datastore (#2081 F3): in the system
// tenant's keyspace, not the legacy tenant-less one nor another tenant's.
func TestPXEDeviceStore_Embedded_SystemTenantNamespace(t *testing.T) {
	setup := newTestClient(t)
	defer setup.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	legacyCtx := ctx
	systemCtx := iam.ContextWithTenant(ctx, "system")
	otherCtx := iam.ContextWithTenant(ctx, "other-tenant")

	store := mustPXEDeviceStore(t, setup.client)
	require.NoError(t, store.Put(ctx, testPXEDevice(t, "dev-tenant", "aa:bb:cc:dd:ee:01")))

	legacy, _, err := setup.client.List(legacyCtx, entityTypePXEDevice, 1000, "", 0)
	require.NoError(t, err)
	require.Empty(t, legacy, "the store must not write the legacy tenant-less namespace")

	system, _, err := setup.client.List(systemCtx, entityTypePXEDevice, 1000, "", 0)
	require.NoError(t, err)
	require.Len(t, system, 1)
	require.Equal(t, pxeDeviceEntityID("dev-tenant"), system[0].ID)

	other, _, err := setup.client.List(otherCtx, entityTypePXEDevice, 1000, "", 0)
	require.NoError(t, err)
	require.Empty(t, other, "another tenant must not see the system tenant's records")

	// A record written with no tenant is not the store's.
	data, err := json.Marshal(testPXEDevice(t, "dev-legacy", "aa:bb:cc:dd:ee:02"))
	require.NoError(t, err)
	require.NoError(t, setup.client.Put(legacyCtx, entityTypePXEDevice, pxeDeviceEntityID("dev-legacy"), data, 0))

	devices, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, devices, 1)
	require.Equal(t, "dev-tenant", devices[0].ID)

	// Delete touches only the system namespace.
	require.NoError(t, store.Delete(ctx, "dev-tenant"))
	system, _, err = setup.client.List(systemCtx, entityTypePXEDevice, 1000, "", 0)
	require.NoError(t, err)
	require.Empty(t, system)
	legacy, _, err = setup.client.List(legacyCtx, entityTypePXEDevice, 1000, "", 0)
	require.NoError(t, err)
	require.Len(t, legacy, 1)
	require.Equal(t, pxeDeviceEntityID("dev-legacy"), legacy[0].ID)
}
