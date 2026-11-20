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
	"errors"
	"net"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/require"
)

func setupMockPXEDeviceStore(t *testing.T) (*PXEDeviceStore, *MockStorage) {
	t.Helper()
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	t.Cleanup(func() { _ = mock.Stop(context.Background()) })
	return NewPXEDeviceStore(mock, logging.DefaultLogger()), mock
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

	restarted := NewPXEDeviceStore(mock, logging.DefaultLogger())
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
