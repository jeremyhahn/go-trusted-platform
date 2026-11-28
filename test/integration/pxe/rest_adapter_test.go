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

//go:build integration

package pxe

import (
	"context"
	"fmt"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// parityListLimit is large enough that a filtered list returns every match
// on the shared integration platformd.
const parityListLimit = 1000

// TestPXERESTGRPCParity holds the SDK REST transport to the gRPC one for the
// PXEService RPCs TestPXEMultiProtocol cannot drive through PXECommands
// (#975): StartService, and ListDevices with each PXEDeviceFilter field.
func TestPXERESTGRPCParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rest := NewRESTAdapter()
	grpc := NewGRPCAdapter()
	gate := helpers.NewAdapterGate(t, "pxe-rest-parity", rest.Name(), grpc.Name())
	for _, adapter := range []*SDKAdapter{rest, grpc} {
		gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
		t.Cleanup(func() {
			if err := adapter.Teardown(); err != nil {
				t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
			}
		})
	}

	t.Run("StartServiceRefusedWhileRunning", func(t *testing.T) {
		testStartServiceParity(t, ctx, rest, grpc)
	})
	t.Run("FilteredListDevices", func(t *testing.T) {
		testFilteredListParity(t, ctx, rest, grpc)
	})
	t.Run("StopThenStartOverREST", func(t *testing.T) {
		testStopStartParity(t, ctx, rest, grpc)
	})
}

// testStopStartParity stops the running PXE service over REST, requires gRPC
// to see it stopped and both transports to refuse a second stop alike, starts
// it again over REST, and requires the restarted service to list the same
// devices over REST and gRPC, including one registered before the stop.
func testStopStartParity(t *testing.T, ctx context.Context, rest, grpc *SDKAdapter) {
	device, err := grpc.RegisterDevice(ctx, DefaultRegisterOptions(fmt.Sprintf("rest-restart-%d", time.Now().UnixNano())))
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	t.Cleanup(func() {
		if err := CleanupDevice(context.Background(), grpc, device.ID); err != nil {
			t.Logf("Warning: cleanup of device %s failed: %v", device.ID, err)
		}
	})
	requireServiceRunning(t, ctx, grpc, true)

	_, err = rest.pxe.StopService(ctx, &platformv1.StopPXEServiceRequest{})
	require.NoError(t, err, "REST: StopService on the running service should succeed")
	// The suite shares one platformd: leave its PXE service running even
	// when a step below fails.
	t.Cleanup(func() { restartPXEService(t, grpc) })
	requireServiceRunning(t, ctx, grpc, false)

	for _, adapter := range []*SDKAdapter{rest, grpc} {
		_, err := adapter.pxe.StopService(ctx, &platformv1.StopPXEServiceRequest{})
		require.Error(t, err, "%s: StopService on a stopped service should be refused", adapter.Name())
		assert.Equal(t, codes.FailedPrecondition, status.Code(err),
			"%s: StopService on a stopped service should answer FailedPrecondition", adapter.Name())
	}

	_, err = rest.pxe.StartService(ctx, &platformv1.StartPXEServiceRequest{})
	require.NoError(t, err, "REST: StartService on the stopped service should succeed")
	requireServiceRunning(t, ctx, grpc, true)

	opts := ListDevicesOptions{MACAddress: device.MACAddress, Limit: parityListLimit}
	restIDs := listDeviceIDs(t, ctx, rest, opts)
	grpcIDs := listDeviceIDs(t, ctx, grpc, opts)
	assert.ElementsMatch(t, grpcIDs, restIDs, "REST and gRPC should return the same devices")
	assert.Contains(t, restIDs, device.ID, "the restarted service should list the device registered before the stop")
}

// requireServiceRunning requires GetStatus over adapter to report running.
func requireServiceRunning(t *testing.T, ctx context.Context, adapter *SDKAdapter, running bool) {
	t.Helper()
	result, err := adapter.GetStatus(ctx)
	require.NoError(t, err, "%s: GetStatus should succeed", adapter.Name())
	require.Equal(t, running, result.Running, "%s: GetStatus should report running=%t", adapter.Name(), running)
}

// restartPXEService starts the PXE service over adapter if it is stopped.
func restartPXEService(t *testing.T, adapter *SDKAdapter) {
	ctx := context.Background()
	result, err := adapter.GetStatus(ctx)
	if err != nil {
		t.Errorf("%s: GetStatus failed while restoring the PXE service: %v", adapter.Name(), err)
		return
	}
	if result.Running {
		return
	}
	if _, err := adapter.pxe.StartService(ctx, &platformv1.StartPXEServiceRequest{}); err != nil {
		t.Errorf("%s: StartService failed while restoring the PXE service: %v", adapter.Name(), err)
	}
}

// testStartServiceParity starts the already-running PXE service over both
// transports. StopService is not driven: the shared platformd's iPXE server
// is single-use, so a stopped service cannot be started again.
func testStartServiceParity(t *testing.T, ctx context.Context, rest, grpc *SDKAdapter) {
	statusResult, err := grpc.GetStatus(ctx)
	require.NoError(t, err, "GetStatus should succeed")
	require.True(t, statusResult.Running, "the PXE service should be running")

	for _, adapter := range []*SDKAdapter{rest, grpc} {
		_, err := adapter.pxe.StartService(ctx, &platformv1.StartPXEServiceRequest{})
		require.Error(t, err, "%s: StartService on a running service should be refused", adapter.Name())
		assert.Equal(t, codes.FailedPrecondition, status.Code(err),
			"%s: StartService on a running service should answer FailedPrecondition", adapter.Name())
	}
}

// testFilteredListParity registers three devices, moves one to booting, and
// checks that every filter returns the same devices over REST as over gRPC,
// and that the filter was applied rather than dropped.
func testFilteredListParity(t *testing.T, ctx context.Context, rest, grpc *SDKAdapter) {
	prefix := fmt.Sprintf("rest-parity-%d", time.Now().UnixNano())
	var devices []*RegisterDeviceResult
	for i := 0; i < 3; i++ {
		device, err := grpc.RegisterDevice(ctx, DefaultRegisterOptions(fmt.Sprintf("%s-%d", prefix, i)))
		require.NoError(t, err, "Setup: RegisterDevice should succeed")
		devices = append(devices, device)
	}
	t.Cleanup(func() {
		for _, device := range devices {
			if err := CleanupDevice(context.Background(), grpc, device.ID); err != nil {
				t.Logf("Warning: cleanup of device %s failed: %v", device.ID, err)
			}
		}
	})
	// A registered device sits on the quarantine VLAN; the VLAN case
	// filters on it, and a zero VLAN would be no filter at all.
	require.NotZero(t, devices[2].CurrentVLAN, "Setup: a registered device should carry a VLAN")

	booted := devices[0]
	_, err := grpc.UpdateDeviceState(ctx, UpdateStateOptions{
		DeviceID: booted.ID,
		State:    StateBooting,
		Reason:   "REST parity filter",
	})
	require.NoError(t, err, "Setup: UpdateDeviceState should succeed")

	tests := []struct {
		name     string
		opts     ListDevicesOptions
		includes []string
		excludes []string
	}{
		{
			name:     "State",
			opts:     ListDevicesOptions{State: StateBooting},
			includes: []string{booted.ID},
			excludes: []string{devices[1].ID, devices[2].ID},
		},
		{
			name:     "MACAddress",
			opts:     ListDevicesOptions{MACAddress: devices[1].MACAddress},
			includes: []string{devices[1].ID},
			excludes: []string{booted.ID, devices[2].ID},
		},
		{
			name:     "VLAN",
			opts:     ListDevicesOptions{VLAN: devices[2].CurrentVLAN},
			includes: []string{devices[1].ID, devices[2].ID},
		},
		{
			name:     "StateAndMACAddress",
			opts:     ListDevicesOptions{State: StateDiscovered, MACAddress: booted.MACAddress},
			excludes: []string{booted.ID},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.Limit = parityListLimit
			restIDs := listDeviceIDs(t, ctx, rest, tt.opts)
			grpcIDs := listDeviceIDs(t, ctx, grpc, tt.opts)

			assert.ElementsMatch(t, grpcIDs, restIDs, "REST and gRPC should return the same devices")
			for _, id := range tt.includes {
				assert.Contains(t, restIDs, id, "the filter should match device %s", id)
			}
			for _, id := range tt.excludes {
				assert.NotContains(t, restIDs, id, "the filter should not match device %s", id)
			}
		})
	}
}

// listDeviceIDs lists the devices matching opts over adapter and returns
// their IDs.
func listDeviceIDs(t *testing.T, ctx context.Context, adapter *SDKAdapter, opts ListDevicesOptions) []string {
	t.Helper()
	result, err := adapter.ListDevices(ctx, opts)
	require.NoError(t, err, "%s: ListDevices should succeed", adapter.Name())
	ids := make([]string, 0, len(result.Devices))
	for _, device := range result.Devices {
		ids = append(ids, device.ID)
	}
	return ids
}
