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

package commands

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// inspectionPassRecorder counts the passes the attestation service
// dispatches to its observers.
type inspectionPassRecorder struct {
	mu     sync.Mutex
	passed int
}

func (r *inspectionPassRecorder) OnAttestationFailed(context.Context, uint64, string, string) {}

func (r *inspectionPassRecorder) OnAttestationPassed(context.Context, uint64, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.passed++
}

// A manifest inspection checks no signature and no fresh quote, so with the
// real quarantine observer wired a passing inspection must leave a
// quarantined device quarantined (#2038).
func TestWireQuarantineObserver_APassingInspectionLeavesAQuarantinedDeviceQuarantined(t *testing.T) {
	zones := zone.Defaults()
	plan, err := netplan.New(netplan.Environment{ID: 4}, zones)
	require.NoError(t, err)
	zfm, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName:     "br-fabric",
		FlowController: nullOVSPort{},
		PortController: nullOVSPort{},
		Plan:           plan,
		Zones:          zones,
	})
	require.NoError(t, err)
	eng, err := policy.NewEngine(policy.Config{
		BridgeName:     "br-fabric",
		FlowController: nullOVSPort{},
		PortController: nullOVSPort{},
		Zones:          zones,
		Logger:         quietLogger(),
	})
	require.NoError(t, err)
	for _, step := range []policy.PortState{policy.PortStateProvisioning, policy.PortStateEnrolled, policy.PortStateAuthorized} {
		require.NoError(t, eng.SetPortState("tap07", step))
	}

	devices := &hostnameDevices{stubSaveGetSvc: &stubSaveGetSvc{devices: map[uint64]*entities.Device{
		7: {ID: 7, Hostname: "node-07", State: entities.DeviceStateAttested, NetworkPortID: "tap07"},
	}}}
	svcs := &attestationServices{Service: buildRealAttestationService(t)}
	sdn := &sdnPolicyComponents{Engine: eng, ZoneFlowManager: zfm, ResolvedZones: zones}
	require.NotNil(t, wireQuarantineObserver(svcs, sdn, devices, newTestLogger()))
	rec := &inspectionPassRecorder{}
	svcs.Service.RegisterObserver(rec)

	ctx := context.Background()
	failed, err := svcs.Service.VerifyManifest(ctx,
		&manifest.HostManifest{ID: "m-07", HostID: "node-07", Nonce: []byte("replayed")},
		nil, []byte("fresh"), nil, nil)
	require.NoError(t, err)
	require.Equal(t, manifest.VerificationStatusFailed, failed.Status)
	state, err := eng.GetPortState("tap07")
	require.NoError(t, err)
	require.Equal(t, policy.PortStateQuarantined, state, "precondition: the failed host's port is quarantined")
	require.Equal(t, entities.DeviceStateQuarantined, devices.devices[7].State, "precondition: the device is quarantined")

	passed, err := svcs.Service.VerifyManifest(ctx,
		&manifest.HostManifest{ID: "m-07b", HostID: "node-07"}, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, manifest.VerificationStatusVerified, passed.Status)

	rec.mu.Lock()
	gotPassed := rec.passed
	rec.mu.Unlock()
	assert.Equal(t, 0, gotPassed, "an inspection dispatches no pass")
	state, err = eng.GetPortState("tap07")
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateQuarantined, state, "a passing inspection must not restore the port")
	assert.Equal(t, entities.DeviceStateQuarantined, devices.devices[7].State, "a passing inspection must not restore the device")
}
