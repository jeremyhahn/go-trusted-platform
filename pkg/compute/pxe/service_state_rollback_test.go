package pxe

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A discovered device sits on the quarantine VLAN. When the write of
// discovered -> booting fails, the port must be back on the quarantine
// flows, not left on the provisioning flows the move installed
// (#2081 Codex P1).
func TestService_UpdateDeviceState_FailedWideningWriteRestoresQuarantineFlows(t *testing.T) {
	svc, vlan, store, id := newStoreBackedService(t, StateQuarantined)
	setStoredDevice(t, svc, store, id, StateDiscovered, svc.config.QuarantineVLAN,
		func(d *DeviceInfo) bool { return d.State == StateBooting })
	vlan.set("quarantine")

	require.Error(t, svc.UpdateDeviceState(context.Background(), id, StateBooting, "pxe boot"))
	assert.Equal(t, "quarantine", vlan.flows(), "a failed write must not leave provisioning access")

	got, err := svc.stateManager.Get(id)
	require.NoError(t, err)
	assert.Equal(t, StateDiscovered, got.State)
	assert.Equal(t, svc.config.QuarantineVLAN, got.CurrentVLAN)

	store.mu.Lock()
	store.failPut = nil
	store.mu.Unlock()
	require.NoError(t, svc.UpdateDeviceState(context.Background(), id, StateBooting, "pxe boot"))
	assert.Equal(t, "provisioning", vlan.flows())
}

// A device already on the provisioning VLAN keeps its provisioning flows
// when a provisioning-to-provisioning write fails.
func TestService_UpdateDeviceState_FailedWriteRestoresProvisioningFlows(t *testing.T) {
	svc, vlan, store, id := newStoreBackedService(t, StateQuarantined)
	setStoredDevice(t, svc, store, id, StateBooting, svc.config.ProvisioningVLAN,
		func(d *DeviceInfo) bool { return d.State == StateInstalling })
	vlan.set("provisioning")

	require.Error(t, svc.UpdateDeviceState(context.Background(), id, StateInstalling, "install"))
	assert.Equal(t, "provisioning", vlan.flows())
}

// A failed write on a move to quarantined or failed keeps the restrictive
// flows the move installed.
func TestService_UpdateDeviceState_FailedRestrictiveWriteKeepsQuarantineFlows(t *testing.T) {
	for _, target := range []ProvisioningState{StateQuarantined, StateFailed} {
		t.Run(string(target), func(t *testing.T) {
			svc, vlan, store, id := newStoreBackedService(t, StateQuarantined)
			setStoredDevice(t, svc, store, id, StateBooting, svc.config.ProvisioningVLAN,
				func(d *DeviceInfo) bool { return d.State == target })
			vlan.set("provisioning")

			require.Error(t, svc.UpdateDeviceState(context.Background(), id, target, "posture failed"))
			assert.Equal(t, "quarantine", vlan.flows(), "a datastore outage must not reconnect the device")

			got, err := svc.stateManager.Get(id)
			require.NoError(t, err)
			assert.Equal(t, StateBooting, got.State)
		})
	}
}
