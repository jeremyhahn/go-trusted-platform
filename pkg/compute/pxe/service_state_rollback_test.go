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

// TestService_UpdateDeviceState_FailedRestrictiveWriteBlocksWidening checks
// that a generic restrictive update whose state write fails keeps the
// quarantine flows and refuses every widening report until the restrictive
// state is stored, both during the outage and after it (#2081 Codex round 4
// P1).
func TestService_UpdateDeviceState_FailedRestrictiveWriteBlocksWidening(t *testing.T) {
	for _, target := range []ProvisioningState{StateQuarantined, StateFailed} {
		t.Run(string(target), func(t *testing.T) {
			ctx := context.Background()
			svc, vlan, store, id := newStoreBackedService(t, StateQuarantined)
			setStoredDevice(t, svc, store, id, StateInstalling, svc.config.ProvisioningVLAN,
				func(d *DeviceInfo) bool { return d.State == target })
			vlan.set("provisioning")

			// The failed restrictive write.
			require.Error(t, svc.UpdateDeviceState(ctx, id, target, "posture failed"))
			assert.Equal(t, "quarantine", vlan.flows())

			// A widening report during the outage.
			require.Error(t, svc.UpdateDeviceState(ctx, id, StateInstallComplete, "install complete"))
			assert.Equal(t, "quarantine", vlan.flows(), "a widening report in the outage must not lift the restrictive flows")

			// End the outage.
			store.mu.Lock()
			store.failPut = nil
			store.mu.Unlock()

			// A widening report after the outage.
			require.Error(t, svc.UpdateDeviceState(ctx, id, StateInstallComplete, "install complete"))
			assert.Equal(t, "quarantine", vlan.flows(), "widening is refused until the restrictive state is stored")

			// The restrictive retry.
			require.NoError(t, svc.UpdateDeviceState(ctx, id, target, "posture failed"))
			got, err := reloadFrom(t, store).Get(id)
			require.NoError(t, err)
			assert.Equal(t, target, got.State)
		})
	}
}

// A quarantine whose state write fails stays enforced: a later widening
// report in the same outage must not lift it, and after the outage the
// widening move is still refused until the quarantine is stored (#2081
// Codex round 3 P1).
func TestService_QuarantineDevice_FailedWriteThenInstallCompleteStaysQuarantined(t *testing.T) {
	ctx := context.Background()
	svc, vlan, store, id := newStoreBackedService(t, StateQuarantined)
	setStoredDevice(t, svc, store, id, StateInstalling, svc.config.ProvisioningVLAN,
		func(*DeviceInfo) bool { return true })
	vlan.set("provisioning")

	require.Error(t, svc.QuarantineDevice(ctx, id, "posture failed"))
	assert.Equal(t, "quarantine", vlan.flows())

	require.Error(t, svc.UpdateDeviceState(ctx, id, StateInstallComplete, "install complete"))
	assert.Equal(t, "quarantine", vlan.flows(), "two failed writes in one outage must not lift the quarantine")

	store.mu.Lock()
	store.failPut = nil
	store.mu.Unlock()

	require.Error(t, svc.UpdateDeviceState(ctx, id, StateInstallComplete, "install complete"))
	assert.Equal(t, "quarantine", vlan.flows(), "widening is refused until the quarantine is stored")

	require.NoError(t, svc.QuarantineDevice(ctx, id, "posture failed"))
	assert.Equal(t, "quarantine", vlan.flows())
	got, err := reloadFrom(t, store).Get(id)
	require.NoError(t, err)
	assert.Equal(t, StateQuarantined, got.State)
	assert.Equal(t, svc.config.QuarantineVLAN, got.CurrentVLAN)
}

// An unstored quarantine also blocks authorization to production.
func TestService_QuarantineDevice_FailedWriteBlocksAuthorize(t *testing.T) {
	ctx := context.Background()
	svc, vlan, store, id := newStoreBackedService(t, StateQuarantined)
	setStoredDevice(t, svc, store, id, StateAuthorizing, svc.config.ProvisioningVLAN,
		func(d *DeviceInfo) bool { return d.State == StateQuarantined })
	vlan.set("provisioning")

	require.Error(t, svc.QuarantineDevice(ctx, id, "posture failed"))
	assert.Equal(t, "quarantine", vlan.flows())

	require.Error(t, svc.AuthorizeDevice(ctx, id, 200))
	assert.Equal(t, "quarantine", vlan.flows(), "an unstored quarantine must block production access")
}
