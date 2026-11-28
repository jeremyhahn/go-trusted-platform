package pxe

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ctxHonouringVLAN delegates to the recording fake but, like the OVSDB-backed
// flow manager, returns ctx.Err() from every Apply*Flows call whose context
// is done. refuseProvisioning and refuseAuthorized make the matching call
// fail, so a test can refuse a rollback restore.
type ctxHonouringVLAN struct {
	*recordingFlowsVLAN
	mu                 sync.Mutex
	refuseProvisioning bool
	refuseAuthorized   bool
}

var errFlowsRefused = errors.New("flows refused")

func (c *ctxHonouringVLAN) ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.recordingFlowsVLAN.ApplyQuarantineFlows(ctx, portID, mac)
}

func (c *ctxHonouringVLAN) ApplyProvisioningFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	refuse := c.refuseProvisioning
	c.mu.Unlock()
	if refuse {
		return errFlowsRefused
	}
	return c.recordingFlowsVLAN.ApplyProvisioningFlows(ctx, portID, mac)
}

func (c *ctxHonouringVLAN) ApplyAuthorizedFlows(ctx context.Context, portID string, mac net.HardwareAddr, vlanID uint16) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	refuse := c.refuseAuthorized
	c.mu.Unlock()
	if refuse {
		return errFlowsRefused
	}
	return c.recordingFlowsVLAN.ApplyAuthorizedFlows(ctx, portID, mac, vlanID)
}

// cancelThenFail returns a store hook that cancels the request context and
// then fails the write when match holds: the request expired while the
// datastore write was pending.
func cancelThenFail(cancel context.CancelFunc, match func(*DeviceInfo) bool) func(*DeviceInfo) bool {
	return func(d *DeviceInfo) bool {
		if !match(d) {
			return false
		}
		cancel()
		return true
	}
}

func TestService_AuthorizeDevice_CancelledDuringFailedWriteUndoesFlows(t *testing.T) {
	svc, rec, store, id := newStoreBackedService(t, StateAuthorized)
	vlan := &ctxHonouringVLAN{recordingFlowsVLAN: rec}
	svc.vlanManager = vlan

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setStoredDevice(t, svc, store, id, StateAuthorizing, svc.config.ProvisioningVLAN,
		cancelThenFail(cancel, func(d *DeviceInfo) bool { return d.State == StateAuthorized }))
	vlan.set("provisioning")

	require.Error(t, svc.AuthorizeDevice(ctx, id, 200))
	require.Error(t, ctx.Err(), "the request context must be cancelled by the failing write")
	assert.Equal(t, "provisioning", vlan.flows(),
		"a request cancelled during the failed write must not leave production access")

	got, err := svc.stateManager.Get(id)
	require.NoError(t, err)
	assert.Equal(t, StateAuthorizing, got.State)
}

func TestService_UpdateDeviceState_CancelledDuringFailedWideningWriteRestoresQuarantine(t *testing.T) {
	svc, rec, store, id := newStoreBackedService(t, StateQuarantined)
	vlan := &ctxHonouringVLAN{recordingFlowsVLAN: rec}
	svc.vlanManager = vlan

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setStoredDevice(t, svc, store, id, StateDiscovered, svc.config.QuarantineVLAN,
		cancelThenFail(cancel, func(d *DeviceInfo) bool { return d.State == StateBooting }))
	vlan.set("quarantine")

	require.Error(t, svc.UpdateDeviceState(ctx, id, StateBooting, "pxe boot"))
	require.Error(t, ctx.Err(), "the request context must be cancelled by the failing write")
	assert.Equal(t, "quarantine", vlan.flows(),
		"a request cancelled during the failed write must not leave provisioning access")

	got, err := svc.stateManager.Get(id)
	require.NoError(t, err)
	assert.Equal(t, StateDiscovered, got.State)
}

func TestService_RollbackRestoreFailureFallsBackToQuarantine(t *testing.T) {
	t.Run("authorize undo", func(t *testing.T) {
		svc, rec, store, id := newStoreBackedService(t, StateAuthorized)
		vlan := &ctxHonouringVLAN{recordingFlowsVLAN: rec, refuseProvisioning: true}
		svc.vlanManager = vlan
		setStoredDevice(t, svc, store, id, StateAuthorizing, svc.config.ProvisioningVLAN,
			func(d *DeviceInfo) bool { return d.State == StateAuthorized })
		vlan.set("provisioning")

		require.Error(t, svc.AuthorizeDevice(context.Background(), id, 200))
		assert.Equal(t, "quarantine", vlan.flows(),
			"a refused undo must fail closed to the quarantine flows")
	})

	t.Run("update restore", func(t *testing.T) {
		svc, rec, store, id := newStoreBackedService(t, StateQuarantined)
		vlan := &ctxHonouringVLAN{recordingFlowsVLAN: rec}
		svc.vlanManager = vlan
		setStoredDevice(t, svc, store, id, StateBooting, svc.config.ProvisioningVLAN,
			func(d *DeviceInfo) bool { return d.State == StateInstalling })
		vlan.set("provisioning")

		// The forward move applies flows first; refuse only the restore,
		// which re-applies the provisioning flows of the booting device.
		store.mu.Lock()
		hook := store.failPut
		store.failPut = func(d *DeviceInfo) bool {
			if !hook(d) {
				return false
			}
			vlan.mu.Lock()
			vlan.refuseProvisioning = true
			vlan.mu.Unlock()
			return true
		}
		store.mu.Unlock()

		require.Error(t, svc.UpdateDeviceState(context.Background(), id, StateInstalling, "install"))
		assert.Equal(t, "quarantine", vlan.flows(),
			"a refused restore must fail closed to the quarantine flows")
	})
}

// deadlineRestoreVLAN is a ctxHonouringVLAN whose refused provisioning
// restore waits for its context's deadline before it returns, so the
// rollback context is spent when the quarantine fallback runs.
type deadlineRestoreVLAN struct {
	*ctxHonouringVLAN
}

func (d *deadlineRestoreVLAN) ApplyProvisioningFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	d.mu.Lock()
	refuse := d.refuseProvisioning
	d.mu.Unlock()
	if refuse {
		<-ctx.Done()
		return ctx.Err()
	}
	return d.ctxHonouringVLAN.ApplyProvisioningFlows(ctx, portID, mac)
}

// shortenRollbackTimeout makes the rollback deadline expire quickly.
func shortenRollbackTimeout(t *testing.T) {
	t.Helper()
	old := rollbackTimeout
	rollbackTimeout = 20 * time.Millisecond
	t.Cleanup(func() { rollbackTimeout = old })
}

// The quarantine fallback must not reuse a rollback context the failed
// restore exhausted (#2081 Codex P1).
func TestService_FailClosedGetsFreshContextAfterRollbackDeadline(t *testing.T) {
	t.Run("authorize undo", func(t *testing.T) {
		shortenRollbackTimeout(t)
		svc, rec, store, id := newStoreBackedService(t, StateAuthorized)
		vlan := &deadlineRestoreVLAN{&ctxHonouringVLAN{recordingFlowsVLAN: rec, refuseProvisioning: true}}
		svc.vlanManager = vlan
		setStoredDevice(t, svc, store, id, StateAuthorizing, svc.config.ProvisioningVLAN,
			func(d *DeviceInfo) bool { return d.State == StateAuthorized })
		vlan.set("provisioning")

		require.Error(t, svc.AuthorizeDevice(context.Background(), id, 200))
		assert.Equal(t, "quarantine", vlan.flows(),
			"an undo that ran out its deadline must still fail closed to the quarantine flows")
	})

	t.Run("update restore", func(t *testing.T) {
		shortenRollbackTimeout(t)
		svc, rec, store, id := newStoreBackedService(t, StateQuarantined)
		vlan := &deadlineRestoreVLAN{&ctxHonouringVLAN{recordingFlowsVLAN: rec}}
		svc.vlanManager = vlan
		setStoredDevice(t, svc, store, id, StateBooting, svc.config.ProvisioningVLAN,
			func(d *DeviceInfo) bool { return d.State == StateInstalling })
		vlan.set("provisioning")

		store.mu.Lock()
		hook := store.failPut
		store.failPut = func(d *DeviceInfo) bool {
			if !hook(d) {
				return false
			}
			vlan.mu.Lock()
			vlan.refuseProvisioning = true
			vlan.mu.Unlock()
			return true
		}
		store.mu.Unlock()

		require.Error(t, svc.UpdateDeviceState(context.Background(), id, StateInstalling, "install"))
		assert.Equal(t, "quarantine", vlan.flows(),
			"a restore that ran out its deadline must still fail closed to the quarantine flows")
	})
}
