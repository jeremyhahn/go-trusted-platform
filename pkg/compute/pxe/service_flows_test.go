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

package pxe

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	flowsProvisioning = "provisioning"
	flowsQuarantine   = "quarantine"
)

// errFlowWrite is the failure flowRecorder returns when told to fail.
type errFlowWrite struct{}

func (errFlowWrite) Error() string { return "flow write refused" }

// flowRecorder records the provisioning and quarantine flow writes the
// service makes, in order. With hold set, the first provisioning write
// closes entered and blocks until hold is closed.
type flowRecorder struct {
	VLANIntegration

	mu    sync.Mutex
	flows []string
	fail  bool

	hold    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (r *flowRecorder) ApplyQuarantineFlows(context.Context, string, net.HardwareAddr) error {
	return r.record(flowsQuarantine)
}

func (r *flowRecorder) ApplyProvisioningFlows(context.Context, string, net.HardwareAddr) error {
	if r.hold != nil {
		held := false
		r.once.Do(func() { held = true })
		if held {
			close(r.entered)
			<-r.hold
		}
	}
	return r.record(flowsProvisioning)
}

func (r *flowRecorder) record(kind string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errFlowWrite{}
	}
	r.flows = append(r.flows, kind)
	return nil
}

// since returns the flow writes recorded after the first n.
func (r *flowRecorder) since(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.flows[n:]...)
}

func (r *flowRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.flows)
}

func flowRecordingService(t *testing.T, recorder *flowRecorder) *service {
	t.Helper()
	recorder.VLANIntegration = NewNoopVLANIntegration(testNetPlan)
	svc := &service{
		logger:       logging.DefaultLogger(),
		stateManager: NewStateManager(),
		vlanManager:  recorder,
		config:       createTestConfig(),
	}
	svc.initialized.Store(true)
	return svc
}

// TestService_CompleteInstallation_OnlyTheWinnerWritesFlows races success and
// failure callbacks for one installation: the one completion that wins the
// swap is the only flow write, and it matches the state the device reports
// (Codex review 7988). A refused callback that wrote flows would leave a
// device reporting install_complete on quarantine flows, or failed on
// provisioning ones.
func TestService_CompleteInstallation_OnlyTheWinnerWritesFlows(t *testing.T) {
	fingerprint := CertificateSHA256([]byte("installer certificate"))
	want := map[ProvisioningState]string{
		StateInstallComplete: flowsProvisioning,
		StateFailed:          flowsQuarantine,
	}
	for round := 0; round < 20; round++ {
		recorder := &flowRecorder{}
		svc := flowRecordingService(t, recorder)
		ctx := context.Background()
		device := installingTestDevice(t, svc, fingerprint)
		before := recorder.count()

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(success bool) {
				defer wg.Done()
				err := svc.CompleteInstallation(ctx, device.ID, fingerprint, success, "done")
				if err != nil {
					var notBound ErrInstallationNotBound
					assert.ErrorAs(t, err, &notBound, "round %d", round)
				}
			}(i%2 == 0)
		}
		wg.Wait()

		retrieved, err := svc.GetDevice(ctx, device.ID)
		require.NoError(t, err)
		require.Contains(t, want, retrieved.State, "round %d", round)
		assert.Equal(t, []string{want[retrieved.State]}, recorder.since(before), "round %d", round)
	}
}

// TestService_CompleteInstallation_RacingQuarantineKeepsQuarantineFlows
// holds a winning success callback inside its flow write while an operator
// quarantines the device: the quarantine waits for the device lock, so its
// flows land last and match the quarantined state. Before the fix the
// success callback wrote its flows before its swap, so it could overwrite
// the quarantine flows of a transition it then lost.
func TestService_CompleteInstallation_RacingQuarantineKeepsQuarantineFlows(t *testing.T) {
	fingerprint := CertificateSHA256([]byte("installer certificate"))
	recorder := &flowRecorder{}
	svc := flowRecordingService(t, recorder)
	ctx := context.Background()
	device := installingTestDevice(t, svc, fingerprint)
	before := recorder.count()
	recorder.hold = make(chan struct{})
	recorder.entered = make(chan struct{})

	completed := make(chan error, 1)
	go func() {
		completed <- svc.CompleteInstallation(ctx, device.ID, fingerprint, true, "done")
	}()
	<-recorder.entered

	quarantined := make(chan error, 1)
	go func() {
		quarantined <- svc.QuarantineDevice(ctx, device.ID, "operator")
	}()
	close(recorder.hold)

	require.NoError(t, <-completed)
	require.NoError(t, <-quarantined)
	retrieved, err := svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, StateQuarantined, retrieved.State)
	assert.Equal(t, []string{flowsProvisioning, flowsQuarantine}, recorder.since(before))
}

// TestService_CompleteInstallation_RacingQuarantine races one success
// callback against an operator quarantine, unheld: whichever order they run
// in, the device ends quarantined on quarantine flows, and a refused
// completion wrote no flows at all.
func TestService_CompleteInstallation_RacingQuarantine(t *testing.T) {
	fingerprint := CertificateSHA256([]byte("installer certificate"))
	for round := 0; round < 20; round++ {
		recorder := &flowRecorder{}
		svc := flowRecordingService(t, recorder)
		ctx := context.Background()
		device := installingTestDevice(t, svc, fingerprint)
		before := recorder.count()

		var completeErr, quarantineErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			completeErr = svc.CompleteInstallation(ctx, device.ID, fingerprint, true, "done")
		}()
		go func() {
			defer wg.Done()
			quarantineErr = svc.QuarantineDevice(ctx, device.ID, "operator")
		}()
		wg.Wait()

		require.NoError(t, quarantineErr, "round %d", round)
		retrieved, err := svc.GetDevice(ctx, device.ID)
		require.NoError(t, err)
		assert.Equal(t, StateQuarantined, retrieved.State, "round %d", round)
		if completeErr == nil {
			assert.Equal(t, []string{flowsProvisioning, flowsQuarantine}, recorder.since(before), "round %d", round)
			continue
		}
		var notBound ErrInstallationNotBound
		require.ErrorAs(t, completeErr, &notBound, "round %d", round)
		assert.Equal(t, []string{flowsQuarantine}, recorder.since(before), "round %d", round)
	}
}

// TestService_CompleteInstallation_RefusedAfterQuarantineWritesNoFlows ends
// an installation by quarantine first: the late completion is refused and
// leaves the quarantine flows in place.
func TestService_CompleteInstallation_RefusedAfterQuarantineWritesNoFlows(t *testing.T) {
	fingerprint := CertificateSHA256([]byte("installer certificate"))
	recorder := &flowRecorder{}
	svc := flowRecordingService(t, recorder)
	ctx := context.Background()
	device := installingTestDevice(t, svc, fingerprint)
	require.NoError(t, svc.QuarantineDevice(ctx, device.ID, "operator"))
	before := recorder.count()

	err := svc.CompleteInstallation(ctx, device.ID, fingerprint, true, "done")

	var notBound ErrInstallationNotBound
	require.ErrorAs(t, err, &notBound)
	assert.Empty(t, recorder.since(before))
}

// TestService_CompleteInstallation_FlowWriteFailure fails the winner's flow
// write: the caller gets ErrVLANTransitionFailed, and the device stays in the
// state it won with its binding released, so the callback cannot be resent
// against it.
func TestService_CompleteInstallation_FlowWriteFailure(t *testing.T) {
	fingerprint := CertificateSHA256([]byte("installer certificate"))
	for _, tc := range []struct {
		name     string
		success  bool
		state    ProvisioningState
		wantVLAN func(*ServiceConfig) uint16
	}{
		{"success", true, StateInstallComplete, func(c *ServiceConfig) uint16 { return c.ProvisioningVLAN }},
		{"failure", false, StateFailed, func(c *ServiceConfig) uint16 { return c.QuarantineVLAN }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &flowRecorder{}
			svc := flowRecordingService(t, recorder)
			ctx := context.Background()
			device := installingTestDevice(t, svc, fingerprint)
			recorder.fail = true

			err := svc.CompleteInstallation(ctx, device.ID, fingerprint, tc.success, "done")

			var vlanErr ErrVLANTransitionFailed
			require.ErrorAs(t, err, &vlanErr)
			assert.Equal(t, device.ID, vlanErr.DeviceID)
			assert.Equal(t, tc.wantVLAN(svc.config), vlanErr.ToVLAN)
			assert.ErrorIs(t, err, errFlowWrite{})
			retrieved, err := svc.GetDevice(ctx, device.ID)
			require.NoError(t, err)
			assert.Equal(t, tc.state, retrieved.State)
			assert.Empty(t, retrieved.InstallCertificateSHA256)

			var notBound ErrInstallationNotBound
			require.ErrorAs(t, svc.CompleteInstallation(ctx, device.ID, fingerprint, tc.success, "resent"), &notBound)
		})
	}
}

// TestService_LockDevice_DropsReleasedLocks takes and releases locks on two
// devices at once: distinct devices do not contend, and a released lock
// leaves no entry behind, so removed devices do not accumulate.
func TestService_LockDevice_DropsReleasedLocks(t *testing.T) {
	svc := &service{}

	releaseA := svc.lockDevice("device-a")
	releaseB := svc.lockDevice("device-b")
	assert.Len(t, svc.deviceLocks, 2)
	releaseA()
	releaseB()

	assert.Empty(t, svc.deviceLocks)
}

// TestService_LockDevice_SerialisesOneDevice hands one device's lock from a
// holder to a waiter: the waiter acquires only after the holder releases,
// and the entry survives until the waiter releases too.
func TestService_LockDevice_SerialisesOneDevice(t *testing.T) {
	svc := &service{}
	release := svc.lockDevice("device-a")

	acquired := make(chan func())
	go func() { acquired <- svc.lockDevice("device-a") }()

	select {
	case <-acquired:
		t.Fatal("a second holder acquired a held device lock")
	default:
	}
	release()
	releaseWaiter := <-acquired
	svc.deviceLocksMu.Lock()
	assert.Len(t, svc.deviceLocks, 1)
	svc.deviceLocksMu.Unlock()
	releaseWaiter()

	assert.Empty(t, svc.deviceLocks)
}
