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

package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// errInjected is the failure the operator tests inject into a dependency.
type errInjected struct{}

func (errInjected) Error() string { return "injected failure" }

// failingFlowController rejects every batch install, so ApplyZoneFlows fails.
type failingFlowController struct{ nullFlowController }

func (f *failingFlowController) InstallFlows(string, []zoneflows.FlowRule) error {
	return errInjected{}
}

// failingSaveStore is a memDeviceStore whose SaveDevice always fails.
type failingSaveStore struct{ *memDeviceStore }

func (s failingSaveStore) SaveDevice(context.Context, *entities.Device) error {
	return errInjected{}
}

// admitToClass places a port on a port class, as an activated device's port is.
func admitToClass(t *testing.T, qm *QuarantineManager, portID string) {
	t.Helper()
	if err := qm.zoneFlowManager.ApplyPortClassFlows(context.Background(), portID, zone.PortClassHypervisor); err != nil {
		t.Fatalf("admit %s: %v", portID, err)
	}
}

func TestOperatorSuspend_BlocksPortAndRecordsPrior(t *testing.T) {
	store := newMemDeviceStore(&entities.Device{ID: 20, State: entities.DeviceStateAttested})
	engine := newMockPolicyEngine()
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)
	admitToClass(t, qm, "port20")

	device, err := qm.OperatorSuspend(context.Background(), 20, "port20", "maintenance window")
	if err != nil {
		t.Fatalf("OperatorSuspend: %v", err)
	}
	if device.State != entities.DeviceStateSuspended {
		t.Errorf("state = %s, want suspended", device.State)
	}
	if device.StateReason != "operator: maintenance window" {
		t.Errorf("state reason = %q, want the operator-prefixed reason", device.StateReason)
	}
	if device.PriorState != entities.DeviceStateAttested {
		t.Errorf("prior state = %s, want attested", device.PriorState)
	}
	if device.PriorPortClass != string(zone.PortClassHypervisor) {
		t.Errorf("prior port class = %q, want hypervisor", device.PriorPortClass)
	}
	if !engine.blockedPorts["port20"] {
		t.Error("port20 should be blocked")
	}
	if store.devices[20].State != entities.DeviceStateSuspended {
		t.Error("the suspension was not saved")
	}
}

func TestOperatorSuspend_EmptyReasonGetsDefault(t *testing.T) {
	store := newMemDeviceStore(&entities.Device{ID: 21, State: entities.DeviceStateAttested})
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), newMockPolicyEngine())

	device, err := qm.OperatorSuspend(context.Background(), 21, "port21", "")
	if err != nil {
		t.Fatalf("OperatorSuspend: %v", err)
	}
	if device.StateReason != "operator: disabled" {
		t.Errorf("state reason = %q, want %q", device.StateReason, "operator: disabled")
	}
}

func TestOperatorSuspend_KeepsQuarantinedDevicesPriorRecord(t *testing.T) {
	store := newMemDeviceStore(&entities.Device{
		ID: 22, State: entities.DeviceStateQuarantined,
		PriorState: entities.DeviceStateAttested, PriorZone: string(zone.ZoneControlPlane),
	})
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), newMockPolicyEngine())

	device, err := qm.OperatorSuspend(context.Background(), 22, "port22", "escalate")
	if err != nil {
		t.Fatalf("OperatorSuspend: %v", err)
	}
	if device.PriorState != entities.DeviceStateAttested || device.PriorZone != string(zone.ZoneControlPlane) {
		t.Errorf("prior = %s/%q, want the pre-quarantine attested/control-plane record", device.PriorState, device.PriorZone)
	}
}

func TestOperatorSuspend_RejectsWithoutTouchingPort(t *testing.T) {
	for _, state := range []entities.DeviceState{entities.DeviceStateRevoked, entities.DeviceStateSuspended} {
		t.Run(string(state), func(t *testing.T) {
			store := newMemDeviceStore(&entities.Device{ID: 23, State: state})
			engine := newMockPolicyEngine()
			qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

			_, err := qm.OperatorSuspend(context.Background(), 23, "port23", "")
			var invalid entities.ErrInvalidTransition
			if !errors.As(err, &invalid) {
				t.Fatalf("err = %v, want ErrInvalidTransition", err)
			}
			if engine.blockedPorts["port23"] {
				t.Error("a rejected suspend must not block the port")
			}
		})
	}
}

func TestOperatorSuspend_Errors(t *testing.T) {
	t.Run("empty port", func(t *testing.T) {
		qm := buildQM(t, newMemDeviceStore(), resolvedZonesWithQuarantine(), newMockPolicyEngine())
		_, err := qm.OperatorSuspend(context.Background(), 24, "", "")
		var unknown ErrUnknownDevicePort
		if !errors.As(err, &unknown) || unknown.DeviceID != 24 {
			t.Fatalf("err = %v, want ErrUnknownDevicePort for device 24", err)
		}
	})
	t.Run("unknown device", func(t *testing.T) {
		qm := buildQM(t, newMemDeviceStore(), resolvedZonesWithQuarantine(), newMockPolicyEngine())
		_, err := qm.OperatorSuspend(context.Background(), 25, "port25", "")
		var notFound *errQMNotFound
		if !errors.As(err, &notFound) {
			t.Fatalf("err = %v, want the store's not-found error", err)
		}
	})
	t.Run("block fails", func(t *testing.T) {
		store := newMemDeviceStore(&entities.Device{ID: 26, State: entities.DeviceStateAttested})
		engine := newMockPolicyEngine()
		engine.blockPortErr = errInjected{}
		qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

		if _, err := qm.OperatorSuspend(context.Background(), 26, "port26", ""); !errors.As(err, new(errInjected)) {
			t.Fatalf("err = %v, want the block failure", err)
		}
		if store.devices[26].State != entities.DeviceStateAttested {
			t.Errorf("state = %s, want attested when the port was not blocked", store.devices[26].State)
		}
	})
}

// suspendedDevice returns a device suspended from attested on a hypervisor port class.
func suspendedDevice(id uint64) *entities.Device {
	return &entities.Device{
		ID: id, State: entities.DeviceStateSuspended, StateReason: "operator: disabled",
		PriorState: entities.DeviceStateAttested, PriorPortClass: string(zone.PortClassHypervisor),
	}
}

func TestOperatorReadmit_UnblocksIntoQuarantine(t *testing.T) {
	store := newMemDeviceStore(suspendedDevice(30))
	engine := newMockPolicyEngine()
	engine.blockedPorts["port30"] = true
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

	device, err := qm.OperatorReadmit(context.Background(), 30, "port30")
	if err != nil {
		t.Fatalf("OperatorReadmit: %v", err)
	}
	if device.State != entities.DeviceStateQuarantined {
		t.Errorf("state = %s, want quarantined until re-attestation passes", device.State)
	}
	if !strings.HasPrefix(device.StateReason, "operator: ") {
		t.Errorf("state reason = %q, want an operator reason", device.StateReason)
	}
	if engine.blockedPorts["port30"] {
		t.Error("port30 should be unblocked")
	}
	if z, err := qm.zoneFlowManager.GetPortZone("port30"); err != nil || z != zone.ZoneQuarantine {
		t.Errorf("port zone = %q (%v), want quarantine", z, err)
	}
	if device.PriorState != entities.DeviceStateAttested || device.PriorPortClass != string(zone.PortClassHypervisor) {
		t.Error("the prior record must survive re-enable for the re-attestation restore")
	}
}

func TestOperatorReadmit_NotSuspended(t *testing.T) {
	store := newMemDeviceStore(&entities.Device{ID: 31, State: entities.DeviceStateAttested})
	engine := newMockPolicyEngine()
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

	_, err := qm.OperatorReadmit(context.Background(), 31, "port31")
	var notSuspended ErrDeviceNotSuspended
	if !errors.As(err, &notSuspended) || notSuspended.State != entities.DeviceStateAttested {
		t.Fatalf("err = %v, want ErrDeviceNotSuspended from attested", err)
	}
	if store.devices[31].State != entities.DeviceStateAttested {
		t.Error("a rejected re-enable must not change state")
	}
}

func TestOperatorReadmit_PreconditionErrors(t *testing.T) {
	t.Run("empty port", func(t *testing.T) {
		qm := buildQM(t, newMemDeviceStore(suspendedDevice(32)), resolvedZonesWithQuarantine(), newMockPolicyEngine())
		if _, err := qm.OperatorReadmit(context.Background(), 32, ""); !errors.As(err, new(ErrUnknownDevicePort)) {
			t.Fatalf("err = %v, want ErrUnknownDevicePort", err)
		}
	})
	t.Run("unknown device", func(t *testing.T) {
		qm := buildQM(t, newMemDeviceStore(), resolvedZonesWithQuarantine(), newMockPolicyEngine())
		var notFound *errQMNotFound
		if _, err := qm.OperatorReadmit(context.Background(), 33, "port33"); !errors.As(err, &notFound) {
			t.Fatalf("err = %v, want the store's not-found error", err)
		}
	})
	t.Run("no quarantine zone", func(t *testing.T) {
		engine := newMockPolicyEngine()
		engine.blockedPorts["port34"] = true
		qm := buildQM(t, newMemDeviceStore(suspendedDevice(34)), resolvedZonesWithoutQuarantine(), engine)
		if _, err := qm.OperatorReadmit(context.Background(), 34, "port34"); !errors.As(err, new(ErrNoQuarantineZone)) {
			t.Fatalf("err = %v, want ErrNoQuarantineZone", err)
		}
		if !engine.blockedPorts["port34"] {
			t.Error("the port must stay blocked when there is no quarantine zone")
		}
	})
	t.Run("unblock fails", func(t *testing.T) {
		engine := newMockPolicyEngine()
		engine.unblockPortErr = errInjected{}
		store := newMemDeviceStore(suspendedDevice(35))
		qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)
		if _, err := qm.OperatorReadmit(context.Background(), 35, "port35"); !errors.As(err, new(errInjected)) {
			t.Fatalf("err = %v, want the unblock failure", err)
		}
		if store.devices[35].State != entities.DeviceStateSuspended {
			t.Error("state must stay suspended when the port was not unblocked")
		}
	})
}

// newQMWith builds a QuarantineManager over a given flow controller and store.
func newQMWith(t *testing.T, fc *failingFlowController, store DeviceStateStore, engine PolicyEngine) *QuarantineManager {
	t.Helper()
	zones := resolvedZonesWithQuarantine()
	zm, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br-test",
		FlowController: fc,
		PortController: &nullPortController{},
		Plan:           testPlan(t),
		Zones:          zones,
	})
	if err != nil {
		t.Fatalf("NewZoneFlowManager: %v", err)
	}
	qm, err := NewQuarantineManager(QuarantineManagerConfig{
		PolicyEngine: engine, ZoneFlowManager: zm, ResolvedZones: zones, DeviceStateStore: store,
	})
	if err != nil {
		t.Fatalf("NewQuarantineManager: %v", err)
	}
	return qm
}

func TestOperatorReadmit_FailureAfterUnblockReblocks(t *testing.T) {
	t.Run("zone flows fail", func(t *testing.T) {
		engine := newMockPolicyEngine()
		engine.blockedPorts["port36"] = true
		store := newMemDeviceStore(suspendedDevice(36))
		qm := newQMWith(t, &failingFlowController{}, store, engine)

		if _, err := qm.OperatorReadmit(context.Background(), 36, "port36"); err == nil {
			t.Fatal("expected the zone flow failure")
		}
		if !engine.blockedPorts["port36"] {
			t.Error("a failed re-enable must leave the port blocked")
		}
		if store.devices[36].State != entities.DeviceStateSuspended {
			t.Error("state must stay suspended after a failed re-enable")
		}
	})
	t.Run("save fails", func(t *testing.T) {
		engine := newMockPolicyEngine()
		engine.blockedPorts["port37"] = true
		store := failingSaveStore{newMemDeviceStore(suspendedDevice(37))}
		qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

		if _, err := qm.OperatorReadmit(context.Background(), 37, "port37"); !errors.As(err, new(errInjected)) {
			t.Fatalf("err = %v, want the save failure", err)
		}
		if !engine.blockedPorts["port37"] {
			t.Error("a failed re-enable must leave the port blocked")
		}
	})
}

// TestOperatorDisableEnable_ReattestationRestores drives the whole operator
// loop for a device disabled before it first attested: disable, re-enable
// into quarantine, then a passing re-attestation restores the port class and
// lands the device attested (its recorded "activated" is not reachable from
// quarantine).
func TestOperatorDisableEnable_ReattestationRestores(t *testing.T) {
	store := newMemDeviceStore(&entities.Device{ID: 40, State: entities.DeviceStateActivated})
	engine := newMockPolicyEngine()
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)
	admitToClass(t, qm, "port40")
	ctx := context.Background()

	if _, err := qm.OperatorSuspend(ctx, 40, "port40", "lost"); err != nil {
		t.Fatalf("OperatorSuspend: %v", err)
	}
	if _, err := qm.OperatorReadmit(ctx, 40, "port40"); err != nil {
		t.Fatalf("OperatorReadmit: %v", err)
	}
	if err := qm.HandleRestoreAttestation(ctx, 40, "port40"); err != nil {
		t.Fatalf("HandleRestoreAttestation: %v", err)
	}
	saved := store.devices[40]
	if saved.State != entities.DeviceStateAttested {
		t.Errorf("state = %s, want attested after a passing re-attestation", saved.State)
	}
	if c, err := qm.zoneFlowManager.GetPortClass("port40"); err != nil || c != zone.PortClassHypervisor {
		t.Errorf("port class = %q (%v), want the hypervisor class restored", c, err)
	}
}

func TestHandleViolation_WarningLeavesSuspendedDeviceSuspended(t *testing.T) {
	store := newMemDeviceStore(suspendedDevice(41))
	engine := newMockPolicyEngine()
	engine.blockedPorts["port41"] = true
	qm := buildQM(t, store, resolvedZonesWithQuarantine(), engine)

	ev := &entities.ViolationEvent{
		DeviceID: 41, Severity: entities.ViolationSeverityWarning,
		Source: entities.ViolationSourceAttestation, Detail: "PCR[7] mismatch", OccurredAt: time.Now(),
	}
	if err := qm.HandleViolation(context.Background(), ev, "port41"); err != nil {
		t.Fatalf("HandleViolation: %v", err)
	}
	if store.devices[41].State != entities.DeviceStateSuspended {
		t.Errorf("state = %s, want suspended", store.devices[41].State)
	}
	if _, err := qm.zoneFlowManager.GetPortZone("port41"); err == nil {
		t.Error("a suspended device's port must not be moved to the quarantine zone")
	}
}

func TestErrDeviceNotSuspended_Error(t *testing.T) {
	msg := ErrDeviceNotSuspended{DeviceID: 7, State: entities.DeviceStateAttested}.Error()
	if !strings.Contains(msg, "7") || !strings.Contains(msg, "attested") {
		t.Errorf("message %q should name the device and its state", msg)
	}
}
