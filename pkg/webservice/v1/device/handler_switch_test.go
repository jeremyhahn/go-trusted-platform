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

package device

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newSwitchTestPlan returns a clean activation plan for the switch-path
// tests: the handler derives every physical-switch VLAN from this plan's
// value-copy snapshot, never from a separate lookup. The provisioning
// VLAN 998 is the fail-closed revert target for the physical switch move.
func newSwitchTestPlan(serial string, vlan uint16) *fakeActivationPlan {
	return &fakeActivationPlan{
		serial: serial,
		vlans: policy.ActivationVLANs{
			Admitted:        vlan,
			Provisioning:    998,
			HasProvisioning: true,
		},
	}
}

// newQuarantineTestPlan returns a plan carrying a zone mismatch: activating
// it applies the quarantine policy and the physical port is never opened.
func newQuarantineTestPlan(serial string, vlan uint16) *fakeActivationPlan {
	plan := newSwitchTestPlan(serial, vlan)
	plan.zoneMismatch = &policy.ErrZoneMismatch{
		CertZone:    "tenant-a",
		ProfileZone: "tenant-b",
		Serial:      serial,
	}
	return plan
}

// newSwitchActivateRequest builds an mTLS-style activate request carrying the
// device serial and, when switchName is non-empty, the switch mapping.
func newSwitchActivateRequest(serial, switchName, switchPort string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, serial)
	if switchName != "" {
		ctx = context.WithValue(ctx, contextKeySwitchName, switchName)
		ctx = context.WithValue(ctx, contextKeySwitchPort, switchPort)
	}
	return req.WithContext(ctx)
}

func TestActivate_WithSwitchService_VLANTransition(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	// Record the validate-then-commit call order: the hook precheck and
	// the switch-move validation run first with no side effects, the SDN
	// enforcement is applied next, and only then is the physical port
	// moved — the admitted VLAN never opens onto an unenforced datapath.
	var callOrder []string

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").
		Run(func(mock.Arguments) { callOrder = append(callOrder, "precheck") }).
		Return(plan, nil).Once()
	mockSwitchService.On("Manager", "spine-01").
		Run(func(mock.Arguments) { callOrder = append(callOrder, "manager") }).
		Return(mockSwitchManager, nil)
	mockActivator.On("ActivateDevice", plan).
		Run(func(mock.Arguments) { callOrder = append(callOrder, "activate") }).
		Return(activatedResult(200), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").
		Run(func(mock.Arguments) { callOrder = append(callOrder, "move") }).
		Return(uint16(998), nil).Once()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(200)).Return(nil).Once()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "activated", response.Status)
	assert.Equal(t, uint16(200), response.VLAN)

	assert.Equal(t, []string{"precheck", "manager", "activate", "move"}, callOrder,
		"validate first, enforce the SDN policy next, open the physical port last")

	mockSwitchService.AssertExpectations(t)
	mockSwitchManager.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
}

// TestActivate_PlanSnapshotDrivesSwitchVLANs verifies that every physical
// switch VLAN comes from the activation plan's value-copy snapshot — taken
// at precheck from the same profile the SDN policy was built from — and
// that the profile service is never consulted during activation: a
// concurrently updated profile store cannot desynchronize the physical
// move from the SDN policy.
func TestActivate_PlanSnapshotDrivesSwitchVLANs(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	// The plan's snapshot says admitted VLAN 300; no profile-service
	// expectation is registered at all — a GetBySerial call would fail
	// the test as an unexpected mock invocation.
	plan := newSwitchTestPlan("DEVICE-12345", 300)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(998), nil).Once()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(300)).Return(nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(300), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	assert.Equal(t, http.StatusOK, w.Code)
	mockProfileService.AssertNotCalled(t, "GetBySerial", mock.Anything, mock.Anything)
	mockSwitchManager.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
}

// TestActivate_SwitchVLANFailed_ReturnsError verifies the fail-closed
// physical commit: the SDN policy is enforced first, and when the
// subsequent physical VLAN move fails the port is reverted to the
// provisioning VLAN and VERIFIED by read-back before the transition error
// is surfaced as a 500 — the SDN side is authorized, the physical port
// stays closed.
func TestActivate_SwitchVLANFailed_ReturnsError(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(200), nil).Once()
	mockActivator.On("ReinstateActivation", plan).Return().Once()
	// Initial capture, then the post-failure verification read-back.
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(998), nil).Twice()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(200)).
		Return(errors.New("SSH connection refused")).Once()
	// The revert to the plan's provisioning VLAN.
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(998)).Return(nil).Once()

	// Revert verified: the plain transition error stands.
	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			_, ok := err.(ErrSwitchVLANTransitionFailed)
			return ok
		})).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	mockResponseWriter.AssertExpectations(t)
	mockSwitchManager.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
}

// TestActivate_CommitPreReadFails_FailsClosed verifies that a failed
// pre-move VLAN read during the physical commit — with the SDN side
// already authorized and the port's state unknown — takes the same
// fail-closed path as a failed move: the port is forced to the
// provisioning VLAN and verified by read-back before the plain transition
// error stands.
func TestActivate_CommitPreReadFails_FailsClosed(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(200), nil).Once()
	mockActivator.On("ReinstateActivation", plan).Return().Once()
	// The pre-move read fails: port state unknown, SDN already authorized.
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").
		Return(uint16(0), errors.New("SSH connection refused")).Once()
	// Fail closed: force the provisioning VLAN and verify by read-back.
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(998)).Return(nil).Once()
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(998), nil).Once()
	// The port was never moved to the admitted VLAN.
	// (No SetPortVLAN(200) expectation: such a call fails the test.)

	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			_, ok := err.(ErrSwitchVLANTransitionFailed)
			return ok
		})).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	mockResponseWriter.AssertExpectations(t)
	mockSwitchManager.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
	mockSwitchManager.AssertNotCalled(t, "SetPortVLAN", mock.Anything, "Eth1/3", uint16(200))
}

// TestActivate_FailedCommitThenRetry_Succeeds is the transient-switch
// regression: a first request whose verified physical commit fails
// reinstates the activation (500, retryable), and a second request — with
// no re-enrollment — prechecks again and completes end to end.
func TestActivate_FailedCommitThenRetry_Succeeds(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)

	// Request 1: SDN activation succeeds, the physical move fails with a
	// verified revert, and the plan is reinstated for retry.
	plan1 := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan1, nil).Once()
	mockActivator.On("ActivateDevice", plan1).Return(activatedResult(200), nil).Once()
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(998), nil).Twice()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(200)).
		Return(errors.New("SSH connection refused")).Once()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(998)).Return(nil).Once()
	mockActivator.On("ReinstateActivation", plan1).Return().Once()
	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			_, ok := err.(ErrSwitchVLANTransitionFailed)
			return ok
		})).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	// Request 2: the reinstated activation prechecks again (fresh plan for
	// the same record) and completes without re-enrollment.
	plan2 := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan2, nil).Once()
	mockActivator.On("ActivateDevice", plan2).Return(activatedResult(200), nil).Once()
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(998), nil).Once()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(200)).Return(nil).Once()
	mockActivator.On("FinalizeActivation", plan2).Return().Once()

	w2 := httptest.NewRecorder()
	handler.Activate(w2, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	assert.Equal(t, http.StatusOK, w2.Code)
	var response ActivateResponse
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&response))
	assert.Equal(t, "activated", response.Status)

	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
	mockSwitchManager.AssertExpectations(t)
}

// TestActivate_SDNFailure_SwitchNeverOpened is the fail-open regression the
// review asked for: when the SDN policy application fails, the physical
// switch is never touched — no port ever reaches the admitted VLAN while an
// unenforced datapath is observable. The move was validated up front
// (Manager resolved) but never committed.
func TestActivate_SDNFailure_SwitchNeverOpened(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	hookErr := errors.New("flow installation failed")

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	mockActivator.On("ActivateDevice", plan).Return(nil, hookErr).Once()
	mockResponseWriter.On("Error500", mock.Anything, mock.Anything, hookErr).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
	// The physical switch must never be touched on an SDN failure.
	mockSwitchManager.AssertNotCalled(t, "SetPortVLAN", mock.Anything, mock.Anything, mock.Anything)
	mockSwitchManager.AssertNotCalled(t, "GetPortVLAN", mock.Anything, mock.Anything)
}

// TestActivate_SwitchMoveFailed_Indeterminate verifies the honest failure
// contract: when the post-enforcement move fails and the revert cannot be
// verified (the read-back still shows the admitted VLAN), the response is
// the explicit INDETERMINATE error, not a claim that the port was never
// opened.
func TestActivate_SwitchMoveFailed_Indeterminate(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(200), nil).Once()
	mockActivator.On("ReinstateActivation", plan).Return().Once()
	// Initial capture reads the provisioning VLAN; the verification
	// read-back after the failed move/revert still shows the admitted VLAN.
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(998), nil).Once()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(200)).
		Return(errors.New("SSH sequence failed after vlan command")).Once()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(998)).
		Return(errors.New("SSH connection lost")).Once()
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(200), nil).Once()

	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			_, ok := err.(ErrSwitchPortIndeterminate)
			return ok
		})).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	mockResponseWriter.AssertExpectations(t)
	mockSwitchManager.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
}

func TestActivate_SwitchNotConfigured_ReturnsError(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockSwitchService.On("Manager", "unknown-switch").
		Return(nil, errors.New("manager not found"))

	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			_, ok := err.(ErrSwitchNotConfigured)
			return ok
		})).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "unknown-switch", "Eth1/5"))

	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertNotCalled(t, "ActivateDevice", mock.Anything)
}

// TestActivate_PrecheckFailure_SkipsSwitchMove verifies validate-then-commit:
// a failed precheck (here, a deferred device whose port is still unknown)
// returns 404 without consulting the switch service or running the SDN
// activation — nothing is changed anywhere.
func TestActivate_PrecheckFailure_SkipsSwitchMove(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	hookErr := policy.ErrPortNotRegisteredForDevice{MAC: "3c:ec:ef:00:00:ec"}

	mockActivator.On("PrecheckActivation", "SRV-MGMT-01").Return(nil, hookErr).Once()
	mockResponseWriter.On("Error404", mock.Anything, mock.Anything, hookErr).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("SRV-MGMT-01", "spine-01", "Eth1/3"))

	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
	// The physical port must never be opened for a failed precheck.
	mockSwitchService.AssertNotCalled(t, "Manager")
	mockActivator.AssertNotCalled(t, "ActivateDevice", mock.Anything)
}

// TestActivate_ZoneMismatch_SkipsSwitchMove verifies that a plan carrying a
// zone mismatch leaves the physical port on its current VLAN: moving it to
// the admitted VLAN would defeat the isolation the quarantine policy applies.
func TestActivate_ZoneMismatch_SkipsSwitchMove(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := newQuarantineTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(quarantinedResult(666), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "quarantined", response.Status)
	assert.Equal(t, uint16(666), response.VLAN, "the response carries the VLAN actually applied, not the admitted VLAN")

	mockActivator.AssertExpectations(t)
	// The quarantined device stays on its current VLAN.
	mockSwitchService.AssertNotCalled(t, "Manager")
}

// TestActivate_Superseded_SwitchNeverTouched is the concurrent
// re-enrollment regression at the handler level: the pending activation the
// plan reserved was replaced before it could be consumed, ActivateDevice
// refuses with ErrPendingActivationSuperseded, and — because the physical
// commit runs only after a successful SDN activation — the switch was
// never touched: no port ever reached the admitted VLAN for a profile that
// was never activated.
func TestActivate_Superseded_SwitchNeverTouched(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	hookErr := policy.ErrPendingActivationSuperseded{Serial: "DEVICE-12345"}

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	mockActivator.On("ActivateDevice", plan).Return(nil, hookErr).Once()
	mockResponseWriter.On("Error500", mock.Anything, mock.Anything, hookErr).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
	mockSwitchManager.AssertNotCalled(t, "SetPortVLAN", mock.Anything, mock.Anything, mock.Anything)
	mockSwitchManager.AssertNotCalled(t, "GetPortVLAN", mock.Anything, mock.Anything)
}

// TestActivate_PortAlreadyOnAdmittedVLAN_WarnsAndProceeds verifies the
// anomaly path: a pre-move read showing the port already on the admitted
// VLAN is a divergence between the port state machine and switch reality —
// it is logged at WARN and the activation proceeds.
func TestActivate_PortAlreadyOnAdmittedVLAN_WarnsAndProceeds(t *testing.T) {
	var logBuf bytes.Buffer
	logger := logging.NewLogger(slog.LevelWarn, &logBuf)
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	// The pre-move read already shows the admitted VLAN.
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(200), nil).Once()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(200)).Return(nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(200), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "activated", response.Status)

	// The divergence between the port state machine and switch reality
	// must be alarmed, not silently accepted.
	assert.Contains(t, logBuf.String(), "ALREADY on admitted VLAN")

	mockSwitchManager.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
}

// TestActivate_VLANsNotDistinct_RefusesMove verifies the runtime guard for
// a stored profile whose provisioning and admitted VLANs are equal: the
// fail-closed target would be the admitted VLAN itself, so the physical move
// is refused before the switch is touched and the SDN activation never runs.
func TestActivate_VLANsNotDistinct_RefusesMove(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := &fakeActivationPlan{
		serial: "DEVICE-12345",
		vlans: policy.ActivationVLANs{
			Admitted:        200,
			Provisioning:    200,
			HasProvisioning: true,
		},
	}
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()

	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			notDistinct, ok := err.(device.ErrProfileVLANsNotDistinct)
			return ok && notDistinct.VLAN == 200
		})).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	mockResponseWriter.AssertExpectations(t)
	mockSwitchService.AssertNotCalled(t, "Manager")
	mockActivator.AssertNotCalled(t, "ActivateDevice", mock.Anything)
}

// TestActivate_NoProvisioningNetwork_RefusesMove verifies that a plan whose
// profile has no provisioning network — and therefore no fail-closed revert
// target — refuses the physical VLAN move outright: the switch is never
// touched and the SDN activation never runs.
func TestActivate_NoProvisioningNetwork_RefusesMove(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := &fakeActivationPlan{
		serial: "DEVICE-12345",
		vlans:  policy.ActivationVLANs{Admitted: 200},
	}
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()

	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "no provisioning network")
		})).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	mockResponseWriter.AssertExpectations(t)
	mockSwitchService.AssertNotCalled(t, "Manager")
	mockActivator.AssertNotCalled(t, "ActivateDevice", mock.Anything)
}

// TestActivate_PreviousWasAdmitted_RevertTargetsProvisioning is the
// discriminating fixture for the fail-closed revert target: the port was
// ALREADY on the admitted VLAN before the move (anomaly, WARN logged), the
// move itself fails, and the read-back after the revert still shows the
// admitted VLAN. Under the old "revert to whatever it was" semantics this
// counted as closed (read-back == previous); under the provisioning-VLAN
// rule it MUST be INDETERMINATE, because closed means read-back ==
// provisioning VLAN, full stop.
func TestActivate_PreviousWasAdmitted_RevertTargetsProvisioning(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(200), nil).Once()
	mockActivator.On("ReinstateActivation", plan).Return().Once()
	// Pre-move read: the port is ALREADY on the admitted VLAN (anomaly,
	// WARN logged, proceed).
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(200), nil).Once()
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(200)).
		Return(errors.New("SSH sequence failed after vlan command")).Once()
	// The revert targets the provisioning VLAN (998) unconditionally.
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(998)).Return(nil).Once()
	// The verification read-back still shows the admitted VLAN (200): not
	// the provisioning VLAN, so the outcome is indeterminate — even though
	// 200 is exactly what the port showed before the move.
	mockSwitchManager.On("GetPortVLAN", mock.Anything, "Eth1/3").Return(uint16(200), nil).Once()

	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			_, ok := err.(ErrSwitchPortIndeterminate)
			return ok
		})).Return()

	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
	mockSwitchManager.AssertExpectations(t)
}

func TestActivate_NoSwitchInfo_SkipsVLANMove(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(200), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()

	// No switch context values set - VLAN move should be skipped.
	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "", ""))

	assert.Equal(t, http.StatusOK, w.Code)
	// Switch service Manager should never be called when context has no switch info.
	mockSwitchService.AssertNotCalled(t, "Manager")
	mockActivator.AssertExpectations(t)
}

func TestActivate_NilSwitchService_SkipsVLANMove(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	// No WithSwitchService option - handler has nil switchService.
	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(200), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()

	// Context has switch info but handler has no switch service.
	w := httptest.NewRecorder()
	handler.Activate(w, newSwitchActivateRequest("DEVICE-12345", "spine-01", "Eth1/3"))

	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "activated", response.Status)
	mockActivator.AssertExpectations(t)
}

func TestWithSwitchService_SetsField(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
		WithSwitchService(mockSwitchService),
	)

	require.NotNil(t, handler)
	h, ok := handler.(*Handler)
	require.True(t, ok)
	assert.NotNil(t, h.switchService)
	assert.Equal(t, mockSwitchService, h.switchService)
}

func TestErrSwitchNotConfigured(t *testing.T) {
	err := ErrSwitchNotConfigured{SwitchName: "spine-01"}
	assert.Contains(t, err.Error(), "switch not configured")
	assert.Contains(t, err.Error(), "spine-01")
}

func TestErrSwitchVLANTransitionFailed(t *testing.T) {
	cause := errors.New("SSH connection refused")
	err := ErrSwitchVLANTransitionFailed{
		SwitchName: "spine-01",
		Port:       "Eth1/3",
		VLAN:       200,
		Cause:      cause,
	}
	assert.Contains(t, err.Error(), "switch vlan transition failed")
	assert.Contains(t, err.Error(), "spine-01")
	assert.Contains(t, err.Error(), "Eth1/3")
	assert.Contains(t, err.Error(), "SSH connection refused")
	assert.Equal(t, cause, errors.Unwrap(err))
}

func TestErrSwitchVLANTransitionFailed_NilCause(t *testing.T) {
	err := ErrSwitchVLANTransitionFailed{
		SwitchName: "spine-01",
		Port:       "Eth1/3",
		VLAN:       200,
	}
	assert.Contains(t, err.Error(), "switch vlan transition failed")
	assert.NotContains(t, err.Error(), "cause=")
	assert.Nil(t, errors.Unwrap(err))
}

func TestErrSwitchPortIndeterminate(t *testing.T) {
	cause := errors.New("SSH connection lost")
	err := ErrSwitchPortIndeterminate{
		SwitchName: "spine-01",
		Port:       "Eth1/3",
		Cause:      cause,
	}
	assert.Contains(t, err.Error(), "INDETERMINATE")
	assert.Contains(t, err.Error(), "operator action required")
	assert.Contains(t, err.Error(), "spine-01")
	assert.Contains(t, err.Error(), "Eth1/3")
	assert.Contains(t, err.Error(), "SSH connection lost")
	assert.Equal(t, cause, errors.Unwrap(err))
}

func TestErrSwitchPortIndeterminate_NilCause(t *testing.T) {
	err := ErrSwitchPortIndeterminate{
		SwitchName: "spine-01",
		Port:       "Eth1/3",
	}
	assert.Contains(t, err.Error(), "INDETERMINATE")
	assert.NotContains(t, err.Error(), "cause=")
	assert.Nil(t, errors.Unwrap(err))
}
