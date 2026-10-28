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
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStateManager(t *testing.T) {
	sm := NewStateManager()

	assert.NotNil(t, sm)
	assert.NotNil(t, sm.handlers)
	assert.Equal(t, 0, len(sm.handlers))
}

func TestIsValidTransition(t *testing.T) {
	tests := []struct {
		name     string
		from     ProvisioningState
		to       ProvisioningState
		expected bool
	}{
		// Valid transitions for each state
		{"unknown_to_discovered", StateUnknown, StateDiscovered, true},
		{"unknown_to_failed", StateUnknown, StateFailed, true},
		{"discovered_to_booting", StateDiscovered, StateBooting, true},
		{"discovered_to_quarantined", StateDiscovered, StateQuarantined, true},
		{"discovered_to_failed", StateDiscovered, StateFailed, true},
		{"booting_to_installing", StateBooting, StateInstalling, true},
		{"booting_to_quarantined", StateBooting, StateQuarantined, true},
		{"booting_to_failed", StateBooting, StateFailed, true},
		{"installing_to_install_complete", StateInstalling, StateInstallComplete, true},
		{"installing_to_quarantined", StateInstalling, StateQuarantined, true},
		{"installing_to_failed", StateInstalling, StateFailed, true},
		{"install_complete_to_enrolling", StateInstallComplete, StateEnrolling, true},
		{"install_complete_to_quarantined", StateInstallComplete, StateQuarantined, true},
		{"install_complete_to_failed", StateInstallComplete, StateFailed, true},
		{"enrolling_to_enrolled", StateEnrolling, StateEnrolled, true},
		{"enrolling_to_quarantined", StateEnrolling, StateQuarantined, true},
		{"enrolling_to_failed", StateEnrolling, StateFailed, true},
		{"enrolled_to_authorizing", StateEnrolled, StateAuthorizing, true},
		{"enrolled_to_quarantined", StateEnrolled, StateQuarantined, true},
		{"enrolled_to_failed", StateEnrolled, StateFailed, true},
		{"authorizing_to_authorized", StateAuthorizing, StateAuthorized, true},
		{"authorizing_to_quarantined", StateAuthorizing, StateQuarantined, true},
		{"authorizing_to_failed", StateAuthorizing, StateFailed, true},
		{"authorized_to_quarantined", StateAuthorized, StateQuarantined, true},
		{"authorized_to_failed", StateAuthorized, StateFailed, true},
		{"failed_to_discovered", StateFailed, StateDiscovered, true},
		{"failed_to_quarantined", StateFailed, StateQuarantined, true},
		{"quarantined_to_discovered", StateQuarantined, StateDiscovered, true},
		{"quarantined_to_failed", StateQuarantined, StateFailed, true},

		// Invalid transitions
		{"unknown_to_authorized", StateUnknown, StateAuthorized, false},
		{"discovered_to_enrolled", StateDiscovered, StateEnrolled, false},
		{"authorized_to_booting", StateAuthorized, StateBooting, false},
		{"invalid_from_state", ProvisioningState("invalid"), StateDiscovered, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidTransition(tt.from, tt.to))
		})
	}
}

func TestStateManager_Register(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
		PortID:     "port-1",
	}

	err := sm.Register(device)
	assert.NoError(t, err)

	// Verify device was registered
	retrieved, err := sm.Get("device-123")
	assert.NoError(t, err)
	assert.Equal(t, "device-123", retrieved.ID)
	assert.Equal(t, mac, retrieved.MACAddress)
}

func TestStateManager_Register_SetsTimestamps(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	before := time.Now()
	err := sm.Register(device)
	assert.NoError(t, err)
	after := time.Now()

	retrieved, err := sm.Get("device-123")
	assert.NoError(t, err)

	assert.True(t, retrieved.CreatedAt.After(before) || retrieved.CreatedAt.Equal(before))
	assert.True(t, retrieved.CreatedAt.Before(after) || retrieved.CreatedAt.Equal(after))
	assert.True(t, retrieved.UpdatedAt.After(before) || retrieved.UpdatedAt.Equal(before))
	assert.True(t, retrieved.StateChangedAt.After(before) || retrieved.StateChangedAt.Equal(before))
}

func TestStateManager_Register_PreservesExistingTimestamps(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	customTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	device := &DeviceInfo{
		ID:             "device-123",
		MACAddress:     mac,
		State:          StateDiscovered,
		CreatedAt:      customTime,
		UpdatedAt:      customTime,
		StateChangedAt: customTime,
	}

	err := sm.Register(device)
	assert.NoError(t, err)

	retrieved, err := sm.Get("device-123")
	assert.NoError(t, err)

	assert.Equal(t, customTime, retrieved.CreatedAt)
	assert.Equal(t, customTime, retrieved.UpdatedAt)
	assert.Equal(t, customTime, retrieved.StateChangedAt)
}

func TestStateManager_Register_NilDevice(t *testing.T) {
	sm := NewStateManager()

	err := sm.Register(nil)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
	assert.Equal(t, "device is nil", macErr.Reason)
}

func TestStateManager_Register_EmptyMAC(t *testing.T) {
	sm := NewStateManager()

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: nil,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
	assert.Equal(t, "MAC address is empty", macErr.Reason)
}

func TestStateManager_Register_EmptyDeviceID(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
	assert.Equal(t, "device ID is empty", macErr.Reason)
}

func TestStateManager_Register_DuplicateMAC(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device1 := &DeviceInfo{
		ID:         "device-1",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	device2 := &DeviceInfo{
		ID:         "device-2",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device1)
	assert.NoError(t, err)

	err = sm.Register(device2)
	assert.Error(t, err)

	var existsErr ErrDeviceAlreadyExists
	assert.True(t, errors.As(err, &existsErr))
	assert.Equal(t, "device-1", existsErr.DeviceID)
	assert.Equal(t, mac.String(), existsErr.MACAddress)
}

func TestStateManager_Register_DuplicateID(t *testing.T) {
	sm := NewStateManager()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	device1 := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac1,
		State:      StateDiscovered,
	}

	device2 := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac2,
		State:      StateDiscovered,
	}

	err := sm.Register(device1)
	assert.NoError(t, err)

	err = sm.Register(device2)
	assert.Error(t, err)

	var existsErr ErrDeviceAlreadyExists
	assert.True(t, errors.As(err, &existsErr))
	assert.Equal(t, "device-123", existsErr.DeviceID)
}

func TestStateManager_Unregister(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	err = sm.Unregister("device-123")
	assert.NoError(t, err)

	// Verify device was removed
	_, err = sm.Get("device-123")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))

	// Verify MAC was removed from byMAC map
	_, err = sm.GetByMAC(mac)
	assert.Error(t, err)
}

func TestStateManager_Unregister_EmptyID(t *testing.T) {
	sm := NewStateManager()

	err := sm.Unregister("")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestStateManager_Unregister_NotFound(t *testing.T) {
	sm := NewStateManager()

	err := sm.Unregister("nonexistent")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
	assert.Equal(t, "nonexistent", notFoundErr.DeviceID)
}

func TestStateManager_Get(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
		PortID:     "port-1",
	}

	err := sm.Register(device)
	require.NoError(t, err)

	retrieved, err := sm.Get("device-123")
	assert.NoError(t, err)
	assert.Equal(t, "device-123", retrieved.ID)
	assert.Equal(t, mac, retrieved.MACAddress)
	assert.Equal(t, StateDiscovered, retrieved.State)
	assert.Equal(t, "port-1", retrieved.PortID)
}

func TestStateManager_Get_EmptyID(t *testing.T) {
	sm := NewStateManager()

	_, err := sm.Get("")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestStateManager_Get_NotFound(t *testing.T) {
	sm := NewStateManager()

	_, err := sm.Get("nonexistent")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
	assert.Equal(t, "nonexistent", notFoundErr.DeviceID)
}

func TestStateManager_Get_ReturnsCopy(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	retrieved1, _ := sm.Get("device-123")
	retrieved1.State = StateBooting

	retrieved2, _ := sm.Get("device-123")
	assert.Equal(t, StateDiscovered, retrieved2.State)
}

func TestStateManager_GetByMAC(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	retrieved, err := sm.GetByMAC(mac)
	assert.NoError(t, err)
	assert.Equal(t, "device-123", retrieved.ID)
	assert.Equal(t, mac, retrieved.MACAddress)
}

func TestStateManager_GetByMAC_EmptyMAC(t *testing.T) {
	sm := NewStateManager()

	_, err := sm.GetByMAC(nil)
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestStateManager_GetByMAC_NotFound(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	_, err := sm.GetByMAC(mac)
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
	assert.Equal(t, mac.String(), notFoundErr.MACAddress)
}

func TestStateManager_List_NoFilter(t *testing.T) {
	sm := NewStateManager()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	device1 := &DeviceInfo{ID: "device-1", MACAddress: mac1, State: StateDiscovered}
	device2 := &DeviceInfo{ID: "device-2", MACAddress: mac2, State: StateBooting}

	err := sm.Register(device1)
	require.NoError(t, err)
	err = sm.Register(device2)
	require.NoError(t, err)

	devices := sm.List(nil)
	assert.Len(t, devices, 2)
}

func TestStateManager_List_FilterByState(t *testing.T) {
	sm := NewStateManager()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	device1 := &DeviceInfo{ID: "device-1", MACAddress: mac1, State: StateDiscovered}
	device2 := &DeviceInfo{ID: "device-2", MACAddress: mac2, State: StateBooting}

	err := sm.Register(device1)
	require.NoError(t, err)
	err = sm.Register(device2)
	require.NoError(t, err)

	devices := sm.List(&DeviceFilter{State: StateDiscovered})
	assert.Len(t, devices, 1)
	assert.Equal(t, "device-1", devices[0].ID)
}

func TestStateManager_List_FilterByVLAN(t *testing.T) {
	sm := NewStateManager()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	device1 := &DeviceInfo{ID: "device-1", MACAddress: mac1, State: StateDiscovered, CurrentVLAN: 100}
	device2 := &DeviceInfo{ID: "device-2", MACAddress: mac2, State: StateBooting, CurrentVLAN: 200}

	err := sm.Register(device1)
	require.NoError(t, err)
	err = sm.Register(device2)
	require.NoError(t, err)

	devices := sm.List(&DeviceFilter{VLAN: 100})
	assert.Len(t, devices, 1)
	assert.Equal(t, "device-1", devices[0].ID)
}

func TestStateManager_List_FilterByMAC(t *testing.T) {
	sm := NewStateManager()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	device1 := &DeviceInfo{ID: "device-1", MACAddress: mac1, State: StateDiscovered}
	device2 := &DeviceInfo{ID: "device-2", MACAddress: mac2, State: StateBooting}

	err := sm.Register(device1)
	require.NoError(t, err)
	err = sm.Register(device2)
	require.NoError(t, err)

	devices := sm.List(&DeviceFilter{MACAddress: "00:11:22:33:44:55"})
	assert.Len(t, devices, 1)
	assert.Equal(t, "device-1", devices[0].ID)
}

func TestStateManager_List_WithLimit(t *testing.T) {
	sm := NewStateManager()

	for i := 0; i < 5; i++ {
		// Generate valid MAC addresses: 00:11:22:33:44:50, 51, 52, 53, 54
		mac, _ := net.ParseMAC(fmt.Sprintf("00:11:22:33:44:%02x", 0x50+i))
		device := &DeviceInfo{
			ID:         fmt.Sprintf("device-%d", i),
			MACAddress: mac,
			State:      StateDiscovered,
		}
		err := sm.Register(device)
		require.NoError(t, err)
	}

	devices := sm.List(&DeviceFilter{Limit: 3})
	assert.Len(t, devices, 3)
}

func TestStateManager_List_WithOffset(t *testing.T) {
	sm := NewStateManager()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	mac3, _ := net.ParseMAC("00:11:22:33:44:77")

	device1 := &DeviceInfo{ID: "device-1", MACAddress: mac1, State: StateDiscovered}
	device2 := &DeviceInfo{ID: "device-2", MACAddress: mac2, State: StateDiscovered}
	device3 := &DeviceInfo{ID: "device-3", MACAddress: mac3, State: StateDiscovered}

	err := sm.Register(device1)
	require.NoError(t, err)
	err = sm.Register(device2)
	require.NoError(t, err)
	err = sm.Register(device3)
	require.NoError(t, err)

	// Note: sync.Map iteration order is not guaranteed, so we just check length
	devices := sm.List(&DeviceFilter{Offset: 1})
	assert.Len(t, devices, 2)
}

func TestStateManager_List_Empty(t *testing.T) {
	sm := NewStateManager()

	devices := sm.List(nil)
	assert.Empty(t, devices)
}

func TestStateManager_Transition(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	err = sm.Transition("device-123", StateBooting, "test transition")
	assert.NoError(t, err)

	retrieved, err := sm.Get("device-123")
	assert.NoError(t, err)
	assert.Equal(t, StateBooting, retrieved.State)
	assert.Equal(t, "test transition", retrieved.StateReason)
}

func TestStateManager_Transition_EmptyID(t *testing.T) {
	sm := NewStateManager()

	err := sm.Transition("", StateBooting, "test")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestStateManager_Transition_InvalidState(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	err = sm.Transition("device-123", ProvisioningState("invalid_state"), "test")
	assert.Error(t, err)

	var invalidErr ErrInvalidState
	assert.True(t, errors.As(err, &invalidErr))
}

func TestStateManager_Transition_DeviceNotFound(t *testing.T) {
	sm := NewStateManager()

	err := sm.Transition("nonexistent", StateBooting, "test")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestStateManager_Transition_InvalidTransition(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	// Skip from discovered to authorized (invalid)
	err = sm.Transition("device-123", StateAuthorized, "test")
	assert.Error(t, err)

	var transitionErr ErrInvalidStateTransition
	assert.True(t, errors.As(err, &transitionErr))
}

func TestStateManager_UpdateDevice(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
		RetryCount: 0,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	err = sm.UpdateDevice("device-123", func(d *DeviceInfo) error {
		d.RetryCount = 5
		d.CertificateSerial = "serial-123"
		return nil
	})
	assert.NoError(t, err)

	retrieved, err := sm.Get("device-123")
	assert.NoError(t, err)
	assert.Equal(t, 5, retrieved.RetryCount)
	assert.Equal(t, "serial-123", retrieved.CertificateSerial)
}

func TestStateManager_UpdateDevice_EmptyID(t *testing.T) {
	sm := NewStateManager()

	err := sm.UpdateDevice("", func(d *DeviceInfo) error {
		return nil
	})
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestStateManager_UpdateDevice_NilFunction(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	err = sm.UpdateDevice("device-123", nil)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestStateManager_UpdateDevice_FunctionReturnsError(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	expectedErr := errors.New("update failed")
	err = sm.UpdateDevice("device-123", func(d *DeviceInfo) error {
		return expectedErr
	})
	assert.Equal(t, expectedErr, err)
}

func TestStateManager_UpdateDevice_NotFound(t *testing.T) {
	sm := NewStateManager()

	err := sm.UpdateDevice("nonexistent", func(d *DeviceInfo) error {
		return nil
	})
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

// stateTestEventHandler implements EventHandler for state tests
type stateTestEventHandler struct {
	mu     sync.Mutex
	events []*ProvisioningEvent

	// delivered signals each event so a test can wait for the dispatch
	// goroutine instead of sleeping (#262). Nil is fine: a test that does
	// not wait does not have to set it.
	delivered *eventSignal
}

func (h *stateTestEventHandler) OnEvent(ctx context.Context, event *ProvisioningEvent) {
	h.mu.Lock()
	h.events = append(h.events, event)
	sig := h.delivered
	h.mu.Unlock()

	if sig != nil {
		sig.fire()
	}
}

func (h *stateTestEventHandler) getEvents() []*ProvisioningEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.events
}

func TestStateManager_RegisterEventHandler(t *testing.T) {
	sm := NewStateManager()
	handler := &stateTestEventHandler{delivered: newEventSignal()}

	sm.RegisterEventHandler(handler)

	sm.handlersMu.RLock()
	assert.Len(t, sm.handlers, 1)
	sm.handlersMu.RUnlock()
}

func TestStateManager_RegisterEventHandler_Nil(t *testing.T) {
	sm := NewStateManager()

	sm.RegisterEventHandler(nil)

	sm.handlersMu.RLock()
	assert.Len(t, sm.handlers, 0)
	sm.handlersMu.RUnlock()
}

func TestStateManager_EventEmission(t *testing.T) {
	sm := NewStateManager()
	handler := &stateTestEventHandler{delivered: newEventSignal()}
	sm.RegisterEventHandler(handler)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	err = sm.Transition("device-123", StateBooting, "test transition")
	require.NoError(t, err)

	handler.delivered.await(t, 1)

	events := handler.getEvents()
	assert.Len(t, events, 1)
	assert.Equal(t, "device-123", events[0].DeviceID)
	assert.Equal(t, StateDiscovered, events[0].FromState)
	assert.Equal(t, StateBooting, events[0].ToState)
	assert.Equal(t, EventPXEBootStarted, events[0].EventType)
}

func TestStateManager_Count(t *testing.T) {
	sm := NewStateManager()

	assert.Equal(t, 0, sm.Count())

	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	device1 := &DeviceInfo{ID: "device-1", MACAddress: mac1, State: StateDiscovered}
	device2 := &DeviceInfo{ID: "device-2", MACAddress: mac2, State: StateBooting}

	err := sm.Register(device1)
	require.NoError(t, err)
	assert.Equal(t, 1, sm.Count())

	err = sm.Register(device2)
	require.NoError(t, err)
	assert.Equal(t, 2, sm.Count())
}

func TestStateManager_CountByState(t *testing.T) {
	sm := NewStateManager()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	mac3, _ := net.ParseMAC("00:11:22:33:44:77")

	device1 := &DeviceInfo{ID: "device-1", MACAddress: mac1, State: StateDiscovered}
	device2 := &DeviceInfo{ID: "device-2", MACAddress: mac2, State: StateDiscovered}
	device3 := &DeviceInfo{ID: "device-3", MACAddress: mac3, State: StateBooting}

	err := sm.Register(device1)
	require.NoError(t, err)
	err = sm.Register(device2)
	require.NoError(t, err)
	err = sm.Register(device3)
	require.NoError(t, err)

	assert.Equal(t, 2, sm.CountByState(StateDiscovered))
	assert.Equal(t, 1, sm.CountByState(StateBooting))
	assert.Equal(t, 0, sm.CountByState(StateAuthorized))
}

func TestStateManager_ConcurrentOperations(t *testing.T) {
	sm := NewStateManager()
	var wg sync.WaitGroup
	numDevices := 100

	// Register devices concurrently
	for i := 0; i < numDevices; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			mac := make(net.HardwareAddr, 6)
			mac[0] = 0x00
			mac[1] = 0x11
			mac[2] = 0x22
			mac[3] = 0x33
			mac[4] = byte(idx / 256)
			mac[5] = byte(idx % 256)

			device := &DeviceInfo{
				ID:         fmt.Sprintf("device-%d", idx),
				MACAddress: mac,
				State:      StateDiscovered,
			}
			sm.Register(device)
		}(i)
	}

	wg.Wait()
	assert.Equal(t, numDevices, sm.Count())
}

func TestStateManager_ConcurrentTransitions(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	// Multiple goroutines trying to transition at the same time
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sm.Transition("device-123", StateBooting, "concurrent test")
			if err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// At least one should succeed, others may fail due to state already changed
	assert.GreaterOrEqual(t, successCount, 1)

	// Final state should be booting
	retrieved, err := sm.Get("device-123")
	assert.NoError(t, err)
	assert.Equal(t, StateBooting, retrieved.State)
}

func TestCopyDeviceInfo(t *testing.T) {
	t.Run("nil_input", func(t *testing.T) {
		result := copyDeviceInfo(nil)
		assert.Nil(t, result)
	})

	t.Run("with_events", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		now := time.Now()

		src := &DeviceInfo{
			ID:             "device-123",
			MACAddress:     mac,
			State:          StateDiscovered,
			StateReason:    "test",
			CurrentVLAN:    100,
			TargetVLAN:     200,
			CreatedAt:      now,
			UpdatedAt:      now,
			StateChangedAt: now,
			RetryCount:     1,
			Events: []*ProvisioningEvent{
				{
					ID:        "event-1",
					DeviceID:  "device-123",
					EventType: EventDeviceDiscovered,
					Details:   map[string]string{"key": "value"},
				},
			},
		}

		dst := copyDeviceInfo(src)

		assert.NotSame(t, src, dst)
		assert.Equal(t, src.ID, dst.ID)
		assert.Equal(t, src.State, dst.State)
		assert.NotSame(t, &src.MACAddress[0], &dst.MACAddress[0])
		assert.Equal(t, src.MACAddress.String(), dst.MACAddress.String())
		assert.Len(t, dst.Events, 1)
		assert.NotSame(t, src.Events[0], dst.Events[0])
		assert.Equal(t, src.Events[0].ID, dst.Events[0].ID)
		assert.Equal(t, src.Events[0].Details["key"], dst.Events[0].Details["key"])

		// Verify map is a deep copy by modifying source and checking destination is unchanged
		src.Events[0].Details["key"] = "modified"
		assert.Equal(t, "value", dst.Events[0].Details["key"])
	})

	t.Run("empty_events", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		src := &DeviceInfo{
			ID:         "device-123",
			MACAddress: mac,
			State:      StateDiscovered,
			Events:     nil,
		}

		dst := copyDeviceInfo(src)

		assert.Equal(t, src.ID, dst.ID)
		assert.Nil(t, dst.Events)
	})

	t.Run("nil_event_in_slice", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		src := &DeviceInfo{
			ID:         "device-123",
			MACAddress: mac,
			State:      StateDiscovered,
			Events:     []*ProvisioningEvent{nil},
		}

		dst := copyDeviceInfo(src)

		assert.Len(t, dst.Events, 1)
		assert.Nil(t, dst.Events[0])
	})
}

func TestStateToEventType(t *testing.T) {
	tests := []struct {
		state    ProvisioningState
		expected ProvisioningEventType
	}{
		{StateDiscovered, EventDeviceDiscovered},
		{StateBooting, EventPXEBootStarted},
		{StateInstalling, EventInstallStarted},
		{StateInstallComplete, EventInstallCompleted},
		{StateEnrolling, EventEnrollmentStarted},
		{StateEnrolled, EventEnrollmentCompleted},
		{StateAuthorizing, EventAuthorizationStarted},
		{StateAuthorized, EventAuthorizationCompleted},
		{StateQuarantined, EventQuarantined},
		{StateFailed, EventFailed},
		{StateUnknown, EventDeviceDiscovered},
		{ProvisioningState("invalid"), EventDeviceDiscovered},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			result := stateToEventType(tt.state)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidTransitions_Coverage(t *testing.T) {
	// Ensure all valid states have transition definitions
	allStates := []ProvisioningState{
		StateUnknown,
		StateDiscovered,
		StateBooting,
		StateInstalling,
		StateInstallComplete,
		StateEnrolling,
		StateEnrolled,
		StateAuthorizing,
		StateAuthorized,
		StateFailed,
		StateQuarantined,
	}

	for _, state := range allStates {
		t.Run(string(state), func(t *testing.T) {
			_, exists := ValidTransitions[state]
			assert.True(t, exists, "ValidTransitions should contain entry for state %s", state)
		})
	}
}

func TestStateManager_emitEvent_NilEvent(t *testing.T) {
	sm := NewStateManager()
	handler := &stateTestEventHandler{delivered: newEventSignal()}
	sm.RegisterEventHandler(handler)

	// This should not panic and should be a no-op
	sm.emitEvent(nil)

	// No wait: emitEvent returns immediately for a nil event without
	// dispatching anything (state.go), so "no events" is true the instant it
	// returns. The 50ms sleep asserted nothing that was not already settled —
	// and waiting can never prove a negative anyway (#262).
	events := handler.getEvents()
	assert.Len(t, events, 0)
}

func TestStateManager_emitEvent_NoHandlers(t *testing.T) {
	sm := NewStateManager()

	// Create a valid event
	event := &ProvisioningEvent{
		ID:        "test-event",
		DeviceID:  "device-123",
		EventType: EventDeviceDiscovered,
	}

	// This should not panic
	sm.emitEvent(event)
}

func TestStateManager_Transition_QuarantinedSetsError(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	handler := &stateTestEventHandler{delivered: newEventSignal()}
	sm.RegisterEventHandler(handler)

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	err = sm.Transition("device-123", StateQuarantined, "security violation")
	assert.NoError(t, err)

	handler.delivered.await(t, 1)

	events := handler.getEvents()
	assert.Len(t, events, 1)
	assert.Equal(t, EventQuarantined, events[0].EventType)
	assert.Equal(t, "security violation", events[0].Error)
}

func TestStateManager_Transition_FailedSetsError(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	handler := &stateTestEventHandler{delivered: newEventSignal()}
	sm.RegisterEventHandler(handler)

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	err = sm.Transition("device-123", StateFailed, "boot failure")
	assert.NoError(t, err)

	handler.delivered.await(t, 1)

	events := handler.getEvents()
	assert.Len(t, events, 1)
	assert.Equal(t, EventFailed, events[0].EventType)
	assert.Equal(t, "boot failure", events[0].Error)
}

func TestCopyDeviceInfo_WithNilDetails(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	src := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
		Events: []*ProvisioningEvent{
			{
				ID:        "event-1",
				DeviceID:  "device-123",
				EventType: EventDeviceDiscovered,
				Details:   nil, // nil details map
			},
		},
	}

	dst := copyDeviceInfo(src)

	assert.Len(t, dst.Events, 1)
	assert.Nil(t, dst.Events[0].Details)
}

func TestCopyDeviceInfo_EmptyMACAddress(t *testing.T) {
	src := &DeviceInfo{
		ID:         "device-123",
		MACAddress: nil, // Empty MAC
		State:      StateDiscovered,
	}

	dst := copyDeviceInfo(src)

	assert.Equal(t, src.ID, dst.ID)
	assert.Nil(t, dst.MACAddress)
}

func TestStateManager_Transition_EmptyReason(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	handler := &stateTestEventHandler{delivered: newEventSignal()}
	sm.RegisterEventHandler(handler)

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	// Transition with empty reason
	err = sm.Transition("device-123", StateBooting, "")
	assert.NoError(t, err)

	handler.delivered.await(t, 1)

	events := handler.getEvents()
	assert.Len(t, events, 1)
	// Empty reason should not add a "reason" key to details
	_, hasReason := events[0].Details["reason"]
	assert.False(t, hasReason)
}

func TestStateManager_Transition_CASRetryOnConcurrentModification(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	// Create multiple goroutines that all try to transition the device
	// through different valid states
	var wg sync.WaitGroup
	results := make(chan error, 20)

	// All goroutines try to transition from discovered to booting
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			err := sm.Transition("device-123", StateBooting, fmt.Sprintf("concurrent-%d", idx))
			results <- err
		}(i)
	}

	wg.Wait()
	close(results)

	// Count successes and failures
	successCount := 0
	failCount := 0
	for err := range results {
		if err == nil {
			successCount++
		} else {
			failCount++
		}
	}

	// At least one should succeed
	assert.GreaterOrEqual(t, successCount, 1)
	// Most should fail because state already changed
	assert.Greater(t, failCount, 0)

	// Final state should be booting
	retrieved, err := sm.Get("device-123")
	assert.NoError(t, err)
	assert.Equal(t, StateBooting, retrieved.State)
}

func TestStateManager_UpdateDevice_CASRetryOnConcurrentModification(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
		RetryCount: 0,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	// Create multiple goroutines that all try to update the retry count
	var wg sync.WaitGroup
	numUpdates := 10 // Reduced from 50 to be more reliable with race detector
	var successCount int32

	for i := 0; i < numUpdates; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sm.UpdateDevice("device-123", func(d *DeviceInfo) error {
				d.RetryCount++
				return nil
			})
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}

	wg.Wait()

	// All updates should have succeeded with the CAS retry mechanism
	// If maxRetries is exceeded, some may fail
	retrieved, err := sm.Get("device-123")
	assert.NoError(t, err)

	// The retry count should equal the number of successful updates
	assert.Equal(t, int(successCount), retrieved.RetryCount)
	// At least some updates should succeed
	assert.Greater(t, int(successCount), 0)
}

func TestStateManager_Register_ConcurrentMACRegistration(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// Try to register two devices with same MAC concurrently
	var wg sync.WaitGroup
	results := make(chan error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			device := &DeviceInfo{
				ID:         fmt.Sprintf("device-%d", idx),
				MACAddress: mac,
				State:      StateDiscovered,
			}
			results <- sm.Register(device)
		}(i)
	}

	wg.Wait()
	close(results)

	successCount := 0
	failCount := 0
	for err := range results {
		if err == nil {
			successCount++
		} else {
			failCount++
			var existsErr ErrDeviceAlreadyExists
			assert.True(t, errors.As(err, &existsErr))
		}
	}

	// Exactly one should succeed, one should fail
	assert.Equal(t, 1, successCount)
	assert.Equal(t, 1, failCount)
}

func TestStateManager_GetByMAC_DeviceDeletedAfterMACLookup(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	// Manually remove the device from devices map but leave MAC mapping
	// This simulates a race condition where device is deleted between
	// byMAC lookup and devices lookup
	sm.devices.Delete("device-123")

	// Should return not found since device was deleted
	_, err = sm.GetByMAC(mac)
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestStateManager_Transition_MultipleHandlers(t *testing.T) {
	sm := NewStateManager()
	handler1 := &stateTestEventHandler{delivered: newEventSignal()}
	handler2 := &stateTestEventHandler{delivered: newEventSignal()}
	sm.RegisterEventHandler(handler1)
	sm.RegisterEventHandler(handler2)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	err = sm.Transition("device-123", StateBooting, "test")
	assert.NoError(t, err)

	handler1.delivered.await(t, 1)
	handler2.delivered.await(t, 1)

	// Both handlers should receive the event
	events1 := handler1.getEvents()
	events2 := handler2.getEvents()
	assert.Len(t, events1, 1)
	assert.Len(t, events2, 1)
}

func TestStateManager_Transition_UpdatesStateChangedAt(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	sm := newStateManager(clock.Now)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	beforeTransition, _ := sm.Get("device-123")
	assert.Equal(t, clock.now, beforeTransition.StateChangedAt)

	clock.advance(time.Second)
	err = sm.Transition("device-123", StateBooting, "test")
	assert.NoError(t, err)

	afterTransition, _ := sm.Get("device-123")
	assert.Equal(t, clock.now, afterTransition.StateChangedAt)
	assert.Equal(t, clock.now, afterTransition.UpdatedAt)
	assert.True(t, afterTransition.StateChangedAt.After(beforeTransition.StateChangedAt))
}

func TestStateManager_Transition_RejectedLeavesStateChangedAt(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	sm := newStateManager(clock.Now)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	err := sm.Register(&DeviceInfo{ID: "device-123", MACAddress: mac, State: StateDiscovered})
	require.NoError(t, err)
	registeredAt := clock.now

	// Discovered -> Authorized is not allowed; the clock moving on must not
	// restamp a device whose transition was rejected
	clock.advance(time.Second)
	err = sm.Transition("device-123", StateAuthorized, "test")
	var transitionErr ErrInvalidStateTransition
	require.ErrorAs(t, err, &transitionErr)

	device, _ := sm.Get("device-123")
	assert.Equal(t, registeredAt, device.StateChangedAt)
	assert.Equal(t, StateDiscovered, device.State)
}

// stepClock is a clock the test steps by hand. onNow, when set, runs once on
// the next reading, which lets a test act inside Transition's CAS loop: the
// loop reads the clock after loading the entry and before swapping it.
type stepClock struct {
	now   time.Time
	onNow func()
}

func (c *stepClock) Now() time.Time {
	if hook := c.onNow; hook != nil {
		c.onNow = nil
		hook()
	}
	return c.now
}

func (c *stepClock) advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func TestStateManager_Register_MACConflictCleansUpDevice(t *testing.T) {
	sm := NewStateManager()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	// First register a device with the MAC
	device1 := &DeviceInfo{
		ID:         "device-1",
		MACAddress: mac,
		State:      StateDiscovered,
	}
	err := sm.Register(device1)
	require.NoError(t, err)

	// Now manually store a device ID in devices map without the MAC mapping
	// This simulates the scenario where device ID is stored but MAC registration
	// fails because another goroutine registered the same MAC
	device2 := &DeviceInfo{
		ID:         "device-2",
		MACAddress: mac,
		State:      StateDiscovered,
	}
	entry := &deviceEntry{
		device:  device2,
		version: 1,
	}
	sm.devices.Store("device-2", entry)

	// Verify device-2 was stored
	_, loaded := sm.devices.Load("device-2")
	require.True(t, loaded)

	// Try to register device-3 with the same MAC - this should fail at the
	// byMAC.LoadOrStore check since device-1 already has that MAC
	device3 := &DeviceInfo{
		ID:         "device-3",
		MACAddress: mac,
		State:      StateDiscovered,
	}
	err = sm.Register(device3)
	assert.Error(t, err)

	var existsErr ErrDeviceAlreadyExists
	assert.True(t, errors.As(err, &existsErr))
	assert.Equal(t, "device-1", existsErr.DeviceID)

	// Verify device-3 was NOT stored (cleanup happened)
	_, loaded = sm.devices.Load("device-3")
	assert.False(t, loaded)
}

func TestStateManager_Transition_DeviceDeletedDuringCASRetry(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	sm := newStateManager(clock.Now)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	// Delete the device inside Transition's CAS loop, after it loaded the
	// entry and before it swaps: the swap fails and the reload finds nothing
	clock.onNow = func() {
		sm.devices.Delete("device-123")
		sm.byMAC.Delete(mac.String())
	}

	err = sm.Transition("device-123", StateBooting, "test")
	var notFoundErr ErrDeviceNotFound
	require.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "device-123", notFoundErr.DeviceID)
}

func TestStateManager_Transition_InvalidTransitionAfterConcurrentStateChange(t *testing.T) {
	clock := &stepClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	sm := newStateManager(clock.Now)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &DeviceInfo{
		ID:         "device-123",
		MACAddress: mac,
		State:      StateDiscovered,
	}

	err := sm.Register(device)
	require.NoError(t, err)

	// Quarantine the device inside the CAS loop of a Discovered -> Booting
	// transition. Booting was valid from Discovered but is not from
	// Quarantined, so the re-validation after the failed swap must reject it.
	var quarantineErr error
	clock.onNow = func() {
		quarantineErr = sm.Transition("device-123", StateQuarantined, "concurrent")
	}

	err = sm.Transition("device-123", StateBooting, "first")
	require.NoError(t, quarantineErr)

	var transitionErr ErrInvalidStateTransition
	require.ErrorAs(t, err, &transitionErr)
	assert.Equal(t, string(StateQuarantined), transitionErr.FromState)
	assert.Equal(t, string(StateBooting), transitionErr.ToState)

	current, _ := sm.Get("device-123")
	assert.Equal(t, StateQuarantined, current.State)
}
