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
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// ValidTransitions defines the allowed state transitions in the provisioning workflow.
// Each state maps to a slice of valid target states that can be transitioned to.
var ValidTransitions = map[ProvisioningState][]ProvisioningState{
	StateUnknown:         {StateDiscovered, StateFailed},
	StateDiscovered:      {StateBooting, StateQuarantined, StateFailed},
	StateBooting:         {StateInstalling, StateQuarantined, StateFailed},
	StateInstalling:      {StateInstallComplete, StateQuarantined, StateFailed},
	StateInstallComplete: {StateEnrolling, StateQuarantined, StateFailed},
	StateEnrolling:       {StateEnrolled, StateQuarantined, StateFailed},
	StateEnrolled:        {StateAuthorizing, StateQuarantined, StateFailed},
	StateAuthorizing:     {StateAuthorized, StateQuarantined, StateFailed},
	StateAuthorized:      {StateQuarantined, StateFailed},
	StateFailed:          {StateDiscovered, StateQuarantined},
	StateQuarantined:     {StateDiscovered, StateFailed},
}

// deviceEntry wraps DeviceInfo with a version field for CAS operations.
type deviceEntry struct {
	device  *DeviceInfo
	version uint64
}

// StateManager manages device provisioning state with thread-safe operations.
// It provides validated state transitions, event generation, and CAS-based updates.
type StateManager struct {
	devices    sync.Map       // map[string]*deviceEntry (by device ID)
	byMAC      sync.Map       // map[string]string (MAC address string -> device ID)
	handlers   []EventHandler // Registered event handlers
	handlersMu sync.RWMutex   // Protects handlers slice
	now        func() time.Time
}

// NewStateManager creates a new StateManager instance.
func NewStateManager() *StateManager {
	return newStateManager(time.Now)
}

// newStateManager creates a state manager that stamps devices and events with
// the time from now, so tests can drive the clock.
func newStateManager(now func() time.Time) *StateManager {
	return &StateManager{
		handlers: make([]EventHandler, 0),
		now:      now,
	}
}

// IsValidTransition checks if a state transition from one state to another is valid.
func IsValidTransition(from, to ProvisioningState) bool {
	allowed, exists := ValidTransitions[from]
	if !exists {
		return false
	}
	for _, state := range allowed {
		if state == to {
			return true
		}
	}
	return false
}

// Register adds a device to the state manager.
// Returns an error if the device has an invalid MAC address or already exists.
func (sm *StateManager) Register(device *DeviceInfo) error {
	if device == nil {
		return ErrInvalidMACAddress{Reason: "device is nil"}
	}

	if len(device.MACAddress) == 0 {
		return ErrInvalidMACAddress{Reason: "MAC address is empty"}
	}

	if device.ID == "" {
		return ErrInvalidMACAddress{Reason: "device ID is empty"}
	}

	macKey := device.MACAddress.String()

	// Check for existing device by MAC address
	if existingID, loaded := sm.byMAC.Load(macKey); loaded {
		return ErrDeviceAlreadyExists{
			DeviceID:   existingID.(string),
			MACAddress: macKey,
		}
	}

	// Check for existing device by ID
	if _, loaded := sm.devices.Load(device.ID); loaded {
		return ErrDeviceAlreadyExists{DeviceID: device.ID}
	}

	// Set timestamps if not already set
	now := sm.now()
	if device.CreatedAt.IsZero() {
		device.CreatedAt = now
	}
	if device.UpdatedAt.IsZero() {
		device.UpdatedAt = now
	}
	if device.StateChangedAt.IsZero() {
		device.StateChangedAt = now
	}

	// Create entry with initial version
	entry := &deviceEntry{
		device:  device,
		version: 1,
	}

	// Store device in both maps
	// Use LoadOrStore to handle potential race conditions
	if _, loaded := sm.devices.LoadOrStore(device.ID, entry); loaded {
		return ErrDeviceAlreadyExists{DeviceID: device.ID}
	}

	if existingID, loaded := sm.byMAC.LoadOrStore(macKey, device.ID); loaded {
		// Clean up the device entry since MAC was already registered
		sm.devices.Delete(device.ID)
		return ErrDeviceAlreadyExists{
			DeviceID:   existingID.(string),
			MACAddress: macKey,
		}
	}

	return nil
}

// Unregister removes a device from the state manager.
// Returns an error if the device is not found.
func (sm *StateManager) Unregister(deviceID string) error {
	if deviceID == "" {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	entryVal, loaded := sm.devices.Load(deviceID)
	if !loaded {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	entry := entryVal.(*deviceEntry)
	macKey := entry.device.MACAddress.String()

	// Remove from both maps
	sm.devices.Delete(deviceID)
	sm.byMAC.Delete(macKey)

	return nil
}

// Get retrieves a device by its ID.
// Returns a copy of the device to prevent external modification.
func (sm *StateManager) Get(deviceID string) (*DeviceInfo, error) {
	if deviceID == "" {
		return nil, ErrDeviceNotFound{DeviceID: deviceID}
	}

	entryVal, loaded := sm.devices.Load(deviceID)
	if !loaded {
		return nil, ErrDeviceNotFound{DeviceID: deviceID}
	}

	entry := entryVal.(*deviceEntry)
	return copyDeviceInfo(entry.device), nil
}

// GetByMAC retrieves a device by its MAC address.
// Returns a copy of the device to prevent external modification.
func (sm *StateManager) GetByMAC(mac net.HardwareAddr) (*DeviceInfo, error) {
	if len(mac) == 0 {
		return nil, ErrInvalidMACAddress{Reason: "MAC address is empty"}
	}

	macKey := mac.String()
	deviceIDVal, loaded := sm.byMAC.Load(macKey)
	if !loaded {
		return nil, ErrDeviceNotFound{MACAddress: macKey}
	}

	deviceID := deviceIDVal.(string)
	return sm.Get(deviceID)
}

// List returns devices matching the provided filter.
// If filter is nil, all devices are returned.
func (sm *StateManager) List(filter *DeviceFilter) []*DeviceInfo {
	var results []*DeviceInfo
	offset := 0
	count := 0

	sm.devices.Range(func(key, value interface{}) bool {
		entry := value.(*deviceEntry)
		device := entry.device

		// Apply filter if provided
		if filter != nil {
			if !filter.Matches(device) {
				return true // Continue iteration
			}

			// Handle offset
			if filter.Offset > 0 && offset < filter.Offset {
				offset++
				return true
			}

			// Handle limit
			if filter.Limit > 0 && count >= filter.Limit {
				return false // Stop iteration
			}
		}

		results = append(results, copyDeviceInfo(device))
		count++
		return true
	})

	return results
}

// Transition changes a device's state and emits an event.
// Returns an error if the device is not found or the transition is invalid.
func (sm *StateManager) Transition(deviceID string, newState ProvisioningState, reason string) error {
	if deviceID == "" {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !newState.IsValid() {
		return ErrInvalidState{
			DeviceID: deviceID,
			State:    string(newState),
			Reason:   "unknown state",
		}
	}

	entryVal, loaded := sm.devices.Load(deviceID)
	if !loaded {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	entry := entryVal.(*deviceEntry)
	currentState := entry.device.State

	// Validate the transition
	if !IsValidTransition(currentState, newState) {
		return ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(currentState),
			ToState:   string(newState),
			Reason:    "transition not allowed",
		}
	}

	// Update state atomically using CAS pattern
	for {
		currentEntry := entry
		currentVersion := currentEntry.version

		// Create updated device
		now := sm.now()
		updatedDevice := copyDeviceInfo(currentEntry.device)
		updatedDevice.State = newState
		updatedDevice.StateReason = reason
		updatedDevice.UpdatedAt = now
		updatedDevice.StateChangedAt = now

		// Create new entry with incremented version
		newEntry := &deviceEntry{
			device:  updatedDevice,
			version: currentVersion + 1,
		}

		// Attempt atomic swap
		if sm.devices.CompareAndSwap(deviceID, currentEntry, newEntry) {
			// Generate and emit event
			event := sm.createTransitionEvent(deviceID, currentState, newState, reason)
			sm.emitEvent(event)
			return nil
		}

		// Reload and retry if CAS failed
		entryVal, loaded = sm.devices.Load(deviceID)
		if !loaded {
			return ErrDeviceNotFound{DeviceID: deviceID}
		}
		entry = entryVal.(*deviceEntry)

		// Re-validate transition with new state
		if entry.device.State != currentState {
			if !IsValidTransition(entry.device.State, newState) {
				return ErrInvalidStateTransition{
					DeviceID:  deviceID,
					FromState: string(entry.device.State),
					ToState:   string(newState),
					Reason:    "transition not allowed after concurrent modification",
				}
			}
			currentState = entry.device.State
		}
	}
}

// UpdateDevice applies an update function to a device using CAS-style semantics.
// The function is called with a copy of the device, and changes are persisted
// only if no concurrent modification occurred.
func (sm *StateManager) UpdateDevice(deviceID string, fn func(*DeviceInfo) error) error {
	if deviceID == "" {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	if fn == nil {
		return ErrInvalidConfiguration{Field: "update function", Reason: "function is nil"}
	}

	const maxRetries = 10

	for attempt := 0; attempt < maxRetries; attempt++ {
		entryVal, loaded := sm.devices.Load(deviceID)
		if !loaded {
			return ErrDeviceNotFound{DeviceID: deviceID}
		}

		entry := entryVal.(*deviceEntry)
		currentVersion := entry.version

		// Create a copy for the update function
		updatedDevice := copyDeviceInfo(entry.device)

		// Apply the update function
		if err := fn(updatedDevice); err != nil {
			return err
		}

		// Update timestamp
		updatedDevice.UpdatedAt = sm.now()

		// Create new entry with incremented version
		newEntry := &deviceEntry{
			device:  updatedDevice,
			version: currentVersion + 1,
		}

		// Attempt atomic swap
		if sm.devices.CompareAndSwap(deviceID, entry, newEntry) {
			return nil
		}
		// CAS failed, retry
	}

	return ErrMaxRetriesExceeded{
		Operation:  "UpdateDevice",
		MaxRetries: maxRetries,
		Reason:     "concurrent modification prevented update",
	}
}

// RegisterEventHandler adds an event handler to receive provisioning events.
func (sm *StateManager) RegisterEventHandler(handler EventHandler) {
	if handler == nil {
		return
	}

	sm.handlersMu.Lock()
	sm.handlers = append(sm.handlers, handler)
	sm.handlersMu.Unlock()
}

// emitEvent notifies all registered handlers of an event.
// Each handler is invoked in its own goroutine to prevent blocking.
func (sm *StateManager) emitEvent(event *ProvisioningEvent) {
	if event == nil {
		return
	}

	sm.handlersMu.RLock()
	handlers := make([]EventHandler, len(sm.handlers))
	copy(handlers, sm.handlers)
	sm.handlersMu.RUnlock()

	ctx := context.Background()
	for _, handler := range handlers {
		go handler.OnEvent(ctx, event)
	}
}

// Count returns the total number of devices being tracked.
func (sm *StateManager) Count() int {
	var count int64
	sm.devices.Range(func(key, value interface{}) bool {
		atomic.AddInt64(&count, 1)
		return true
	})
	return int(atomic.LoadInt64(&count))
}

// CountByState returns the number of devices in a specific provisioning state.
func (sm *StateManager) CountByState(state ProvisioningState) int {
	var count int64
	sm.devices.Range(func(key, value interface{}) bool {
		entry := value.(*deviceEntry)
		if entry.device.State == state {
			atomic.AddInt64(&count, 1)
		}
		return true
	})
	return int(atomic.LoadInt64(&count))
}

// createTransitionEvent creates a ProvisioningEvent for a state transition.
func (sm *StateManager) createTransitionEvent(deviceID string, fromState, toState ProvisioningState, reason string) *ProvisioningEvent {
	eventType := stateToEventType(toState)

	event := &ProvisioningEvent{
		ID:        uuid.New().String(),
		DeviceID:  deviceID,
		Timestamp: sm.now(),
		EventType: eventType,
		FromState: fromState,
		ToState:   toState,
		Details:   make(map[string]string),
	}

	if reason != "" {
		event.Details["reason"] = reason
	}

	// Set error field for failure states
	if toState == StateFailed || toState == StateQuarantined {
		event.Error = reason
	}

	return event
}

// stateToEventType maps a provisioning state to the corresponding event type.
func stateToEventType(state ProvisioningState) ProvisioningEventType {
	switch state {
	case StateDiscovered:
		return EventDeviceDiscovered
	case StateBooting:
		return EventPXEBootStarted
	case StateInstalling:
		return EventInstallStarted
	case StateInstallComplete:
		return EventInstallCompleted
	case StateEnrolling:
		return EventEnrollmentStarted
	case StateEnrolled:
		return EventEnrollmentCompleted
	case StateAuthorizing:
		return EventAuthorizationStarted
	case StateAuthorized:
		return EventAuthorizationCompleted
	case StateQuarantined:
		return EventQuarantined
	case StateFailed:
		return EventFailed
	default:
		return EventDeviceDiscovered
	}
}

// copyDeviceInfo creates a deep copy of a DeviceInfo struct.
func copyDeviceInfo(src *DeviceInfo) *DeviceInfo {
	if src == nil {
		return nil
	}

	dst := &DeviceInfo{
		ID:                src.ID,
		PortID:            src.PortID,
		State:             src.State,
		StateReason:       src.StateReason,
		Profile:           src.Profile, // Shallow copy - profiles should be immutable
		CertificateSerial: src.CertificateSerial,
		CurrentVLAN:       src.CurrentVLAN,
		TargetVLAN:        src.TargetVLAN,
		CreatedAt:         src.CreatedAt,
		UpdatedAt:         src.UpdatedAt,
		StateChangedAt:    src.StateChangedAt,
		RetryCount:        src.RetryCount,
	}

	// Copy MAC address
	if len(src.MACAddress) > 0 {
		dst.MACAddress = make(net.HardwareAddr, len(src.MACAddress))
		copy(dst.MACAddress, src.MACAddress)
	}

	// Copy events slice
	if len(src.Events) > 0 {
		dst.Events = make([]*ProvisioningEvent, len(src.Events))
		for i, event := range src.Events {
			if event != nil {
				eventCopy := *event
				if event.Details != nil {
					eventCopy.Details = make(map[string]string, len(event.Details))
					for k, v := range event.Details {
						eventCopy.Details[k] = v
					}
				}
				dst.Events[i] = &eventCopy
			}
		}
	}

	return dst
}
