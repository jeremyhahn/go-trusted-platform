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

package compute

import (
	"testing"
	"time"
)

func TestInstanceState_String(t *testing.T) {
	tests := []struct {
		name  string
		state InstanceState
		want  string
	}{
		{"Unknown", StateUnknown, "unknown"},
		{"Creating", StateCreating, "creating"},
		{"Stopped", StateStopped, "stopped"},
		{"Starting", StateStarting, "starting"},
		{"Running", StateRunning, "running"},
		{"Stopping", StateStopping, "stopping"},
		{"Error", StateError, "error"},
		{"Deleting", StateDeleting, "deleting"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("InstanceState.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInstanceState_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		state InstanceState
		want  bool
	}{
		{"Valid Unknown", StateUnknown, true},
		{"Valid Creating", StateCreating, true},
		{"Valid Stopped", StateStopped, true},
		{"Valid Running", StateRunning, true},
		{"Invalid", InstanceState("invalid"), false},
		{"Empty", InstanceState(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsValid(); got != tt.want {
				t.Errorf("InstanceState.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInstanceState_IsTerminal(t *testing.T) {
	tests := []struct {
		name  string
		state InstanceState
		want  bool
	}{
		{"Error is terminal", StateError, true},
		{"Deleting is terminal", StateDeleting, true},
		{"Running is not terminal", StateRunning, false},
		{"Stopped is not terminal", StateStopped, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsTerminal(); got != tt.want {
				t.Errorf("InstanceState.IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInstanceState_CanTransitionTo(t *testing.T) {
	tests := []struct {
		name string
		from InstanceState
		to   InstanceState
		want bool
	}{
		{"Unknown to Creating", StateUnknown, StateCreating, true},
		{"Creating to Stopped", StateCreating, StateStopped, true},
		{"Stopped to Starting", StateStopped, StateStarting, true},
		{"Starting to Running", StateStarting, StateRunning, true},
		{"Running to Stopping", StateRunning, StateStopping, true},
		{"Stopping to Stopped", StateStopping, StateStopped, true},
		{"Stopped to Deleting", StateStopped, StateDeleting, true},
		{"Any to Error", StateRunning, StateError, true},
		{"Error to anything is invalid", StateError, StateRunning, false},
		{"Deleting to anything is invalid", StateDeleting, StateStopped, false},
		{"Running to Stopped is invalid", StateRunning, StateStopped, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.from.CanTransitionTo(tt.to); got != tt.want {
				t.Errorf("InstanceState.CanTransitionTo(%v -> %v) = %v, want %v",
					tt.from, tt.to, got, tt.want)
			}
		})
	}
}

func TestLifecycleManager_SetState(t *testing.T) {
	lm := NewLifecycleManager()
	instanceID := "test-instance"

	// Test setting initial state
	err := lm.SetState(instanceID, StateCreating)
	if err != nil {
		t.Fatalf("Failed to set initial state: %v", err)
	}

	// Test valid transition
	err = lm.SetState(instanceID, StateStopped)
	if err != nil {
		t.Errorf("Failed to transition Creating -> Stopped: %v", err)
	}

	// Test invalid transition
	err = lm.SetState(instanceID, StateDeleting)
	if err != nil {
		t.Errorf("Failed to transition Stopped -> Deleting: %v", err)
	}

	// Test empty instance ID
	err = lm.SetState("", StateRunning)
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID for empty ID, got: %v", err)
	}

	// Test invalid state
	err = lm.SetState(instanceID, InstanceState("invalid"))
	if err == nil {
		t.Error("Expected error for invalid state")
	}
}

func TestLifecycleManager_GetState(t *testing.T) {
	lm := NewLifecycleManager()
	instanceID := "test-instance"

	// Test getting state for non-existent instance
	_, err := lm.GetState(instanceID)
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got: %v", err)
	}

	// Set state and get it
	lm.SetState(instanceID, StateRunning)
	state, err := lm.GetState(instanceID)
	if err != nil {
		t.Fatalf("Failed to get state: %v", err)
	}
	if state != StateRunning {
		t.Errorf("Expected state %v, got %v", StateRunning, state)
	}

	// Test empty instance ID
	_, err = lm.GetState("")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID for empty ID, got: %v", err)
	}
}

func TestLifecycleManager_GetStateTimestamp(t *testing.T) {
	lm := NewLifecycleManager()
	instanceID := "test-instance"

	// Test getting timestamp for non-existent instance
	_, err := lm.GetStateTimestamp(instanceID)
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got: %v", err)
	}

	// Set state and get timestamp
	before := time.Now()
	lm.SetState(instanceID, StateRunning)
	after := time.Now()

	ts, err := lm.GetStateTimestamp(instanceID)
	if err != nil {
		t.Fatalf("Failed to get timestamp: %v", err)
	}

	if ts.Before(before) || ts.After(after) {
		t.Errorf("Timestamp %v is outside expected range [%v, %v]", ts, before, after)
	}
}

func TestLifecycleManager_DeleteInstance(t *testing.T) {
	lm := NewLifecycleManager()
	instanceID := "test-instance"

	// Test deleting non-existent instance
	err := lm.DeleteInstance(instanceID)
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got: %v", err)
	}

	// Create instance and delete it
	lm.SetState(instanceID, StateRunning)
	err = lm.DeleteInstance(instanceID)
	if err != nil {
		t.Fatalf("Failed to delete instance: %v", err)
	}

	// Verify it's deleted
	_, err = lm.GetState(instanceID)
	if err != ErrInstanceNotFound {
		t.Errorf("Instance should be deleted, got error: %v", err)
	}

	// Test empty instance ID
	err = lm.DeleteInstance("")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID for empty ID, got: %v", err)
	}
}

func TestLifecycleManager_ListInstances(t *testing.T) {
	lm := NewLifecycleManager()

	// Test empty list
	list := lm.ListInstances()
	if len(list) != 0 {
		t.Errorf("Expected empty list, got %d instances", len(list))
	}

	// Add instances
	instances := map[string]InstanceState{
		"instance-1": StateRunning,
		"instance-2": StateStopped,
		"instance-3": StateError,
	}

	for id, state := range instances {
		lm.SetState(id, state)
	}

	// List and verify
	list = lm.ListInstances()
	if len(list) != len(instances) {
		t.Errorf("Expected %d instances, got %d", len(instances), len(list))
	}

	for id, expectedState := range instances {
		if state, exists := list[id]; !exists {
			t.Errorf("Instance %s not found in list", id)
		} else if state != expectedState {
			t.Errorf("Instance %s has state %v, expected %v", id, state, expectedState)
		}
	}
}

func TestLifecycleManager_WaitForState(t *testing.T) {
	lm := NewLifecycleManager()
	instanceID := "test-instance"

	// Test timeout
	lm.SetState(instanceID, StateStarting)
	err := lm.WaitForState(instanceID, StateRunning, 100*time.Millisecond)
	if err != ErrTimeout {
		t.Errorf("Expected ErrTimeout, got: %v", err)
	}

	// Test successful wait
	lm.SetState(instanceID, StateStarting)
	go func() {
		time.Sleep(50 * time.Millisecond)
		lm.SetState(instanceID, StateRunning)
	}()
	err = lm.WaitForState(instanceID, StateRunning, 200*time.Millisecond)
	if err != nil {
		t.Errorf("WaitForState failed: %v", err)
	}

	// Test error state
	lm.SetState(instanceID, StateStarting)
	go func() {
		time.Sleep(50 * time.Millisecond)
		lm.SetState(instanceID, StateError)
	}()
	err = lm.WaitForState(instanceID, StateRunning, 200*time.Millisecond)
	if err == nil {
		t.Error("Expected error when instance enters error state")
	}

	// Test invalid instance ID
	err = lm.WaitForState("", StateRunning, 100*time.Millisecond)
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got: %v", err)
	}

	// Test invalid target state
	err = lm.WaitForState(instanceID, InstanceState("invalid"), 100*time.Millisecond)
	if err == nil {
		t.Error("Expected error for invalid target state")
	}
}

func TestLifecycleManager_Concurrent(t *testing.T) {
	lm := NewLifecycleManager()
	numInstances := 100
	done := make(chan bool, numInstances)

	// Concurrent state changes
	for i := 0; i < numInstances; i++ {
		go func(id int) {
			instanceID := time.Now().Format("2006-01-02T15:04:05.000000000Z07:00")
			instanceID += string(rune(id))

			lm.SetState(instanceID, StateCreating)
			lm.SetState(instanceID, StateStopped)
			lm.SetState(instanceID, StateStarting)
			lm.SetState(instanceID, StateRunning)
			lm.GetState(instanceID)
			lm.DeleteInstance(instanceID)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numInstances; i++ {
		<-done
	}

	// Verify all instances are deleted
	list := lm.ListInstances()
	if len(list) != 0 {
		t.Errorf("Expected no instances after cleanup, got %d", len(list))
	}
}
