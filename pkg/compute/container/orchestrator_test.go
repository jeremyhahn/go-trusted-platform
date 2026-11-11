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

package container

import (
	"testing"
)

func TestContainerState_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state    ContainerState
		expected string
	}{
		{StateCreated, "created"},
		{StateRunning, "running"},
		{StateStopped, "stopped"},
		{StateRemoving, "removing"},
		{StatePaused, "paused"},
		{StateRestarting, "restarting"},
		{StateExited, "exited"},
		{StateDead, "dead"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("ContainerState.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestContainerState_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state ContainerState
		valid bool
	}{
		{"created", StateCreated, true},
		{"running", StateRunning, true},
		{"stopped", StateStopped, true},
		{"removing", StateRemoving, true},
		{"paused", StatePaused, true},
		{"restarting", StateRestarting, true},
		{"exited", StateExited, true},
		{"dead", StateDead, true},
		{"empty", ContainerState(""), false},
		{"invalid", ContainerState("invalid"), false},
		{"unknown", ContainerState("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.IsValid(); got != tt.valid {
				t.Errorf("ContainerState.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestContainerState_IsRunning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state     ContainerState
		isRunning bool
	}{
		{StateCreated, false},
		{StateRunning, true},
		{StateStopped, false},
		{StateRemoving, false},
		{StatePaused, false},
		{StateRestarting, false},
		{StateExited, false},
		{StateDead, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			t.Parallel()
			if got := tt.state.IsRunning(); got != tt.isRunning {
				t.Errorf("ContainerState.IsRunning() = %v, want %v", got, tt.isRunning)
			}
		})
	}
}

func TestContainerState_IsStopped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state     ContainerState
		isStopped bool
	}{
		{StateCreated, false},
		{StateRunning, false},
		{StateStopped, true},
		{StateRemoving, false},
		{StatePaused, false},
		{StateRestarting, false},
		{StateExited, true},
		{StateDead, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			t.Parallel()
			if got := tt.state.IsStopped(); got != tt.isStopped {
				t.Errorf("ContainerState.IsStopped() = %v, want %v", got, tt.isStopped)
			}
		})
	}
}
