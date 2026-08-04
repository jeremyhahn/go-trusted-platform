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

package entities

import (
	"errors"
	"testing"
)

// TestDevice_BareMetalInstallPath verifies the full bare-metal lifecycle
// Registered -> Installing -> Installed -> Activated is permitted by the
// state machine and that each step updates the device state.
func TestDevice_BareMetalInstallPath(t *testing.T) {
	d := &Device{State: DeviceStateRegistered}

	steps := []DeviceState{
		DeviceStateInstalling,
		DeviceStateInstalled,
		DeviceStateActivated,
	}
	for _, next := range steps {
		if err := d.Transition(next); err != nil {
			t.Fatalf("Transition to %s failed: %v", next, err)
		}
		if d.State != next {
			t.Fatalf("expected state %s, got %s", next, d.State)
		}
	}
}

// TestDevice_TransitionRejectsIllegal verifies that an illegal transition
// (Installed -> Registered) is rejected with ErrInvalidTransition and that
// the device state is left unchanged.
func TestDevice_TransitionRejectsIllegal(t *testing.T) {
	d := &Device{State: DeviceStateInstalled}

	err := d.Transition(DeviceStateRegistered)
	if err == nil {
		t.Fatal("expected ErrInvalidTransition, got nil")
	}

	var invalid ErrInvalidTransition
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidTransition, got %T: %v", err, err)
	}
	if invalid.From != DeviceStateInstalled || invalid.To != DeviceStateRegistered {
		t.Fatalf("unexpected transition error: %s -> %s", invalid.From, invalid.To)
	}
	if d.State != DeviceStateInstalled {
		t.Fatalf("state should be unchanged after rejected transition, got %s", d.State)
	}
}

// TestDevice_RegisteredDirectActivation verifies that the legacy non-bare-metal
// path Registered -> Activated is still permitted alongside the install path.
func TestDevice_RegisteredDirectActivation(t *testing.T) {
	d := &Device{State: DeviceStateRegistered}

	if err := d.Transition(DeviceStateActivated); err != nil {
		t.Fatalf("Registered -> Activated should be allowed: %v", err)
	}
	if d.State != DeviceStateActivated {
		t.Fatalf("expected activated, got %s", d.State)
	}
}

// TestDeviceState_IsValidNewStates verifies the new install states are
// recognised by IsValid and that an unrecognised value is not.
func TestDeviceState_IsValidNewStates(t *testing.T) {
	for _, s := range []DeviceState{DeviceStateInstalling, DeviceStateInstalled} {
		if !s.IsValid() {
			t.Errorf("expected %s to be valid", s)
		}
	}
	if DeviceState("bogus").IsValid() {
		t.Error("expected bogus state to be invalid")
	}
}

// TestDevice_InstallStateHelpers verifies the IsInstalling / IsInstalled
// helpers report the correct state.
func TestDevice_InstallStateHelpers(t *testing.T) {
	installing := &Device{State: DeviceStateInstalling}
	if !installing.IsInstalling() {
		t.Error("expected IsInstalling true")
	}
	if installing.IsInstalled() {
		t.Error("expected IsInstalled false for installing device")
	}

	installed := &Device{State: DeviceStateInstalled}
	if !installed.IsInstalled() {
		t.Error("expected IsInstalled true")
	}
	if installed.IsInstalling() {
		t.Error("expected IsInstalling false for installed device")
	}
}
