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
	"testing"
	"time"
)

func TestViolationSeverity_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		sev   ViolationSeverity
		valid bool
	}{
		{"warning", ViolationSeverityWarning, true},
		{"severe", ViolationSeveritySevere, true},
		{"empty", "", false},
		{"unknown", "critical", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sev.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestViolationSeverity_String(t *testing.T) {
	if ViolationSeverityWarning.String() != "warning" {
		t.Errorf("expected 'warning', got %q", ViolationSeverityWarning.String())
	}
	if ViolationSeveritySevere.String() != "severe" {
		t.Errorf("expected 'severe', got %q", ViolationSeveritySevere.String())
	}
}

func TestViolationSource_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		src   ViolationSource
		valid bool
	}{
		{"attestation", ViolationSourceAttestation, true},
		{"empty", "", false},
		{"unknown", "vuln-scan", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.src.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestViolationSource_String(t *testing.T) {
	if ViolationSourceAttestation.String() != "attestation" {
		t.Errorf("expected 'attestation', got %q", ViolationSourceAttestation.String())
	}
}

func TestViolationEvent_Validate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		ev      ViolationEvent
		wantErr bool
	}{
		{
			name: "valid warning event",
			ev: ViolationEvent{
				DeviceID:   42,
				Severity:   ViolationSeverityWarning,
				Source:     ViolationSourceAttestation,
				Detail:     "PCR[4] mismatch",
				OccurredAt: now,
			},
			wantErr: false,
		},
		{
			name: "valid severe event",
			ev: ViolationEvent{
				DeviceID:   1,
				Severity:   ViolationSeveritySevere,
				Source:     ViolationSourceAttestation,
				OccurredAt: now,
			},
			wantErr: false,
		},
		{
			name: "zero device ID",
			ev: ViolationEvent{
				Severity:   ViolationSeverityWarning,
				Source:     ViolationSourceAttestation,
				OccurredAt: now,
			},
			wantErr: true,
		},
		{
			name: "invalid severity",
			ev: ViolationEvent{
				DeviceID:   1,
				Severity:   "critical",
				Source:     ViolationSourceAttestation,
				OccurredAt: now,
			},
			wantErr: true,
		},
		{
			name: "invalid source",
			ev: ViolationEvent{
				DeviceID:   1,
				Severity:   ViolationSeverityWarning,
				Source:     "vuln-scan",
				OccurredAt: now,
			},
			wantErr: true,
		},
		{
			name: "zero occurred_at",
			ev: ViolationEvent{
				DeviceID: 1,
				Severity: ViolationSeverityWarning,
				Source:   ViolationSourceAttestation,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ev.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestDeviceState_CanTransitionTo(t *testing.T) {
	tests := []struct {
		from    DeviceState
		to      DeviceState
		wantErr bool
	}{
		// Valid transitions
		{DeviceStateUnknown, DeviceStateRegistered, false},
		{DeviceStateRegistered, DeviceStateActivated, false},
		{DeviceStateRegistered, DeviceStateQuarantined, false},
		{DeviceStateRegistered, DeviceStateSuspended, false},
		{DeviceStateRegistered, DeviceStateRevoked, false},
		{DeviceStateActivated, DeviceStateAttested, false},
		{DeviceStateActivated, DeviceStateQuarantined, false},
		{DeviceStateActivated, DeviceStateSuspended, false},
		{DeviceStateActivated, DeviceStateRevoked, false},
		{DeviceStateAttested, DeviceStateQuarantined, false},
		{DeviceStateAttested, DeviceStateSuspended, false},
		{DeviceStateAttested, DeviceStateRevoked, false},
		{DeviceStateQuarantined, DeviceStateAttested, false},
		{DeviceStateQuarantined, DeviceStateSuspended, false},
		{DeviceStateQuarantined, DeviceStateRevoked, false},
		{DeviceStateSuspended, DeviceStateAttested, false},
		{DeviceStateSuspended, DeviceStateQuarantined, false},
		{DeviceStateSuspended, DeviceStateRevoked, false},
		// Invalid transitions
		{DeviceStateRevoked, DeviceStateAttested, true},
		{DeviceStateRevoked, DeviceStateRegistered, true},
		{DeviceStateAttested, DeviceStateRegistered, true},
		{DeviceStateQuarantined, DeviceStateRegistered, true},
		{DeviceStateSuspended, DeviceStateActivated, true},
		{"bogus", DeviceStateRegistered, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.from)+"→"+string(tt.to), func(t *testing.T) {
			err := tt.from.CanTransitionTo(tt.to)
			if (err != nil) != tt.wantErr {
				t.Errorf("CanTransitionTo(%s) error = %v, wantErr = %v", tt.to, err, tt.wantErr)
			}
			if err != nil {
				if _, ok := err.(ErrInvalidTransition); !ok {
					t.Errorf("expected ErrInvalidTransition, got %T", err)
				}
			}
		})
	}
}

func TestDevice_Transition(t *testing.T) {
	t.Run("valid transition updates state", func(t *testing.T) {
		d := &Device{State: DeviceStateRegistered}
		if err := d.Transition(DeviceStateActivated); err != nil {
			t.Fatal(err)
		}
		if d.State != DeviceStateActivated {
			t.Errorf("expected activated, got %s", d.State)
		}
		if d.UpdatedAt.IsZero() {
			t.Error("UpdatedAt should be set after transition")
		}
	})

	t.Run("invalid transition returns error without mutating state", func(t *testing.T) {
		d := &Device{State: DeviceStateRevoked}
		if err := d.Transition(DeviceStateAttested); err == nil {
			t.Error("expected error for invalid transition")
		}
		if d.State != DeviceStateRevoked {
			t.Errorf("state should not change on invalid transition, got %s", d.State)
		}
	})
}

func TestErrInvalidViolationSeverity_Error(t *testing.T) {
	e := ErrInvalidViolationSeverity{Value: "bad"}
	if e.Error() == "" {
		t.Error("Error() should return non-empty string")
	}
}

func TestErrInvalidViolationSource_Error(t *testing.T) {
	e := ErrInvalidViolationSource{Value: "bad"}
	if e.Error() == "" {
		t.Error("Error() should return non-empty string")
	}
}

func TestErrInvalidTransition_Error(t *testing.T) {
	e := ErrInvalidTransition{From: DeviceStateRegistered, To: DeviceStateRevoked}
	if e.Error() == "" {
		t.Error("Error() should return non-empty string")
	}
}
