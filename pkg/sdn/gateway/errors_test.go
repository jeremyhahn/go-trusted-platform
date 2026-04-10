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

package gateway

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"ErrGatewayNotFound", ErrGatewayNotFound, "gateway not found"},
		{"ErrGatewayAlreadyExists", ErrGatewayAlreadyExists, "gateway already exists"},
		{"ErrGatewayNotRunning", ErrGatewayNotRunning, "gateway not running"},
		{"ErrGatewayAlreadyRunning", ErrGatewayAlreadyRunning, "gateway already running"},
		{"ErrConfigNil", ErrConfigNil, "configuration is nil"},
		{"ErrConfigurationInvalid", ErrConfigurationInvalid, "invalid configuration"},
		{"ErrUplinkNotFound", ErrUplinkNotFound, "uplink port not found"},
		{"ErrIPv6PoolExhausted", ErrIPv6PoolExhausted, "IPv6 address pool exhausted"},
		{"ErrIPv4PoolExhausted", ErrIPv4PoolExhausted, "IPv4 address pool exhausted"},
		{"ErrShutdownTimeout", ErrShutdownTimeout, "shutdown timeout exceeded"},
		{"ErrBGPSpeakerNil", ErrBGPSpeakerNil, "BGP speaker is nil"},
		{"ErrLoggerNil", ErrLoggerNil, "logger is nil"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatalf("sentinel error %s is nil", tt.name)
			}
			if !strings.Contains(tt.err.Error(), tt.contains) {
				t.Errorf("error %q does not contain %q", tt.err.Error(), tt.contains)
			}
		})
	}
}

func TestErrModeNotSupported(t *testing.T) {
	tests := []struct {
		name     string
		mode     GatewayMode
		contains string
	}{
		{"overlay", GatewayModeOverlay, "overlay"},
		{"edge", GatewayModeEdge, "edge"},
		{"transit", GatewayModeTransit, "transit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ErrModeNotSupported{Mode: tt.mode}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.contains)
			}
			if !strings.Contains(err.Error(), "not supported") {
				t.Errorf("error %q does not contain 'not supported'", err.Error())
			}
		})
	}
}

func TestErrModeActivationFailed(t *testing.T) {
	cause := errors.New("activation cause")

	tests := []struct {
		name     string
		err      *ErrModeActivationFailed
		contains []string
		hasCause bool
	}{
		{
			name:     "with cause",
			err:      &ErrModeActivationFailed{Mode: GatewayModeOverlay, Cause: cause},
			contains: []string{"overlay", "activation cause", "activate"},
			hasCause: true,
		},
		{
			name:     "without cause",
			err:      &ErrModeActivationFailed{Mode: GatewayModeEdge, Cause: nil},
			contains: []string{"edge", "activate"},
			hasCause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errStr, s) {
					t.Errorf("error %q does not contain %q", errStr, s)
				}
			}
			unwrapped := tt.err.Unwrap()
			if tt.hasCause && unwrapped == nil {
				t.Error("expected unwrapped cause, got nil")
			}
			if !tt.hasCause && unwrapped != nil {
				t.Errorf("expected nil unwrap, got %v", unwrapped)
			}
		})
	}
}

func TestErrModeDeactivationFailed(t *testing.T) {
	cause := errors.New("deactivation cause")

	tests := []struct {
		name     string
		err      *ErrModeDeactivationFailed
		contains []string
		hasCause bool
	}{
		{
			name:     "with cause",
			err:      &ErrModeDeactivationFailed{Mode: GatewayModeOverlay, Cause: cause},
			contains: []string{"overlay", "deactivation cause", "deactivate"},
			hasCause: true,
		},
		{
			name:     "without cause",
			err:      &ErrModeDeactivationFailed{Mode: GatewayModeEdge, Cause: nil},
			contains: []string{"edge", "deactivate"},
			hasCause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errStr, s) {
					t.Errorf("error %q does not contain %q", errStr, s)
				}
			}
			unwrapped := tt.err.Unwrap()
			if tt.hasCause && unwrapped == nil {
				t.Error("expected unwrapped cause, got nil")
			}
			if !tt.hasCause && unwrapped != nil {
				t.Errorf("expected nil unwrap, got %v", unwrapped)
			}
		})
	}
}

func TestErrReputationTooLow(t *testing.T) {
	err := &ErrReputationTooLow{Required: 0.85, Actual: 0.70}
	errStr := err.Error()

	if !strings.Contains(errStr, "reputation too low") {
		t.Errorf("error %q does not contain 'reputation too low'", errStr)
	}
	if !strings.Contains(errStr, "0.85") {
		t.Errorf("error %q does not contain required value '0.85'", errStr)
	}
	if !strings.Contains(errStr, "0.70") {
		t.Errorf("error %q does not contain actual value '0.70'", errStr)
	}
}

func TestErrAgeTooYoung(t *testing.T) {
	err := &ErrAgeTooYoung{RequiredDays: 175, ActualDays: 100}
	errStr := err.Error()

	if !strings.Contains(errStr, "age too young") {
		t.Errorf("error %q does not contain 'age too young'", errStr)
	}
	if !strings.Contains(errStr, "175") {
		t.Errorf("error %q does not contain required days '175'", errStr)
	}
	if !strings.Contains(errStr, "100") {
		t.Errorf("error %q does not contain actual days '100'", errStr)
	}
}

func TestErrUptimeTooLow(t *testing.T) {
	err := &ErrUptimeTooLow{RequiredPct: 95.0, ActualPct: 80.0}
	errStr := err.Error()

	if !strings.Contains(errStr, "uptime too low") {
		t.Errorf("error %q does not contain 'uptime too low'", errStr)
	}
	if !strings.Contains(errStr, "95") {
		t.Errorf("error %q does not contain required percentage", errStr)
	}
	if !strings.Contains(errStr, "80") {
		t.Errorf("error %q does not contain actual percentage", errStr)
	}
}

func TestErrOnboardingFailed(t *testing.T) {
	cause := errors.New("onboarding cause")

	tests := []struct {
		name     string
		err      *ErrOnboardingFailed
		contains []string
		hasCause bool
	}{
		{
			name:     "with cause",
			err:      &ErrOnboardingFailed{GatewayID: "gw-1", Cause: cause},
			contains: []string{"gw-1", "onboarding failed", "onboarding cause"},
			hasCause: true,
		},
		{
			name:     "without cause",
			err:      &ErrOnboardingFailed{GatewayID: "gw-2", Cause: nil},
			contains: []string{"gw-2", "onboarding failed"},
			hasCause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errStr, s) {
					t.Errorf("error %q does not contain %q", errStr, s)
				}
			}
			unwrapped := tt.err.Unwrap()
			if tt.hasCause && unwrapped == nil {
				t.Error("expected unwrapped cause, got nil")
			}
			if !tt.hasCause && unwrapped != nil {
				t.Errorf("expected nil unwrap, got %v", unwrapped)
			}
		})
	}
}

func TestErrHealthCheckFailed(t *testing.T) {
	cause := errors.New("health cause")

	tests := []struct {
		name     string
		err      *ErrHealthCheckFailed
		contains []string
		hasCause bool
	}{
		{
			name:     "with cause and reason",
			err:      &ErrHealthCheckFailed{GatewayID: "gw-1", Reason: "timeout", Cause: cause},
			contains: []string{"gw-1", "health check failed", "timeout", "health cause"},
			hasCause: true,
		},
		{
			name:     "with reason only",
			err:      &ErrHealthCheckFailed{GatewayID: "gw-2", Reason: "connection refused", Cause: nil},
			contains: []string{"gw-2", "health check failed", "connection refused"},
			hasCause: false,
		},
		{
			name:     "minimal",
			err:      &ErrHealthCheckFailed{GatewayID: "gw-3"},
			contains: []string{"gw-3", "health check failed"},
			hasCause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errStr, s) {
					t.Errorf("error %q does not contain %q", errStr, s)
				}
			}
			unwrapped := tt.err.Unwrap()
			if tt.hasCause && unwrapped == nil {
				t.Error("expected unwrapped cause, got nil")
			}
			if !tt.hasCause && unwrapped != nil {
				t.Errorf("expected nil unwrap, got %v", unwrapped)
			}
		})
	}
}

func TestErrUplinkOperationFailed(t *testing.T) {
	cause := errors.New("uplink cause")

	tests := []struct {
		name     string
		err      *ErrUplinkOperationFailed
		contains []string
		hasCause bool
	}{
		{
			name:     "with cause",
			err:      &ErrUplinkOperationFailed{UplinkName: "eth0", Operation: "configure", Cause: cause},
			contains: []string{"eth0", "configure", "uplink cause"},
			hasCause: true,
		},
		{
			name:     "without cause",
			err:      &ErrUplinkOperationFailed{UplinkName: "eth1", Operation: "remove"},
			contains: []string{"eth1", "remove"},
			hasCause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errStr, s) {
					t.Errorf("error %q does not contain %q", errStr, s)
				}
			}
			unwrapped := tt.err.Unwrap()
			if tt.hasCause && unwrapped == nil {
				t.Error("expected unwrapped cause, got nil")
			}
		})
	}
}

func TestErrIPPoolOperationFailed(t *testing.T) {
	cause := errors.New("pool cause")

	err := &ErrIPPoolOperationFailed{Pool: "ipv6-pool", Operation: "allocate", Cause: cause}
	errStr := err.Error()

	if !strings.Contains(errStr, "ipv6-pool") {
		t.Errorf("error %q does not contain pool name", errStr)
	}
	if !strings.Contains(errStr, "allocate") {
		t.Errorf("error %q does not contain operation", errStr)
	}
	if err.Unwrap() == nil {
		t.Error("expected unwrapped cause, got nil")
	}
}

func TestErrGatewayOperationFailed(t *testing.T) {
	cause := errors.New("gateway cause")

	tests := []struct {
		name     string
		err      *ErrGatewayOperationFailed
		contains []string
		hasCause bool
	}{
		{
			name:     "with cause",
			err:      &ErrGatewayOperationFailed{GatewayID: "gw-1", Operation: "start", Cause: cause},
			contains: []string{"gw-1", "start", "gateway cause"},
			hasCause: true,
		},
		{
			name:     "without cause",
			err:      &ErrGatewayOperationFailed{GatewayID: "gw-2", Operation: "stop"},
			contains: []string{"gw-2", "stop"},
			hasCause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errStr, s) {
					t.Errorf("error %q does not contain %q", errStr, s)
				}
			}
			unwrapped := tt.err.Unwrap()
			if tt.hasCause && unwrapped == nil {
				t.Error("expected unwrapped cause, got nil")
			}
		})
	}
}

func TestErrRequirementsNotMet(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrRequirementsNotMet
		contains []string
	}{
		{
			name: "with checks",
			err: &ErrRequirementsNotMet{
				GatewayID: "gw-1",
				Checks: []RequirementCheck{
					{Name: "reputation", Required: "0.85", Actual: "0.70", Passed: false},
					{Name: "age", Required: "175 days", Actual: "100 days", Passed: false},
				},
			},
			contains: []string{"gw-1", "2 requirement(s) not met"},
		},
		{
			name:     "without checks",
			err:      &ErrRequirementsNotMet{GatewayID: "gw-2", Checks: nil},
			contains: []string{"gw-2", "requirements not met"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errStr, s) {
					t.Errorf("error %q does not contain %q", errStr, s)
				}
			}
		})
	}
}

func TestErrModeNotActive(t *testing.T) {
	err := &ErrModeNotActive{Mode: GatewayModeOverlay}
	errStr := err.Error()

	if !strings.Contains(errStr, "not active") {
		t.Errorf("error %q does not contain 'not active'", errStr)
	}
	if !strings.Contains(errStr, "overlay") {
		t.Errorf("error %q does not contain mode name", errStr)
	}
}

func TestErrModeAlreadyActive(t *testing.T) {
	err := &ErrModeAlreadyActive{Mode: GatewayModeEdge}
	errStr := err.Error()

	if !strings.Contains(errStr, "already active") {
		t.Errorf("error %q does not contain 'already active'", errStr)
	}
	if !strings.Contains(errStr, "edge") {
		t.Errorf("error %q does not contain mode name", errStr)
	}
}

func TestErrStartupFailed(t *testing.T) {
	cause := errors.New("startup cause")

	tests := []struct {
		name     string
		err      *ErrStartupFailed
		contains []string
		hasCause bool
	}{
		{
			name:     "with cause",
			err:      &ErrStartupFailed{GatewayID: "gw-1", Phase: "initialization", Cause: cause},
			contains: []string{"gw-1", "startup failed", "initialization", "startup cause"},
			hasCause: true,
		},
		{
			name:     "without cause",
			err:      &ErrStartupFailed{GatewayID: "gw-2", Phase: "validation"},
			contains: []string{"gw-2", "startup failed", "validation"},
			hasCause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errStr, s) {
					t.Errorf("error %q does not contain %q", errStr, s)
				}
			}
			unwrapped := tt.err.Unwrap()
			if tt.hasCause && unwrapped == nil {
				t.Error("expected unwrapped cause, got nil")
			}
		})
	}
}

func TestErrShutdownFailed(t *testing.T) {
	cause := errors.New("shutdown cause")

	err := &ErrShutdownFailed{GatewayID: "gw-1", Phase: "cleanup", Cause: cause}
	errStr := err.Error()

	if !strings.Contains(errStr, "gw-1") {
		t.Errorf("error %q does not contain gateway ID", errStr)
	}
	if !strings.Contains(errStr, "shutdown failed") {
		t.Errorf("error %q does not contain 'shutdown failed'", errStr)
	}
	if err.Unwrap() == nil {
		t.Error("expected unwrapped cause, got nil")
	}
}

func TestErrBGPOperationFailed(t *testing.T) {
	cause := errors.New("bgp cause")

	tests := []struct {
		name     string
		err      *ErrBGPOperationFailed
		contains []string
		hasCause bool
	}{
		{
			name:     "with cause",
			err:      &ErrBGPOperationFailed{Operation: "announce", Cause: cause},
			contains: []string{"announce", "bgp cause", "BGP operation"},
			hasCause: true,
		},
		{
			name:     "without cause",
			err:      &ErrBGPOperationFailed{Operation: "withdraw"},
			contains: []string{"withdraw", "BGP operation"},
			hasCause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				if !strings.Contains(errStr, s) {
					t.Errorf("error %q does not contain %q", errStr, s)
				}
			}
			unwrapped := tt.err.Unwrap()
			if tt.hasCause && unwrapped == nil {
				t.Error("expected unwrapped cause, got nil")
			}
		})
	}
}

func TestErrContextCanceled(t *testing.T) {
	err := &ErrContextCanceled{Operation: "start"}
	errStr := err.Error()

	if !strings.Contains(errStr, "start") {
		t.Errorf("error %q does not contain operation", errStr)
	}
	if !strings.Contains(errStr, "canceled") {
		t.Errorf("error %q does not contain 'canceled'", errStr)
	}
}

func TestErrTimeout(t *testing.T) {
	err := &ErrTimeout{Operation: "stop", Duration: 30 * time.Second}
	errStr := err.Error()

	if !strings.Contains(errStr, "stop") {
		t.Errorf("error %q does not contain operation", errStr)
	}
	if !strings.Contains(errStr, "timed out") {
		t.Errorf("error %q does not contain 'timed out'", errStr)
	}
	if !strings.Contains(errStr, "30s") {
		t.Errorf("error %q does not contain duration", errStr)
	}
}

func TestErrInvalidState(t *testing.T) {
	err := &ErrInvalidState{Expected: GatewayStateStopped, Actual: GatewayStateRunning}
	errStr := err.Error()

	if !strings.Contains(errStr, "stopped") {
		t.Errorf("error %q does not contain expected state", errStr)
	}
	if !strings.Contains(errStr, "running") {
		t.Errorf("error %q does not contain actual state", errStr)
	}
	if !strings.Contains(errStr, "invalid") {
		t.Errorf("error %q does not contain 'invalid'", errStr)
	}
}

func TestErrServiceNotFound(t *testing.T) {
	err := &ErrServiceNotFound{ServiceID: "svc-123"}
	errStr := err.Error()

	if !strings.Contains(errStr, "svc-123") {
		t.Errorf("error %q does not contain service ID", errStr)
	}
	if !strings.Contains(errStr, "not found") {
		t.Errorf("error %q does not contain 'not found'", errStr)
	}
}

func TestErrServiceAlreadyExists(t *testing.T) {
	err := &ErrServiceAlreadyExists{ServiceID: "svc-456"}
	errStr := err.Error()

	if !strings.Contains(errStr, "svc-456") {
		t.Errorf("error %q does not contain service ID", errStr)
	}
	if !strings.Contains(errStr, "already exists") {
		t.Errorf("error %q does not contain 'already exists'", errStr)
	}
}

func TestErrDeviceNotFound(t *testing.T) {
	err := &ErrDeviceNotFound{DeviceID: "dev-abc"}
	errStr := err.Error()

	if !strings.Contains(errStr, "dev-abc") {
		t.Errorf("error %q does not contain device ID", errStr)
	}
	if !strings.Contains(errStr, "not found") {
		t.Errorf("error %q does not contain 'not found'", errStr)
	}
}

func TestErrDeviceAlreadyExists(t *testing.T) {
	err := &ErrDeviceAlreadyExists{DeviceID: "dev-xyz"}
	errStr := err.Error()

	if !strings.Contains(errStr, "dev-xyz") {
		t.Errorf("error %q does not contain device ID", errStr)
	}
	if !strings.Contains(errStr, "already exists") {
		t.Errorf("error %q does not contain 'already exists'", errStr)
	}
}

func TestErrCapacityExceeded(t *testing.T) {
	err := &ErrCapacityExceeded{Resource: "devices", Limit: 100, Current: 100}
	errStr := err.Error()

	if !strings.Contains(errStr, "devices") {
		t.Errorf("error %q does not contain resource name", errStr)
	}
	if !strings.Contains(errStr, "capacity exceeded") {
		t.Errorf("error %q does not contain 'capacity exceeded'", errStr)
	}
	if !strings.Contains(errStr, "100") {
		t.Errorf("error %q does not contain limit/current value", errStr)
	}
}

func TestErrorsIs(t *testing.T) {
	// Test that sentinel errors work with errors.Is
	tests := []struct {
		name string
		err  error
	}{
		{"ErrGatewayNotFound", ErrGatewayNotFound},
		{"ErrGatewayAlreadyExists", ErrGatewayAlreadyExists},
		{"ErrConfigNil", ErrConfigNil},
		{"ErrUplinkNotFound", ErrUplinkNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.err) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.err)
			}
		})
	}
}

func TestRequirementCheck_Fields(t *testing.T) {
	check := RequirementCheck{
		Name:     "reputation",
		Required: "0.85",
		Actual:   "0.70",
		Passed:   false,
	}

	if check.Name != "reputation" {
		t.Errorf("Name = %q, want 'reputation'", check.Name)
	}
	if check.Required != "0.85" {
		t.Errorf("Required = %q, want '0.85'", check.Required)
	}
	if check.Actual != "0.70" {
		t.Errorf("Actual = %q, want '0.70'", check.Actual)
	}
	if check.Passed {
		t.Error("Passed should be false")
	}
}
