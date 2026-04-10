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

package bmc

import (
	"errors"
	"strings"
	"testing"
)

func TestErrInvalidConfig_Error(t *testing.T) {
	t.Run("with field", func(t *testing.T) {
		err := ErrInvalidConfig{Field: "address", Reason: "address is required"}
		got := err.Error()
		if !strings.Contains(got, "bmc:") || !strings.Contains(got, "address") {
			t.Errorf("unexpected error message: %s", got)
		}
	})
	t.Run("without field", func(t *testing.T) {
		err := ErrInvalidConfig{Reason: "something wrong"}
		got := err.Error()
		if !strings.HasPrefix(got, "bmc:") {
			t.Errorf("error should start with 'bmc:', got: %s", got)
		}
	})
}

func TestErrConnectionFailed_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("refused")
	err := ErrConnectionFailed{Address: "10.0.0.1:623", Cause: cause}
	got := err.Error()
	if !strings.Contains(got, "bmc:") || !strings.Contains(got, "10.0.0.1:623") {
		t.Errorf("unexpected error message: %s", got)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() did not return the cause")
	}
}

func TestErrConnectionFailed_NilCause(t *testing.T) {
	err := ErrConnectionFailed{Address: "10.0.0.1:623"}
	if err.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no cause")
	}
}

func TestErrClientClosed_Error(t *testing.T) {
	err := ErrClientClosed{}
	if !strings.Contains(err.Error(), "bmc:") || !strings.Contains(err.Error(), "closed") {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrPowerOperation_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrPowerOperation{Operation: "on", Cause: cause}
	got := err.Error()
	if !strings.Contains(got, "power") || !strings.Contains(got, "on") {
		t.Errorf("unexpected error message: %s", got)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() did not return the cause")
	}
}

func TestErrPowerOperation_NoOperation(t *testing.T) {
	err := ErrPowerOperation{}
	if !strings.Contains(err.Error(), "bmc:") {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrBootDevice_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("not supported")
	err := ErrBootDevice{Device: "pxe", Cause: cause}
	got := err.Error()
	if !strings.Contains(got, "boot device") || !strings.Contains(got, "pxe") {
		t.Errorf("unexpected error message: %s", got)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() did not return the cause")
	}
}

func TestErrVirtualMedia_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("mount failed")
	err := ErrVirtualMedia{Operation: "mount", Cause: cause}
	got := err.Error()
	if !strings.Contains(got, "virtual media") || !strings.Contains(got, "mount") {
		t.Errorf("unexpected error message: %s", got)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() did not return the cause")
	}
}

func TestErrInventory_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("connection lost")
	err := ErrInventory{Cause: cause}
	got := err.Error()
	if !strings.Contains(got, "inventory") {
		t.Errorf("unexpected error message: %s", got)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() did not return the cause")
	}
}

func TestErrInventory_NoCause(t *testing.T) {
	err := ErrInventory{}
	if !strings.Contains(err.Error(), "inventory") {
		t.Errorf("unexpected error message: %s", err.Error())
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no cause")
	}
}

func TestErrProfileNotFound_Error(t *testing.T) {
	err := ErrProfileNotFound{ProfileID: 42}
	got := err.Error()
	if !strings.Contains(got, "42") || !strings.Contains(got, "profile") {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestErrInvalidBootDevice_Error(t *testing.T) {
	err := ErrInvalidBootDevice{Device: "floppy"}
	got := err.Error()
	if !strings.Contains(got, "floppy") || !strings.Contains(got, "invalid") {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestErrInvalidPowerState_Error(t *testing.T) {
	err := ErrInvalidPowerState{State: "sleeping"}
	got := err.Error()
	if !strings.Contains(got, "sleeping") || !strings.Contains(got, "invalid") {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestErrNilConfig_Error(t *testing.T) {
	err := ErrNilConfig{}
	got := err.Error()
	if !strings.Contains(got, "bmc:") || !strings.Contains(got, "nil") {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestErrUnsupportedOperation_Error(t *testing.T) {
	err := ErrUnsupportedOperation{Operation: "mount ISO via IPMI"}
	got := err.Error()
	if !strings.Contains(got, "unsupported") || !strings.Contains(got, "mount ISO via IPMI") {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestErrSensorRead_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrSensorRead{Cause: cause}
	got := err.Error()
	if !strings.Contains(got, "sensor read") || !strings.Contains(got, "timeout") {
		t.Errorf("unexpected error message: %s", got)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() did not return the cause")
	}
}

func TestErrSensorRead_NoCause(t *testing.T) {
	err := ErrSensorRead{}
	if !strings.Contains(err.Error(), "sensor read") {
		t.Errorf("unexpected error message: %s", err.Error())
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no cause")
	}
}

func TestErrFRURead_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("io error")
	err := ErrFRURead{Reason: "read failed", Cause: cause}
	got := err.Error()
	if !strings.Contains(got, "FRU") || !strings.Contains(got, "read failed") || !strings.Contains(got, "io error") {
		t.Errorf("unexpected error message: %s", got)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() did not return the cause")
	}
}

func TestErrFRURead_ReasonOnly(t *testing.T) {
	err := ErrFRURead{Reason: "area size is zero"}
	got := err.Error()
	if !strings.Contains(got, "area size is zero") {
		t.Errorf("unexpected error message: %s", got)
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no cause")
	}
}

func TestErrSDRParse_Error(t *testing.T) {
	err := ErrSDRParse{Reason: "record too short"}
	got := err.Error()
	if !strings.Contains(got, "SDR") || !strings.Contains(got, "record too short") {
		t.Errorf("unexpected error message: %s", got)
	}
}
