package embedded

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestErrNilRegistry_Error(t *testing.T) {
	err := ErrNilRegistry{}
	msg := err.Error()

	if !strings.Contains(msg, "ServiceRegistry") {
		t.Errorf("expected error message to contain 'ServiceRegistry', got %q", msg)
	}

	if !strings.Contains(msg, "nil") {
		t.Errorf("expected error message to contain 'nil', got %q", msg)
	}
}

func TestErrNilRegistry_IsError(t *testing.T) {
	var err error = ErrNilRegistry{}

	var target ErrNilRegistry
	if !errors.As(err, &target) {
		t.Error("expected errors.As to match ErrNilRegistry")
	}
}

func TestErrNotConnected_Error(t *testing.T) {
	err := ErrNotConnected{}
	msg := err.Error()

	if !strings.Contains(msg, "not connected") {
		t.Errorf("expected error message to contain 'not connected', got %q", msg)
	}
}

func TestErrNotConnected_IsError(t *testing.T) {
	var err error = ErrNotConnected{}

	var target ErrNotConnected
	if !errors.As(err, &target) {
		t.Error("expected errors.As to match ErrNotConnected")
	}
}

func TestErrMethodNotFound_Error(t *testing.T) {
	method := "/platform.v1.PlatformDaemon/GetVersion"
	err := ErrMethodNotFound{Method: method}
	msg := err.Error()

	if !strings.Contains(msg, method) {
		t.Errorf("expected error message to contain method %q, got %q", method, msg)
	}

	if !strings.Contains(msg, "method not found") {
		t.Errorf("expected error message to contain 'method not found', got %q", msg)
	}
}

func TestErrMethodNotFound_EmptyMethod(t *testing.T) {
	err := ErrMethodNotFound{Method: ""}
	msg := err.Error()

	if !strings.Contains(msg, "method not found") {
		t.Errorf("expected error message to contain 'method not found', got %q", msg)
	}
}

func TestErrTypeMismatch_Error(t *testing.T) {
	err := ErrTypeMismatch{
		Expected: "*platformv1.GetVersionRequest",
		Got:      "string",
	}
	msg := err.Error()

	if !strings.Contains(msg, "*platformv1.GetVersionRequest") {
		t.Errorf("expected error message to contain expected type, got %q", msg)
	}

	if !strings.Contains(msg, "string") {
		t.Errorf("expected error message to contain got type, got %q", msg)
	}

	if !strings.Contains(msg, "type mismatch") {
		t.Errorf("expected error message to contain 'type mismatch', got %q", msg)
	}
}

func TestErrTypeMismatch_IsError(t *testing.T) {
	var err error = ErrTypeMismatch{Expected: "A", Got: "B"}

	var target ErrTypeMismatch
	if !errors.As(err, &target) {
		t.Error("expected errors.As to match ErrTypeMismatch")
	}

	if target.Expected != "A" {
		t.Errorf("expected Expected = %q, got %q", "A", target.Expected)
	}

	if target.Got != "B" {
		t.Errorf("expected Got = %q, got %q", "B", target.Got)
	}
}

func TestErrMarshalFailed_Error(t *testing.T) {
	inner := fmt.Errorf("proto: required field not set")
	err := ErrMarshalFailed{Err: inner}
	msg := err.Error()

	if !strings.Contains(msg, "marshal failed") {
		t.Errorf("expected error message to contain 'marshal failed', got %q", msg)
	}

	if !strings.Contains(msg, "required field not set") {
		t.Errorf("expected error message to contain inner error, got %q", msg)
	}
}

func TestErrMarshalFailed_Unwrap(t *testing.T) {
	inner := fmt.Errorf("proto: marshal error")
	err := ErrMarshalFailed{Err: inner}

	unwrapped := err.Unwrap()
	if unwrapped == nil {
		t.Fatal("expected Unwrap() to return non-nil error")
	}

	if unwrapped != inner {
		t.Errorf("expected Unwrap() to return inner error, got %v", unwrapped)
	}
}

func TestErrMarshalFailed_UnwrapNil(t *testing.T) {
	err := ErrMarshalFailed{Err: nil}

	unwrapped := err.Unwrap()
	if unwrapped != nil {
		t.Errorf("expected Unwrap() to return nil when inner error is nil, got %v", unwrapped)
	}
}

func TestErrUnmarshalFailed_Error(t *testing.T) {
	inner := fmt.Errorf("proto: cannot parse invalid wire-format data")
	err := ErrUnmarshalFailed{Err: inner}
	msg := err.Error()

	if !strings.Contains(msg, "unmarshal failed") {
		t.Errorf("expected error message to contain 'unmarshal failed', got %q", msg)
	}

	if !strings.Contains(msg, "cannot parse invalid wire-format data") {
		t.Errorf("expected error message to contain inner error, got %q", msg)
	}
}

func TestErrUnmarshalFailed_Unwrap(t *testing.T) {
	inner := fmt.Errorf("proto: unmarshal error")
	err := ErrUnmarshalFailed{Err: inner}

	unwrapped := err.Unwrap()
	if unwrapped == nil {
		t.Fatal("expected Unwrap() to return non-nil error")
	}

	if unwrapped != inner {
		t.Errorf("expected Unwrap() to return inner error, got %v", unwrapped)
	}
}

func TestErrUnmarshalFailed_UnwrapNil(t *testing.T) {
	err := ErrUnmarshalFailed{Err: nil}

	unwrapped := err.Unwrap()
	if unwrapped != nil {
		t.Errorf("expected Unwrap() to return nil when inner error is nil, got %v", unwrapped)
	}
}

func TestErrServiceNotRegistered_Error(t *testing.T) {
	err := ErrServiceNotRegistered{Service: "PlatformDaemon"}
	msg := err.Error()

	if !strings.Contains(msg, "PlatformDaemon") {
		t.Errorf("expected error message to contain service name, got %q", msg)
	}

	if !strings.Contains(msg, "service not registered") {
		t.Errorf("expected error message to contain 'service not registered', got %q", msg)
	}
}

func TestErrServiceNotRegistered_EmptyService(t *testing.T) {
	err := ErrServiceNotRegistered{Service: ""}
	msg := err.Error()

	if !strings.Contains(msg, "service not registered") {
		t.Errorf("expected error message to contain 'service not registered', got %q", msg)
	}
}

func TestErrServiceNotRegistered_IsError(t *testing.T) {
	var err error = ErrServiceNotRegistered{Service: "TestService"}

	var target ErrServiceNotRegistered
	if !errors.As(err, &target) {
		t.Error("expected errors.As to match ErrServiceNotRegistered")
	}

	if target.Service != "TestService" {
		t.Errorf("expected Service = %q, got %q", "TestService", target.Service)
	}
}
