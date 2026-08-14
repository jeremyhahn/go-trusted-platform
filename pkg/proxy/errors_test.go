package proxy

import (
	"errors"
	"strings"
	"testing"
)

func TestConfigError(t *testing.T) {
	err := &ConfigError{Kind: "route", ID: "api", Err: ErrInvalidAuthMode}
	if !errors.Is(err, ErrInvalidAuthMode) {
		t.Error("errors.Is must match the wrapped sentinel")
	}
	msg := err.Error()
	if !strings.Contains(msg, "route") || !strings.Contains(msg, "api") {
		t.Errorf("Error() = %q, want kind and id present", msg)
	}
}

func TestListenerError(t *testing.T) {
	inner := errors.New("address in use")
	err := &ListenerError{ID: "main", Err: inner}
	if !errors.Is(err, inner) {
		t.Error("errors.Is must match the wrapped error")
	}
	if msg := err.Error(); !strings.Contains(msg, "main") || !strings.Contains(msg, "address in use") {
		t.Errorf("Error() = %q", msg)
	}
}

func TestTrustResolveError(t *testing.T) {
	inner := errors.New("unknown class")
	err := &TrustResolveError{PoolID: "p1", TrustClass: "bmc", Err: inner}
	if !errors.Is(err, inner) {
		t.Error("errors.Is must match the wrapped error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "p1") || !strings.Contains(msg, "bmc") {
		t.Errorf("Error() = %q", msg)
	}
}
