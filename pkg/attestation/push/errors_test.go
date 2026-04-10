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

package push

import (
	"errors"
	"testing"
)

func TestErrPushFailed(t *testing.T) {
	t.Run("full error message", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := ErrPushFailed{
			TargetID: "target-1",
			Endpoint: "https://example.com/push",
			Reason:   "network error",
			Cause:    cause,
		}

		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
		if !containsAll(msg, "push: failed", "target-1", "example.com", "network error", "connection refused") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("minimal error message", func(t *testing.T) {
		err := ErrPushFailed{}
		msg := err.Error()
		if msg != "push: failed" {
			t.Errorf("expected 'push: failed', got '%s'", msg)
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrPushFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
	})

	t.Run("nil unwrap", func(t *testing.T) {
		err := ErrPushFailed{}
		if err.Unwrap() != nil {
			t.Error("Unwrap should return nil when no cause")
		}
	})
}

func TestErrTargetUnreachable(t *testing.T) {
	t.Run("full error message", func(t *testing.T) {
		cause := errors.New("timeout")
		err := ErrTargetUnreachable{
			TargetID: "target-2",
			Endpoint: "https://api.example.com",
			Reason:   "connection timeout",
			Cause:    cause,
		}

		msg := err.Error()
		if !containsAll(msg, "push: target unreachable", "target-2", "api.example.com", "connection timeout", "timeout") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("minimal error message", func(t *testing.T) {
		err := ErrTargetUnreachable{}
		if err.Error() != "push: target unreachable" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		cause := errors.New("network unreachable")
		err := ErrTargetUnreachable{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
	})
}

func TestErrAuthFailed(t *testing.T) {
	t.Run("full error message", func(t *testing.T) {
		cause := errors.New("invalid token")
		err := ErrAuthFailed{
			TargetID: "secure-target",
			Endpoint: "https://secure.example.com",
			Reason:   "token expired",
			Cause:    cause,
		}

		msg := err.Error()
		if !containsAll(msg, "push: authentication failed", "secure-target", "secure.example.com", "token expired", "invalid token") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("minimal error message", func(t *testing.T) {
		err := ErrAuthFailed{}
		if err.Error() != "push: authentication failed" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		cause := errors.New("auth error")
		err := ErrAuthFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
	})
}

func TestErrRetryExhausted(t *testing.T) {
	t.Run("full error message", func(t *testing.T) {
		lastErr := errors.New("connection failed")
		err := ErrRetryExhausted{
			TargetID:    "retry-target",
			Endpoint:    "https://retry.example.com",
			Attempts:    3,
			MaxAttempts: 3,
			LastError:   lastErr,
		}

		msg := err.Error()
		if !containsAll(msg, "push: retry exhausted", "3/3", "retry-target", "retry.example.com", "connection failed") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("minimal error message", func(t *testing.T) {
		err := ErrRetryExhausted{Attempts: 5, MaxAttempts: 5}
		msg := err.Error()
		if !containsAll(msg, "push: retry exhausted", "5/5") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		lastErr := errors.New("last error")
		err := ErrRetryExhausted{LastError: lastErr}
		if err.Unwrap() != lastErr {
			t.Error("Unwrap should return last error")
		}
	})
}

func TestErrInvalidTarget(t *testing.T) {
	t.Run("full error message", func(t *testing.T) {
		err := ErrInvalidTarget{
			TargetID: "bad-target",
			Field:    "Endpoint",
			Reason:   "URL is malformed",
		}

		msg := err.Error()
		if !containsAll(msg, "push: invalid target", "bad-target", "Endpoint", "URL is malformed") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("minimal error message", func(t *testing.T) {
		err := ErrInvalidTarget{}
		if err.Error() != "push: invalid target" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrInvalidConfig(t *testing.T) {
	t.Run("with field", func(t *testing.T) {
		err := ErrInvalidConfig{
			Field:  "Timeout",
			Reason: "must be positive",
		}

		msg := err.Error()
		if !containsAll(msg, "push: invalid config", "Timeout", "must be positive") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("without field", func(t *testing.T) {
		err := ErrInvalidConfig{
			Reason: "missing required fields",
		}

		msg := err.Error()
		if !containsAll(msg, "push: invalid config", "missing required fields") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})
}

func TestErrClientNotInitialized(t *testing.T) {
	err := ErrClientNotInitialized{}
	if err.Error() != "push: client not initialized" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrClientClosed(t *testing.T) {
	err := ErrClientClosed{}
	if err.Error() != "push: client closed" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrSchedulerNotInitialized(t *testing.T) {
	err := ErrSchedulerNotInitialized{}
	if err.Error() != "push: scheduler not initialized" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrSchedulerStopped(t *testing.T) {
	err := ErrSchedulerStopped{}
	if err.Error() != "push: scheduler stopped" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrSchedulerAlreadyRunning(t *testing.T) {
	err := ErrSchedulerAlreadyRunning{}
	if err.Error() != "push: scheduler already running" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrContextCanceled(t *testing.T) {
	t.Run("with operation", func(t *testing.T) {
		err := ErrContextCanceled{Operation: "push manifest"}
		msg := err.Error()
		if !containsAll(msg, "push:", "push manifest", "canceled") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("without operation", func(t *testing.T) {
		err := ErrContextCanceled{}
		if err.Error() != "push: operation canceled" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrNoTargetsConfigured(t *testing.T) {
	err := ErrNoTargetsConfigured{}
	if err.Error() != "push: no targets configured" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrTargetNotFound(t *testing.T) {
	t.Run("with target ID", func(t *testing.T) {
		err := ErrTargetNotFound{TargetID: "missing-target"}
		msg := err.Error()
		if !containsAll(msg, "push: target not found", "missing-target") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("without target ID", func(t *testing.T) {
		err := ErrTargetNotFound{}
		if err.Error() != "push: target not found" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrSerializationFailed(t *testing.T) {
	t.Run("full error", func(t *testing.T) {
		cause := errors.New("json encoding failed")
		err := ErrSerializationFailed{
			Reason: "invalid manifest format",
			Cause:  cause,
		}

		msg := err.Error()
		if !containsAll(msg, "push: serialization failed", "invalid manifest format", "json encoding failed") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("minimal error", func(t *testing.T) {
		err := ErrSerializationFailed{}
		if err.Error() != "push: serialization failed" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		cause := errors.New("encoding error")
		err := ErrSerializationFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
	})
}

func TestErrTransportNotSupported(t *testing.T) {
	t.Run("with transport", func(t *testing.T) {
		err := ErrTransportNotSupported{Transport: "websocket"}
		msg := err.Error()
		if !containsAll(msg, "push: transport not supported", "websocket") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("without transport", func(t *testing.T) {
		err := ErrTransportNotSupported{}
		if err.Error() != "push: transport not supported" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrTLSConfigFailed(t *testing.T) {
	t.Run("full error", func(t *testing.T) {
		cause := errors.New("certificate expired")
		err := ErrTLSConfigFailed{
			Reason: "failed to load certificate",
			Cause:  cause,
		}

		msg := err.Error()
		if !containsAll(msg, "push: TLS configuration failed", "failed to load certificate", "certificate expired") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("minimal error", func(t *testing.T) {
		err := ErrTLSConfigFailed{}
		if err.Error() != "push: TLS configuration failed" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		cause := errors.New("tls error")
		err := ErrTLSConfigFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
	})
}

func TestErrInvalidResponse(t *testing.T) {
	t.Run("full error", func(t *testing.T) {
		err := ErrInvalidResponse{
			StatusCode: 500,
			Body:       "Internal Server Error",
			Reason:     "unexpected response",
		}

		msg := err.Error()
		if !containsAll(msg, "push: invalid response", "500", "Internal Server Error", "unexpected response") {
			t.Errorf("error message missing expected parts: %s", msg)
		}
	})

	t.Run("minimal error", func(t *testing.T) {
		err := ErrInvalidResponse{}
		if err.Error() != "push: invalid response" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("truncates long body", func(t *testing.T) {
		longBody := make([]byte, 300)
		for i := range longBody {
			longBody[i] = 'x'
		}
		err := ErrInvalidResponse{Body: string(longBody)}
		msg := err.Error()
		// Body > 200 chars should be excluded
		if len(msg) > 100 {
			t.Errorf("long body should be excluded from error message")
		}
	})
}

// Helper function to check if all substrings are present
func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		found := false
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
