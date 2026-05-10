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

package encrypt

import (
	"errors"
	"strings"
	"testing"
)

func TestErrValueOrFileRequired(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrValueOrFileRequired{}
		msg := err.Error()
		if !strings.Contains(msg, "--value") || !strings.Contains(msg, "--file") {
			t.Errorf("expected error to mention --value and --file, got %q", msg)
		}
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrValueOrFileRequired{}
		if err == nil {
			t.Fatal("expected non-nil error")
		}
	})
}

func TestErrValueAndFileMutuallyExclusive(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrValueAndFileMutuallyExclusive{}
		msg := err.Error()
		if !strings.Contains(msg, "mutually exclusive") {
			t.Errorf("expected error to mention mutual exclusion, got %q", msg)
		}
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrValueAndFileMutuallyExclusive{}
		if err == nil {
			t.Fatal("expected non-nil error")
		}
	})
}

func TestErrReadSecretFile(t *testing.T) {
	cause := errors.New("permission denied")

	t.Run("error message includes path and cause", func(t *testing.T) {
		err := ErrReadSecretFile{Path: "/tmp/secret.txt", Cause: cause}
		msg := err.Error()
		if !strings.Contains(msg, "/tmp/secret.txt") {
			t.Errorf("expected error to contain path, got %q", msg)
		}
		if !strings.Contains(msg, "permission denied") {
			t.Errorf("expected error to contain cause, got %q", msg)
		}
	})

	t.Run("unwraps to cause", func(t *testing.T) {
		err := ErrReadSecretFile{Path: "/tmp/secret.txt", Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("expected Unwrap to return the cause")
		}
	})
}

func TestErrEncryptionFailed(t *testing.T) {
	cause := errors.New("key not found")

	t.Run("error message includes cause", func(t *testing.T) {
		err := ErrEncryptionFailed{Cause: cause}
		msg := err.Error()
		if !strings.Contains(msg, "key not found") {
			t.Errorf("expected error to contain cause, got %q", msg)
		}
	})

	t.Run("unwraps to cause", func(t *testing.T) {
		err := ErrEncryptionFailed{Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("expected Unwrap to return the cause")
		}
	})
}

func TestErrConnectionFailed(t *testing.T) {
	cause := errors.New("connection refused")

	t.Run("error message includes cause", func(t *testing.T) {
		err := ErrConnectionFailed{Cause: cause}
		msg := err.Error()
		if !strings.Contains(msg, "connection refused") {
			t.Errorf("expected error to contain cause, got %q", msg)
		}
	})

	t.Run("unwraps to cause", func(t *testing.T) {
		err := ErrConnectionFailed{Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("expected Unwrap to return the cause")
		}
	})
}
