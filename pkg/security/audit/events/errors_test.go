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

package events

import (
	"errors"
	"testing"
)

func TestErrNilBuilder(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrNilBuilder{}
		msg := err.Error()

		if msg == "" {
			t.Error("error message should not be empty")
		}
		if msg != "enrollment event builder is nil" {
			t.Errorf("unexpected error message: %s", msg)
		}
	})

	t.Run("implements error interface", func(t *testing.T) {
		// Compile-time check that ErrNilBuilder implements error
		var _ error = ErrNilBuilder{}
		err := ErrNilBuilder{}
		if err.Error() == "" {
			t.Error("should have non-empty error message")
		}
	})

	t.Run("errors.As matching", func(t *testing.T) {
		err := ErrNilBuilder{}
		var target ErrNilBuilder
		if !errors.As(err, &target) {
			t.Error("should match with errors.As")
		}
	})
}

func TestErrNilLogger(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrNilLogger{}
		msg := err.Error()

		if msg == "" {
			t.Error("error message should not be empty")
		}
		if msg != "audit logger cannot be nil" {
			t.Errorf("unexpected error message: %s", msg)
		}
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrNilLogger{}
		if err.Error() == "" {
			t.Error("should have non-empty error message")
		}
	})

	t.Run("errors.As matching", func(t *testing.T) {
		err := ErrNilLogger{}
		var target ErrNilLogger
		if !errors.As(err, &target) {
			t.Error("should match with errors.As")
		}
	})
}

func TestErrEmptyDeviceID(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrEmptyDeviceID{}
		msg := err.Error()

		if msg == "" {
			t.Error("error message should not be empty")
		}
		if msg != "device ID cannot be empty" {
			t.Errorf("unexpected error message: %s", msg)
		}
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrEmptyDeviceID{}
		if err.Error() == "" {
			t.Error("should have non-empty error message")
		}
	})

	t.Run("errors.As matching", func(t *testing.T) {
		err := ErrEmptyDeviceID{}
		var target ErrEmptyDeviceID
		if !errors.As(err, &target) {
			t.Error("should match with errors.As")
		}
	})
}

func TestErrNilVerificationResult(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := ErrNilVerificationResult{}
		msg := err.Error()

		if msg == "" {
			t.Error("error message should not be empty")
		}
		if msg != "verification result cannot be nil" {
			t.Errorf("unexpected error message: %s", msg)
		}
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrNilVerificationResult{}
		if err.Error() == "" {
			t.Error("should have non-empty error message")
		}
	})

	t.Run("errors.As matching", func(t *testing.T) {
		err := ErrNilVerificationResult{}
		var target ErrNilVerificationResult
		if !errors.As(err, &target) {
			t.Error("should match with errors.As")
		}
	})
}
