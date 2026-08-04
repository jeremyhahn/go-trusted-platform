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

package luks

import (
	"errors"
	"strings"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrTokenNil",
			err:  ErrTokenNil,
			want: "luks: token cannot be nil",
		},
		{
			name: "ErrTokenTypeEmpty",
			err:  ErrTokenTypeEmpty,
			want: "luks: token type cannot be empty",
		},
		{
			name: "ErrTokenNoFreeSlot",
			err:  ErrTokenNoFreeSlot,
			want: "luks: no free token slots available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.want {
				t.Errorf("Error() = %q, want %q", tt.err.Error(), tt.want)
			}
		})
	}
}

func TestTokenNotFoundError(t *testing.T) {
	t.Parallel()

	t.Run("Error message", func(t *testing.T) {
		err := &TokenNotFoundError{ID: 5}
		want := "luks: token not found at slot 5"
		if err.Error() != want {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	})

	t.Run("ID 0", func(t *testing.T) {
		err := &TokenNotFoundError{ID: 0}
		want := "luks: token not found at slot 0"
		if err.Error() != want {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	})

	t.Run("ID 31", func(t *testing.T) {
		err := &TokenNotFoundError{ID: 31}
		want := "luks: token not found at slot 31"
		if err.Error() != want {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	})

	t.Run("errors.As", func(t *testing.T) {
		err := &WrappedError{Msg: "wrapped", Err: &TokenNotFoundError{ID: 3}}
		var target *TokenNotFoundError
		if !errors.As(err, &target) {
			t.Error("errors.As should return true for TokenNotFoundError")
		}
		if target.ID != 3 {
			t.Errorf("ID = %d, want 3", target.ID)
		}
	})
}

func TestTokenInvalidIDError(t *testing.T) {
	t.Parallel()

	t.Run("Negative ID", func(t *testing.T) {
		err := &TokenInvalidIDError{ID: -1}
		if !strings.Contains(err.Error(), "-1") {
			t.Errorf("Error() should contain ID, got: %q", err.Error())
		}
		if !strings.Contains(err.Error(), "0-31") {
			t.Errorf("Error() should contain valid range, got: %q", err.Error())
		}
	})

	t.Run("Too large ID", func(t *testing.T) {
		err := &TokenInvalidIDError{ID: 50}
		if !strings.Contains(err.Error(), "50") {
			t.Errorf("Error() should contain ID, got: %q", err.Error())
		}
	})

	t.Run("errors.As", func(t *testing.T) {
		err := &WrappedError{Msg: "wrapped", Err: &TokenInvalidIDError{ID: 99}}
		var target *TokenInvalidIDError
		if !errors.As(err, &target) {
			t.Error("errors.As should return true for TokenInvalidIDError")
		}
		if target.ID != 99 {
			t.Errorf("ID = %d, want 99", target.ID)
		}
	})
}

func TestTokenSlotOccupiedError(t *testing.T) {
	t.Parallel()

	t.Run("Error message", func(t *testing.T) {
		err := &TokenSlotOccupiedError{ID: 7}
		want := "luks: token slot 7 is already occupied"
		if err.Error() != want {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	})

	t.Run("errors.As", func(t *testing.T) {
		err := &WrappedError{Msg: "operation failed", Err: &TokenSlotOccupiedError{ID: 15}}
		var target *TokenSlotOccupiedError
		if !errors.As(err, &target) {
			t.Error("errors.As should return true for TokenSlotOccupiedError")
		}
		if target.ID != 15 {
			t.Errorf("ID = %d, want 15", target.ID)
		}
	})
}

func TestTokenOperationError(t *testing.T) {
	t.Parallel()

	t.Run("Error message", func(t *testing.T) {
		underlying := errors.New("device not found")
		err := &TokenOperationError{Op: "read", Err: underlying}
		want := `luks: token operation "read" failed: device not found`
		if err.Error() != want {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	})

	t.Run("Different operations", func(t *testing.T) {
		operations := []string{"create", "delete", "update", "list", "count"}
		for _, op := range operations {
			err := &TokenOperationError{Op: op, Err: errors.New("test")}
			if !strings.Contains(err.Error(), op) {
				t.Errorf("Error() for op %q should contain operation name, got: %q", op, err.Error())
			}
		}
	})

	t.Run("Unwrap", func(t *testing.T) {
		underlying := errors.New("underlying error")
		err := &TokenOperationError{Op: "test", Err: underlying}
		if err.Unwrap() != underlying {
			t.Error("Unwrap() should return the underlying error")
		}
	})

	t.Run("errors.Is with wrapped error", func(t *testing.T) {
		underlying := errors.New("specific error")
		err := &TokenOperationError{Op: "test", Err: underlying}
		if !errors.Is(err, underlying) {
			t.Error("errors.Is should find the underlying error")
		}
	})

	t.Run("errors.As", func(t *testing.T) {
		wrapped := &WrappedError{Msg: "context", Err: &TokenOperationError{
			Op:  "create",
			Err: errors.New("failed"),
		}}
		var target *TokenOperationError
		if !errors.As(wrapped, &target) {
			t.Error("errors.As should return true for TokenOperationError")
		}
		if target.Op != "create" {
			t.Errorf("Op = %q, want %q", target.Op, "create")
		}
	})

	t.Run("Nested error unwrapping", func(t *testing.T) {
		inner := &TokenNotFoundError{ID: 5}
		opErr := &TokenOperationError{Op: "update", Err: inner}
		wrapped := &WrappedError{Msg: "handler error", Err: opErr}

		var notFoundErr *TokenNotFoundError
		if !errors.As(wrapped, &notFoundErr) {
			t.Error("errors.As should find nested TokenNotFoundError")
		}
		if notFoundErr.ID != 5 {
			t.Errorf("ID = %d, want 5", notFoundErr.ID)
		}
	})
}

func TestErrorDistinction(t *testing.T) {
	t.Parallel()

	// Ensure different error types are distinguishable
	t.Run("Different error types", func(t *testing.T) {
		notFound := &TokenNotFoundError{ID: 1}
		invalidID := &TokenInvalidIDError{ID: 1}
		occupied := &TokenSlotOccupiedError{ID: 1}

		// Each should only match its own type
		var nfTarget *TokenNotFoundError
		var idTarget *TokenInvalidIDError
		var occTarget *TokenSlotOccupiedError

		if !errors.As(notFound, &nfTarget) {
			t.Error("TokenNotFoundError should match TokenNotFoundError")
		}
		if errors.As(notFound, &idTarget) {
			t.Error("TokenNotFoundError should not match TokenInvalidIDError")
		}
		if errors.As(notFound, &occTarget) {
			t.Error("TokenNotFoundError should not match TokenSlotOccupiedError")
		}

		if errors.As(invalidID, &nfTarget) {
			t.Error("TokenInvalidIDError should not match TokenNotFoundError")
		}
		if !errors.As(invalidID, &idTarget) {
			t.Error("TokenInvalidIDError should match TokenInvalidIDError")
		}
		if errors.As(invalidID, &occTarget) {
			t.Error("TokenInvalidIDError should not match TokenSlotOccupiedError")
		}

		if errors.As(occupied, &nfTarget) {
			t.Error("TokenSlotOccupiedError should not match TokenNotFoundError")
		}
		if errors.As(occupied, &idTarget) {
			t.Error("TokenSlotOccupiedError should not match TokenInvalidIDError")
		}
		if !errors.As(occupied, &occTarget) {
			t.Error("TokenSlotOccupiedError should match TokenSlotOccupiedError")
		}
	})

	t.Run("Sentinel errors are distinct", func(t *testing.T) {
		if errors.Is(ErrTokenNil, ErrTokenTypeEmpty) {
			t.Error("ErrTokenNil should not equal ErrTokenTypeEmpty")
		}
		if errors.Is(ErrTokenNil, ErrTokenNoFreeSlot) {
			t.Error("ErrTokenNil should not equal ErrTokenNoFreeSlot")
		}
		if errors.Is(ErrTokenTypeEmpty, ErrTokenNoFreeSlot) {
			t.Error("ErrTokenTypeEmpty should not equal ErrTokenNoFreeSlot")
		}
	})
}
