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

package adapters

import (
	"errors"
	"testing"
)

// cov964SentinelError is a typed cause used to prove the error chain.
type cov964SentinelError struct{}

func (cov964SentinelError) Error() string { return "sentinel cause" }

var cov964ErrSentinel = &cov964SentinelError{}

func TestAdapterError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *AdapterError
		want string
	}{
		{
			name: "without cause",
			err:  &AdapterError{Component: "xkms", Op: "sign", Msg: "key not found"},
			want: "xkms adapter sign: key not found",
		},
		{
			name: "with cause",
			err: &AdapterError{
				Component: "quicbaas",
				Op:        "connect",
				Msg:       "dial failed",
				Cause:     cov964ErrSentinel,
			},
			want: "quicbaas adapter connect: dial failed: sentinel cause",
		},
		{
			name: "empty fields keep the layout",
			err:  &AdapterError{},
			want: " adapter : ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdapterError_Unwrap(t *testing.T) {
	tests := []struct {
		name      string
		cause     error
		wantIsHit bool
	}{
		{name: "sentinel cause is found", cause: cov964ErrSentinel, wantIsHit: true},
		{name: "nil cause unwraps to nil", cause: nil, wantIsHit: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &AdapterError{Component: "ca", Op: "issue", Msg: "failed", Cause: tt.cause}
			if got := err.Unwrap(); got != tt.cause {
				t.Errorf("Unwrap() = %v, want %v", got, tt.cause)
			}
			if got := errors.Is(err, cov964ErrSentinel); got != tt.wantIsHit {
				t.Errorf("errors.Is(sentinel) = %v, want %v", got, tt.wantIsHit)
			}
			var target *cov964SentinelError
			if got := errors.As(err, &target); got != tt.wantIsHit {
				t.Errorf("errors.As(sentinel) = %v, want %v", got, tt.wantIsHit)
			}
		})
	}
}

func TestAdapterError_WithCause(t *testing.T) {
	oldCause := errors.New("old cause")
	tests := []struct {
		name     string
		receiver *AdapterError
		cause    error
	}{
		{
			name:     "adds a cause",
			receiver: &AdapterError{Component: "quicbaaskms", Op: "decrypt", Msg: "denied"},
			cause:    cov964ErrSentinel,
		},
		{
			name:     "replaces an existing cause",
			receiver: &AdapterError{Component: "ca", Op: "revoke", Msg: "rejected", Cause: oldCause},
			cause:    cov964ErrSentinel,
		},
		{
			name:     "clears the cause with nil",
			receiver: &AdapterError{Component: "xkms", Op: "seal", Msg: "failed", Cause: oldCause},
			cause:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := *tt.receiver
			got := tt.receiver.WithCause(tt.cause)

			if got == tt.receiver {
				t.Fatal("WithCause returned the receiver, want a new value")
			}
			if got.Component != before.Component || got.Op != before.Op || got.Msg != before.Msg {
				t.Errorf("WithCause() = %+v, want Component/Op/Msg of %+v", got, before)
			}
			if got.Cause != tt.cause {
				t.Errorf("WithCause().Cause = %v, want %v", got.Cause, tt.cause)
			}
			if *tt.receiver != before {
				t.Errorf("receiver changed to %+v, want %+v", *tt.receiver, before)
			}
			wantIs := tt.cause == cov964ErrSentinel
			if isHit := errors.Is(got, cov964ErrSentinel); isHit != wantIs {
				t.Errorf("errors.Is(sentinel) = %v, want %v", isHit, wantIs)
			}
		})
	}
}
