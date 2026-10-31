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

package backends

import (
	"errors"
	"testing"
)

var (
	errTestSentinel = errors.New("sentinel")
	errTestCause    = errors.New("cause")
)

func TestPackageErrors_Messages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"message", &MessageError{Msg: "plain message"}, "plain message"},
		{"wrapped", &WrappedError{Msg: "open device", Err: errTestCause}, "open device: cause"},
		{"sentinel with cause", &SentinelCauseError{Sentinel: errTestSentinel, Cause: errTestCause}, "sentinel: cause"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPackageErrors_Unwrap(t *testing.T) {
	wrapped := &WrappedError{Msg: "open device", Err: errTestCause}
	if !errors.Is(wrapped, errTestCause) {
		t.Error("WrappedError does not match its cause")
	}
	if errors.Is(wrapped, errTestSentinel) {
		t.Error("WrappedError matches an unrelated error")
	}

	both := &SentinelCauseError{Sentinel: errTestSentinel, Cause: errTestCause}
	if !errors.Is(both, errTestSentinel) || !errors.Is(both, errTestCause) {
		t.Error("SentinelCauseError must match both its sentinel and its cause")
	}

	var msg *MessageError
	if errors.As(wrapped, &msg) {
		t.Error("WrappedError unwraps to a MessageError it does not hold")
	}
}
