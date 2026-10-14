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
	"testing"
)

func TestErrors_UnwrapToCause(t *testing.T) {
	cause := errors.New("underlying")

	tests := []struct {
		name string
		err  error
	}{
		{"StatusFailed", &ErrStatusFailed{Cause: cause}},
		{"ListSlotsFailed", &ErrListSlotsFailed{Cause: cause}},
		{"InfoFailed", &ErrInfoFailed{Cause: cause}},
		{"EnrollPassphraseFailed", &ErrEnrollPassphraseFailed{Cause: cause}},
		{"EnrollFIDO2Failed", &ErrEnrollFIDO2Failed{Cause: cause}},
		{"EnrollTPMFailed", &ErrEnrollTPMFailed{Cause: cause}},
		{"EnrollRecoveryFailed", &ErrEnrollRecoveryFailed{Cause: cause}},
		{"RemoveKeyFailed", &ErrRemoveKeyFailed{Cause: cause}},
		{"TestUnlockFailed", &ErrTestUnlockFailed{Cause: cause}},
		{"ChangePassphraseFailed", &ErrChangePassphraseFailed{Cause: cause}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() == "" {
				t.Error("expected non-empty error string")
			}
			if !errors.Is(tc.err, cause) {
				t.Errorf("expected errors.Is to unwrap to cause, got %v", tc.err)
			}
		})
	}
}
