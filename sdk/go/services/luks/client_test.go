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
	"context"
	"errors"
	"testing"
)

func TestNewClient_NotNil(t *testing.T) {
	if NewClient() == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClient_AllMethodsReturnNotYetWired(t *testing.T) {
	ctx := context.Background()
	c := NewClient()

	if _, err := c.Status(ctx, &StatusRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Status: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.ListSlots(ctx, &ListSlotsRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("ListSlots: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Info(ctx, &InfoRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Info: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.EnrollPassphrase(ctx, &EnrollPassphraseRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("EnrollPassphrase: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.EnrollFIDO2(ctx, &EnrollFIDO2Request{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("EnrollFIDO2: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.EnrollTPM(ctx, &EnrollTPMRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("EnrollTPM: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.EnrollRecovery(ctx, &EnrollRecoveryRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("EnrollRecovery: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.RemoveKey(ctx, &RemoveKeyRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("RemoveKey: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.TestUnlock(ctx, &TestUnlockRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("TestUnlock: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.ChangePassphrase(ctx, &ChangePassphraseRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("ChangePassphrase: expected ErrNotYetWired, got %v", err)
	}
}

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

func TestClientImplementsService(t *testing.T) {
	var _ Service = (*Client)(nil)
}
