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

package ceremony

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

	if _, err := c.Init(ctx, &InitRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Init: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Status(ctx); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Status: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.ClaimCertBegin(ctx, &ClaimCertBeginRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("ClaimCertBegin: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.ClaimCertComplete(ctx, &ClaimCertCompleteRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("ClaimCertComplete: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.ClaimShareBegin(ctx, &ClaimShareBeginRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("ClaimShareBegin: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.ClaimShareComplete(ctx, &ClaimShareCompleteRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("ClaimShareComplete: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.SignCSR(ctx, &SignCSRRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("SignCSR: expected ErrNotYetWired, got %v", err)
	}
}

func TestErrors_Messages(t *testing.T) {
	cause := errors.New("underlying")

	tests := []struct {
		name string
		err  error
	}{
		{"InitFailed", &ErrInitFailed{Cause: cause}},
		{"StatusFailed", &ErrStatusFailed{Cause: cause}},
		{"ClaimCertBeginFailed", &ErrClaimCertBeginFailed{Cause: cause}},
		{"ClaimCertCompleteFailed", &ErrClaimCertCompleteFailed{Cause: cause}},
		{"ClaimShareFailed", &ErrClaimShareFailed{Cause: cause}},
		{"SignCSRFailed", &ErrSignCSRFailed{Cause: cause}},
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
