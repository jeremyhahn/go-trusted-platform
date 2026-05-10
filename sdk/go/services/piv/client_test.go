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

package piv

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

	if _, err := c.ListDevices(ctx, &ListDevicesRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("ListDevices: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.ListSlots(ctx, &ListSlotsRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("ListSlots: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.SlotInfo(ctx, &SlotInfoRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("SlotInfo: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Generate(ctx, &GenerateRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Generate: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Import(ctx, &ImportRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Import: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Sign(ctx, &SignRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Sign: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Attest(ctx, &AttestRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Attest: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Reset(ctx, &ResetRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Reset: expected ErrNotYetWired, got %v", err)
	}
}

func TestErrors_UnwrapToCause(t *testing.T) {
	cause := errors.New("underlying")

	tests := []struct {
		name string
		err  error
	}{
		{"ListDevicesFailed", &ErrListDevicesFailed{Cause: cause}},
		{"ListSlotsFailed", &ErrListSlotsFailed{Cause: cause}},
		{"SlotInfoFailed", &ErrSlotInfoFailed{Cause: cause}},
		{"GenerateFailed", &ErrGenerateFailed{Cause: cause}},
		{"ImportFailed", &ErrImportFailed{Cause: cause}},
		{"SignFailed", &ErrSignFailed{Cause: cause}},
		{"AttestFailed", &ErrAttestFailed{Cause: cause}},
		{"ResetFailed", &ErrResetFailed{Cause: cause}},
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
