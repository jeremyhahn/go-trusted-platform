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

package fido2

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
	if _, err := c.WaitDevice(ctx, &WaitDeviceRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("WaitDevice: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Info(ctx, &InfoRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Info: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Register(ctx, &RegisterRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Register: expected ErrNotYetWired, got %v", err)
	}
	if _, err := c.Authenticate(ctx, &AuthenticateRequest{}); err == nil || !errors.Is(err, ErrNotYetWired) {
		t.Errorf("Authenticate: expected ErrNotYetWired, got %v", err)
	}
}

func TestErrors_UnwrapToCause(t *testing.T) {
	cause := errors.New("underlying")

	tests := []struct {
		name string
		err  error
	}{
		{"ListDevicesFailed", &ErrListDevicesFailed{Cause: cause}},
		{"WaitDeviceFailed", &ErrWaitDeviceFailed{Cause: cause}},
		{"DeviceInfoFailed", &ErrDeviceInfoFailed{Cause: cause}},
		{"RegisterFailed", &ErrRegisterFailed{Cause: cause}},
		{"AuthenticateFailed", &ErrAuthenticateFailed{Cause: cause}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() == "" {
				t.Error("expected non-empty message")
			}
			if !errors.Is(tc.err, cause) {
				t.Errorf("expected errors.Is to unwrap")
			}
		})
	}
}

func TestClientImplementsService(t *testing.T) {
	var _ Service = (*Client)(nil)
}
