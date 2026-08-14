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

package daemon

import (
	"context"
	"log/slog"
	"testing"
)

func TestNewKMSService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		app     interface{}
		wantErr bool
		errType error
	}{
		{
			name:    "returns error for nil application",
			app:     nil,
			wantErr: true,
			errType: ErrInvalidConfig{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.Default()
			svc, err := NewKMSService(nil, logger)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if svc != nil {
					t.Error("expected nil service on error")
				}
				// Verify error type
				if _, ok := err.(ErrInvalidConfig); !ok {
					t.Errorf("expected ErrInvalidConfig, got %T", err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestKMSService_RegisterGRPCServices_NilServer(t *testing.T) {
	t.Parallel()

	// Create a minimal KMSService for testing
	svc := &KMSService{
		logger: slog.Default(),
	}

	err := svc.RegisterGRPCServices(nil)
	if err == nil {
		t.Error("expected error for nil gRPC server, got nil")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected ErrInvalidConfig, got %T", err)
	}
}

func TestKMSService_StartStop(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()

	// Test Start
	if err := svc.Start(ctx); err != nil {
		t.Errorf("Start failed: %v", err)
	}

	if !svc.IsRunning() {
		t.Error("expected service to be running after Start")
	}

	// Test idempotent Start
	if err := svc.Start(ctx); err != nil {
		t.Errorf("idempotent Start failed: %v", err)
	}

	// Test Stop
	if err := svc.Stop(ctx); err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	if svc.IsRunning() {
		t.Error("expected service to not be running after Stop")
	}

	// Test idempotent Stop
	if err := svc.Stop(ctx); err != nil {
		t.Errorf("idempotent Stop failed: %v", err)
	}
}

func TestKMSService_Name(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	if name := svc.Name(); name != "kms" {
		t.Errorf("expected name 'kms', got '%s'", name)
	}
}

func TestKMSService_IsRunning(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Initially not running
	if svc.IsRunning() {
		t.Error("expected service to not be running initially")
	}

	// After Start
	ctx := context.Background()
	_ = svc.Start(ctx)
	if !svc.IsRunning() {
		t.Error("expected service to be running after Start")
	}

	// After Stop
	_ = svc.Stop(ctx)
	if svc.IsRunning() {
		t.Error("expected service to not be running after Stop")
	}
}

func TestKMSService_ServerAccessors(t *testing.T) {
	t.Parallel()

	svc := &KMSService{
		logger: slog.Default(),
	}

	// Without initialization, all servers should be nil
	if svc.KMSServer() != nil {
		t.Error("expected nil KMSServer before initialization")
	}

	if svc.SecretsServer() != nil {
		t.Error("expected nil SecretsServer before initialization")
	}

	if svc.CryptoServer() != nil {
		t.Error("expected nil CryptoServer before initialization")
	}

	if svc.DEKServer() != nil {
		t.Error("expected nil DEKServer before initialization")
	}
}
