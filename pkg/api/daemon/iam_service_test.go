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

//go:build iam

package daemon

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func iamServiceTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestIAMService_StartStop(t *testing.T) {
	t.Run("Start sets running to true", func(t *testing.T) {
		svc := &IAMService{
			logger: iamServiceTestLogger(),
		}

		if svc.IsRunning() {
			t.Error("service should not be running initially")
		}

		err := svc.Start(context.Background())
		if err != nil {
			t.Errorf("Start() error = %v", err)
		}

		if !svc.IsRunning() {
			t.Error("service should be running after Start()")
		}
	})

	t.Run("Start is idempotent", func(t *testing.T) {
		svc := &IAMService{
			logger: iamServiceTestLogger(),
		}

		// Start twice
		_ = svc.Start(context.Background())
		err := svc.Start(context.Background())
		if err != nil {
			t.Errorf("second Start() error = %v", err)
		}

		if !svc.IsRunning() {
			t.Error("service should still be running")
		}
	})

	t.Run("Stop sets running to false", func(t *testing.T) {
		svc := &IAMService{
			logger: iamServiceTestLogger(),
		}

		// Start first
		_ = svc.Start(context.Background())
		if !svc.IsRunning() {
			t.Error("service should be running after Start()")
		}

		err := svc.Stop(context.Background())
		if err != nil {
			t.Errorf("Stop() error = %v", err)
		}

		if svc.IsRunning() {
			t.Error("service should not be running after Stop()")
		}
	})

	t.Run("Stop is idempotent", func(t *testing.T) {
		svc := &IAMService{
			logger: iamServiceTestLogger(),
		}

		// Stop without starting
		err := svc.Stop(context.Background())
		if err != nil {
			t.Errorf("Stop() on non-running service error = %v", err)
		}

		if svc.IsRunning() {
			t.Error("service should not be running")
		}
	})
}

func TestIAMService_Name(t *testing.T) {
	svc := &IAMService{}

	name := svc.Name()
	if name != "iam" {
		t.Errorf("Name() = %v, want iam", name)
	}
}

func TestIAMService_IsRunning(t *testing.T) {
	t.Run("returns false initially", func(t *testing.T) {
		svc := &IAMService{}
		if svc.IsRunning() {
			t.Error("IsRunning() should return false initially")
		}
	})

	t.Run("returns true after start", func(t *testing.T) {
		svc := &IAMService{
			logger: iamServiceTestLogger(),
		}
		svc.running.Store(true)
		if !svc.IsRunning() {
			t.Error("IsRunning() should return true after running.Store(true)")
		}
	})

	t.Run("returns false after stop", func(t *testing.T) {
		svc := &IAMService{
			logger: iamServiceTestLogger(),
		}
		svc.running.Store(true)
		svc.running.Store(false)
		if svc.IsRunning() {
			t.Error("IsRunning() should return false after running.Store(false)")
		}
	})
}

func TestNewIAMService_NilApp(t *testing.T) {
	_, err := NewIAMService(nil, iamServiceTestLogger())
	if err == nil {
		t.Error("NewIAMService(nil, logger) should return error")
	}

	var invalidConfig ErrInvalidConfig
	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("NewIAMService(nil, logger) error = %T, want ErrInvalidConfig", err)
	}
	_ = invalidConfig
}
