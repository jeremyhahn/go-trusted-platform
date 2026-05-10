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

package switchmgmt

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
)

// --- NewManager factory tests ---

func TestNewManager_NilConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mgr, err := NewManager(nil, logger)
	if err != nil {
		t.Fatalf("expected no error for nil config, got: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected noop manager, got nil")
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("expected noop Close to return nil, got: %v", err)
	}
}

func TestNewManager_Noop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := &Config{Vendor: VendorNoop}
	mgr, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected noop manager, got nil")
	}
}

func TestNewManager_UnsupportedVendor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := &Config{
		Vendor:   SwitchVendor("arista"),
		Host:     "10.0.0.1",
		User:     "admin",
		Password: "secret",
	}
	mgr, err := NewManager(config, logger)
	if mgr != nil {
		t.Fatal("expected nil manager for unsupported vendor")
	}
	var unsupported ErrUnsupportedVendor
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected ErrUnsupportedVendor, got: %T %v", err, err)
	}
}

func TestNewManager_CiscoNexus_InvalidConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "",
		User:   "admin",
	}
	mgr, err := NewManager(config, logger)
	if mgr != nil {
		t.Fatal("expected nil manager for invalid config")
	}
	var invalidCfg ErrInvalidConfig
	if !errors.As(err, &invalidCfg) {
		t.Fatalf("expected ErrInvalidConfig, got: %T %v", err, err)
	}
}

// --- Noop Manager interface compliance ---

func TestNoopManager_SetPortVLAN(t *testing.T) {
	mgr := NewNoopManager()
	ctx := context.Background()
	if err := mgr.SetPortVLAN(ctx, "Eth1/1", 100); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestNoopManager_GetPortVLAN(t *testing.T) {
	mgr := NewNoopManager()
	ctx := context.Background()
	vlan, err := mgr.GetPortVLAN(ctx, "Eth1/1")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if vlan != 0 {
		t.Fatalf("expected vlan 0, got: %d", vlan)
	}
}

func TestNoopManager_GetPortStatus(t *testing.T) {
	mgr := NewNoopManager()
	ctx := context.Background()
	status, err := mgr.GetPortStatus(ctx, "Eth1/1")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if status == nil {
		t.Fatal("expected non-nil status")
	}
}

func TestNoopManager_ListPorts(t *testing.T) {
	mgr := NewNoopManager()
	ctx := context.Background()
	ports, err := mgr.ListPorts(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if ports != nil {
		t.Fatalf("expected nil ports, got: %v", ports)
	}
}

func TestNoopManager_EnablePort(t *testing.T) {
	mgr := NewNoopManager()
	ctx := context.Background()
	if err := mgr.EnablePort(ctx, "Eth1/1"); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestNoopManager_DisablePort(t *testing.T) {
	mgr := NewNoopManager()
	ctx := context.Background()
	if err := mgr.DisablePort(ctx, "Eth1/1"); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestNoopManager_Close(t *testing.T) {
	mgr := NewNoopManager()
	if err := mgr.Close(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

// --- Service tests ---

func TestNewService_Empty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	svc, err := NewService(nil, logger)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("expected nil error on close, got: %v", err)
	}
}

func TestNewService_NoopConfigs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	configs := []Config{
		{Name: "switch-01", Vendor: VendorNoop},
		{Name: "switch-02", Vendor: VendorNoop},
	}
	svc, err := NewService(configs, logger)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	mgr1, err := svc.Manager("switch-01")
	if err != nil {
		t.Fatalf("expected manager for switch-01, got: %v", err)
	}
	if mgr1 == nil {
		t.Fatal("expected non-nil manager")
	}

	mgr2, err := svc.Manager("switch-02")
	if err != nil {
		t.Fatalf("expected manager for switch-02, got: %v", err)
	}
	if mgr2 == nil {
		t.Fatal("expected non-nil manager")
	}

	if err := svc.Close(); err != nil {
		t.Fatalf("unexpected error on close: %v", err)
	}
}

func TestNewService_ManagerNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	svc, err := NewService(nil, logger)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	_, mgrErr := svc.Manager("nonexistent")
	if mgrErr == nil {
		t.Fatal("expected error for nonexistent manager")
	}
	var notFound ErrManagerNotFound
	if !errors.As(mgrErr, &notFound) {
		t.Fatalf("expected ErrManagerNotFound, got: %T %v", mgrErr, mgrErr)
	}
}

func TestNewService_FallbackToHostAsName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	configs := []Config{
		{Vendor: VendorNoop, Host: "192.168.1.1"},
	}
	svc, err := NewService(configs, logger)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	mgr, mgrErr := svc.Manager("192.168.1.1")
	if mgrErr != nil {
		t.Fatalf("expected manager by host fallback, got: %v", mgrErr)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}

	if err := svc.Close(); err != nil {
		t.Fatalf("unexpected error on close: %v", err)
	}
}

func TestNewService_InvalidConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	configs := []Config{
		{
			Name:   "bad-switch",
			Vendor: VendorCiscoNexus,
			Host:   "",
		},
	}
	_, err := NewService(configs, logger)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}
