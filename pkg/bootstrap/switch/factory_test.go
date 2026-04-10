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
	"errors"
	"log/slog"
	"os"
	"testing"
)

func TestNewConfigurator_NilConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	configurator, err := NewConfigurator(nil, logger)
	if err != nil {
		t.Fatalf("expected no error for nil config, got: %v", err)
	}
	if configurator == nil {
		t.Fatal("expected noop configurator, got nil")
	}
	// Verify it is a noop by checking it does not error
	if closeErr := configurator.Close(); closeErr != nil {
		t.Fatalf("expected noop Close to return nil, got: %v", closeErr)
	}
}

func TestNewConfigurator_CiscoNexus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		Port:   22,
		User:   "admin",
		SSHKey: "/tmp/test-key",
	}
	configurator, err := NewConfigurator(config, logger)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if configurator == nil {
		t.Fatal("expected configurator, got nil")
	}
	// Clean up — no actual SSH connection is made until ensureConnected
	configurator.Close()
}

func TestNewConfigurator_Noop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := &Config{
		Vendor: VendorNoop,
	}
	configurator, err := NewConfigurator(config, logger)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if configurator == nil {
		t.Fatal("expected noop configurator, got nil")
	}
}

func TestNewConfigurator_UnsupportedVendor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := &Config{
		Vendor: SwitchVendor("juniper"),
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}
	configurator, err := NewConfigurator(config, logger)
	if configurator != nil {
		t.Fatal("expected nil configurator for unsupported vendor")
	}
	var unsupported ErrUnsupportedVendor
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected ErrUnsupportedVendor, got: %T %v", err, err)
	}
	if unsupported.Vendor != "juniper" {
		t.Fatalf("expected vendor 'juniper', got: %s", unsupported.Vendor)
	}
}

func TestNewConfigurator_CiscoNexus_InvalidConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "", // missing host
		User:   "admin",
		SSHKey: "/tmp/key",
	}
	configurator, err := NewConfigurator(config, logger)
	if configurator != nil {
		t.Fatal("expected nil configurator for invalid config")
	}
	var invalidCfg ErrInvalidConfig
	if !errors.As(err, &invalidCfg) {
		t.Fatalf("expected ErrInvalidConfig, got: %T %v", err, err)
	}
}
