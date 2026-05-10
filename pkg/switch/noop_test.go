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
	"testing"
)

func TestNoopConfigurator_Configure(t *testing.T) {
	ctx := context.Background()
	noop := NewNoopConfigurator()

	config := &Config{
		VLANs: []VLANConfig{{ID: 10, Name: "test"}},
		Ports: []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10}}},
	}

	if err := noop.Configure(ctx, config); err != nil {
		t.Fatalf("expected nil error from noop Configure, got: %v", err)
	}

	if err := noop.ConfigureVLANs(ctx, config.VLANs); err != nil {
		t.Fatalf("expected nil error from noop ConfigureVLANs, got: %v", err)
	}

	if err := noop.ConfigurePorts(ctx, config.Ports); err != nil {
		t.Fatalf("expected nil error from noop ConfigurePorts, got: %v", err)
	}

	if err := noop.Close(); err != nil {
		t.Fatalf("expected nil error from noop Close, got: %v", err)
	}
}

func TestNoopConfigurator_Verify(t *testing.T) {
	ctx := context.Background()
	noop := NewNoopConfigurator()

	config := &Config{
		VLANs: []VLANConfig{{ID: 10, Name: "test"}},
	}

	if err := noop.Verify(ctx, config); err != nil {
		t.Fatalf("expected nil error from noop Verify, got: %v", err)
	}
}

func TestNoopConfigurator_NilConfig(t *testing.T) {
	ctx := context.Background()
	noop := NewNoopConfigurator()

	// Noop handles nil gracefully
	if err := noop.Configure(ctx, nil); err != nil {
		t.Fatalf("expected nil error from noop Configure with nil config, got: %v", err)
	}

	if err := noop.Verify(ctx, nil); err != nil {
		t.Fatalf("expected nil error from noop Verify with nil config, got: %v", err)
	}
}
