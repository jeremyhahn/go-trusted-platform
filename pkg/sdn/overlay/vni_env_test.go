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

package overlay

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// newEnvController creates a running overlay controller for environment env
// (0 = none).
func newEnvController(t *testing.T, env uint16) *Controller {
	t.Helper()
	cfg := &Config{
		NodeID:            "test-node-env",
		VTEPIP:            netip.MustParseAddr("10.4.1.20"),
		UnderlayInterface: "eth0",
		UnderlayMTU:       9000,
		VXLANPort:         4789,
		BridgeName:        DefaultBridgeName,
		Environment:       env,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Stop(context.Background())
	})
	return c
}

// TestAddVNI_DerivesLowestFreeNetwork derives E·100000+n with n the lowest
// free network number, reusing a freed number.
func TestAddVNI_DerivesLowestFreeNetwork(t *testing.T) {
	c := newEnvController(t, 4)
	ctx := context.Background()

	for _, want := range []uint32{400001, 400002, 400003} {
		cfg := &VNIConfig{Kind: OverlayKindTenant}
		if err := c.AddVNI(ctx, cfg); err != nil {
			t.Fatalf("AddVNI: %v", err)
		}
		if cfg.VNI != want {
			t.Fatalf("derived VNI %d, want %d", cfg.VNI, want)
		}
	}
	if err := c.RemoveVNI(ctx, 400002); err != nil {
		t.Fatalf("RemoveVNI: %v", err)
	}
	cfg := &VNIConfig{}
	if err := c.AddVNI(ctx, cfg); err != nil {
		t.Fatalf("AddVNI: %v", err)
	}
	if cfg.VNI != 400002 {
		t.Fatalf("derived VNI %d, want the freed 400002", cfg.VNI)
	}
}

// TestAddVNI_ExplicitVNIInBlock accepts an explicit VNI of the environment.
func TestAddVNI_ExplicitVNIInBlock(t *testing.T) {
	c := newEnvController(t, 4)
	if err := c.AddVNI(context.Background(), &VNIConfig{VNI: 499999, Kind: OverlayKindPublic}); err != nil {
		t.Fatalf("AddVNI: %v", err)
	}
}

// TestAddVNI_ExplicitVNIOutsideBlock refuses a VNI of another environment.
func TestAddVNI_ExplicitVNIOutsideBlock(t *testing.T) {
	c := newEnvController(t, 4)
	for _, vni := range []uint32{300001, 400000, 1000} {
		err := c.AddVNI(context.Background(), &VNIConfig{VNI: vni})
		var target ErrVNIOutsideEnvironment
		if !errors.As(err, &target) || target.VNI != vni || target.Environment != 4 {
			t.Fatalf("VNI %d: want ErrVNIOutsideEnvironment, got %v", vni, err)
		}
		if !strings.Contains(err.Error(), "environment 4") {
			t.Errorf("message %q", err.Error())
		}
	}
}

// TestAddVNI_NoEnvironment needs an explicit VNI: derivation has no block.
func TestAddVNI_NoEnvironment(t *testing.T) {
	c := newEnvController(t, 0)
	err := c.AddVNI(context.Background(), &VNIConfig{})
	if !errors.As(err, new(ErrEnvironmentRequired)) {
		t.Fatalf("want ErrEnvironmentRequired, got %v", err)
	}
	if !strings.Contains(err.Error(), "sdn.environment.id") {
		t.Errorf("message %q", err.Error())
	}
	if err := c.AddVNI(context.Background(), &VNIConfig{VNI: 5000}); err != nil {
		t.Fatalf("explicit VNI without an environment: %v", err)
	}
}

// TestAddVNI_InvalidKind refuses a kind that is not an overlay kind.
func TestAddVNI_InvalidKind(t *testing.T) {
	c := newEnvController(t, 4)
	err := c.AddVNI(context.Background(), &VNIConfig{Kind: "trusted"})
	var target ErrInvalidOverlayKind
	if !errors.As(err, &target) || target.Kind != "trusted" {
		t.Fatalf("want ErrInvalidOverlayKind, got %v", err)
	}
}

// TestAddVNI_NilConfig returns ErrVNINotFound.
func TestAddVNI_NilConfig(t *testing.T) {
	c := newEnvController(t, 4)
	if err := c.AddVNI(context.Background(), nil); !errors.Is(err, ErrVNINotFound) {
		t.Fatalf("want ErrVNINotFound, got %v", err)
	}
}

// TestErrVNIBlockExhausted_Error names the environment.
func TestErrVNIBlockExhausted_Error(t *testing.T) {
	if msg := (ErrVNIBlockExhausted{Environment: 4}).Error(); !strings.Contains(msg, "environment 4") {
		t.Errorf("message %q", msg)
	}
}

// TestAddVNI_ConcurrentDerivationIsUnique adds many overlay networks at once
// with derived VNIs: every call succeeds and no two get the same VNI.
func TestAddVNI_ConcurrentDerivationIsUnique(t *testing.T) {
	c := newEnvController(t, 4)
	ctx := context.Background()

	const n = 32
	vnis := make(chan uint32, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := &VNIConfig{Kind: OverlayKindTenant}
			if err := c.AddVNI(ctx, cfg); err != nil {
				errs <- err
				return
			}
			vnis <- cfg.VNI
		}()
	}
	wg.Wait()
	close(vnis)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent AddVNI: %v", err)
	}
	seen := make(map[uint32]struct{}, n)
	for v := range vnis {
		if _, dup := seen[v]; dup {
			t.Fatalf("VNI %d derived twice", v)
		}
		seen[v] = struct{}{}
	}
	if len(seen) != n {
		t.Fatalf("got %d VNIs, want %d", len(seen), n)
	}
}
