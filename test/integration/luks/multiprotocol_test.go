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

//go:build integration

// Package luks provides multi-protocol integration tests for the platformd
// LUKS2 volume service. Mutating operations (enroll, remove, change-passphrase,
// test-unlock) require root plus a loopback LUKS2 volume; when not root the
// test falls back to a read-only contract check that asserts each transport
// returns a consistent "backend not configured" / "root required" error
// surface.
//
// Run via (in the devcontainer, as root):
//
//	make integration-test-luks
package luks

import (
	"context"
	"testing"
	"time"

	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestLUKSMultiProtocol runs the LUKS scenario against every transport.
func TestLUKSMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	// If running as root and cryptsetup is available, provision a loopback
	// LUKS2 volume and exercise mutating operations against it. Otherwise
	// the test still validates the read-only contract surface.
	var loop *LoopDevice
	if IsRoot() {
		d, err := NewLoopDevice(ctx)
		if err != nil {
			t.Logf("loopback setup failed (mutating tests will be skipped): %v", err)
		} else {
			loop = d
			t.Cleanup(func() { loop.Cleanup(context.Background()) })
		}
	}

	adapters := []LUKSCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "luks", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			})
			runLUKSScenario(t, ctx, adapter, loop)
		})
	}
}

// runLUKSScenario exercises the LUKS contract. When loop is non-nil and we are
// root, mutating ops target the loopback device; otherwise only read-only
// contract checks run.
func runLUKSScenario(t *testing.T, ctx context.Context, cmd LUKSCommands, loop *LoopDevice) {
	t.Helper()

	device := ""
	initialPassphrase := ""
	if loop != nil {
		device = loop.DevicePath
		initialPassphrase = loop.InitialPassphrase
	}

	t.Run("Status", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.Status(cctx, &lukssdk.StatusRequest{Device: device})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Status error: %v", err)
		}
	})

	t.Run("ListSlots", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.ListSlots(cctx, &lukssdk.ListSlotsRequest{Device: device})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected ListSlots error: %v", err)
		}
	})

	t.Run("Info", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.Info(cctx, &lukssdk.InfoRequest{Device: device})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Info error: %v", err)
		}
	})

	// Mutating operations require both root and a configured backend. The
	// adapter still invokes them so we exercise wire serialization; failure
	// is accepted as long as it matches the unavailable surface.
	if loop == nil {
		t.Log("skipping mutating LUKS tests: require root + loopback volume")
	}

	t.Run("EnrollPassphrase", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &lukssdk.EnrollPassphraseRequest{
			Device:             device,
			ExistingPassphrase: initialPassphrase,
			NewPassphrase:      "multiprotocol-test-pp",
		}
		_, err := cmd.EnrollPassphrase(cctx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected EnrollPassphrase error: %v", err)
		}
	})

	t.Run("EnrollRecovery", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &lukssdk.EnrollRecoveryRequest{
			Device:             device,
			ExistingPassphrase: initialPassphrase,
		}
		_, err := cmd.EnrollRecovery(cctx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected EnrollRecovery error: %v", err)
		}
	})

	// A PIN-required FIDO2 keyslot is refused on every transport until the
	// SDK ships a PIN-capable handler (#584), and nothing is written.
	t.Run("EnrollFIDO2RequirePIN", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		before, beforeErr := cmd.ListSlots(cctx, &lukssdk.ListSlotsRequest{Device: device})
		_, err := cmd.EnrollFIDO2(cctx, &lukssdk.EnrollFIDO2Request{
			Device:             device,
			ExistingPassphrase: initialPassphrase,
			CredentialID:       "multiprotocol-cred",
			RequirePIN:         true,
		})
		if err == nil {
			t.Fatal("EnrollFIDO2 with RequirePIN succeeded; want the PIN refusal")
		}
		if !isPINRefusal(err) && !isBackendUnavailable(err) {
			t.Fatalf("unexpected EnrollFIDO2 error: %v", err)
		}
		after, afterErr := cmd.ListSlots(cctx, &lukssdk.ListSlotsRequest{Device: device})
		if beforeErr == nil && afterErr == nil && len(after.Slots) != len(before.Slots) {
			t.Errorf("keyslots changed across a refused enrolment: before %v, after %v", before.Slots, after.Slots)
		}
	})

	t.Run("TestUnlock", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &lukssdk.TestUnlockRequest{Device: device, Slot: 0}
		_, err := cmd.TestUnlock(cctx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected TestUnlock error: %v", err)
		}
	})

	t.Run("RemoveKey", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &lukssdk.RemoveKeyRequest{Device: device, Slot: 1}
		_, err := cmd.RemoveKey(cctx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected RemoveKey error: %v", err)
		}
	})

	t.Run("ChangePassphrase", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &lukssdk.ChangePassphraseRequest{
			Device: device, Slot: 0,
			OldPassphrase: initialPassphrase,
			NewPassphrase: "multiprotocol-change-pp",
		}
		_, err := cmd.ChangePassphrase(cctx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected ChangePassphrase error: %v", err)
		}
	})
}
