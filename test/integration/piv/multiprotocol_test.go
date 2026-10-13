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

// Package piv provides multi-protocol integration tests for the platformd
// PIV service. The suite drives the SDK clients across all six protocols
// (CLI, REST, gRPC, QUIC, MCP, Unix) and validates that operations return
// either a real backend result or a consistent "backend not configured"
// error surface across every transport.
//
// No real smartcards are required. When the daemon has no PIV backend, every
// transport must report ErrPIVNotConfigured; any other error fails the test.
//
// Run via:
//
//	make integration-test-piv
package piv

import (
	"context"
	"testing"
	"time"

	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestPIVMultiProtocol runs the shared scenario against every protocol.
func TestPIVMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []PIVCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "piv", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			})
			runPIVScenario(t, ctx, adapter)
		})
	}
}

func runPIVScenario(t *testing.T, ctx context.Context, cmd PIVCommands) {
	t.Helper()

	t.Run("ListDevices", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.ListDevices(cctx, &pivsdk.ListDevicesRequest{})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected ListDevices error: %v", err)
		}
	})

	t.Run("ListSlots", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.ListSlots(cctx, &pivsdk.ListSlotsRequest{Device: "software-0"})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected ListSlots error: %v", err)
		}
	})

	t.Run("SlotInfo", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.SlotInfo(cctx, &pivsdk.SlotInfoRequest{Slot: "9a"})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected SlotInfo error: %v", err)
		}
	})

	t.Run("Generate", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.Generate(cctx, &pivsdk.GenerateRequest{
			Slot:      "9a",
			Algorithm: pivsdk.AlgorithmECDSA,
			PIN:       "123456",
		})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Generate error: %v", err)
		}
	})

	t.Run("Import", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.Import(cctx, &pivsdk.ImportRequest{
			Slot:          "9a",
			PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
			PIN:           "123456",
		})
		// Import fails closed (ErrPIVKeyImportUnsupported): reporting
		// success would mean the key was filed as a certificate.
		if err == nil {
			t.Fatal("Import reported success; it must fail closed")
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Import error: %v", err)
		}
	})

	t.Run("Sign", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.Sign(cctx, &pivsdk.SignRequest{
			Slot:    "9a",
			Payload: []byte("multiprotocol-piv-test"),
			PIN:     "123456",
		})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Sign error: %v", err)
		}
	})

	t.Run("Attest", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.Attest(cctx, &pivsdk.AttestRequest{Slot: "9a"})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Attest error: %v", err)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.Reset(cctx, &pivsdk.ResetRequest{Device: "software-0"})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Reset error: %v", err)
		}
	})
}
