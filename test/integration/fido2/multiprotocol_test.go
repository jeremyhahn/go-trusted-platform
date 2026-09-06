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

// Package fido2 provides multi-protocol integration tests for the platformd
// FIDO2 service. The suite drives the SDK clients across all six protocols
// (CLI, REST, gRPC, QUIC, MCP, Unix) and validates that each transport
// returns either a real backend result or a consistent "backend not
// configured" error when no FIDO2 authenticator is attached to the host.
//
// No physical authenticator is required for the CI path: the test treats
// the Unavailable surface as the contract under test.
//
// Run via:
//
//	make integration-test-fido2
package fido2

import (
	"context"
	"testing"
	"time"

	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestFIDO2MultiProtocol runs the shared scenario against every protocol.
func TestFIDO2MultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []FIDO2Commands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "fido2", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			})
			runFIDO2Scenario(t, ctx, adapter)
		})
	}
}

func runFIDO2Scenario(t *testing.T, ctx context.Context, cmd FIDO2Commands) {
	t.Helper()

	t.Run("ListDevices", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.ListDevices(cctx, &fido2sdk.ListDevicesRequest{})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected ListDevices error: %v", err)
		}
	})

	t.Run("WaitDevice", func(t *testing.T) {
		// Use a short timeout to bound worst-case CI time when no device is
		// attached. The backend returns Unavailable once the timeout fires
		// or immediately if not configured.
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_, err := cmd.WaitDevice(cctx, &fido2sdk.WaitDeviceRequest{TimeoutSeconds: 1})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected WaitDevice error: %v", err)
		}
	})

	t.Run("Info", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.Info(cctx, &fido2sdk.InfoRequest{Device: "software-0"})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Info error: %v", err)
		}
	})

	t.Run("Register", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &fido2sdk.RegisterRequest{
			Username:   "alice",
			Role:       fido2sdk.RoleAdmin,
			RequirePIN: false,
			RequireUV:  false,
		}
		_, err := cmd.Register(cctx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Register error: %v", err)
		}
	})

	t.Run("Authenticate", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &fido2sdk.AuthenticateRequest{CredentialID: "integration-credential-placeholder"}
		_, err := cmd.Authenticate(cctx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Authenticate error: %v", err)
		}
	})
}
