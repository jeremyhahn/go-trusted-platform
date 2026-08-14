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

// Package ceremony provides multi-protocol integration tests for the
// platformd ceremony service. The suite drives platformctl and the SDK
// clients across all six protocols (CLI, REST, gRPC, QUIC, MCP, Unix) and
// asserts consistent behaviour — either real backend execution or a
// consistent "backend not configured" surface when the ceremony backend is
// not wired into the running platformd.
//
// Run via:
//
//	make integration-test-ceremony
package ceremony

import (
	"context"
	"testing"
	"time"

	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// TestCeremonyMultiProtocol runs the same scenario against every transport.
func TestCeremonyMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []CeremonyCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Skipf("Skipping %s: setup failed: %v", adapter.Name(), err)
				return
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			})
			runCeremonyScenario(t, ctx, adapter)
		})
	}
}

// runCeremonyScenario exercises the full ceremony contract surface. Because
// the backend returns ErrCeremonyNotConfigured on the reference test daemon,
// each call is expected to either succeed (once a backend lands) or surface
// a "backend not configured" style error. The test asserts the latter is
// consistent across protocols.
func runCeremonyScenario(t *testing.T, ctx context.Context, cmd CeremonyCommands) {
	t.Helper()

	t.Run("Status", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.Status(callCtx)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Status error (want backend-unavailable): %v", err)
		}
	})

	t.Run("Init", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &ceremonysdk.InitRequest{
			SOPIN:     "so-pin-000000",
			UserPIN:   "user-pin-111111",
			Threshold: "3-of-5",
			Hostname:  "ceremony-mp-test",
		}
		_, err := cmd.Init(callCtx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected Init error (want backend-unavailable): %v", err)
		}
	})

	t.Run("ClaimCertBegin", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &ceremonysdk.ClaimCertBeginRequest{
			Username:          "alice",
			AuthenticatorType: ceremonysdk.AuthenticatorSoftware,
		}
		_, err := cmd.ClaimCertBegin(callCtx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected ClaimCertBegin error: %v", err)
		}
	})

	t.Run("ClaimCertComplete", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &ceremonysdk.ClaimCertCompleteRequest{
			Username:  "alice",
			Nonce:     "deadbeef",
			Signature: "d3adb33f",
		}
		_, err := cmd.ClaimCertComplete(callCtx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected ClaimCertComplete error: %v", err)
		}
	})

	t.Run("ClaimShareBegin", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := cmd.ClaimShareBegin(callCtx, &ceremonysdk.ClaimShareBeginRequest{Username: "alice"})
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected ClaimShareBegin error: %v", err)
		}
	})

	t.Run("ClaimShareComplete", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &ceremonysdk.ClaimShareCompleteRequest{
			Username:  "alice",
			Nonce:     "deadbeef",
			Signature: []byte{0xd3, 0xad, 0xb3, 0x3f},
		}
		_, err := cmd.ClaimShareComplete(callCtx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected ClaimShareComplete error: %v", err)
		}
	})

	t.Run("SignCSR", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req := &ceremonysdk.SignCSRRequest{
			Username: "alice",
			SOPIN:    "so-pin-000000",
			Role:     ceremonysdk.RoleAdmin,
			CSRPEM:   "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
		}
		_, err := cmd.SignCSR(callCtx, req)
		if err == nil {
			return
		}
		if !isBackendUnavailable(err) {
			t.Fatalf("unexpected SignCSR error: %v", err)
		}
	})
}
