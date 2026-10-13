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
// (CLI, REST, gRPC, QUIC, MCP, Unix) and asserts that each transport carries
// the typed ErrFIDO2NotConfigured for every operation: platformd wires no
// FIDO2 backend until the SDK exposes a runtime authenticator surface.
//
// Run via:
//
//	make integration-test-fido2
package fido2

import (
	"context"
	"testing"
	"time"

	daemonpkg "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
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

	// No FIDO2 backend is wired into platformd: the daemon reaches FIDO2 only
	// through the SDK, which has no runtime authenticator surface yet. Every
	// operation must therefore fail with the typed ErrFIDO2NotConfigured. A
	// nil error would mean a ceremony "succeeded" with no authenticator.
	steps := []struct {
		name string
		call func(context.Context) error
	}{
		{"ListDevices", func(c context.Context) error {
			_, err := cmd.ListDevices(c, &fido2sdk.ListDevicesRequest{})
			return err
		}},
		{"WaitDevice", func(c context.Context) error {
			_, err := cmd.WaitDevice(c, &fido2sdk.WaitDeviceRequest{TimeoutSeconds: 1})
			return err
		}},
		{"Info", func(c context.Context) error {
			_, err := cmd.Info(c, &fido2sdk.InfoRequest{Device: "software-0"})
			return err
		}},
		{"Register", func(c context.Context) error {
			_, err := cmd.Register(c, &fido2sdk.RegisterRequest{
				Username: "alice",
				Role:     fido2sdk.RoleAdmin,
			})
			return err
		}},
		{"Authenticate", func(c context.Context) error {
			_, err := cmd.Authenticate(c, &fido2sdk.AuthenticateRequest{CredentialID: "integration-credential-placeholder"})
			return err
		}},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			err := step.call(cctx)
			if !isBackendUnavailable(err) {
				t.Fatalf("%s error = %v, want %v", step.name, err, daemonpkg.ErrFIDO2NotConfigured)
			}
		})
	}
}
