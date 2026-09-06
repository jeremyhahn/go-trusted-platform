// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package ntp provides multi-protocol integration tests for the platformd
// time-synchronization service. The suite drives the operator CLI plus all
// five SDK transports (REST, gRPC, QUIC, MCP, Unix) against a live daemon and
// asserts feature parity: every transport must answer the same three
// operations with the same shape and the same failure classes.
//
// Run via:
//
//	make integration-test-ntp
package ntp

import (
	"context"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestNTPMultiProtocol runs the shared scenario against every protocol.
func TestNTPMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []NTPCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "ntp", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			})
			runNTPScenario(t, ctx, adapter)
		})
	}
}

// runNTPScenario exercises the full NTP surface over one transport.
func runNTPScenario(t *testing.T, ctx context.Context, cmd NTPCommands) {
	t.Helper()

	t.Run("Status", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		status, err := cmd.Status(cctx)
		if err != nil {
			if IsNotConfigured(err) {
				t.Skipf("%s: platformd has no ntp: section: %v", cmd.Name(), err)
				return
			}
			t.Fatalf("%s Status: %v", cmd.Name(), err)
		}
		assertStatusIsCoherent(t, cmd.Name(), status)
	})

	t.Run("Sources", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		sources, err := cmd.Sources(cctx)
		if err != nil {
			if IsNotConfigured(err) {
				t.Skipf("%s: platformd has no ntp: section: %v", cmd.Name(), err)
				return
			}
			t.Fatalf("%s Sources: %v", cmd.Name(), err)
		}
		for _, source := range sources {
			if source.GetAddress() == "" {
				t.Fatalf("%s: source %+v has no address", cmd.Name(), source)
			}
			// Reachability must agree with the reachability register:
			// a source with no successful poll cannot be reachable.
			if source.GetReachable() && source.GetReach() == 0 {
				t.Fatalf("%s: source %s reports reachable with an empty reach register",
					cmd.Name(), source.GetAddress())
			}
		}
	})

	t.Run("Step", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		status, err := cmd.Step(cctx)
		switch {
		case err == nil:
			assertStatusIsCoherent(t, cmd.Name(), status)
		case IsNotConfigured(err):
			t.Skipf("%s: platformd has no ntp: section: %v", cmd.Name(), err)
		case IsNoReachableSource(err):
			// The documented conflict contract: a step with nothing to
			// step towards is refused rather than moving the clock on
			// stale data.
			t.Logf("%s: step refused with no reachable source (expected contract): %v",
				cmd.Name(), err)
		default:
			t.Fatalf("%s Step: %v", cmd.Name(), err)
		}
	})
}

// assertStatusIsCoherent checks the invariants every transport must uphold.
func assertStatusIsCoherent(t *testing.T, transport string, status *platformv1.NTPStatus) {
	t.Helper()

	if status == nil {
		t.Fatalf("%s: nil status", transport)
	}
	if status.GetStratum() > 16 {
		t.Fatalf("%s: stratum %d is out of range", transport, status.GetStratum())
	}
	if status.GetSourcesReachable() > status.GetSourcesTotal() {
		t.Fatalf("%s: %d reachable of %d total sources", transport,
			status.GetSourcesReachable(), status.GetSourcesTotal())
	}
	if status.GetSynced() && status.GetLeapStatus() == "Not synchronised" {
		t.Fatalf("%s: synced=true contradicts leap status %q", transport, status.GetLeapStatus())
	}
	if status.GetMode() == "" {
		t.Fatalf("%s: status carries no mode", transport)
	}
	if status.GetAnomaly() && status.GetAnomalyReason() == "" {
		t.Fatalf("%s: anomaly flagged with no reason", transport)
	}
}
